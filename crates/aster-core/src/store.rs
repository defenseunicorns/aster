//! Durable local state for an offline-first mesh node.
//!
//! The durable implementation uses SQLite through the safe `rusqlite` wrapper.
//! SQLite is implemented in C, which is an intentional, narrowly-scoped exception
//! to the Rust-first implementation rule: its transactions make the publisher
//! counter, sealed envelope, indexes, and outbound work queue one crash-atomic
//! commit, while its long maintenance history avoids inventing a new persistence
//! engine. The build pins `rusqlite` and enables only its `bundled` feature, so the
//! reviewed SQLite source is compiled with the library instead of depending on an
//! unknown system copy. No SQLite extension loading or optional cache/wasm layer is
//! enabled. Payloads remain source-sealed opaque bytes in this module.

use crate::bridge::{
    AuthorizationEnvelope, BridgeAuthorization, BridgeRoute, MAX_AUTHORIZATION_TOTAL_BYTES,
    MAX_WRAPPER_TOTAL_BYTES, exact_object_id, priority_allowed,
};
use crate::crypto::{PendingBatchItem, VerifiedBatchItem, VerifiedBatchProof};
use crate::custody::{CustodyAge, CustodyContinuity, CustodyDisposition, evaluate_custody};
pub use crate::envelope::{ControlPrincipal, EnvelopeId, Revocation, ScopeEpoch};
use crate::model::{
    CausalStamp, ConflictAnnotation, DataClass, Dot, ItemId, MAX_CAUSAL_CONTEXT_ENTRIES, NodeId,
    PeerStatus, Priority, Scope, SyncStatus, Topic, VersionVector,
};
use crate::wire::{
    ObjectId, ObjectKind, SEMANTIC_PROTOCOL_V2, SEMANTIC_PROTOCOL_V3, SEMANTIC_PROTOCOL_V4,
    SEMANTIC_PROTOCOL_V5, SEMANTIC_PROTOCOL_V6, SEMANTIC_PROTOCOL_V7,
};
use rusqlite::{Connection, OptionalExtension, Row, Transaction, params};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::error::Error;
use std::fmt::{self, Display, Formatter};
use std::path::Path;

const SCHEMA_VERSION: i64 = 16;
// Schema-11 stores had one node-global frontier. Schema 12 preserves every one
// of those observations in this domain, which cannot collide with validated
// Topic or Scope values because both reject the empty string.
const LEGACY_CAUSAL_TOPIC: &str = "";
const LEGACY_CAUSAL_SCOPE: &str = "";
const TRANSFER_STORAGE_KEY_DOMAIN: &[u8] = b"aster/transfer-storage-key/v1";
const DAY_MS: u64 = 24 * 60 * 60 * 1_000;
const MAX_STAGED_OBJECT_BYTES: u64 = 4 * 1024 * 1024;
const MAX_STAGING_BYTES: u64 = 64 * 1024 * 1024;
const MAX_STAGING_OBJECTS: u64 = 10_000;
const MAX_STAGED_RANGES_PER_OBJECT: u64 = 4_095;
const MAX_STAGED_RANGES_GLOBAL: u64 = 65_536;
const MAX_BATCH_STORE_PAGE: usize = 1_024;
pub(crate) const MAX_COMPOSITE_INVENTORY_OBJECTS: usize = 100_000;
pub(crate) const INVENTORY_OBJECT_LIMIT_ERROR: &str = "composite inventory object limit exceeded";
#[allow(dead_code)]
const MAX_BRIDGE_STORE_BATCH: usize = 1_024;
#[allow(dead_code)]
const MAX_BRIDGE_PROJECTION_RESULTS: usize = 4_096;
#[allow(dead_code)]
const MAX_ACTIVE_BRIDGE_AUTHORIZATIONS: u64 = 4_096;

/// Retention and capacity policy persisted with a store.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StoreConfig {
    /// Whole-store hard item-count limit.
    pub max_items: u64,
    /// Whole-store hard byte limit. One quarter (up to 64 MiB) is isolated for
    /// unauthenticated transfer staging; committed records cannot be evicted
    /// by bytes admitted to that staging partition.
    pub max_bytes: u64,
    /// Minimum time deletion markers remain eligible for synchronization.
    pub tombstone_retention_ms: u64,
    /// Recovery window for causally superseded or tie-break-losing versions.
    pub superseded_retention_ms: u64,
}

impl Default for StoreConfig {
    fn default() -> Self {
        Self {
            max_items: 100_000,
            max_bytes: 512 * 1024 * 1024,
            // Longer than the proposed thirty-day disconnected interval.
            tombstone_retention_ms: 45 * DAY_MS,
            superseded_retention_ms: 45 * DAY_MS,
        }
    }
}

/// A scope-specific relay capacity override.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ScopeQuota {
    pub scope: Scope,
    pub max_items: u64,
    pub max_bytes: u64,
}

/// Current bounded-storage accounting.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct QuotaUsage {
    pub items: u64,
    pub bytes: u64,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
#[allow(dead_code)]
pub(crate) struct BridgeGcReport {
    pub(crate) mappings: u64,
    pub(crate) wrappers: u64,
    pub(crate) sources: u64,
    pub(crate) authorizations: u64,
    pub(crate) metadata_rows: u64,
}

/// Whether a retained version participates in the application projection.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum VersionStatus {
    /// Deterministically selected application-visible version.
    Current = 0,
    /// Concurrent version retained for recovery or record conflict display.
    Concurrent = 1,
    /// Version causally replaced by a later version.
    Superseded = 2,
}

/// An authenticated item stored exactly as its source-sealed envelope.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StoredItem {
    pub id: ItemId,
    /// SHA-256 of the stable source-sealed envelope transferred by sync.
    pub envelope_id: EnvelopeId,
    pub class: DataClass,
    pub topic: Topic,
    pub scope: Scope,
    pub priority: Priority,
    pub stamp: CausalStamp,
    /// Sequence within an Event topic and scope. Other classes use `None`.
    pub event_sequence: Option<u64>,
    /// Application key for State and Record projections.
    pub logical_key: Vec<u8>,
    pub ttl_ms: Option<u64>,
    /// Local observation time. `None` means no trustworthy time was available.
    pub observed_at_ms: Option<u64>,
    /// Source-sealed and authenticated bytes; never plaintext.
    pub sealed: Vec<u8>,
    /// Plaintext length disclosed by the authenticated envelope for quota/UI use.
    pub content_len: u64,
    pub tombstone: bool,
    pub key_epoch: u64,
    /// Authenticated age accumulated across prior custodians.
    pub custody_age_ms: u64,
    /// Local elapsed-clock continuity token for the persisted observation.
    pub custody_clock_id: Option<[u8; 16]>,
    /// Local elapsed tick at which `custody_age_ms` was persisted.
    pub custody_tick_ms: Option<u64>,
    /// False once elapsed time cannot be accounted for conservatively.
    pub custody_elapsed_available: bool,
    pub status: VersionStatus,
    pub inserted_order: u64,
}

/// Metadata-only inventory row used to reconcile stable objects without
/// materializing their source-sealed bytes or application/causal payloads.
///
/// Data rows retain exactly the fields needed for expiry and peer-route
/// authorization. Applied controls are mission-wide and therefore carry no
/// topic, scope, or route epoch.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum InventoryMetadata {
    Data {
        envelope_id: EnvelopeId,
        total_len: u64,
        priority: Priority,
        scope: Scope,
        key_epoch: u64,
        ttl_ms: Option<u64>,
        tombstone: bool,
        custody_age_ms: u64,
        custody_clock_id: Option<[u8; 16]>,
        custody_tick_ms: Option<u64>,
        custody_elapsed_available: bool,
    },
    Control {
        envelope_id: EnvelopeId,
        total_len: u64,
    },
}

impl InventoryMetadata {
    pub fn envelope_id(&self) -> EnvelopeId {
        match self {
            Self::Data { envelope_id, .. } | Self::Control { envelope_id, .. } => *envelope_id,
        }
    }

    pub fn total_len(&self) -> u64 {
        match self {
            Self::Data { total_len, .. } | Self::Control { total_len, .. } => *total_len,
        }
    }

    pub fn priority(&self) -> Priority {
        match self {
            Self::Data { priority, .. } => *priority,
            Self::Control { .. } => Priority::Flash,
        }
    }

    pub fn is_control(&self) -> bool {
        matches!(self, Self::Control { .. })
    }

    pub fn route(&self) -> Option<(&Scope, u64)> {
        match self {
            Self::Data {
                scope, key_epoch, ..
            } => Some((scope, *key_epoch)),
            Self::Control { .. } => None,
        }
    }

    pub fn is_forwardable_at(&self, sample: Option<CustodySample>) -> bool {
        match self {
            Self::Control { .. } => true,
            Self::Data {
                ttl_ms,
                tombstone,
                custody_age_ms,
                custody_clock_id,
                custody_tick_ms,
                custody_elapsed_available,
                ..
            } => custody_disposition_from_fields(
                *ttl_ms,
                *tombstone,
                *custody_age_ms,
                *custody_clock_id,
                *custody_tick_ms,
                *custody_elapsed_available,
                sample,
            )
            .is_forwardable(),
        }
    }
}

/// An authority control which the cryptographic provider has authenticated
/// before it crosses the durable-store boundary.
///
/// Construction performs byte-identity and canonical-structure checks. The
/// caller remains responsible for the authority signature, credential, route
/// commitments, and control AEAD checks which make this token provider-verified.
#[derive(Clone, Debug, Eq, PartialEq)]
#[allow(dead_code)]
pub(crate) struct VerifiedBridgeAuthorization {
    envelope_id: EnvelopeId,
    authorization: BridgeAuthorization,
    control_signer: NodeId,
    exact_bytes: Vec<u8>,
}

#[allow(dead_code)]
impl VerifiedBridgeAuthorization {
    pub(crate) fn from_provider(
        envelope_id: EnvelopeId,
        authorization: BridgeAuthorization,
        control_signer: NodeId,
        exact_bytes: Vec<u8>,
    ) -> Result<Self, StoreError> {
        authorization
            .validate()
            .map_err(|error| StoreError::Invalid(error.to_string()))?;
        if exact_bytes.is_empty()
            || exact_bytes.len() > MAX_AUTHORIZATION_TOTAL_BYTES
            || exact_object_id(&exact_bytes) != envelope_id
        {
            return Err(StoreError::Invalid(
                "bridge authorization exact bytes or identity are invalid".into(),
            ));
        }
        Ok(Self {
            envelope_id,
            authorization,
            control_signer,
            exact_bytes,
        })
    }
}

/// Durable but not implicitly re-authenticated bridge-control record.
///
/// Reopening a store yields this record. A cryptographic provider must verify
/// `exact_bytes` again before the record can authorize new work.
#[derive(Clone, Debug, Eq, PartialEq)]
#[allow(dead_code)]
pub(crate) struct StoredBridgeAuthorization {
    pub(crate) envelope_id: EnvelopeId,
    pub(crate) authorization: BridgeAuthorization,
    pub(crate) control_signer: NodeId,
    pub(crate) exact_bytes: Vec<u8>,
    pub(crate) applied: bool,
    pub(crate) inserted_order: u64,
}

/// Stable cursor for bounded authority-chain restart scans.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[allow(dead_code)]
pub(crate) struct BridgeAuthorizationCursor {
    pub(crate) authority_id: NodeId,
    pub(crate) sequence: u64,
}

/// Result of crash-atomically storing a bridge-control record.
#[derive(Clone, Debug, Eq, PartialEq)]
#[allow(dead_code)]
pub(crate) enum BridgeControlOutcome {
    Duplicate {
        envelope_id: EnvelopeId,
    },
    Pending {
        envelope_id: EnvelopeId,
    },
    Rejected {
        envelope_id: EnvelopeId,
        signer: NodeId,
        rejected: Vec<RejectedControl>,
    },
    Applied {
        envelope_id: EnvelopeId,
        activated: Vec<StoredBridgeAuthorization>,
        rejected: Vec<RejectedControl>,
    },
}

impl BridgeControlOutcome {
    pub(crate) fn rejected_input(&self) -> Option<RejectedControl> {
        match self {
            Self::Rejected {
                envelope_id,
                signer,
                ..
            } => Some(RejectedControl {
                envelope_id: *envelope_id,
                signer: *signer,
            }),
            Self::Applied {
                envelope_id,
                rejected,
                ..
            } => rejected
                .iter()
                .find(|control| control.envelope_id == *envelope_id)
                .copied(),
            Self::Duplicate { .. } | Self::Pending { .. } => None,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum BridgeControlStage {
    Inserted,
    Duplicate,
    Rejected(RejectedControl),
}

#[derive(Default)]
struct BridgeControlActivation {
    activated: Vec<StoredBridgeAuthorization>,
    rejected: Vec<RejectedControl>,
}

/// A route wrapper and exact source dependency which have both been verified
/// by the cryptographic provider without exposing payload or key material.
#[derive(Clone, Debug, Eq, PartialEq)]
#[allow(dead_code)]
pub(crate) struct VerifiedBridgeRoute {
    wrapper_envelope_id: EnvelopeId,
    route: BridgeRoute,
    exact_wrapper_bytes: Vec<u8>,
    authenticated_forwarding_age_ms: u64,
    source: VerifiedBridgeSource,
}

/// Durable target-route metadata. Exact wrapper and source bytes remain sealed;
/// the public application projection must use the distinct origin/current
/// fields and never infer source authorship from `current_scope`.
#[derive(Clone, Debug, Eq, PartialEq)]
#[allow(dead_code)]
pub(crate) struct StoredBridgeRoute {
    pub(crate) wrapper_envelope_id: EnvelopeId,
    pub(crate) bridge_route_id: [u8; 32],
    pub(crate) origin_envelope_id: EnvelopeId,
    pub(crate) source_item_id: ItemId,
    pub(crate) source_publisher: NodeId,
    pub(crate) origin_scope: Scope,
    pub(crate) origin_route_epoch: u64,
    pub(crate) current_scope: Scope,
    pub(crate) current_route_epoch: u64,
    pub(crate) topic: Topic,
    pub(crate) priority: Priority,
    pub(crate) ttl_ms: Option<u64>,
    pub(crate) tombstone: bool,
    pub(crate) hop_count: u8,
    pub(crate) cumulative_custody_age_ms: u64,
    pub(crate) authenticated_forwarding_age_ms: u64,
    pub(crate) age_continuity_unknown: bool,
    pub(crate) custody_clock_id: Option<[u8; 16]>,
    pub(crate) custody_tick_ms: Option<u64>,
    pub(crate) custody_elapsed_available: bool,
    pub(crate) exact_wrapper_bytes: Vec<u8>,
    pub(crate) exact_source_bytes: Vec<u8>,
    pub(crate) active: bool,
    pub(crate) inserted_order: u64,
}

/// A structurally verified wrapper whose private source or authority objects
/// may not have arrived yet. Construction does not confer bridge authority.
#[derive(Clone, Debug, Eq, PartialEq)]
#[allow(dead_code)]
pub(crate) struct VerifiedPendingBridgeWrapper {
    wrapper_envelope_id: EnvelopeId,
    route: BridgeRoute,
    exact_wrapper_bytes: Vec<u8>,
    authenticated_forwarding_age_ms: u64,
}

#[allow(dead_code)]
impl VerifiedPendingBridgeWrapper {
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn from_provider(
        wrapper_envelope_id: EnvelopeId,
        route: BridgeRoute,
        exact_wrapper_bytes: Vec<u8>,
        authenticated_forwarding_age_ms: u64,
    ) -> Result<Self, StoreError> {
        route
            .validate_structure()
            .map_err(|error| StoreError::Invalid(error.to_string()))?;
        if exact_wrapper_bytes.is_empty()
            || exact_wrapper_bytes.len() > MAX_WRAPPER_TOTAL_BYTES
            || exact_object_id(&exact_wrapper_bytes) != wrapper_envelope_id
        {
            return Err(StoreError::Invalid(
                "bridge wrapper exact bytes or identity are invalid".into(),
            ));
        }
        Ok(Self {
            wrapper_envelope_id,
            route,
            exact_wrapper_bytes,
            authenticated_forwarding_age_ms,
        })
    }
}

/// Durable dependency-incomplete wrapper. It is private synchronization state,
/// never an inventory or application-visible object, and must be reverified
/// after every process restart before it can accept a source dependency.
#[derive(Clone, Debug, Eq, PartialEq)]
#[allow(dead_code)]
pub(crate) struct StoredPendingBridgeWrapper {
    pub(crate) wrapper_envelope_id: EnvelopeId,
    pub(crate) route: BridgeRoute,
    pub(crate) exact_wrapper_bytes: Vec<u8>,
    pub(crate) cumulative_custody_age_ms: u64,
    pub(crate) authenticated_forwarding_age_ms: u64,
    pub(crate) age_continuity_unknown: bool,
    pub(crate) custody_clock_id: Option<[u8; 16]>,
    pub(crate) custody_tick_ms: Option<u64>,
    pub(crate) custody_elapsed_available: bool,
    pub(crate) inserted_order: u64,
}

/// Provider-authenticated exact source carrier received before any wrapper has
/// named it. This capability deliberately contains no source semantics: those
/// may be accepted only after a process-verified wrapper identifies the exact
/// EnvelopeID and the provider reopens the carrier in that context.
#[derive(Clone, Debug, Eq, PartialEq)]
#[allow(dead_code)]
pub(crate) struct VerifiedUnresolvedBridgeSource {
    origin_envelope_id: EnvelopeId,
    authenticated_forwarding_age_ms: u64,
    exact_bytes: Vec<u8>,
}

#[allow(dead_code)]
impl VerifiedUnresolvedBridgeSource {
    pub(crate) fn from_provider(
        origin_envelope_id: EnvelopeId,
        exact_bytes: Vec<u8>,
        authenticated_forwarding_age_ms: u64,
    ) -> Result<Self, StoreError> {
        if exact_bytes.is_empty() || exact_object_id(&exact_bytes) != origin_envelope_id {
            return Err(StoreError::Invalid(
                "unresolved bridge source exact bytes or identity are invalid".into(),
            ));
        }
        Ok(Self {
            origin_envelope_id,
            authenticated_forwarding_age_ms,
            exact_bytes,
        })
    }
}

/// Restart-durable, semantics-free source carrier. Reloading this record never
/// authenticates it or makes it inventory/application visible.
#[derive(Clone, Debug, Eq, PartialEq)]
#[allow(dead_code)]
pub(crate) struct StoredUnresolvedBridgeSource {
    pub(crate) origin_envelope_id: EnvelopeId,
    pub(crate) cumulative_custody_age_ms: u64,
    pub(crate) authenticated_forwarding_age_ms: u64,
    pub(crate) age_continuity_unknown: bool,
    pub(crate) custody_clock_id: Option<[u8; 16]>,
    pub(crate) custody_tick_ms: Option<u64>,
    pub(crate) custody_elapsed_available: bool,
    pub(crate) exact_bytes: Vec<u8>,
    pub(crate) inserted_order: u64,
}

/// Provider-authenticated Blob carrier structure/content address received
/// before an exact bridged source manifest can authorize its route proof.
#[derive(Clone, Debug, Eq, PartialEq)]
#[allow(dead_code)]
pub(crate) struct VerifiedPendingBridgeBlobCarrier {
    object_id: ObjectId,
    source_envelope_id: EnvelopeId,
    exact_bytes: Vec<u8>,
}

#[allow(dead_code)]
impl VerifiedPendingBridgeBlobCarrier {
    pub(crate) fn from_provider(
        object_id: ObjectId,
        source_envelope_id: EnvelopeId,
        exact_bytes: Vec<u8>,
    ) -> Result<Self, StoreError> {
        if object_id.kind() != ObjectKind::BlobChunk || exact_bytes.is_empty() {
            return Err(StoreError::Invalid(
                "pending bridge Blob carrier identity or bytes are invalid".into(),
            ));
        }
        Ok(Self {
            object_id,
            source_envelope_id,
            exact_bytes,
        })
    }
}

/// Stronger provider capability issued only after the exact source manifest
/// has authenticated this carrier's source association and route proof.
#[derive(Clone, Debug, Eq, PartialEq)]
#[allow(dead_code)]
pub(crate) struct VerifiedBridgeBlobCarrierCommit {
    object_id: ObjectId,
    source_envelope_id: EnvelopeId,
    exact_bytes: Vec<u8>,
}

/// Provider capability proving that the exact pending carrier failed route
/// association/proof verification and may be discarded without promotion.
#[derive(Clone, Debug, Eq, PartialEq)]
#[allow(dead_code)]
pub(crate) struct VerifiedRejectedBridgeBlobCarrier {
    object_id: ObjectId,
    source_envelope_id: EnvelopeId,
    exact_bytes: Vec<u8>,
}

#[allow(dead_code)]
impl VerifiedRejectedBridgeBlobCarrier {
    pub(crate) fn from_provider(
        object_id: ObjectId,
        source_envelope_id: EnvelopeId,
        exact_bytes: Vec<u8>,
    ) -> Result<Self, StoreError> {
        if object_id.kind() != ObjectKind::BlobChunk || exact_bytes.is_empty() {
            return Err(StoreError::Invalid(
                "rejected bridge Blob carrier identity or bytes are invalid".into(),
            ));
        }
        Ok(Self {
            object_id,
            source_envelope_id,
            exact_bytes,
        })
    }
}

#[allow(dead_code)]
impl VerifiedBridgeBlobCarrierCommit {
    pub(crate) fn from_provider(
        object_id: ObjectId,
        source_envelope_id: EnvelopeId,
        exact_bytes: Vec<u8>,
    ) -> Result<Self, StoreError> {
        if object_id.kind() != ObjectKind::BlobChunk || exact_bytes.is_empty() {
            return Err(StoreError::Invalid(
                "verified bridge Blob carrier identity or bytes are invalid".into(),
            ));
        }
        Ok(Self {
            object_id,
            source_envelope_id,
            exact_bytes,
        })
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
#[allow(dead_code)]
pub(crate) struct StoredPendingBridgeBlobCarrier {
    pub(crate) object_id: ObjectId,
    pub(crate) source_envelope_id: EnvelopeId,
    pub(crate) exact_bytes: Vec<u8>,
    pub(crate) inserted_order: u64,
}

/// Provider-authenticated, non-plaintext semantics bound to an exact source
/// carrier. Store APIs never accept these fields independently.
#[derive(Clone, Debug, Eq, PartialEq)]
#[allow(dead_code)]
pub(crate) struct VerifiedBlobRouteMetadata {
    pub(crate) blob_id: [u8; 32],
    pub(crate) chunk_count: u64,
    pub(crate) merkle_root: [u8; 32],
}

#[derive(Clone, Debug, Eq, PartialEq)]
#[allow(dead_code)]
pub(crate) struct VerifiedBridgeSourceMetadata {
    pub(crate) source_item_id: ItemId,
    pub(crate) class: DataClass,
    pub(crate) topic: Topic,
    pub(crate) priority: Priority,
    pub(crate) stamp: CausalStamp,
    pub(crate) event_sequence: Option<u64>,
    pub(crate) logical_key: Vec<u8>,
    pub(crate) ttl_ms: Option<u64>,
    pub(crate) blob_route: Option<VerifiedBlobRouteMetadata>,
    pub(crate) content_len: u64,
    pub(crate) tombstone: bool,
    pub(crate) origin_scope: Scope,
    pub(crate) origin_route_epoch: u64,
}

/// Exact provider-authenticated source carrier for an already referenced
/// wrapper. This token contains no plaintext and confers no route authority.
#[derive(Clone, Debug, Eq, PartialEq)]
#[allow(dead_code)]
pub(crate) struct VerifiedBridgeSource {
    origin_envelope_id: EnvelopeId,
    metadata: VerifiedBridgeSourceMetadata,
    authenticated_forwarding_age_ms: u64,
    exact_bytes: Vec<u8>,
}

#[allow(dead_code)]
impl VerifiedBridgeSource {
    pub(crate) fn from_provider(
        origin_envelope_id: EnvelopeId,
        metadata: VerifiedBridgeSourceMetadata,
        exact_bytes: Vec<u8>,
        authenticated_forwarding_age_ms: u64,
    ) -> Result<Self, StoreError> {
        if exact_bytes.is_empty() || exact_object_id(&exact_bytes) != origin_envelope_id {
            return Err(StoreError::Invalid(
                "bridge source exact bytes or identity are invalid".into(),
            ));
        }
        if metadata.stamp.dot.counter == 0
            || metadata.stamp.context.len() > MAX_CAUSAL_CONTEXT_ENTRIES
            || metadata
                .stamp
                .context
                .iter()
                .any(|(_, counter)| *counter == 0)
            || metadata
                .stamp
                .context
                .counter(&metadata.stamp.dot.publisher)
                >= metadata.stamp.dot.counter
            || metadata.logical_key.len() > 4 * 1024
            || (matches!(metadata.class, DataClass::State | DataClass::Record)
                && metadata.logical_key.is_empty())
            || match (metadata.class, metadata.event_sequence) {
                (DataClass::Event, Some(sequence)) => sequence == 0,
                (DataClass::Event, None) => true,
                (_, Some(_)) => true,
                (_, None) => false,
            }
            || (metadata.class == DataClass::Blob) != metadata.blob_route.is_some()
            || metadata
                .blob_route
                .as_ref()
                .is_some_and(|blob| blob.chunk_count == 0)
            || metadata.origin_route_epoch == 0
        {
            return Err(StoreError::Invalid(
                "bridge source authenticated metadata is internally inconsistent".into(),
            ));
        }
        Ok(Self {
            origin_envelope_id,
            metadata,
            exact_bytes,
            authenticated_forwarding_age_ms,
        })
    }
}

/// Exact source bytes retained only to satisfy referenced bridge wrappers.
#[derive(Clone, Debug, Eq, PartialEq)]
#[allow(dead_code)]
pub(crate) struct StoredBridgeSource {
    pub(crate) origin_envelope_id: EnvelopeId,
    pub(crate) metadata: VerifiedBridgeSourceMetadata,
    pub(crate) exact_bytes: Vec<u8>,
    pub(crate) cumulative_custody_age_ms: u64,
    pub(crate) authenticated_forwarding_age_ms: u64,
    pub(crate) age_continuity_unknown: bool,
    pub(crate) custody_clock_id: Option<[u8; 16]>,
    pub(crate) custody_tick_ms: Option<u64>,
    pub(crate) custody_elapsed_available: bool,
    pub(crate) inserted_order: u64,
}

/// Result of atomically promoting a dependency-complete bridge route.
#[derive(Clone, Debug, Eq, PartialEq)]
#[allow(dead_code)]
pub(crate) enum BridgeRouteOutcome {
    Duplicate {
        wrapper_envelope_id: EnvelopeId,
        active: bool,
    },
    Active {
        wrapper_envelope_id: EnvelopeId,
        replaced: Option<EnvelopeId>,
    },
    RetainedAlternate {
        wrapper_envelope_id: EnvelopeId,
        active_wrapper_envelope_id: EnvelopeId,
    },
}

/// Provider-token readiness for a private route row. Ineligible rows retain
/// their exact recovery bytes but must not produce Wants or abort activation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[allow(dead_code)]
pub(crate) enum BridgeRouteReadiness {
    Eligible,
    MissingDependency,
    Ineligible,
}

#[allow(dead_code)]
impl VerifiedBridgeRoute {
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn from_provider(
        wrapper_envelope_id: EnvelopeId,
        route: BridgeRoute,
        exact_wrapper_bytes: Vec<u8>,
        authenticated_forwarding_age_ms: u64,
        source: VerifiedBridgeSource,
    ) -> Result<Self, StoreError> {
        route
            .validate_structure()
            .map_err(|error| StoreError::Invalid(error.to_string()))?;
        if exact_wrapper_bytes.is_empty()
            || exact_wrapper_bytes.len() > MAX_WRAPPER_TOTAL_BYTES
            || exact_object_id(&exact_wrapper_bytes) != wrapper_envelope_id
            || source.origin_envelope_id != route.origin_envelope_id
            || source.metadata.source_item_id != route.source_item_id
            || source.metadata.origin_scope != route.origin_scope
            || source.metadata.origin_route_epoch != route.origin_route_epoch
        {
            return Err(StoreError::Invalid(
                "bridge wrapper or source exact bytes do not match their identity".into(),
            ));
        }
        Ok(Self {
            wrapper_envelope_id,
            route,
            exact_wrapper_bytes,
            authenticated_forwarding_age_ms,
            source,
        })
    }
}

/// One reading from a local elapsed clock continuity domain.
pub use crate::custody::CustodySample;

type LegacyCustodyFields = (u64, bool, Option<[u8; 16]>, Option<u64>, bool);

fn custody_age_from_legacy_fields(
    cumulative_age_ms: u64,
    age_continuity_unknown: bool,
    custody_clock_id: Option<[u8; 16]>,
    custody_tick_ms: Option<u64>,
    custody_elapsed_available: bool,
) -> CustodyAge {
    let checkpoint = custody_checkpoint(custody_clock_id, custody_tick_ms);
    let continuity = if !age_continuity_unknown && custody_elapsed_available {
        CustodyContinuity::Continuous
    } else {
        CustodyContinuity::Lost
    };
    CustodyAge::from_parts(cumulative_age_ms, checkpoint, continuity).unwrap_or_else(|_| {
        CustodyAge::from_parts(cumulative_age_ms, checkpoint, CustodyContinuity::Lost)
            .unwrap_or(CustodyAge::unknown(cumulative_age_ms))
    })
}

fn custody_fields_from_age(age: CustodyAge) -> LegacyCustodyFields {
    let checkpoint = age.checkpoint_sample();
    (
        age.cumulative_age_ms(),
        !age.is_continuous(),
        checkpoint.map(|value| value.clock_id),
        checkpoint.map(|value| value.tick_ms),
        checkpoint.is_some(),
    )
}

fn merge_authenticated_custody_fields(
    existing: Option<LegacyCustodyFields>,
    authenticated_age_ms: u64,
    sample: Option<CustodySample>,
) -> LegacyCustodyFields {
    let Some((age_ms, unknown, clock_id, tick_ms, available)) = existing else {
        return sample.map_or_else(
            || custody_fields_from_age(CustodyAge::unknown(authenticated_age_ms)),
            |sample| custody_fields_from_age(CustodyAge::new(authenticated_age_ms, sample)),
        );
    };
    let mut age = custody_age_from_legacy_fields(age_ms, unknown, clock_id, tick_ms, available);
    let _ = age.merge_authenticated_age(authenticated_age_ms, sample);
    custody_fields_from_age(age)
}

impl StoredItem {
    pub fn publisher(&self) -> NodeId {
        self.stamp.dot.publisher
    }

    pub fn is_expired_at(&self, sample: Option<CustodySample>) -> bool {
        custody_disposition_from_fields(
            self.ttl_ms,
            self.tombstone,
            self.custody_age_ms,
            self.custody_clock_id,
            self.custody_tick_ms,
            self.custody_elapsed_available,
            sample,
        )
        .is_expired()
    }

    pub fn is_forwardable_at(&self, sample: Option<CustodySample>) -> bool {
        custody_disposition_from_fields(
            self.ttl_ms,
            self.tombstone,
            self.custody_age_ms,
            self.custody_clock_id,
            self.custody_tick_ms,
            self.custody_elapsed_available,
            sample,
        )
        .is_forwardable()
    }

    fn accounted_bytes(&self) -> u64 {
        self.sealed.len() as u64
            + self.logical_key.len() as u64
            + self.topic.as_str().len() as u64
            + self.scope.as_str().len() as u64
            + 192
    }
}

/// Reservation read before sealing. Committing it is a compare-and-swap.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PublishReservation {
    pub previous_counter: u64,
    pub counter: u64,
    pub event_previous: Option<u64>,
    pub event_sequence: Option<u64>,
    pub context: VersionVector,
}

/// One atomic contiguous publisher/event range reserved before a source batch
/// is sealed. Committing compares the whole range, not just its first item.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BatchPublishReservation {
    pub previous_counter: u64,
    pub first_counter: u64,
    pub item_count: u16,
    pub event_previous: Option<u64>,
    pub first_event_sequence: Option<u64>,
    pub context: VersionVector,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum BatchStoragePolicy {
    #[default]
    RetainedDual,
    BatchOnly,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LocalBatchItemCommit {
    pub compact: StoredItem,
    pub singleton: Option<StoredItem>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LocalBatchCommit {
    pub proof_envelope_id: EnvelopeId,
    pub batch_id: [u8; 32],
    pub proof_bytes: Vec<u8>,
    pub items: Vec<LocalBatchItemCommit>,
    pub storage_policy: BatchStoragePolicy,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BatchCommitOutcome {
    pub outcomes: Vec<ApplyOutcome>,
    pub evicted: Vec<ItemId>,
}

/// Exact durable batch proof bytes. `process_verified` is deliberately absent:
/// authentication is a process-local capability held by [`SqliteStore`].
#[derive(Clone, Debug, Eq, PartialEq)]
#[doc(hidden)]
pub struct StoredBatchProof {
    pub(crate) proof_envelope_id: EnvelopeId,
    pub(crate) batch_id: [u8; 32],
    pub(crate) scope: Scope,
    pub(crate) exact_bytes: Vec<u8>,
    pub(crate) inserted_order: u64,
    pub(crate) effective_priority: Priority,
}

/// Route-authenticated compact carrier that remains private until its exact
/// proof dependency is provider-authenticated in this process.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct StoredPendingBatchItem {
    pub(crate) envelope_id: EnvelopeId,
    pub(crate) item_id: ItemId,
    pub(crate) proof_envelope_id: EnvelopeId,
    pub(crate) scope: Scope,
    pub(crate) priority: Priority,
    pub(crate) ttl_ms: Option<u64>,
    pub(crate) cumulative_custody_age_ms: u64,
    pub(crate) authenticated_forwarding_age_ms: u64,
    pub(crate) age_continuity_unknown: bool,
    pub(crate) custody_clock_id: Option<[u8; 16]>,
    pub(crate) custody_tick_ms: Option<u64>,
    pub(crate) custody_elapsed_available: bool,
    pub(crate) exact_bytes: Vec<u8>,
    pub(crate) inserted_order: u64,
}

impl StoredPendingBatchItem {
    pub(crate) fn effective_custody_age_ms(&self, sample: Option<CustodySample>) -> Option<u64> {
        let mut age = custody_age_from_legacy_fields(
            self.cumulative_custody_age_ms,
            self.age_continuity_unknown,
            self.custody_clock_id,
            self.custody_tick_ms,
            self.custody_elapsed_available,
        );
        match age.effective_age(sample) {
            Ok(value) => Some(value),
            Err(_) if self.ttl_ms.is_none() => Some(age.cumulative_age_ms()),
            Err(_) => None,
        }
    }
}

/// One exact source-envelope representation selected for a negotiated semantic
/// version. Compact representations always identify their proof dependency.
#[derive(Clone, Debug, Eq, PartialEq)]
#[allow(dead_code)]
pub(crate) struct StoredItemRepresentation {
    pub(crate) item_id: ItemId,
    pub(crate) envelope_id: EnvelopeId,
    pub(crate) proof_envelope_id: Option<EnvelopeId>,
    pub(crate) exact_bytes: Vec<u8>,
    pub(crate) semantic_version: u16,
}

/// Exact compact provenance used by restart recovery and application reads.
#[derive(Clone, Debug, Eq, PartialEq)]
#[doc(hidden)]
pub struct StoredBatchMaterial {
    pub(crate) item_id: ItemId,
    pub(crate) compact_envelope_id: EnvelopeId,
    pub(crate) compact_bytes: Vec<u8>,
    pub(crate) singleton_envelope_id: Option<EnvelopeId>,
    pub(crate) inserted_order: u64,
    pub(crate) proof: StoredBatchProof,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct BatchItemCommitOutcome {
    pub(crate) outcome: ApplyOutcome,
    pub(crate) evicted: Vec<ItemId>,
}

/// Result of applying an immutable envelope.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ApplyOutcome {
    Inserted {
        id: ItemId,
        status: VersionStatus,
        conflict: Option<ConflictAnnotation>,
        evicted: Vec<ItemId>,
    },
    Duplicate {
        id: ItemId,
    },
}

/// Query controls. Empty optional fields are wildcards.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct StoreQuery {
    pub topic: Option<Topic>,
    pub scope: Option<Scope>,
    pub include_descendant_scopes: bool,
    pub class: Option<DataClass>,
    pub logical_key: Option<Vec<u8>>,
    pub include_recoverable_versions: bool,
    pub include_tombstones: bool,
    pub now_ms: Option<u64>,
    pub custody_sample: Option<CustodySample>,
    pub limit: Option<usize>,
}

/// Active bridge projection controls. Every optional field is an exact-match
/// filter; there are no implicit topic or scope wildcards.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
#[allow(dead_code)]
pub(crate) struct BridgeProjectionQuery {
    pub(crate) target_scope: Option<Scope>,
    pub(crate) target_route_epoch: Option<u64>,
    pub(crate) topic: Option<Topic>,
    pub(crate) class: Option<DataClass>,
    /// Restricts a wildcard class query to mutable State/Record entries before
    /// any matching bridge route or source material is loaded.
    pub(crate) mutable_classes_only: bool,
    /// Restricts results to entries acknowledged by one durable subscription.
    pub(crate) acknowledged_subscription: Option<SubscriptionId>,
    pub(crate) logical_key: Option<Vec<u8>>,
    pub(crate) version_status: Option<VersionStatus>,
    pub(crate) include_tombstones: bool,
    pub(crate) custody_sample: Option<CustodySample>,
    pub(crate) limit: Option<usize>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
#[allow(dead_code)]
pub(crate) struct StoredBridgeProjection {
    pub(crate) route: StoredBridgeRoute,
    pub(crate) source: StoredBridgeSource,
    pub(crate) version_status: VersionStatus,
}

/// Opaque ordering seam for bounded bridge-projection scans. Scope matching
/// remains exact; the cursor carries no authorization meaning.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[allow(dead_code)]
pub(crate) struct BridgeProjectionCursor {
    source_priority: Priority,
    inserted_order: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
#[allow(dead_code)]
pub(crate) struct BridgeProjectionPage {
    pub(crate) entries: Vec<StoredBridgeProjection>,
    pub(crate) next_cursor: Option<BridgeProjectionCursor>,
}

/// Provider-gated at-least-once delivery of one active bridge projection.
#[derive(Clone, Debug, Eq, PartialEq)]
#[allow(dead_code)]
pub(crate) struct BridgeProjectionDelivery {
    pub(crate) subscription: SubscriptionId,
    pub(crate) projection: StoredBridgeProjection,
    pub(crate) delivery_attempt: u64,
}

/// Capability returned across the store boundary only after the engine's
/// provider has opened the projection content for this application node.
#[derive(Clone, Debug, Eq, PartialEq)]
#[allow(dead_code)]
pub(crate) struct ProviderOpenedBridgeProjection {
    projection: StoredBridgeProjection,
}

#[allow(dead_code)]
impl ProviderOpenedBridgeProjection {
    pub(crate) fn from_provider(projection: StoredBridgeProjection) -> Self {
        Self { projection }
    }

    pub(crate) fn projection(&self) -> &StoredBridgeProjection {
        &self.projection
    }
}

/// Durable subscription filter.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SubscriptionSpec {
    pub topic: Topic,
    pub scope: Scope,
    pub include_descendant_scopes: bool,
    pub class: Option<DataClass>,
}

/// Stable identifier for a durable application subscription.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct SubscriptionId(pub u64);

/// An at-least-once application delivery. It remains pending until acknowledged.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AppDelivery {
    pub subscription: SubscriptionId,
    pub item: StoredItem,
    pub delivery_attempt: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SubscriptionCursor {
    pub(crate) priority: Priority,
    pub(crate) inserted_order: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SubscriptionCandidatePage {
    pub(crate) entries: Vec<StoredItem>,
    pub(crate) next_cursor: Option<SubscriptionCursor>,
}

/// Inclusive-exclusive missing byte range.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct ChunkRange {
    pub start: u64,
    pub end: u64,
}

/// Exact crash-durable transfer progress independent of any peer, session, or
/// transport address.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TransferProgress {
    pub object_id: ObjectId,
    /// Semantic protocol selected when this exact transfer was first staged.
    /// `None` is fail-closed provenance (including migrated rows).
    pub origin_semantic_version: Option<u16>,
    pub total_len: u64,
    pub received: Vec<ChunkRange>,
}

/// Maps the 33-byte typed wire identity into the existing fixed-width local
/// chunk-store key without truncating either SHA-256 identity.
pub fn transfer_storage_key(object_id: ObjectId) -> ItemId {
    let mut hasher = Sha256::new();
    hasher.update((TRANSFER_STORAGE_KEY_DOMAIN.len() as u64).to_be_bytes());
    hasher.update(TRANSFER_STORAGE_KEY_DOMAIN);
    hasher.update(object_id.to_wire_bytes());
    hasher.finalize().into()
}

fn transfer_resume_is_compatible(
    kind: ObjectKind,
    stored_origin: Option<u16>,
    requested_version: Option<u16>,
) -> bool {
    match (stored_origin, requested_version) {
        (None, None) => true,
        (None, Some(_)) | (Some(_), None) => false,
        (Some(origin), Some(requested))
            if !matches!(origin, 1..=7) || !matches!(requested, 1..=7) =>
        {
            false
        }
        (Some(_), Some(_)) if kind == ObjectKind::BlobChunk => true,
        (Some(1), Some(requested))
            if kind == ObjectKind::SourceEnvelope && matches!(requested, 1..=7) =>
        {
            true
        }
        (Some(origin), Some(requested)) if kind == ObjectKind::SourceEnvelope => {
            origin >= 2 && requested >= 2
        }
        (Some(origin), Some(requested)) => origin >= 2 && requested >= 2,
    }
}

impl ChunkRange {
    pub fn new(start: u64, end: u64) -> Result<Self, StoreError> {
        if start >= end {
            return Err(StoreError::Invalid("chunk range must be non-empty".into()));
        }
        Ok(Self { start, end })
    }

    pub fn len(self) -> u64 {
        self.end.saturating_sub(self.start)
    }

    pub fn is_empty(self) -> bool {
        self.start >= self.end
    }
}

impl From<crate::wire::ByteRange> for ChunkRange {
    fn from(value: crate::wire::ByteRange) -> Self {
        Self {
            start: value.start,
            end: value.end,
        }
    }
}

impl From<ChunkRange> for crate::wire::ByteRange {
    fn from(value: ChunkRange) -> Self {
        Self {
            start: value.start,
            end: value.end,
        }
    }
}

/// Authority control-chain reservation used before cryptographic sealing.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ControlReservation {
    pub authority: NodeId,
    pub signer: NodeId,
    pub previous_sequence: u64,
    pub sequence: u64,
    pub previous_control: Option<EnvelopeId>,
}

/// Durable authority control kind.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum ControlKind {
    Revocation = 1,
    ScopeEpoch = 2,
}

/// Durable source-sealed control object.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StoredControl {
    pub envelope_id: EnvelopeId,
    pub authority: NodeId,
    pub signer: NodeId,
    pub sequence: u64,
    pub previous_control: Option<EnvelopeId>,
    pub kind: ControlKind,
    pub sealed: Vec<u8>,
    pub applied: bool,
    pub inserted_order: u64,
}

/// Authenticated control discarded because its stable authority or delegated
/// signer was revoked, or because it followed an invalidated pending link.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RejectedControl {
    pub envelope_id: EnvelopeId,
    pub signer: NodeId,
}

/// Result of storing a control and advancing any now-contiguous chain prefix.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ControlOutcome {
    Duplicate {
        envelope_id: EnvelopeId,
    },
    Pending {
        envelope_id: EnvelopeId,
    },
    Rejected {
        envelope_id: EnvelopeId,
        signer: NodeId,
        rejected: Vec<RejectedControl>,
    },
    Applied {
        envelope_id: EnvelopeId,
        activated: Vec<StoredControl>,
        rejected: Vec<RejectedControl>,
    },
}

impl ControlOutcome {
    /// Returns the authenticated input rejected by this operation, even when
    /// an unrelated pending prefix activated in the same transaction.
    ///
    /// Callers must not acknowledge or advertise the input as committed when
    /// this returns `Some`; the independently listed `activated` prefix remains
    /// durable and still needs provider activation.
    pub fn rejected_input(&self) -> Option<RejectedControl> {
        match self {
            Self::Rejected {
                envelope_id,
                signer,
                ..
            } => Some(RejectedControl {
                envelope_id: *envelope_id,
                signer: *signer,
            }),
            Self::Applied {
                envelope_id,
                rejected,
                ..
            } => rejected
                .iter()
                .find(|control| control.envelope_id == *envelope_id)
                .copied(),
            Self::Duplicate { .. } | Self::Pending { .. } => None,
        }
    }
}

/// Persisted coarse peer and reconciliation state.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PeerSnapshot {
    pub node: NodeId,
    pub peer: PeerStatus,
    pub sync: SyncStatus,
    pub last_change_ms: Option<u64>,
    pub detail: Option<String>,
}

/// Legacy bridge propagation rule with explicit scopes and topics only.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BridgeFilter {
    pub from_scope: Scope,
    pub to_scope: Scope,
    pub topics: BTreeSet<Topic>,
    pub minimum_priority: Priority,
}

/// Failures surfaced by either durable or in-memory stores.
#[derive(Debug)]
pub enum StoreError {
    Sqlite(rusqlite::Error),
    Invalid(String),
    Corrupt(String),
    CounterChanged,
    Equivocation { publisher: NodeId, counter: u64 },
    EventEquivocation { publisher: NodeId, sequence: u64 },
    NotFound(&'static str),
    QuotaExceeded,
    Zeroized,
    ControlFork,
    ControlRollback,
    ControlSignerRevoked(NodeId),
    ControlAuthorityRevoked(NodeId),
    BridgeControlFork,
    BridgeControlRollback,
    BridgeControlSignerRevoked(NodeId),
    BridgeControlAuthorityRevoked(NodeId),
    LegacyControlMigrationRequired,
    BridgeDependencyMissing,
    BridgeRouteIneligible,
    BridgeObjectReferenced,
}

impl Display for StoreError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::Sqlite(error) => write!(formatter, "sqlite: {error}"),
            Self::Invalid(message) => write!(formatter, "invalid store input: {message}"),
            Self::Corrupt(message) => write!(formatter, "corrupt store: {message}"),
            Self::CounterChanged => {
                formatter.write_str("publisher reservation changed; retry publish")
            }
            Self::Equivocation { counter, .. } => {
                write!(
                    formatter,
                    "different item already uses publisher counter {counter}"
                )
            }
            Self::EventEquivocation { sequence, .. } => {
                write!(
                    formatter,
                    "different event already uses sequence {sequence}"
                )
            }
            Self::NotFound(kind) => write!(formatter, "{kind} not found"),
            Self::QuotaExceeded => formatter.write_str("storage quota cannot admit item"),
            Self::Zeroized => formatter.write_str("node has been zeroized"),
            Self::ControlFork => formatter.write_str("authority control chain fork detected"),
            Self::ControlRollback => formatter.write_str("authority control rollback detected"),
            Self::ControlSignerRevoked(_) => {
                formatter.write_str("delegated control signer is revoked")
            }
            Self::ControlAuthorityRevoked(_) => {
                formatter.write_str("stable control authority is revoked")
            }
            Self::BridgeControlFork => {
                formatter.write_str("bridge authority control chain fork detected")
            }
            Self::BridgeControlRollback => {
                formatter.write_str("bridge authorization generation rollback detected")
            }
            Self::BridgeControlSignerRevoked(_) => {
                formatter.write_str("delegated bridge-control signer is revoked")
            }
            Self::BridgeControlAuthorityRevoked(_) => {
                formatter.write_str("stable bridge-control authority is revoked")
            }
            Self::LegacyControlMigrationRequired => formatter.write_str(
                "schema-10 control state requires an explicit signed authority cutover or a fresh store",
            ),
            Self::BridgeDependencyMissing => {
                formatter.write_str("verified bridge dependency is missing")
            }
            Self::BridgeRouteIneligible => {
                formatter.write_str("verified bridge route is currently ineligible")
            }
            Self::BridgeObjectReferenced => formatter.write_str("bridge object remains referenced"),
        }
    }
}

impl Error for StoreError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Sqlite(error) => Some(error),
            _ => None,
        }
    }
}

impl From<rusqlite::Error> for StoreError {
    fn from(value: rusqlite::Error) -> Self {
        Self::Sqlite(value)
    }
}

/// Complete persistence boundary used by the high-level engine.
///
/// Every mutating method is required to be crash-atomic. Implementations must
/// preserve idempotence by item identifier and reject reuse of a causal dot.
pub trait RecordStore {
    fn config(&self) -> &StoreConfig;
    fn reserve_publish(
        &mut self,
        publisher: NodeId,
        class: DataClass,
        topic: &Topic,
        scope: &Scope,
    ) -> Result<PublishReservation, StoreError>;
    fn reserve_batch_publish(
        &mut self,
        publisher: NodeId,
        class: DataClass,
        topic: &Topic,
        scope: &Scope,
        item_count: u16,
    ) -> Result<BatchPublishReservation, StoreError>;
    fn commit_publish(
        &mut self,
        reservation: &PublishReservation,
        item: StoredItem,
    ) -> Result<ApplyOutcome, StoreError>;
    fn commit_local_batch(
        &mut self,
        reservation: &BatchPublishReservation,
        commit: LocalBatchCommit,
    ) -> Result<BatchCommitOutcome, StoreError>;
    fn ingest(&mut self, item: StoredItem) -> Result<ApplyOutcome, StoreError>;
    /// Selects one exact topic/scope cross-product as a single bounded,
    /// metadata-only inventory operation. The sets are canonical by type and
    /// the protocol INTEREST work ceiling is enforced again at this boundary.
    /// Implementations must reject rather than truncate when the result exceeds
    /// the 100,000-object composite inventory ceiling.
    fn select_inventory_metadata(
        &mut self,
        topics: &BTreeSet<Topic>,
        scopes: &BTreeSet<Scope>,
    ) -> Result<Vec<InventoryMetadata>, StoreError>;
    fn query(&mut self, query: &StoreQuery) -> Result<Vec<StoredItem>, StoreError>;
    fn get(&mut self, id: &ItemId) -> Result<Option<StoredItem>, StoreError>;
    #[doc(hidden)]
    fn stored_batch_material(
        &mut self,
        _id: &ItemId,
    ) -> Result<Option<StoredBatchMaterial>, StoreError> {
        Ok(None)
    }
    fn conflicts(&mut self, query: &StoreQuery) -> Result<Vec<ConflictAnnotation>, StoreError>;
    fn create_subscription(
        &mut self,
        spec: &SubscriptionSpec,
    ) -> Result<SubscriptionId, StoreError>;
    fn peek_subscription_page(
        &mut self,
        id: SubscriptionId,
        after: Option<SubscriptionCursor>,
        custody_sample: Option<CustodySample>,
    ) -> Result<SubscriptionCandidatePage, StoreError>;
    fn record_subscription_deliveries(
        &mut self,
        id: SubscriptionId,
        items: &[StoredItem],
        now_ms: Option<u64>,
        custody_sample: Option<CustodySample>,
    ) -> Result<Vec<AppDelivery>, StoreError>;
    fn poll_subscription(
        &mut self,
        id: SubscriptionId,
        limit: usize,
        now_ms: Option<u64>,
        custody_sample: Option<CustodySample>,
    ) -> Result<Vec<AppDelivery>, StoreError>;
    fn acknowledge_delivery(
        &mut self,
        id: SubscriptionId,
        item: &ItemId,
        now_ms: Option<u64>,
    ) -> Result<(), StoreError>;
    fn next_outbound(
        &mut self,
        peer: NodeId,
        minimum: Priority,
        limit: usize,
        byte_budget: u64,
        now_ms: Option<u64>,
        custody_sample: Option<CustodySample>,
    ) -> Result<Vec<StoredItem>, StoreError>;
    fn acknowledge_peer(
        &mut self,
        peer: NodeId,
        ids: &[ItemId],
        now_ms: Option<u64>,
    ) -> Result<(), StoreError>;
    fn set_scope_quota(&mut self, quota: ScopeQuota) -> Result<(), StoreError>;
    fn quota_usage(&mut self, scope: Option<&Scope>) -> Result<QuotaUsage, StoreError>;
    fn collect_garbage(
        &mut self,
        now_ms: Option<u64>,
        custody_sample: Option<CustodySample>,
    ) -> Result<Vec<ItemId>, StoreError>;
    fn get_by_envelope(
        &mut self,
        envelope_id: &EnvelopeId,
    ) -> Result<Option<StoredItem>, StoreError>;
    fn read_item_envelope_range(
        &mut self,
        envelope_id: &EnvelopeId,
        range: ChunkRange,
        max_bytes: usize,
    ) -> Result<Vec<u8>, StoreError>;
    fn reserve_control(
        &mut self,
        principal: ControlPrincipal,
    ) -> Result<ControlReservation, StoreError>;
    fn commit_local_control(
        &mut self,
        reservation: &ControlReservation,
        control: &VerifiedStoredControl,
    ) -> Result<ControlOutcome, StoreError>;
    fn ingest_control(
        &mut self,
        control: &VerifiedStoredControl,
    ) -> Result<ControlOutcome, StoreError>;
    fn applied_controls(&mut self) -> Result<Vec<StoredControl>, StoreError>;
    fn next_control_outbound(
        &mut self,
        peer: NodeId,
        limit: usize,
        byte_budget: u64,
        now_ms: Option<u64>,
    ) -> Result<Vec<StoredControl>, StoreError>;
    fn acknowledge_control_peer(
        &mut self,
        peer: NodeId,
        envelope_ids: &[EnvelopeId],
        now_ms: Option<u64>,
    ) -> Result<(), StoreError>;
    fn read_control_envelope_range(
        &mut self,
        envelope_id: &EnvelopeId,
        range: ChunkRange,
        max_bytes: usize,
    ) -> Result<Vec<u8>, StoreError>;
    /// Atomically establishes (or idempotently reopens) the local mapping from
    /// a full typed wire identity to its fixed-width staging key.
    fn begin_transfer(
        &mut self,
        object_id: ObjectId,
        total_len: u64,
        priority: Priority,
        now_ms: Option<u64>,
    ) -> Result<(), StoreError> {
        self.begin_want(transfer_storage_key(object_id), total_len, priority, now_ms)
    }
    fn begin_transfer_for_semantic_version(
        &mut self,
        object_id: ObjectId,
        total_len: u64,
        priority: Priority,
        now_ms: Option<u64>,
        semantic_version: u16,
    ) -> Result<(), StoreError> {
        if !matches!(semantic_version, 1..=7) {
            return Err(StoreError::Invalid(
                "unsupported transfer semantic version".into(),
            ));
        }
        self.begin_transfer(object_id, total_len, priority, now_ms)
    }
    /// Returns only restart-durable transfers whose first semantic-version
    /// provenance is compatible with the selected reducer. Filtering occurs
    /// before `limit`, so incompatible low ObjectIDs cannot starve hydration.
    fn transfer_progress_for_semantic_version(
        &mut self,
        semantic_version: u16,
        limit: usize,
    ) -> Result<Vec<TransferProgress>, StoreError>;
    /// Bounded peer-neutral progress used to hydrate a new sync reducer after
    /// process restart. Stores without identity persistence may return empty.
    fn transfer_progress(&mut self, _limit: usize) -> Result<Vec<TransferProgress>, StoreError> {
        Ok(Vec::new())
    }
    /// Retires durable staging only after the typed object has been
    /// authenticated and committed to its final store.
    fn finish_transfer(&mut self, _object_id: ObjectId) -> Result<(), StoreError> {
        Ok(())
    }
    /// Atomically discards every durable byte, range, known length, and typed
    /// identity for a transfer that failed final authentication.
    fn abort_transfer(&mut self, object_id: ObjectId) -> Result<(), StoreError> {
        self.finish_transfer(object_id)
    }
    fn begin_want(
        &mut self,
        object: ItemId,
        total_len: u64,
        priority: Priority,
        now_ms: Option<u64>,
    ) -> Result<(), StoreError>;
    fn missing_ranges(
        &mut self,
        object: &ItemId,
        limit: usize,
    ) -> Result<Vec<ChunkRange>, StoreError>;
    fn put_sealed_chunk(
        &mut self,
        object: ItemId,
        total_len: u64,
        offset: u64,
        bytes: &[u8],
        now_ms: Option<u64>,
    ) -> Result<bool, StoreError>;
    fn read_sealed_range(
        &mut self,
        object: &ItemId,
        range: ChunkRange,
        max_bytes: usize,
    ) -> Result<Vec<u8>, StoreError>;
    fn apply_revocation(&mut self, revocation: &Revocation) -> Result<bool, StoreError>;
    fn is_revoked(&mut self, node: &NodeId) -> Result<bool, StoreError>;
    fn set_scope_epoch(&mut self, epoch: &ScopeEpoch) -> Result<bool, StoreError>;
    fn scope_epoch(&mut self, scope: &Scope) -> Result<u64, StoreError>;
    fn update_peer(&mut self, snapshot: &PeerSnapshot) -> Result<(), StoreError>;
    fn peer(&mut self, node: &NodeId) -> Result<Option<PeerSnapshot>, StoreError>;
    fn peers(&mut self) -> Result<Vec<PeerSnapshot>, StoreError>;
    fn replace_bridge_filters(&mut self, filters: &[BridgeFilter]) -> Result<(), StoreError>;
    /// Local narrowing/candidate policy only. A positive result cannot
    /// authorize bridging without a separately verified, active authority
    /// object and exact route scope match.
    fn bridge_allows(
        &mut self,
        from: &Scope,
        to: &Scope,
        topic: &Topic,
        priority: Priority,
    ) -> Result<bool, StoreError>;
    fn event_gaps(&mut self, query: &StoreQuery) -> Result<Vec<EventGap>, StoreError>;
    fn mark_zeroized(&mut self) -> Result<(), StoreError>;
    fn is_zeroized(&mut self) -> Result<bool, StoreError>;
}

/// Control metadata already authenticated by the envelope provider.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VerifiedStoredControl {
    pub envelope_id: EnvelopeId,
    pub authority: NodeId,
    pub signer: NodeId,
    pub sequence: u64,
    pub previous_control: Option<EnvelopeId>,
    pub kind: ControlKind,
    pub revocation: Option<Revocation>,
    pub scope_epoch: Option<ScopeEpoch>,
    pub sealed: Vec<u8>,
}

/// Missing contiguous range in one publisher's Event stream.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EventGap {
    pub publisher: NodeId,
    pub topic: Topic,
    pub scope: Scope,
    pub start_sequence: u64,
    pub end_sequence: u64,
}

fn validate_item(item: &StoredItem) -> Result<(), StoreError> {
    let calculated: EnvelopeId = Sha256::digest(&item.sealed).into();
    if calculated != item.envelope_id {
        return Err(StoreError::Invalid(
            "source-sealed envelope does not match envelope identifier".into(),
        ));
    }
    if item.stamp.dot.counter == 0 {
        return Err(StoreError::Invalid("causal counter must be nonzero".into()));
    }
    if item.stamp.context.len() > MAX_CAUSAL_CONTEXT_ENTRIES {
        return Err(StoreError::Invalid(
            "causal context exceeds the publisher-entry bound".into(),
        ));
    }
    if item.stamp.context.iter().any(|(_, counter)| *counter == 0) {
        return Err(StoreError::Invalid(
            "causal context counters must be nonzero".into(),
        ));
    }
    if item.stamp.context.counter(&item.stamp.dot.publisher) >= item.stamp.dot.counter {
        return Err(StoreError::Invalid(
            "causal context cannot observe its own dot or a future publisher dot".into(),
        ));
    }
    if item.logical_key.len() > 4 * 1024 {
        return Err(StoreError::Invalid("logical key exceeds 4096 bytes".into()));
    }
    if matches!(item.class, DataClass::State | DataClass::Record) && item.logical_key.is_empty() {
        return Err(StoreError::Invalid(
            "State and Record require a logical key".into(),
        ));
    }
    match (item.class, item.event_sequence) {
        (DataClass::Event, Some(sequence)) if sequence > 0 => {}
        (DataClass::Event, _) => {
            return Err(StoreError::Invalid(
                "Event requires a nonzero per-stream sequence".into(),
            ));
        }
        (_, None) => {}
        (_, Some(_)) => {
            return Err(StoreError::Invalid(
                "only Event may carry an event sequence".into(),
            ));
        }
    }
    if item.custody_elapsed_available
        && (item.custody_clock_id.is_none() || item.custody_tick_ms.is_none())
    {
        return Err(StoreError::Invalid(
            "available custody elapsed state requires a clock sample".into(),
        ));
    }
    Ok(())
}

fn causally_after(left: &StoredItem, right: &StoredItem) -> bool {
    left.stamp.context.observes(right.stamp.dot)
}

#[derive(Default)]
struct Reduction {
    statuses: Vec<(ItemId, VersionStatus)>,
    conflict: Option<ConflictAnnotation>,
}

fn reduce_group(mut items: Vec<StoredItem>) -> Reduction {
    if items.is_empty() {
        return Reduction::default();
    }
    items.sort_by_key(|item| item.id);
    if !matches!(items[0].class, DataClass::State | DataClass::Record) {
        return Reduction {
            statuses: items
                .into_iter()
                .map(|item| (item.id, VersionStatus::Current))
                .collect(),
            conflict: None,
        };
    }

    let mut maximal = Vec::new();
    for candidate in &items {
        let dominated = items
            .iter()
            .any(|other| other.id != candidate.id && causally_after(other, candidate));
        if !dominated {
            maximal.push(candidate.id);
        }
    }
    maximal.sort();
    let winner = *maximal.last().expect("non-empty version set has a maximum");
    let maximal_set: BTreeSet<ItemId> = maximal.iter().copied().collect();
    let statuses = items
        .iter()
        .map(|item| {
            let status = if item.id == winner {
                VersionStatus::Current
            } else if maximal_set.contains(&item.id) {
                VersionStatus::Concurrent
            } else {
                VersionStatus::Superseded
            };
            (item.id, status)
        })
        .collect();
    let conflict = if items[0].class == DataClass::Record && maximal.len() > 1 {
        Some(ConflictAnnotation {
            logical_key: items[0].logical_key.clone(),
            siblings: maximal,
            merge_policy: None,
        })
    } else {
        None
    };
    Reduction { statuses, conflict }
}

fn encode_context(context: &VersionVector) -> Vec<u8> {
    let mut encoded = Vec::with_capacity(4 + context.iter().len() * 40);
    encoded.extend_from_slice(&(context.iter().len() as u32).to_be_bytes());
    for (publisher, counter) in context.iter() {
        encoded.extend_from_slice(publisher);
        encoded.extend_from_slice(&counter.to_be_bytes());
    }
    encoded
}

fn decode_context(encoded: &[u8]) -> Result<VersionVector, StoreError> {
    if encoded.len() < 4 {
        return Err(StoreError::Corrupt("causal context is truncated".into()));
    }
    let count = u32::from_be_bytes(encoded[..4].try_into().unwrap()) as usize;
    if count > MAX_CAUSAL_CONTEXT_ENTRIES {
        return Err(StoreError::Corrupt(
            "causal context exceeds the publisher-entry bound".into(),
        ));
    }
    let expected = 4usize
        .checked_add(
            count
                .checked_mul(40)
                .ok_or_else(|| StoreError::Corrupt("causal context length overflow".into()))?,
        )
        .ok_or_else(|| StoreError::Corrupt("causal context length overflow".into()))?;
    if encoded.len() != expected {
        return Err(StoreError::Corrupt("causal context length mismatch".into()));
    }
    let mut context = VersionVector::default();
    let mut previous: Option<NodeId> = None;
    for entry in encoded[4..].chunks_exact(40) {
        let publisher: NodeId = entry[..32].try_into().unwrap();
        if previous.is_some_and(|value| value >= publisher) {
            return Err(StoreError::Corrupt(
                "causal context is not canonical".into(),
            ));
        }
        let counter = u64::from_be_bytes(entry[32..].try_into().unwrap());
        if counter == 0 {
            return Err(StoreError::Corrupt(
                "causal context contains zero counter".into(),
            ));
        }
        context.observe(Dot { publisher, counter });
        previous = Some(publisher);
    }
    Ok(context)
}

fn sql_u64(value: u64, field: &'static str) -> Result<i64, StoreError> {
    i64::try_from(value)
        .map_err(|_| StoreError::Invalid(format!("{field} exceeds SQLite integer range")))
}

fn from_sql_u64(value: i64, field: &'static str) -> Result<u64, StoreError> {
    u64::try_from(value).map_err(|_| StoreError::Corrupt(format!("negative {field}")))
}

fn sql_bool(value: i64, field: &'static str) -> Result<bool, StoreError> {
    match value {
        0 => Ok(false),
        1 => Ok(true),
        _ => Err(StoreError::Corrupt(format!("invalid {field} flag"))),
    }
}

fn class_to_i64(class: DataClass) -> i64 {
    class as u8 as i64
}

fn class_from_i64(value: i64) -> Result<DataClass, StoreError> {
    match value {
        0 => Ok(DataClass::State),
        1 => Ok(DataClass::Event),
        2 => Ok(DataClass::Record),
        3 => Ok(DataClass::Blob),
        _ => Err(StoreError::Corrupt("unknown data class".into())),
    }
}

fn priority_from_i64(value: i64) -> Result<Priority, StoreError> {
    let wire = u8::try_from(value)
        .map_err(|_| StoreError::Corrupt("priority outside byte range".into()))?;
    Priority::from_wire(wire).ok_or_else(|| StoreError::Corrupt("unknown priority".into()))
}

fn status_from_i64(value: i64) -> Result<VersionStatus, StoreError> {
    match value {
        0 => Ok(VersionStatus::Current),
        1 => Ok(VersionStatus::Concurrent),
        2 => Ok(VersionStatus::Superseded),
        _ => Err(StoreError::Corrupt("unknown version status".into())),
    }
}

fn node_from_vec(value: Vec<u8>, field: &'static str) -> Result<NodeId, StoreError> {
    value
        .try_into()
        .map_err(|_| StoreError::Corrupt(format!("{field} is not 32 bytes")))
}

fn item_from_vec(value: Vec<u8>, field: &'static str) -> Result<ItemId, StoreError> {
    value
        .try_into()
        .map_err(|_| StoreError::Corrupt(format!("{field} is not 32 bytes")))
}

fn clock_from_vec(value: Vec<u8>, field: &'static str) -> Result<[u8; 16], StoreError> {
    value
        .try_into()
        .map_err(|_| StoreError::Corrupt(format!("{field} is not 16 bytes")))
}

fn object_id_from_vec(value: Vec<u8>, field: &'static str) -> Result<ObjectId, StoreError> {
    let encoded: [u8; ObjectId::WIRE_LEN] = value
        .try_into()
        .map_err(|_| StoreError::Corrupt(format!("{field} has invalid length")))?;
    ObjectId::from_wire_bytes(encoded)
        .ok_or_else(|| StoreError::Corrupt(format!("{field} has invalid kind")))
}

/// SQLite-backed crash-durable record store.
pub struct SqliteStore {
    connection: Connection,
    config: StoreConfig,
    /// Provider verification is deliberately process-local. Reopen starts
    /// empty so cached controls cannot authorize work before re-authentication.
    #[allow(dead_code)]
    verified_bridge_authorizations: BTreeSet<EnvelopeId>,
    #[allow(dead_code)]
    verified_bridge_routes: BTreeSet<EnvelopeId>,
    #[allow(dead_code)]
    verified_pending_bridge_wrappers: BTreeSet<EnvelopeId>,
    #[allow(dead_code)]
    verified_bridge_sources: BTreeSet<EnvelopeId>,
    /// Verified batch proofs are process capabilities. Exact proof bytes are
    /// durable, but reopen must repopulate this set through the provider.
    verified_batch_proofs: BTreeSet<EnvelopeId>,
}

impl SqliteStore {
    /// Opens or creates a durable store and applies the supplied bounded-storage
    /// policy. WAL plus `synchronous=FULL` makes acknowledged commits durable
    /// across abrupt process termination and power-loss behavior supported by the
    /// underlying filesystem.
    pub fn open(path: impl AsRef<Path>, config: StoreConfig) -> Result<Self, StoreError> {
        validate_config(&config)?;
        let connection = Connection::open(path)?;
        connection.busy_timeout(std::time::Duration::from_secs(5))?;
        connection.execute_batch(
            "PRAGMA foreign_keys=ON;\n\
             PRAGMA journal_mode=WAL;\n\
             PRAGMA synchronous=FULL;\n\
             PRAGMA temp_store=MEMORY;\n\
             PRAGMA secure_delete=ON;",
        )?;
        let mut version: i64 = connection.query_row("PRAGMA user_version", [], |row| row.get(0))?;
        if version > SCHEMA_VERSION {
            return Err(StoreError::Corrupt(format!(
                "store schema {version} is newer than supported {SCHEMA_VERSION}"
            )));
        }
        if version == 0 {
            create_schema(&connection)?;
            version = SCHEMA_VERSION;
        } else if version == 1 {
            migrate_v1_to_v2(&connection)?;
            version = 2;
        }
        if version == 2 {
            migrate_v2_to_v3(&connection)?;
            version = 3;
        }
        if version == 3 {
            migrate_v3_to_v4(&connection)?;
            version = 4;
        }
        if version == 4 {
            migrate_v4_to_v5(&connection)?;
            version = 5;
        }
        if version == 5 {
            migrate_v5_to_v6(&connection)?;
            version = 6;
        }
        if version == 6 {
            migrate_v6_to_v7(&connection)?;
            version = 7;
        }
        if version == 7 {
            migrate_v7_to_v8(&connection)?;
            version = 8;
        }
        if version == 8 {
            migrate_v8_to_v9(&connection)?;
            version = 9;
        }
        if version == 9 {
            migrate_v9_to_v10(&connection)?;
            version = 10;
        }
        if version == 10 {
            migrate_v10_to_v11(&connection)?;
            version = 11;
        }
        if version == 11 {
            migrate_v11_to_v12(&connection)?;
            version = 12;
        }
        if version == 12 {
            migrate_v12_to_v13(&connection)?;
            version = 13;
        }
        if version == 13 {
            migrate_v13_to_v14(&connection)?;
            version = 14;
        }
        if version == 14 {
            migrate_v14_to_v15(&connection)?;
            version = 15;
        }
        if version == 15 {
            migrate_v15_to_v16(&connection)?;
        }
        persist_config(&connection, &config)?;
        Ok(Self {
            connection,
            config,
            verified_bridge_authorizations: BTreeSet::new(),
            verified_bridge_routes: BTreeSet::new(),
            verified_pending_bridge_wrappers: BTreeSet::new(),
            verified_bridge_sources: BTreeSet::new(),
            verified_batch_proofs: BTreeSet::new(),
        })
    }

    /// Test-only crash-window fixture: persist one already-provider-verified
    /// control without running contiguous-prefix activation.
    #[cfg(test)]
    pub(crate) fn stage_verified_control_without_activation_for_test(
        &mut self,
        control: &VerifiedStoredControl,
    ) -> Result<(), StoreError> {
        let transaction = self.connection.transaction()?;
        match insert_control_tx(&transaction, control)? {
            ControlInsert::Inserted => {}
            ControlInsert::Duplicate => {
                return Err(StoreError::Invalid(
                    "test fixture control was already staged".into(),
                ));
            }
            ControlInsert::Rejected(_) => {
                return Err(StoreError::Invalid(
                    "test fixture control signer was already revoked".into(),
                ));
            }
        }
        transaction.commit()?;
        Ok(())
    }

    /// Opens an isolated SQLite database for tests and ephemeral nodes.
    pub fn open_in_memory(config: StoreConfig) -> Result<Self, StoreError> {
        validate_config(&config)?;
        let connection = Connection::open_in_memory()?;
        connection.execute_batch(
            "PRAGMA foreign_keys=ON; PRAGMA synchronous=FULL; PRAGMA secure_delete=ON;",
        )?;
        create_schema(&connection)?;
        persist_config(&connection, &config)?;
        Ok(Self {
            connection,
            config,
            verified_bridge_authorizations: BTreeSet::new(),
            verified_bridge_routes: BTreeSet::new(),
            verified_pending_bridge_wrappers: BTreeSet::new(),
            verified_bridge_sources: BTreeSet::new(),
            verified_batch_proofs: BTreeSet::new(),
        })
    }

    /// Underlying SQLite runtime version, useful for the dependency evidence log.
    pub fn sqlite_version(&self) -> Result<String, StoreError> {
        Ok(self
            .connection
            .query_row("SELECT sqlite_version()", [], |row| row.get(0))?)
    }

    fn clear_bridge_process_liveness(&mut self) {
        self.verified_bridge_authorizations.clear();
        self.verified_bridge_routes.clear();
        self.verified_pending_bridge_wrappers.clear();
        self.verified_bridge_sources.clear();
    }

    fn begin_typed_transfer(
        &mut self,
        object_id: ObjectId,
        total_len: u64,
        priority: Priority,
        now_ms: Option<u64>,
        origin_semantic_version: Option<u16>,
    ) -> Result<(), StoreError> {
        if origin_semantic_version.is_some_and(|version| !matches!(version, 1..=7)) {
            return Err(StoreError::Invalid(
                "unsupported transfer semantic version".into(),
            ));
        }
        if let Some(version) = origin_semantic_version
            && !object_id.kind().is_allowed_in_semantic_version(version)
        {
            return Err(StoreError::Invalid(
                "object kind is not allowed by the semantic version".into(),
            ));
        }
        let storage_key = transfer_storage_key(object_id);
        let existing: Option<(Vec<u8>, Option<i64>)> = self
            .connection
            .query_row(
                "SELECT object_id,origin_semantic_version FROM transfer_identities\n\
                 WHERE storage_key=?1",
                params![storage_key.as_slice()],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .optional()?;
        if let Some((stored, version)) = existing {
            let stored_version = version
                .map(|value| {
                    u16::try_from(value).map_err(|_| {
                        StoreError::Corrupt("transfer semantic version is invalid".into())
                    })
                })
                .transpose()?;
            if stored.as_slice() != object_id.to_wire_bytes()
                || !transfer_resume_is_compatible(
                    object_id.kind(),
                    stored_version,
                    origin_semantic_version,
                )
            {
                return Err(StoreError::Invalid(
                    "transfer identity or first semantic version changed".into(),
                ));
            }
        }
        self.begin_want(storage_key, total_len, priority, now_ms)?;
        self.connection.execute(
            "INSERT INTO transfer_identities(\n\
               storage_key,object_id,origin_semantic_version) VALUES(?1,?2,?3)\n\
             ON CONFLICT(storage_key) DO NOTHING",
            params![
                storage_key.as_slice(),
                object_id.to_wire_bytes().as_slice(),
                origin_semantic_version.map(i64::from)
            ],
        )?;
        let stored: (Vec<u8>, Option<i64>) = self.connection.query_row(
            "SELECT object_id,origin_semantic_version FROM transfer_identities\n\
             WHERE storage_key=?1",
            params![storage_key.as_slice()],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )?;
        let stored_version = stored
            .1
            .map(|value| {
                u16::try_from(value)
                    .map_err(|_| StoreError::Corrupt("transfer semantic version is invalid".into()))
            })
            .transpose()?;
        if stored.0.as_slice() != object_id.to_wire_bytes()
            || !transfer_resume_is_compatible(
                object_id.kind(),
                stored_version,
                origin_semantic_version,
            )
        {
            return Err(StoreError::Invalid(
                "transfer identity or first semantic version changed".into(),
            ));
        }
        Ok(())
    }

    fn load_transfer_progress(
        &self,
        selected_version: Option<u16>,
        limit: usize,
    ) -> Result<Vec<TransferProgress>, StoreError> {
        use rusqlite::types::Value;

        if limit == 0 {
            return Ok(Vec::new());
        }
        if selected_version.is_some_and(|version| !matches!(version, 1..=7)) {
            return Err(StoreError::Invalid(
                "unsupported transfer semantic version".into(),
            ));
        }
        let mut sql = String::from(
            "SELECT i.storage_key,i.object_id,i.origin_semantic_version,w.total_len\n\
             FROM transfer_identities i JOIN wants w ON w.object_id=i.storage_key",
        );
        let mut values = Vec::<Value>::new();
        match selected_version {
            None => {}
            Some(1) => {
                sql.push_str(
                    " WHERE i.origin_semantic_version IS NOT NULL AND\n\
                       ((substr(i.object_id,1,1)=? AND i.origin_semantic_version=1) OR\n\
                        substr(i.object_id,1,1)=?)",
                );
                values.push(vec![ObjectKind::SourceEnvelope as u8].into());
                values.push(vec![ObjectKind::BlobChunk as u8].into());
            }
            Some(2) | Some(3) | Some(4) | Some(5) | Some(6) | Some(7) => {
                sql.push_str(
                    " WHERE i.origin_semantic_version IS NOT NULL AND\n\
                       (substr(i.object_id,1,1) IN (?,?) OR\n\
                        (i.origin_semantic_version IN (2,3,4,5,6,7) AND\n\
                         substr(i.object_id,1,1) IN (?,?,?)))",
                );
                values.push(vec![ObjectKind::SourceEnvelope as u8].into());
                values.push(vec![ObjectKind::BlobChunk as u8].into());
                values.push(vec![ObjectKind::SourceBatchProof as u8].into());
                values.push(vec![ObjectKind::BridgeAuthorization as u8].into());
                values.push(vec![ObjectKind::BridgeRouteWrapper as u8].into());
            }
            Some(_) => unreachable!("validated semantic version"),
        }
        sql.push_str(" ORDER BY i.object_id LIMIT ?");
        values.push(i64::try_from(limit).unwrap_or(i64::MAX).into());
        let rows = {
            let mut statement = self.connection.prepare(&sql)?;
            statement
                .query_map(rusqlite::params_from_iter(values), |row| {
                    Ok((
                        row.get::<_, Vec<u8>>(0)?,
                        row.get::<_, Vec<u8>>(1)?,
                        row.get::<_, Option<i64>>(2)?,
                        row.get::<_, i64>(3)?,
                    ))
                })?
                .collect::<Result<Vec<_>, _>>()?
        };
        let mut progress = Vec::with_capacity(rows.len());
        for (storage_key, encoded_id, semantic_version, total_len) in rows {
            let encoded: [u8; ObjectId::WIRE_LEN] = encoded_id
                .try_into()
                .map_err(|_| StoreError::Corrupt("typed transfer identity length".into()))?;
            let object_id = ObjectId::from_wire_bytes(encoded)
                .ok_or_else(|| StoreError::Corrupt("typed transfer identity kind".into()))?;
            if transfer_storage_key(object_id).as_slice() != storage_key.as_slice() {
                return Err(StoreError::Corrupt(
                    "typed transfer identity storage key mismatch".into(),
                ));
            }
            let origin_semantic_version = semantic_version
                .map(|value| {
                    u16::try_from(value).map_err(|_| {
                        StoreError::Corrupt("transfer semantic version is invalid".into())
                    })
                })
                .transpose()?;
            if let Some(selected) = selected_version
                && !transfer_resume_is_compatible(
                    object_id.kind(),
                    origin_semantic_version,
                    Some(selected),
                )
            {
                return Err(StoreError::Corrupt(
                    "version-filtered transfer query returned an incompatible row".into(),
                ));
            }
            let received = {
                let mut statement = self.connection.prepare(
                    "SELECT start_offset,end_offset FROM sealed_chunks\n\
                     WHERE object_id=?1 ORDER BY start_offset",
                )?;
                statement
                    .query_map(params![storage_key], |row| {
                        Ok((row.get::<_, i64>(0)?, row.get::<_, i64>(1)?))
                    })?
                    .map(|row| {
                        let (start, end) = row?;
                        ChunkRange::new(
                            from_sql_u64(start, "transfer range start")?,
                            from_sql_u64(end, "transfer range end")?,
                        )
                    })
                    .collect::<Result<Vec<_>, StoreError>>()?
            };
            progress.push(TransferProgress {
                object_id,
                origin_semantic_version,
                total_len: from_sql_u64(total_len, "transfer total length")?,
                received,
            });
        }
        Ok(progress)
    }

    /// Point lookup for an exact semantic-v2+ transfer which has already been
    /// moved crash-atomically into private dependency or quarantine storage.
    /// These tables are not inventory or acceptance indexes. Their exact byte
    /// lengths equal the immutable completed-transfer lengths checked by the
    /// corresponding transition transaction.
    pub(crate) fn durably_disposed_semantic_object_len(
        &self,
        object_id: ObjectId,
        semantic_version: u16,
    ) -> Result<Option<u64>, StoreError> {
        if !matches!(
            semantic_version,
            SEMANTIC_PROTOCOL_V2
                | SEMANTIC_PROTOCOL_V3
                | SEMANTIC_PROTOCOL_V4
                | SEMANTIC_PROTOCOL_V5
                | SEMANTIC_PROTOCOL_V6
                | SEMANTIC_PROTOCOL_V7
        ) {
            return Ok(None);
        }

        let (sql, key, label) = match object_id.kind() {
            ObjectKind::BridgeAuthorization => (
                "SELECT length(exact_bytes) FROM bridge_authorization_controls\n\
                 WHERE envelope_id=?1 AND applied=0 LIMIT 2",
                object_id.digest().to_vec(),
                "pending bridge authorization",
            ),
            ObjectKind::BridgeRouteWrapper => (
                "SELECT length(exact_bytes) FROM bridge_pending_wrappers\n\
                 WHERE wrapper_envelope_id=?1 LIMIT 2",
                object_id.digest().to_vec(),
                "pending bridge wrapper",
            ),
            ObjectKind::SourceEnvelope => (
                "SELECT length(exact_bytes) FROM pending_batch_items WHERE envelope_id=?1\n\
                 UNION ALL\n\
                 SELECT length(exact_bytes) FROM bridge_pending_sources\n\
                   WHERE origin_envelope_id=?1\n\
                 UNION ALL\n\
                 SELECT length(exact_bytes) FROM bridge_unresolved_sources\n\
                   WHERE origin_envelope_id=?1\n\
                 LIMIT 2",
                object_id.digest().to_vec(),
                "private source disposition",
            ),
            ObjectKind::BlobChunk => (
                "SELECT length(exact_bytes) FROM bridge_pending_blob_carriers\n\
                 WHERE object_id=?1 LIMIT 2",
                object_id.to_wire_bytes().to_vec(),
                "pending bridge Blob carrier",
            ),
            ObjectKind::SourceBatchProof => return Ok(None),
        };
        let lengths = {
            let mut statement = self.connection.prepare(sql)?;
            statement
                .query_map(params![key], |row| row.get::<_, i64>(0))?
                .collect::<Result<Vec<_>, _>>()?
        };
        match lengths.as_slice() {
            [] => Ok(None),
            [length] => Ok(Some(from_sql_u64(*length, label)?)),
            _ => Err(StoreError::Corrupt(format!(
                "{label} exists in multiple private dispositions"
            ))),
        }
    }
}

fn batch_proof_effective_priority(
    connection: &Connection,
    proof_envelope_id: EnvelopeId,
    custody_sample: Option<CustodySample>,
) -> Result<Priority, StoreError> {
    let columns = ITEM_COLUMNS
        .split(',')
        .map(|column| format!("i.{column}"))
        .collect::<Vec<_>>()
        .join(",");
    let sql = format!(
        "SELECT {columns} FROM batch_item_representations r\n\
         JOIN items i ON i.item_id=r.item_id\n\
         LEFT JOIN revocations v ON v.subject=i.publisher\n\
         LEFT JOIN scope_epochs e ON e.scope=i.scope\n\
         WHERE r.proof_envelope_id=?1 AND v.subject IS NULL\n\
           AND (e.epoch IS NULL OR i.key_epoch>=e.epoch)"
    );
    let mut effective = Priority::Routine;
    let mut statement = connection.prepare(&sql)?;
    for row in statement.query_map(params![proof_envelope_id.as_slice()], decode_item_row)? {
        let item = row?;
        if item.is_forwardable_at(custody_sample) {
            effective = effective.max(item.priority);
        }
    }
    drop(statement);
    let pending: Option<i64> = connection.query_row(
        "SELECT max(q.priority) FROM pending_batch_items q\n\
         LEFT JOIN revocations v ON v.subject=q.publisher\n\
         LEFT JOIN scope_epochs e ON e.scope=q.scope\n\
         WHERE q.proof_envelope_id=?1 AND v.subject IS NULL\n\
           AND (e.epoch IS NULL OR q.key_epoch>=e.epoch)",
        params![proof_envelope_id.as_slice()],
        |row| row.get(0),
    )?;
    if let Some(pending) = pending {
        effective = effective.max(priority_from_i64(pending)?);
    }
    Ok(effective)
}

fn load_stored_batch_proof(
    connection: &Connection,
    proof_envelope_id: EnvelopeId,
    custody_sample: Option<CustodySample>,
) -> Result<Option<StoredBatchProof>, StoreError> {
    let stored = connection
        .query_row(
            "SELECT batch_id,scope,exact_bytes,inserted_order FROM batch_proofs\n\
             WHERE proof_envelope_id=?1",
            params![proof_envelope_id.as_slice()],
            |row| {
                Ok((
                    row.get::<_, Vec<u8>>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, Vec<u8>>(2)?,
                    row.get::<_, i64>(3)?,
                ))
            },
        )
        .optional()?;
    let Some((batch_id, scope, exact_bytes, inserted_order)) = stored else {
        return Ok(None);
    };
    let batch_id = item_from_vec(batch_id, "batch id")?;
    let scope = Scope::new(scope).map_err(|error| StoreError::Corrupt(error.to_string()))?;
    if exact_object_id(&exact_bytes) != proof_envelope_id {
        return Err(StoreError::Corrupt(
            "stored batch proof bytes do not match their identity".into(),
        ));
    }
    Ok(Some(StoredBatchProof {
        proof_envelope_id,
        batch_id,
        scope,
        exact_bytes,
        inserted_order: from_sql_u64(inserted_order, "batch proof order")?,
        effective_priority: batch_proof_effective_priority(
            connection,
            proof_envelope_id,
            custody_sample,
        )?,
    }))
}

fn decode_pending_batch_row(row: &Row<'_>) -> rusqlite::Result<StoredPendingBatchItem> {
    fn conversion(error: StoreError) -> rusqlite::Error {
        rusqlite::Error::FromSqlConversionFailure(0, rusqlite::types::Type::Blob, Box::new(error))
    }
    let ttl_ms = row
        .get::<_, Option<i64>>(5)?
        .map(|value| from_sql_u64(value, "pending batch ttl"))
        .transpose()
        .map_err(conversion)?;
    let cumulative_custody_age_ms =
        from_sql_u64(row.get(6)?, "pending batch custody age").map_err(conversion)?;
    let authenticated_forwarding_age_ms =
        from_sql_u64(row.get(7)?, "pending batch forwarding age").map_err(conversion)?;
    let age_continuity_unknown =
        sql_bool(row.get(8)?, "pending batch custody continuity").map_err(conversion)?;
    let custody_clock_id = row
        .get::<_, Option<Vec<u8>>>(9)?
        .map(|value| clock_from_vec(value, "pending batch custody clock"))
        .transpose()
        .map_err(conversion)?;
    let custody_tick_ms = row
        .get::<_, Option<i64>>(10)?
        .map(|value| from_sql_u64(value, "pending batch custody tick"))
        .transpose()
        .map_err(conversion)?;
    let custody_elapsed_available =
        sql_bool(row.get(11)?, "pending batch elapsed custody").map_err(conversion)?;
    if cumulative_custody_age_ms < authenticated_forwarding_age_ms
        || custody_elapsed_available != (custody_clock_id.is_some() && custody_tick_ms.is_some())
        || (age_continuity_unknown && custody_elapsed_available)
    {
        return Err(conversion(StoreError::Corrupt(
            "pending batch custody tuple is inconsistent".into(),
        )));
    }
    Ok(StoredPendingBatchItem {
        envelope_id: item_from_vec(row.get(0)?, "pending batch envelope").map_err(conversion)?,
        item_id: item_from_vec(row.get(1)?, "pending batch item").map_err(conversion)?,
        proof_envelope_id: item_from_vec(row.get(2)?, "pending batch proof").map_err(conversion)?,
        scope: Scope::new(row.get::<_, String>(3)?)
            .map_err(|error| conversion(StoreError::Corrupt(error.to_string())))?,
        priority: priority_from_i64(row.get(4)?).map_err(conversion)?,
        ttl_ms,
        cumulative_custody_age_ms,
        authenticated_forwarding_age_ms,
        age_continuity_unknown,
        custody_clock_id,
        custody_tick_ms,
        custody_elapsed_available,
        exact_bytes: row.get(12)?,
        inserted_order: from_sql_u64(row.get(13)?, "pending batch order").map_err(conversion)?,
    })
}

fn batch_staging_usage_tx(transaction: &Transaction<'_>) -> Result<QuotaUsage, StoreError> {
    let (items, bytes): (i64, i64) = transaction.query_row(
        "SELECT\n\
           (SELECT count(*) FROM wants) +\n\
           (SELECT count(*) FROM pending_batch_items) +\n\
           (SELECT count(*) FROM rejected_batch_proofs),\n\
           (SELECT coalesce(sum(length(bytes)),0) FROM sealed_chunks) +\n\
           (SELECT coalesce(sum(accounted_bytes),0) FROM pending_batch_items) +\n\
           (SELECT coalesce(sum(accounted_bytes),0) FROM rejected_batch_proofs)",
        [],
        |row| Ok((row.get(0)?, row.get(1)?)),
    )?;
    Ok(QuotaUsage {
        items: from_sql_u64(items, "batch staging objects")?,
        bytes: from_sql_u64(bytes, "batch staging bytes")?,
    })
}

fn make_batch_staging_room_tx(
    transaction: &Transaction<'_>,
    config: &StoreConfig,
    additional_items: u64,
    additional_bytes: u64,
    maximum_victim_priority: Priority,
) -> Result<(), StoreError> {
    if additional_bytes > staged_object_byte_limit(config) {
        return Err(StoreError::QuotaExceeded);
    }
    loop {
        let usage = batch_staging_usage_tx(transaction)?;
        if usage
            .items
            .checked_add(additional_items)
            .is_some_and(|value| value <= staging_object_limit(config))
            && usage
                .bytes
                .checked_add(additional_bytes)
                .is_some_and(|value| value <= staging_byte_limit(config))
        {
            return Ok(());
        }
        let candidate: Option<Vec<u8>> = transaction
            .query_row(
                "SELECT q.envelope_id FROM pending_batch_items q\n\
                 WHERE q.priority<=?1\n\
                 ORDER BY EXISTS(SELECT 1 FROM batch_proofs p\n\
                   WHERE p.proof_envelope_id=q.proof_envelope_id),\n\
                   q.priority,q.inserted_order LIMIT 1",
                params![maximum_victim_priority as u8 as i64],
                |row| row.get(0),
            )
            .optional()?;
        let Some(candidate) = candidate else {
            return Err(StoreError::QuotaExceeded);
        };
        transaction.execute(
            "DELETE FROM pending_batch_items WHERE envelope_id=?1",
            params![candidate],
        )?;
    }
}

fn stored_item_matches_verified_batch(item: &StoredItem, verified: &VerifiedBatchItem) -> bool {
    let envelope = verified.verified_envelope();
    item.id == envelope.id
        && item.class == envelope.header.class
        && item.topic == envelope.header.topic
        && item.scope == envelope.header.scope
        && item.priority == envelope.header.priority
        && item.stamp == envelope.header.stamp
        && item.event_sequence == envelope.header.event_sequence
        && item.logical_key == envelope.header.logical_key
        && item.ttl_ms == envelope.header.ttl_ms
        && item.content_len == envelope.header.content_len
        && item.tombstone == envelope.header.tombstone
        && item.key_epoch == envelope.header.key_epoch
}

fn merged_pending_batch_custody(
    existing: Option<&StoredPendingBatchItem>,
    authenticated_age_ms: u64,
    sample: Option<CustodySample>,
) -> (u64, bool, Option<[u8; 16]>, Option<u64>, bool) {
    merge_authenticated_custody_fields(
        existing.map(|value| {
            (
                value.cumulative_custody_age_ms,
                value.age_continuity_unknown,
                value.custody_clock_id,
                value.custody_tick_ms,
                value.custody_elapsed_available,
            )
        }),
        authenticated_age_ms,
        sample,
    )
}

#[allow(dead_code)]
impl SqliteStore {
    /// Pages durable proof carriers for provider reauthentication after restart.
    /// Returned rows confer no authority until [`Self::mark_verified_batch_proof`].
    pub(crate) fn stored_batch_proofs_after(
        &self,
        after_order: Option<u64>,
        limit: usize,
    ) -> Result<Vec<StoredBatchProof>, StoreError> {
        let limit = limit.min(MAX_BATCH_STORE_PAGE);
        if limit == 0 {
            return Ok(Vec::new());
        }
        let ids = {
            let mut statement = self.connection.prepare(
                "SELECT proof_envelope_id FROM batch_proofs\n\
                 WHERE inserted_order>?1 ORDER BY inserted_order LIMIT ?2",
            )?;
            statement
                .query_map(
                    params![
                        sql_u64(after_order.unwrap_or(0), "batch proof cursor")?,
                        i64::try_from(limit).unwrap_or(i64::MAX)
                    ],
                    |row| row.get::<_, Vec<u8>>(0),
                )?
                .collect::<Result<Vec<_>, _>>()?
        };
        ids.into_iter()
            .map(|id| {
                let id = item_from_vec(id, "batch proof id")?;
                load_stored_batch_proof(&self.connection, id, None)?
                    .ok_or_else(|| StoreError::Corrupt("paged batch proof disappeared".into()))
            })
            .collect()
    }

    pub(crate) fn stored_batch_proof(
        &self,
        proof_envelope_id: &EnvelopeId,
    ) -> Result<Option<StoredBatchProof>, StoreError> {
        load_stored_batch_proof(&self.connection, *proof_envelope_id, None)
    }

    /// Reconstitutes only the process-local proof capability after the provider
    /// authenticates the exact durable bytes. It never trusts cached metadata.
    pub(crate) fn mark_verified_batch_proof(
        &mut self,
        verified: &VerifiedBatchProof,
        exact_bytes: &[u8],
    ) -> Result<(), StoreError> {
        let proof_id = verified.proof_envelope_id();
        if exact_bytes.is_empty() || exact_object_id(exact_bytes) != proof_id {
            return Err(StoreError::Invalid(
                "verified batch proof bytes do not match their identity".into(),
            ));
        }
        let scope = Scope::new(verified.manifest().preamble.scope.clone())
            .map_err(|error| StoreError::Invalid(error.to_string()))?;
        if self.connection.query_row(
            "SELECT EXISTS(SELECT 1 FROM rejected_batch_proofs WHERE proof_envelope_id=?1)",
            params![proof_id.as_slice()],
            |row| row.get::<_, bool>(0),
        )? {
            return Err(StoreError::Invalid(
                "batch proof identity is durably rejected".into(),
            ));
        }
        let stored = load_stored_batch_proof(&self.connection, proof_id, None)?
            .ok_or(StoreError::NotFound("batch proof"))?;
        if stored.batch_id != verified.batch_id()
            || stored.scope != scope
            || stored.exact_bytes != exact_bytes
        {
            return Err(StoreError::Corrupt(
                "provider-verified batch proof differs from durable bytes".into(),
            ));
        }
        self.verified_batch_proofs.insert(proof_id);
        Ok(())
    }

    /// Stores a provider-authenticated proof and its proof-before-item outbox
    /// record in one transaction, then activates its process-local capability.
    pub(crate) fn stage_verified_batch_proof(
        &mut self,
        verified: &VerifiedBatchProof,
        exact_bytes: &[u8],
    ) -> Result<bool, StoreError> {
        let proof_id = verified.proof_envelope_id();
        if exact_bytes.is_empty() || exact_object_id(exact_bytes) != proof_id {
            return Err(StoreError::Invalid(
                "verified batch proof bytes do not match their identity".into(),
            ));
        }
        let scope = Scope::new(verified.manifest().preamble.scope.clone())
            .map_err(|error| StoreError::Invalid(error.to_string()))?;
        let config = self.config.clone();
        let transaction = self.connection.transaction()?;
        if transaction.query_row(
            "SELECT EXISTS(SELECT 1 FROM rejected_batch_proofs WHERE proof_envelope_id=?1)",
            params![proof_id.as_slice()],
            |row| row.get::<_, bool>(0),
        )? {
            return Err(StoreError::Invalid(
                "batch proof identity is durably rejected".into(),
            ));
        }
        let existing = transaction
            .query_row(
                "SELECT batch_id,scope,exact_bytes FROM batch_proofs\n\
                 WHERE proof_envelope_id=?1",
                params![proof_id.as_slice()],
                |row| {
                    Ok((
                        row.get::<_, Vec<u8>>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, Vec<u8>>(2)?,
                    ))
                },
            )
            .optional()?;
        if let Some((batch_id, stored_scope, stored_bytes)) = existing {
            if batch_id.as_slice() != verified.batch_id()
                || stored_scope != scope.as_str()
                || stored_bytes != exact_bytes
            {
                return Err(StoreError::Corrupt(
                    "batch proof identity maps to different durable content".into(),
                ));
            }
            transaction.commit()?;
            self.verified_batch_proofs.insert(proof_id);
            return Ok(false);
        }
        let accounted = (exact_bytes.len() as u64)
            .checked_add(scope.as_str().len() as u64)
            .and_then(|value| value.checked_add(128))
            .ok_or(StoreError::QuotaExceeded)?;
        ensure_bridge_admission(
            &transaction,
            &config,
            2,
            accounted.checked_add(96).ok_or(StoreError::QuotaExceeded)?,
        )?;
        let order = next_order(&transaction)?;
        transaction.execute(
            "INSERT INTO batch_proofs(\n\
               proof_envelope_id,batch_id,scope,exact_bytes,inserted_order,accounted_bytes)\n\
             VALUES(?1,?2,?3,?4,?5,?6)",
            params![
                proof_id.as_slice(),
                verified.batch_id().as_slice(),
                scope.as_str(),
                exact_bytes,
                sql_u64(order, "batch proof order")?,
                sql_u64(accounted, "batch proof bytes")?
            ],
        )?;
        let outbox_order = next_order(&transaction)?;
        transaction.execute(
            "INSERT INTO batch_proof_outbox(proof_envelope_id,enqueued_order) VALUES(?1,?2)",
            params![
                proof_id.as_slice(),
                sql_u64(outbox_order, "batch proof outbox order")?
            ],
        )?;
        ensure_scope_quota_tx(&transaction, &scope)?;
        transaction.commit()?;
        self.verified_batch_proofs.insert(proof_id);
        Ok(true)
    }

    pub(crate) fn stored_pending_batch_items_after(
        &self,
        after_order: Option<u64>,
        limit: usize,
    ) -> Result<Vec<StoredPendingBatchItem>, StoreError> {
        let limit = limit.min(MAX_BATCH_STORE_PAGE);
        if limit == 0 {
            return Ok(Vec::new());
        }
        let mut statement = self.connection.prepare(
            "SELECT envelope_id,item_id,proof_envelope_id,scope,priority,ttl_ms,\n\
                    cumulative_custody_age_ms,forwarding_custody_age_ms,\n\
                    age_continuity_unknown,custody_clock_id,custody_tick_ms,\n\
                    custody_elapsed_available,exact_bytes,inserted_order\n\
             FROM pending_batch_items WHERE inserted_order>?1\n\
             ORDER BY inserted_order LIMIT ?2",
        )?;
        Ok(statement
            .query_map(
                params![
                    sql_u64(after_order.unwrap_or(0), "pending batch cursor")?,
                    i64::try_from(limit).unwrap_or(i64::MAX)
                ],
                decode_pending_batch_row,
            )?
            .collect::<Result<Vec<_>, _>>()?)
    }

    pub(crate) fn pending_batch_items_for_proof(
        &self,
        proof_envelope_id: &EnvelopeId,
        after_order: Option<u64>,
        limit: usize,
    ) -> Result<Vec<StoredPendingBatchItem>, StoreError> {
        let limit = limit.min(MAX_BATCH_STORE_PAGE);
        if limit == 0 {
            return Ok(Vec::new());
        }
        let mut statement = self.connection.prepare(
            "SELECT envelope_id,item_id,proof_envelope_id,scope,priority,ttl_ms,\n\
                    cumulative_custody_age_ms,forwarding_custody_age_ms,\n\
                    age_continuity_unknown,custody_clock_id,custody_tick_ms,\n\
                    custody_elapsed_available,exact_bytes,inserted_order\n\
             FROM pending_batch_items WHERE proof_envelope_id=?1 AND inserted_order>?2\n\
             ORDER BY inserted_order LIMIT ?3",
        )?;
        Ok(statement
            .query_map(
                params![
                    proof_envelope_id.as_slice(),
                    sql_u64(after_order.unwrap_or(0), "pending batch cursor")?,
                    i64::try_from(limit).unwrap_or(i64::MAX)
                ],
                decode_pending_batch_row,
            )?
            .collect::<Result<Vec<_>, _>>()?)
    }

    pub(crate) fn stored_pending_batch_item(
        &self,
        envelope_id: &EnvelopeId,
    ) -> Result<Option<StoredPendingBatchItem>, StoreError> {
        self.connection
            .query_row(
                "SELECT envelope_id,item_id,proof_envelope_id,scope,priority,ttl_ms,\n\
                        cumulative_custody_age_ms,forwarding_custody_age_ms,\n\
                        age_continuity_unknown,custody_clock_id,custody_tick_ms,\n\
                        custody_elapsed_available,exact_bytes,inserted_order\n\
                 FROM pending_batch_items WHERE envelope_id=?1",
                params![envelope_id.as_slice()],
                decode_pending_batch_row,
            )
            .optional()
            .map_err(StoreError::from)
    }

    pub(crate) fn clear_verified_batch_proofs(&mut self) {
        self.verified_batch_proofs.clear();
    }

    /// Deletes only the exact private compact carrier rejected by the provider.
    pub(crate) fn discard_rejected_pending_batch_item(
        &mut self,
        envelope_id: EnvelopeId,
        exact_bytes: &[u8],
    ) -> Result<bool, StoreError> {
        if exact_bytes.is_empty() || exact_object_id(exact_bytes) != envelope_id {
            return Err(StoreError::Invalid(
                "rejected compact bytes do not match their exact identity".into(),
            ));
        }
        let transaction = self.connection.transaction()?;
        let existing: Option<Vec<u8>> = transaction
            .query_row(
                "SELECT exact_bytes FROM pending_batch_items WHERE envelope_id=?1",
                params![envelope_id.as_slice()],
                |row| row.get(0),
            )
            .optional()?;
        let Some(existing) = existing else {
            transaction.commit()?;
            return Ok(false);
        };
        if existing != exact_bytes {
            return Err(StoreError::Corrupt(
                "rejected compact identity maps to different pending bytes".into(),
            ));
        }
        let deleted = transaction.execute(
            "DELETE FROM pending_batch_items WHERE envelope_id=?1 AND exact_bytes=?2",
            params![envelope_id.as_slice(), exact_bytes],
        )?;
        if deleted != 1 {
            return Err(StoreError::Corrupt(
                "pending compact changed during rejection".into(),
            ));
        }
        transaction.commit()?;
        Ok(true)
    }

    /// Stores only the exact route-authenticated carrier. This row remains
    /// private and cannot enter projections, inventory, or application reads.
    pub(crate) fn stage_pending_batch_item(
        &mut self,
        pending: &PendingBatchItem,
        exact_bytes: &[u8],
    ) -> Result<bool, StoreError> {
        self.stage_pending_batch_item_at(pending, exact_bytes, 0, None)
    }

    pub(crate) fn stage_pending_batch_item_at(
        &mut self,
        pending: &PendingBatchItem,
        exact_bytes: &[u8],
        authenticated_custody_age_ms: u64,
        sample: Option<CustodySample>,
    ) -> Result<bool, StoreError> {
        let envelope_id = pending.envelope_id();
        if exact_bytes.is_empty()
            || exact_object_id(exact_bytes) != envelope_id
            || pending.header().stamp.dot.counter == 0
            || pending
                .header()
                .stamp
                .context
                .counter(&pending.header().stamp.dot.publisher)
                >= pending.header().stamp.dot.counter
        {
            return Err(StoreError::Invalid(
                "pending compact batch carrier is internally inconsistent".into(),
            ));
        }
        let scope = &pending.header().scope;
        let accounted = (exact_bytes.len() as u64)
            .checked_add(scope.as_str().len() as u64)
            .and_then(|value| value.checked_add(160))
            .ok_or(StoreError::QuotaExceeded)?;
        let config = self.config.clone();
        let existing_pending = self.stored_pending_batch_item(&envelope_id)?;
        let custody = merged_pending_batch_custody(
            existing_pending.as_ref(),
            authenticated_custody_age_ms,
            sample,
        );
        let transaction = self.connection.transaction()?;
        if transaction.query_row(
            "SELECT EXISTS(SELECT 1 FROM rejected_batch_proofs WHERE proof_envelope_id=?1)",
            params![pending.proof_envelope_id().as_slice()],
            |row| row.get::<_, bool>(0),
        )? {
            return Err(StoreError::Invalid(
                "pending compact depends on a durably rejected proof".into(),
            ));
        }
        let accepted: Option<(Vec<u8>, Vec<u8>)> = transaction
            .query_row(
                "SELECT r.envelope_id,coalesce(r.exact_bytes,i.sealed)\n\
                 FROM batch_item_representations r JOIN items i ON i.item_id=r.item_id\n\
                 WHERE r.item_id=?1 AND r.representation=1",
                params![pending.item_id().as_slice()],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .optional()?;
        if let Some((stored_envelope, stored_bytes)) = accepted {
            if stored_envelope.as_slice() != envelope_id || stored_bytes != exact_bytes {
                return Err(StoreError::Invalid(
                    "compact batch item identity maps to different accepted bytes".into(),
                ));
            }
            transaction.commit()?;
            return Ok(false);
        }
        if let Some(existing) = existing_pending {
            if existing.item_id != pending.item_id()
                || existing.proof_envelope_id != pending.proof_envelope_id()
                || existing.scope != *scope
                || existing.priority != pending.header().priority
                || existing.ttl_ms != pending.header().ttl_ms
                || existing.exact_bytes != exact_bytes
            {
                return Err(StoreError::Corrupt(
                    "pending compact identity maps to different durable content".into(),
                ));
            }
            transaction.execute(
                "UPDATE pending_batch_items SET\n\
                   cumulative_custody_age_ms=?1,\n\
                   forwarding_custody_age_ms=max(forwarding_custody_age_ms,?2),\n\
                   age_continuity_unknown=?3,custody_clock_id=?4,custody_tick_ms=?5,\n\
                   custody_elapsed_available=?6 WHERE envelope_id=?7",
                params![
                    sql_u64(custody.0, "pending batch custody age")?,
                    sql_u64(authenticated_custody_age_ms, "pending batch forwarding age")?,
                    i64::from(custody.1),
                    custody.2.map(|value| value.to_vec()),
                    custody
                        .3
                        .map(|value| sql_u64(value, "pending batch custody tick"))
                        .transpose()?,
                    i64::from(custody.4),
                    envelope_id.as_slice()
                ],
            )?;
            transaction.commit()?;
            return Ok(false);
        }
        make_batch_staging_room_tx(
            &transaction,
            &config,
            1,
            accounted,
            pending.header().priority,
        )?;
        let order = next_order(&transaction)?;
        transaction.execute(
            "INSERT INTO pending_batch_items(\n\
               envelope_id,item_id,proof_envelope_id,scope,priority,publisher,key_epoch,\n\
               ttl_ms,cumulative_custody_age_ms,forwarding_custody_age_ms,\n\
               age_continuity_unknown,custody_clock_id,custody_tick_ms,\n\
               custody_elapsed_available,exact_bytes,inserted_order,accounted_bytes)\n\
             VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14,?15,?16,?17)",
            params![
                envelope_id.as_slice(),
                pending.item_id().as_slice(),
                pending.proof_envelope_id().as_slice(),
                scope.as_str(),
                pending.header().priority as u8 as i64,
                pending.header().stamp.dot.publisher.as_slice(),
                sql_u64(pending.header().key_epoch, "pending batch key epoch")?,
                pending
                    .header()
                    .ttl_ms
                    .map(|value| sql_u64(value, "pending batch ttl"))
                    .transpose()?,
                sql_u64(custody.0, "pending batch custody age")?,
                sql_u64(authenticated_custody_age_ms, "pending batch forwarding age")?,
                i64::from(custody.1),
                custody.2.map(|value| value.to_vec()),
                custody
                    .3
                    .map(|value| sql_u64(value, "pending batch custody tick"))
                    .transpose()?,
                i64::from(custody.4),
                exact_bytes,
                sql_u64(order, "pending batch order")?,
                sql_u64(accounted, "pending batch bytes")?
            ],
        )?;
        transaction.commit()?;
        Ok(true)
    }

    /// Atomically promotes one exact pending compact carrier only while its
    /// proof remains provider-verified in this process.
    pub(crate) fn commit_verified_batch_item(
        &mut self,
        verified: &VerifiedBatchItem,
        item: StoredItem,
        exact_bytes: &[u8],
    ) -> Result<BatchItemCommitOutcome, StoreError> {
        self.commit_verified_batch_item_at(verified, item, exact_bytes, None)
    }

    pub(crate) fn commit_verified_batch_item_at(
        &mut self,
        verified: &VerifiedBatchItem,
        mut item: StoredItem,
        exact_bytes: &[u8],
        custody_sample: Option<CustodySample>,
    ) -> Result<BatchItemCommitOutcome, StoreError> {
        let proof_id = verified.proof_envelope_id();
        if !self.verified_batch_proofs.contains(&proof_id)
            || exact_bytes.is_empty()
            || exact_object_id(exact_bytes) != verified.envelope_id()
            || item.envelope_id != verified.envelope_id()
            || item.sealed != exact_bytes
            || !stored_item_matches_verified_batch(&item, verified)
        {
            return Err(StoreError::Invalid(
                "compact batch item lacks an exact process-verified dependency".into(),
            ));
        }
        let pending_snapshot = self
            .stored_pending_batch_item(&verified.envelope_id())?
            .ok_or(StoreError::NotFound("pending compact batch item"))?;
        if pending_snapshot.item_id != item.id
            || pending_snapshot.proof_envelope_id != proof_id
            || pending_snapshot.ttl_ms != item.ttl_ms
            || pending_snapshot.exact_bytes != exact_bytes
        {
            return Err(StoreError::Invalid(
                "pending compact custody or identity changed before promotion".into(),
            ));
        }
        let effective_age = pending_snapshot.effective_custody_age_ms(custody_sample);
        if let Some(ttl_ms) = item.ttl_ms.filter(|_| !item.tombstone) {
            let age = effective_age.ok_or_else(|| {
                StoreError::Invalid(
                    "finite-TTL compact item has no continuous custody clock".into(),
                )
            })?;
            if age >= ttl_ms {
                return Err(StoreError::Invalid(
                    "finite-TTL compact item expired before proof promotion".into(),
                ));
            }
            let sample = custody_sample.ok_or_else(|| {
                StoreError::Invalid("finite-TTL compact promotion lacks a custody sample".into())
            })?;
            item.custody_age_ms = age;
            item.custody_clock_id = Some(sample.clock_id);
            item.custody_tick_ms = Some(sample.tick_ms);
            item.custody_elapsed_available = true;
        } else if let Some(age) = effective_age {
            item.custody_age_ms = age;
            if pending_snapshot.custody_elapsed_available
                && !pending_snapshot.age_continuity_unknown
            {
                item.custody_clock_id = custody_sample.map(|sample| sample.clock_id);
                item.custody_tick_ms = custody_sample.map(|sample| sample.tick_ms);
                item.custody_elapsed_available = custody_sample.is_some();
            } else {
                item.custody_clock_id = None;
                item.custody_tick_ms = None;
                item.custody_elapsed_available = false;
            }
        }
        let config = self.config.clone();
        let transaction = self.connection.transaction()?;
        let proof: Option<(Vec<u8>, String)> = transaction
            .query_row(
                "SELECT batch_id,scope FROM batch_proofs WHERE proof_envelope_id=?1",
                params![proof_id.as_slice()],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .optional()?;
        let Some((batch_id, proof_scope)) = proof else {
            return Err(StoreError::NotFound("process-verified batch proof"));
        };
        if batch_id.as_slice() != verified.batch_id() || proof_scope != item.scope.as_str() {
            return Err(StoreError::Invalid(
                "compact item does not match its durable batch proof".into(),
            ));
        }
        let pending: Option<(Vec<u8>, Vec<u8>, Vec<u8>)> = transaction
            .query_row(
                "SELECT item_id,proof_envelope_id,exact_bytes FROM pending_batch_items\n\
                 WHERE envelope_id=?1",
                params![verified.envelope_id().as_slice()],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .optional()?;
        let Some((pending_item_id, pending_proof_id, pending_bytes)) = pending else {
            return Err(StoreError::NotFound("pending compact batch item"));
        };
        if pending_item_id.as_slice() != item.id
            || pending_proof_id.as_slice() != proof_id
            || pending_bytes != exact_bytes
        {
            return Err(StoreError::Invalid(
                "pending compact carrier changed before promotion".into(),
            ));
        }

        let existing = load_item_tx(&transaction, &item.id)?;
        let (outcome, inserted_order) = if let Some(existing) = existing {
            if !stored_item_matches_verified_batch(&existing, verified) {
                return Err(StoreError::Invalid(
                    "compact representation semantics differ from retained item".into(),
                ));
            }
            let compact: Option<(Vec<u8>, Vec<u8>, Vec<u8>)> = transaction
                .query_row(
                    "SELECT r.envelope_id,r.proof_envelope_id,coalesce(r.exact_bytes,i.sealed)\n\
                     FROM batch_item_representations r JOIN items i ON i.item_id=r.item_id\n\
                     WHERE r.item_id=?1 AND r.representation=1",
                    params![item.id.as_slice()],
                    |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
                )
                .optional()?;
            if let Some((envelope_id, compact_proof, stored_bytes)) = compact {
                if envelope_id.as_slice() != verified.envelope_id()
                    || compact_proof.as_slice() != proof_id
                    || stored_bytes != exact_bytes
                {
                    return Err(StoreError::Invalid(
                        "compact representation identity maps to different bytes".into(),
                    ));
                }
                transaction.execute(
                    "DELETE FROM pending_batch_items WHERE envelope_id=?1",
                    params![verified.envelope_id().as_slice()],
                )?;
                transaction.commit()?;
                return Ok(BatchItemCommitOutcome {
                    outcome: ApplyOutcome::Duplicate { id: item.id },
                    evicted: Vec::new(),
                });
            }
            let has_singleton: bool = transaction.query_row(
                "SELECT EXISTS(SELECT 1 FROM batch_item_representations\n\
                 WHERE item_id=?1 AND representation=0)",
                params![item.id.as_slice()],
                |row| row.get(0),
            )?;
            if !has_singleton {
                let singleton_order = next_order(&transaction)?;
                transaction.execute(
                    "INSERT INTO batch_item_representations(\n\
                       item_id,representation,envelope_id,proof_envelope_id,exact_bytes,\n\
                       canonical,inserted_order,accounted_bytes)\n\
                     VALUES(?1,0,?2,NULL,NULL,1,?3,96)",
                    params![
                        item.id.as_slice(),
                        existing.envelope_id.as_slice(),
                        sql_u64(singleton_order, "singleton representation order")?
                    ],
                )?;
            }
            (
                ApplyOutcome::Duplicate { id: item.id },
                existing.inserted_order,
            )
        } else {
            let outcome = insert_item_tx(&transaction, item.clone(), &config, true)?;
            let inserted = load_item_tx(&transaction, &item.id)?.ok_or(StoreError::Corrupt(
                "promoted compact item disappeared".into(),
            ))?;
            (outcome, inserted.inserted_order)
        };

        let compact_canonical = load_item_tx(&transaction, &item.id)?
            .is_some_and(|stored| stored.envelope_id == verified.envelope_id());
        let representation_order = next_order(&transaction)?;
        let representation_accounted = 96u64
            .checked_add(if compact_canonical {
                0
            } else {
                exact_bytes.len() as u64
            })
            .ok_or(StoreError::QuotaExceeded)?;
        transaction.execute(
            "INSERT INTO batch_item_representations(\n\
               item_id,representation,envelope_id,proof_envelope_id,exact_bytes,\n\
               canonical,inserted_order,accounted_bytes)\n\
             VALUES(?1,1,?2,?3,?4,?5,?6,?7)",
            params![
                item.id.as_slice(),
                verified.envelope_id().as_slice(),
                proof_id.as_slice(),
                (!compact_canonical).then_some(exact_bytes),
                i64::from(compact_canonical),
                sql_u64(representation_order, "compact representation order")?,
                sql_u64(representation_accounted, "compact representation bytes")?
            ],
        )?;
        let outbox_order = next_order(&transaction)?;
        transaction.execute(
            "INSERT INTO batch_compact_outbox(item_id,enqueued_order) VALUES(?1,?2)\n\
             ON CONFLICT(item_id) DO NOTHING",
            params![
                item.id.as_slice(),
                sql_u64(outbox_order, "compact outbox order")?
            ],
        )?;
        if compact_canonical {
            transaction.execute(
                "DELETE FROM outbox WHERE item_id=?1",
                params![item.id.as_slice()],
            )?;
        }
        transaction.execute(
            "DELETE FROM pending_batch_items WHERE envelope_id=?1",
            params![verified.envelope_id().as_slice()],
        )?;
        let protected = [item.id].into_iter().collect();
        let evicted = enforce_quotas_protected_tx(
            &transaction,
            &config,
            &protected,
            item.observed_at_ms,
            item.custody_clock_id
                .zip(item.custody_tick_ms)
                .map(|(clock_id, tick_ms)| CustodySample { clock_id, tick_ms }),
        )?;
        if load_item_tx(&transaction, &item.id)?.is_none() {
            return Err(StoreError::Corrupt(
                "quota removed protected compact batch item".into(),
            ));
        }
        let _ = inserted_order;
        transaction.commit()?;
        Ok(BatchItemCommitOutcome { outcome, evicted })
    }

    #[allow(clippy::type_complexity)]
    pub(crate) fn stored_batch_material(
        &self,
        item_id: &ItemId,
    ) -> Result<Option<StoredBatchMaterial>, StoreError> {
        let row: Option<(Vec<u8>, Vec<u8>, Vec<u8>, Option<Vec<u8>>, i64)> = self
            .connection
            .query_row(
                "SELECT r.envelope_id,coalesce(r.exact_bytes,i.sealed),r.proof_envelope_id,\n\
                   (SELECT s.envelope_id FROM batch_item_representations s\n\
                    WHERE s.item_id=r.item_id AND s.representation=0),r.inserted_order\n\
                 FROM batch_item_representations r JOIN items i ON i.item_id=r.item_id\n\
                 WHERE r.item_id=?1 AND r.representation=1",
                params![item_id.as_slice()],
                |row| {
                    Ok((
                        row.get(0)?,
                        row.get(1)?,
                        row.get(2)?,
                        row.get(3)?,
                        row.get(4)?,
                    ))
                },
            )
            .optional()?;
        let Some((
            compact_envelope_id,
            compact_bytes,
            proof_id,
            singleton_envelope_id,
            inserted_order,
        )) = row
        else {
            return Ok(None);
        };
        let compact_envelope_id = item_from_vec(compact_envelope_id, "compact envelope id")?;
        if exact_object_id(&compact_bytes) != compact_envelope_id {
            return Err(StoreError::Corrupt(
                "stored compact bytes do not match their identity".into(),
            ));
        }
        let proof_id = item_from_vec(proof_id, "compact proof id")?;
        let proof = load_stored_batch_proof(&self.connection, proof_id, None)?
            .ok_or_else(|| StoreError::Corrupt("compact representation has no proof".into()))?;
        Ok(Some(StoredBatchMaterial {
            item_id: *item_id,
            compact_envelope_id,
            compact_bytes,
            singleton_envelope_id: singleton_envelope_id
                .map(|value| item_from_vec(value, "singleton envelope id"))
                .transpose()?,
            inserted_order: from_sql_u64(inserted_order, "batch material order")?,
            proof,
        }))
    }

    pub(crate) fn stored_batch_material_by_compact_envelope(
        &self,
        compact_envelope_id: &EnvelopeId,
    ) -> Result<Option<StoredBatchMaterial>, StoreError> {
        let item_id: Option<Vec<u8>> = self
            .connection
            .query_row(
                "SELECT item_id FROM batch_item_representations\n\
                 WHERE representation=1 AND envelope_id=?1",
                params![compact_envelope_id.as_slice()],
                |row| row.get(0),
            )
            .optional()?;
        let Some(item_id) = item_id else {
            return Ok(None);
        };
        let item_id = item_from_vec(item_id, "compact representation item")?;
        let material = self.stored_batch_material(&item_id)?.ok_or_else(|| {
            StoreError::Corrupt("compact representation index has no material".into())
        })?;
        if material.compact_envelope_id != *compact_envelope_id
            || exact_object_id(&material.compact_bytes) != *compact_envelope_id
        {
            return Err(StoreError::Corrupt(
                "compact representation index maps to different exact bytes".into(),
            ));
        }
        Ok(Some(material))
    }

    pub(crate) fn stored_item(&self, item_id: &ItemId) -> Result<Option<StoredItem>, StoreError> {
        let sql = format!("SELECT {ITEM_COLUMNS} FROM items WHERE item_id=?1");
        Ok(self
            .connection
            .query_row(&sql, params![item_id.as_slice()], decode_item_row)
            .optional()?)
    }

    /// Checks one exact durable ItemID without materializing its sealed bytes.
    pub(crate) fn contains_item(&self, item_id: &ItemId) -> Result<bool, StoreError> {
        Ok(self.connection.query_row(
            "SELECT EXISTS(SELECT 1 FROM items WHERE item_id=?1)",
            params![item_id.as_slice()],
            |row| row.get(0),
        )?)
    }

    pub(crate) fn stored_batch_materials_after(
        &self,
        after_order: Option<u64>,
        limit: usize,
    ) -> Result<Vec<StoredBatchMaterial>, StoreError> {
        self.stored_batch_materials_page(None, after_order, limit)
    }

    pub(crate) fn stored_batch_materials_for_proof(
        &self,
        proof_envelope_id: &EnvelopeId,
        after_order: Option<u64>,
        limit: usize,
    ) -> Result<Vec<StoredBatchMaterial>, StoreError> {
        self.stored_batch_materials_page(Some(proof_envelope_id), after_order, limit)
    }

    fn stored_batch_materials_page(
        &self,
        proof_envelope_id: Option<&EnvelopeId>,
        after_order: Option<u64>,
        limit: usize,
    ) -> Result<Vec<StoredBatchMaterial>, StoreError> {
        let limit = limit.min(MAX_BATCH_STORE_PAGE);
        if limit == 0 {
            return Ok(Vec::new());
        }
        let ids = match proof_envelope_id {
            Some(proof_id) => {
                let mut statement = self.connection.prepare(
                    "SELECT item_id FROM batch_item_representations\n\
                     WHERE representation=1 AND proof_envelope_id=?1 AND inserted_order>?2\n\
                     ORDER BY inserted_order LIMIT ?3",
                )?;
                statement
                    .query_map(
                        params![
                            proof_id.as_slice(),
                            sql_u64(after_order.unwrap_or(0), "batch material cursor")?,
                            i64::try_from(limit).unwrap_or(i64::MAX)
                        ],
                        |row| row.get::<_, Vec<u8>>(0),
                    )?
                    .collect::<Result<Vec<_>, _>>()?
            }
            None => {
                let mut statement = self.connection.prepare(
                    "SELECT item_id FROM batch_item_representations\n\
                     WHERE representation=1 AND inserted_order>?1\n\
                     ORDER BY inserted_order LIMIT ?2",
                )?;
                statement
                    .query_map(
                        params![
                            sql_u64(after_order.unwrap_or(0), "batch material cursor")?,
                            i64::try_from(limit).unwrap_or(i64::MAX)
                        ],
                        |row| row.get::<_, Vec<u8>>(0),
                    )?
                    .collect::<Result<Vec<_>, _>>()?
            }
        };
        ids.into_iter()
            .map(|id| {
                let id = item_from_vec(id, "batch material item")?;
                self.stored_batch_material(&id)?
                    .ok_or_else(|| StoreError::Corrupt("paged batch material disappeared".into()))
            })
            .collect()
    }

    #[allow(clippy::type_complexity)]
    pub(crate) fn stored_item_representation(
        &self,
        item_id: &ItemId,
        semantic_version: u16,
    ) -> Result<Option<StoredItemRepresentation>, StoreError> {
        if !matches!(semantic_version, 1..=7) {
            return Err(StoreError::Invalid(
                "unsupported representation semantic version".into(),
            ));
        }
        let preferred = if semantic_version == 1 { 0 } else { 1 };
        let row: Option<(Vec<u8>, Option<Vec<u8>>, Vec<u8>)> = self
            .connection
            .query_row(
                "SELECT r.envelope_id,r.proof_envelope_id,coalesce(r.exact_bytes,i.sealed)\n\
                 FROM batch_item_representations r JOIN items i ON i.item_id=r.item_id\n\
                 WHERE r.item_id=?1 AND r.representation=?2",
                params![item_id.as_slice(), preferred],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .optional()?;
        if let Some((envelope_id, proof_id, exact_bytes)) = row {
            let envelope_id = item_from_vec(envelope_id, "representation envelope id")?;
            let proof_envelope_id = proof_id
                .map(|value| item_from_vec(value, "representation proof id"))
                .transpose()?;
            if exact_object_id(&exact_bytes) != envelope_id {
                return Err(StoreError::Corrupt(
                    "representation bytes do not match their identity".into(),
                ));
            }
            if proof_envelope_id.is_some_and(|proof| !self.verified_batch_proofs.contains(&proof)) {
                return self.singleton_representation_fallback(item_id, semantic_version);
            }
            return Ok(Some(StoredItemRepresentation {
                item_id: *item_id,
                envelope_id,
                proof_envelope_id,
                exact_bytes,
                semantic_version,
            }));
        }
        self.singleton_representation_fallback(item_id, semantic_version)
    }

    fn singleton_representation_fallback(
        &self,
        item_id: &ItemId,
        semantic_version: u16,
    ) -> Result<Option<StoredItemRepresentation>, StoreError> {
        let has_batch_representations: bool = self.connection.query_row(
            "SELECT EXISTS(SELECT 1 FROM batch_item_representations WHERE item_id=?1)",
            params![item_id.as_slice()],
            |row| row.get(0),
        )?;
        if has_batch_representations {
            if semantic_version == 1 {
                return Ok(None);
            }
            let singleton: Option<(Vec<u8>, Vec<u8>)> = self
                .connection
                .query_row(
                    "SELECT r.envelope_id,coalesce(r.exact_bytes,i.sealed)\n\
                     FROM batch_item_representations r JOIN items i ON i.item_id=r.item_id\n\
                     WHERE r.item_id=?1 AND r.representation=0",
                    params![item_id.as_slice()],
                    |row| Ok((row.get(0)?, row.get(1)?)),
                )
                .optional()?;
            return singleton
                .map(|(envelope_id, exact_bytes)| {
                    let envelope_id = item_from_vec(envelope_id, "singleton envelope id")?;
                    if exact_object_id(&exact_bytes) != envelope_id {
                        return Err(StoreError::Corrupt(
                            "singleton representation bytes do not match identity".into(),
                        ));
                    }
                    Ok(StoredItemRepresentation {
                        item_id: *item_id,
                        envelope_id,
                        proof_envelope_id: None,
                        exact_bytes,
                        semantic_version,
                    })
                })
                .transpose();
        }
        let ordinary: Option<(Vec<u8>, Vec<u8>)> = self
            .connection
            .query_row(
                "SELECT envelope_id,sealed FROM items WHERE item_id=?1",
                params![item_id.as_slice()],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .optional()?;
        ordinary
            .map(|(envelope_id, exact_bytes)| {
                let envelope_id = item_from_vec(envelope_id, "ordinary envelope id")?;
                if exact_object_id(&exact_bytes) != envelope_id {
                    return Err(StoreError::Corrupt(
                        "ordinary representation bytes do not match identity".into(),
                    ));
                }
                Ok(StoredItemRepresentation {
                    item_id: *item_id,
                    envelope_id,
                    proof_envelope_id: None,
                    exact_bytes,
                    semantic_version,
                })
            })
            .transpose()
    }

    pub(crate) fn read_item_representation_range(
        &self,
        item_id: &ItemId,
        semantic_version: u16,
        range: ChunkRange,
        max_bytes: usize,
    ) -> Result<Vec<u8>, StoreError> {
        if range.is_empty() || max_bytes == 0 {
            return Ok(Vec::new());
        }
        let representation = self
            .stored_item_representation(item_id, semantic_version)?
            .ok_or(StoreError::NotFound("item representation"))?;
        let start = usize::try_from(range.start)
            .unwrap_or(usize::MAX)
            .min(representation.exact_bytes.len());
        let requested_end = range.end.min(range.start.saturating_add(max_bytes as u64));
        let end = usize::try_from(requested_end)
            .unwrap_or(usize::MAX)
            .min(representation.exact_bytes.len());
        Ok(representation.exact_bytes[start.min(end)..end].to_vec())
    }

    /// Registers an independently provider-authenticated singleton for an
    /// already accepted compact semantic item, enabling semantic-v1 relay.
    pub(crate) fn register_singleton_representation(
        &mut self,
        singleton: StoredItem,
    ) -> Result<BatchItemCommitOutcome, StoreError> {
        validate_item(&singleton)?;
        if singleton.sealed.is_empty()
            || exact_object_id(&singleton.sealed) != singleton.envelope_id
        {
            return Err(StoreError::Invalid(
                "singleton representation bytes do not match their identity".into(),
            ));
        }
        let config = self.config.clone();
        let transaction = self.connection.transaction()?;
        let existing = load_item_tx(&transaction, &singleton.id)?
            .ok_or(StoreError::NotFound("compact semantic item"))?;
        if existing.envelope_id == singleton.envelope_id {
            merge_duplicate_custody_tx(&transaction, &existing, &singleton)?;
            transaction.commit()?;
            return Ok(BatchItemCommitOutcome {
                outcome: ApplyOutcome::Duplicate { id: singleton.id },
                evicted: Vec::new(),
            });
        }
        if !same_batch_item_semantics(&existing, &singleton) {
            return Err(StoreError::Invalid(
                "singleton representation semantics differ from compact item".into(),
            ));
        }
        let compact: Option<(Vec<u8>, Vec<u8>, i64)> = transaction
            .query_row(
                "SELECT r.envelope_id,coalesce(r.exact_bytes,i.sealed),r.canonical\n\
                 FROM batch_item_representations r JOIN items i ON i.item_id=r.item_id\n\
                 WHERE r.item_id=?1 AND r.representation=1",
                params![singleton.id.as_slice()],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .optional()?;
        let Some((compact_envelope, compact_bytes, compact_canonical)) = compact else {
            return Err(StoreError::Invalid(
                "different singleton envelope reuses an ordinary semantic item".into(),
            ));
        };
        if compact_canonical == 0 {
            return Err(StoreError::Corrupt(
                "compact item already has a different canonical singleton".into(),
            ));
        }
        let compact_envelope = item_from_vec(compact_envelope, "compact envelope id")?;
        if compact_envelope != existing.envelope_id
            || compact_bytes != existing.sealed
            || exact_object_id(&compact_bytes) != compact_envelope
        {
            return Err(StoreError::Corrupt(
                "canonical compact representation is inconsistent".into(),
            ));
        }
        let has_singleton: bool = transaction.query_row(
            "SELECT EXISTS(SELECT 1 FROM batch_item_representations\n\
             WHERE item_id=?1 AND representation=0)",
            params![singleton.id.as_slice()],
            |row| row.get(0),
        )?;
        if has_singleton {
            return Err(StoreError::Corrupt(
                "compact item has a noncanonical singleton before registration".into(),
            ));
        }
        let accounted = singleton.accounted_bytes();
        transaction.execute(
            "UPDATE items SET envelope_id=?1,sealed=?2,accounted_bytes=?3,\n\
               custody_age_ms=max(custody_age_ms,?4),\n\
               custody_clock_id=?5,custody_tick_ms=?6,custody_elapsed_available=?7\n\
             WHERE item_id=?8",
            params![
                singleton.envelope_id.as_slice(),
                &singleton.sealed,
                sql_u64(accounted, "singleton item bytes")?,
                sql_u64(singleton.custody_age_ms, "singleton custody age")?,
                singleton.custody_clock_id.map(|value| value.to_vec()),
                singleton
                    .custody_tick_ms
                    .map(|value| sql_u64(value, "singleton custody tick"))
                    .transpose()?,
                i64::from(singleton.custody_elapsed_available),
                singleton.id.as_slice()
            ],
        )?;
        transaction.execute(
            "UPDATE batch_item_representations SET exact_bytes=?1,canonical=0,\n\
               accounted_bytes=?2 WHERE item_id=?3 AND representation=1",
            params![
                compact_bytes,
                sql_u64(
                    96u64
                        .checked_add(existing.sealed.len() as u64)
                        .ok_or(StoreError::QuotaExceeded)?,
                    "compact representation bytes"
                )?,
                singleton.id.as_slice()
            ],
        )?;
        let order = next_order(&transaction)?;
        transaction.execute(
            "INSERT INTO batch_item_representations(\n\
               item_id,representation,envelope_id,proof_envelope_id,exact_bytes,\n\
               canonical,inserted_order,accounted_bytes)\n\
             VALUES(?1,0,?2,NULL,NULL,1,?3,96)",
            params![
                singleton.id.as_slice(),
                singleton.envelope_id.as_slice(),
                sql_u64(order, "singleton representation order")?
            ],
        )?;
        transaction.execute(
            "INSERT INTO outbox(item_id,enqueued_order) VALUES(?1,?2)\n\
             ON CONFLICT(item_id) DO NOTHING",
            params![
                singleton.id.as_slice(),
                sql_u64(next_order(&transaction)?, "singleton outbox order")?
            ],
        )?;
        let usage = committed_usage_tx(&transaction, None)?;
        if usage.items > config.max_items || usage.bytes > committed_byte_limit(&config) {
            return Err(StoreError::QuotaExceeded);
        }
        ensure_scope_quota_tx(&transaction, &singleton.scope)?;
        transaction.commit()?;
        Ok(BatchItemCommitOutcome {
            outcome: ApplyOutcome::Duplicate { id: singleton.id },
            evicted: Vec::new(),
        })
    }

    pub(crate) fn next_batch_proof_outbound(
        &mut self,
        peer: NodeId,
        minimum: Priority,
        limit: usize,
        byte_budget: u64,
        now_ms: Option<u64>,
        custody_sample: Option<CustodySample>,
    ) -> Result<Vec<StoredBatchProof>, StoreError> {
        let selected =
            self.peek_batch_proof_outbound(peer, minimum, limit, byte_budget, custody_sample)?;
        self.record_batch_proof_attempts(peer, &selected, now_ms)?;
        Ok(selected)
    }

    pub(crate) fn peek_batch_proof_outbound(
        &mut self,
        peer: NodeId,
        minimum: Priority,
        limit: usize,
        byte_budget: u64,
        custody_sample: Option<CustodySample>,
    ) -> Result<Vec<StoredBatchProof>, StoreError> {
        let limit = limit.min(MAX_BATCH_STORE_PAGE);
        if limit == 0 || byte_budget == 0 || self.is_zeroized()? || self.is_revoked(&peer)? {
            return Ok(Vec::new());
        }
        let ids = {
            let mut statement = self.connection.prepare(
                "SELECT o.proof_envelope_id FROM batch_proof_outbox o\n\
                 LEFT JOIN batch_proof_peer_receipts r\n\
                   ON r.peer=?1 AND r.proof_envelope_id=o.proof_envelope_id\n\
                 LEFT JOIN batch_proof_peer_attempts a\n\
                   ON a.peer=?1 AND a.proof_envelope_id=o.proof_envelope_id\n\
                 WHERE r.proof_envelope_id IS NULL\n\
                 ORDER BY coalesce(a.attempts,0),o.enqueued_order LIMIT ?2",
            )?;
            statement
                .query_map(
                    params![
                        peer.as_slice(),
                        i64::try_from(MAX_BATCH_STORE_PAGE).unwrap_or(i64::MAX)
                    ],
                    |row| row.get::<_, Vec<u8>>(0),
                )?
                .collect::<Result<Vec<_>, _>>()?
        };
        let mut selected = Vec::new();
        let mut used = 0u64;
        for id in ids {
            let id = item_from_vec(id, "batch proof outbox id")?;
            if !self.verified_batch_proofs.contains(&id) {
                continue;
            }
            let proof = load_stored_batch_proof(&self.connection, id, custody_sample)?
                .ok_or_else(|| StoreError::Corrupt("batch proof outbox is dangling".into()))?;
            if proof.effective_priority < minimum {
                continue;
            }
            let bytes = proof.exact_bytes.len() as u64;
            if used.saturating_add(bytes) > byte_budget {
                continue;
            }
            used = used.saturating_add(bytes);
            selected.push(proof);
            if selected.len() == limit {
                break;
            }
        }
        Ok(selected)
    }

    pub(crate) fn record_batch_proof_attempts(
        &mut self,
        peer: NodeId,
        proofs: &[StoredBatchProof],
        now_ms: Option<u64>,
    ) -> Result<(), StoreError> {
        if proofs.len() > MAX_BATCH_STORE_PAGE {
            return Err(StoreError::Invalid(
                "batch proof attempt page exceeds bound".into(),
            ));
        }
        let transaction = self.connection.transaction()?;
        for proof in proofs {
            if !self
                .verified_batch_proofs
                .contains(&proof.proof_envelope_id)
            {
                return Err(StoreError::NotFound("process-verified batch proof"));
            }
            let changed = transaction.execute(
                "INSERT INTO batch_proof_peer_attempts(\n\
                   peer,proof_envelope_id,attempts,last_attempt_ms)\n\
                 SELECT ?1,o.proof_envelope_id,1,?3 FROM batch_proof_outbox o\n\
                 WHERE o.proof_envelope_id=?2\n\
                 ON CONFLICT(peer,proof_envelope_id) DO UPDATE SET\n\
                   attempts=attempts+1,last_attempt_ms=excluded.last_attempt_ms",
                params![
                    peer.as_slice(),
                    proof.proof_envelope_id.as_slice(),
                    now_ms
                        .map(|value| sql_u64(value, "batch proof attempt time"))
                        .transpose()?
                ],
            )?;
            if changed == 0 {
                return Err(StoreError::NotFound("batch proof outbox"));
            }
        }
        let usage = committed_usage_tx(&transaction, None)?;
        if usage.items > self.config.max_items || usage.bytes > committed_byte_limit(&self.config) {
            return Err(StoreError::QuotaExceeded);
        }
        for scope in proofs
            .iter()
            .map(|proof| &proof.scope)
            .collect::<BTreeSet<_>>()
        {
            ensure_scope_quota_tx(&transaction, scope)?;
        }
        transaction.commit()?;
        Ok(())
    }

    pub(crate) fn acknowledge_batch_proof_peer(
        &mut self,
        peer: NodeId,
        proof_envelope_ids: &[EnvelopeId],
        now_ms: Option<u64>,
    ) -> Result<(), StoreError> {
        if proof_envelope_ids.len() > MAX_BATCH_STORE_PAGE {
            return Err(StoreError::Invalid(
                "batch proof receipt page exceeds bound".into(),
            ));
        }
        let transaction = self.connection.transaction()?;
        let mut scopes = BTreeSet::new();
        for proof_id in proof_envelope_ids {
            let scope: Option<String> = transaction
                .query_row(
                    "SELECT p.scope FROM batch_proofs p JOIN batch_proof_outbox o\n\
                     ON o.proof_envelope_id=p.proof_envelope_id\n\
                     WHERE p.proof_envelope_id=?1",
                    params![proof_id.as_slice()],
                    |row| row.get(0),
                )
                .optional()?;
            let scope = scope.ok_or(StoreError::NotFound("batch proof outbox"))?;
            scopes
                .insert(Scope::new(scope).map_err(|error| StoreError::Corrupt(error.to_string()))?);
            transaction.execute(
                "INSERT INTO batch_proof_peer_receipts(\n\
                   peer,proof_envelope_id,acknowledged_at_ms) VALUES(?1,?2,?3)\n\
                 ON CONFLICT(peer,proof_envelope_id) DO UPDATE SET\n\
                   acknowledged_at_ms=excluded.acknowledged_at_ms",
                params![
                    peer.as_slice(),
                    proof_id.as_slice(),
                    now_ms
                        .map(|value| sql_u64(value, "batch proof acknowledgement time"))
                        .transpose()?
                ],
            )?;
        }
        let usage = committed_usage_tx(&transaction, None)?;
        if usage.items > self.config.max_items || usage.bytes > committed_byte_limit(&self.config) {
            return Err(StoreError::QuotaExceeded);
        }
        for scope in &scopes {
            ensure_scope_quota_tx(&transaction, scope)?;
        }
        transaction.commit()?;
        Ok(())
    }

    pub(crate) fn read_batch_proof_range(
        &self,
        proof_envelope_id: &EnvelopeId,
        range: ChunkRange,
        max_bytes: usize,
    ) -> Result<Vec<u8>, StoreError> {
        if range.is_empty() || max_bytes == 0 {
            return Ok(Vec::new());
        }
        if !self.verified_batch_proofs.contains(proof_envelope_id) {
            return Err(StoreError::NotFound("process-verified batch proof"));
        }
        let length = range.len().min(max_bytes as u64);
        self.connection
            .query_row(
                "SELECT substr(p.exact_bytes,?2,?3) FROM batch_proofs p\n\
                 JOIN batch_proof_outbox o ON o.proof_envelope_id=p.proof_envelope_id\n\
                 WHERE p.proof_envelope_id=?1",
                params![
                    proof_envelope_id.as_slice(),
                    sql_u64(range.start.saturating_add(1), "batch proof range offset")?,
                    sql_u64(length, "batch proof range length")?
                ],
                |row| row.get(0),
            )
            .optional()?
            .ok_or(StoreError::NotFound("batch proof outbox"))
    }

    pub(crate) fn filter_unacknowledged_batch_proofs(
        &self,
        peer: NodeId,
        candidates: &[EnvelopeId],
        limit: usize,
    ) -> Result<Vec<EnvelopeId>, StoreError> {
        if candidates.len() > MAX_BATCH_STORE_PAGE {
            return Err(StoreError::Invalid(
                "batch proof candidate page exceeds bound".into(),
            ));
        }
        let limit = limit.min(MAX_BATCH_STORE_PAGE);
        if limit == 0 {
            return Ok(Vec::new());
        }
        let mut selected = Vec::new();
        for candidate in candidates {
            if !self.verified_batch_proofs.contains(candidate) {
                continue;
            }
            let eligible: bool = self.connection.query_row(
                "SELECT EXISTS(SELECT 1 FROM batch_proof_outbox o\n\
                   WHERE o.proof_envelope_id=?2)\n\
                 AND NOT EXISTS(SELECT 1 FROM batch_proof_peer_receipts r\n\
                   WHERE r.peer=?1 AND r.proof_envelope_id=?2)",
                params![peer.as_slice(), candidate.as_slice()],
                |row| row.get(0),
            )?;
            if eligible {
                selected.push(*candidate);
                if selected.len() == limit {
                    break;
                }
            }
        }
        Ok(selected)
    }

    pub(crate) fn next_batch_compact_outbound(
        &mut self,
        peer: NodeId,
        minimum: Priority,
        limit: usize,
        byte_budget: u64,
        now_ms: Option<u64>,
        custody_sample: Option<CustodySample>,
    ) -> Result<Vec<StoredItemRepresentation>, StoreError> {
        let selected =
            self.peek_batch_compact_outbound(peer, minimum, limit, byte_budget, custody_sample)?;
        self.record_batch_compact_attempts(peer, &selected, now_ms)?;
        Ok(selected)
    }

    pub(crate) fn peek_batch_compact_outbound(
        &mut self,
        peer: NodeId,
        minimum: Priority,
        limit: usize,
        byte_budget: u64,
        custody_sample: Option<CustodySample>,
    ) -> Result<Vec<StoredItemRepresentation>, StoreError> {
        let limit = limit.min(MAX_BATCH_STORE_PAGE);
        if limit == 0 || byte_budget == 0 || self.is_zeroized()? || self.is_revoked(&peer)? {
            return Ok(Vec::new());
        }
        let ids = {
            let mut statement = self.connection.prepare(
                "SELECT o.item_id FROM batch_compact_outbox o\n\
                 JOIN batch_item_representations x\n\
                   ON x.item_id=o.item_id AND x.representation=1\n\
                 JOIN batch_proof_peer_receipts p\n\
                   ON p.peer=?1 AND p.proof_envelope_id=x.proof_envelope_id\n\
                 LEFT JOIN batch_compact_peer_receipts r\n\
                   ON r.peer=?1 AND r.item_id=o.item_id\n\
                 LEFT JOIN batch_compact_peer_attempts a\n\
                   ON a.peer=?1 AND a.item_id=o.item_id\n\
                 WHERE r.item_id IS NULL\n\
                 ORDER BY coalesce(a.attempts,0),o.enqueued_order LIMIT ?2",
            )?;
            statement
                .query_map(
                    params![
                        peer.as_slice(),
                        i64::try_from(MAX_BATCH_STORE_PAGE).unwrap_or(i64::MAX)
                    ],
                    |row| row.get::<_, Vec<u8>>(0),
                )?
                .collect::<Result<Vec<_>, _>>()?
        };
        let mut selected = Vec::new();
        let mut used = 0u64;
        for id in ids {
            let id = item_from_vec(id, "compact batch outbox item")?;
            let Some(item) = self.get(&id)? else {
                return Err(StoreError::Corrupt(
                    "compact batch outbox item is missing".into(),
                ));
            };
            if item.priority < minimum || !item.is_forwardable_at(custody_sample) {
                continue;
            }
            let Some(representation) = self.stored_item_representation(&id, 2)? else {
                continue;
            };
            let Some(proof_id) = representation.proof_envelope_id else {
                continue;
            };
            if !self.verified_batch_proofs.contains(&proof_id) {
                continue;
            }
            let bytes = representation.exact_bytes.len() as u64;
            if used.saturating_add(bytes) > byte_budget {
                continue;
            }
            used = used.saturating_add(bytes);
            selected.push(representation);
            if selected.len() == limit {
                break;
            }
        }
        Ok(selected)
    }

    pub(crate) fn record_batch_compact_attempts(
        &mut self,
        peer: NodeId,
        items: &[StoredItemRepresentation],
        now_ms: Option<u64>,
    ) -> Result<(), StoreError> {
        if items.len() > MAX_BATCH_STORE_PAGE {
            return Err(StoreError::Invalid(
                "compact batch attempt page exceeds bound".into(),
            ));
        }
        let transaction = self.connection.transaction()?;
        let mut scopes = BTreeSet::new();
        for item in items {
            let proof_id = item.proof_envelope_id.ok_or(StoreError::Invalid(
                "compact attempt lacks proof dependency".into(),
            ))?;
            if !self.verified_batch_proofs.contains(&proof_id) {
                return Err(StoreError::NotFound("process-verified batch proof"));
            }
            let scope: Option<String> = transaction
                .query_row(
                    "SELECT i.scope FROM batch_compact_outbox o JOIN items i\n\
                     ON i.item_id=o.item_id JOIN batch_item_representations r\n\
                     ON r.item_id=i.item_id AND r.representation=1\n\
                     JOIN batch_proof_peer_receipts p\n\
                     ON p.peer=?1 AND p.proof_envelope_id=r.proof_envelope_id\n\
                     WHERE o.item_id=?2 AND r.proof_envelope_id=?3",
                    params![
                        peer.as_slice(),
                        item.item_id.as_slice(),
                        proof_id.as_slice()
                    ],
                    |row| row.get(0),
                )
                .optional()?;
            let scope = scope.ok_or(StoreError::NotFound(
                "compact outbox proof receipt dependency",
            ))?;
            scopes
                .insert(Scope::new(scope).map_err(|error| StoreError::Corrupt(error.to_string()))?);
            transaction.execute(
                "INSERT INTO batch_compact_peer_attempts(\n\
                   peer,item_id,attempts,last_attempt_ms) VALUES(?1,?2,1,?3)\n\
                 ON CONFLICT(peer,item_id) DO UPDATE SET\n\
                   attempts=attempts+1,last_attempt_ms=excluded.last_attempt_ms",
                params![
                    peer.as_slice(),
                    item.item_id.as_slice(),
                    now_ms
                        .map(|value| sql_u64(value, "compact batch attempt time"))
                        .transpose()?
                ],
            )?;
        }
        let usage = committed_usage_tx(&transaction, None)?;
        if usage.items > self.config.max_items || usage.bytes > committed_byte_limit(&self.config) {
            return Err(StoreError::QuotaExceeded);
        }
        for scope in &scopes {
            ensure_scope_quota_tx(&transaction, scope)?;
        }
        transaction.commit()?;
        Ok(())
    }

    pub(crate) fn acknowledge_batch_compact_peer(
        &mut self,
        peer: NodeId,
        item_ids: &[ItemId],
        now_ms: Option<u64>,
    ) -> Result<(), StoreError> {
        if item_ids.len() > MAX_BATCH_STORE_PAGE {
            return Err(StoreError::Invalid(
                "compact batch receipt page exceeds bound".into(),
            ));
        }
        let transaction = self.connection.transaction()?;
        let mut scopes = BTreeSet::new();
        for item_id in item_ids {
            let scope: Option<String> = transaction
                .query_row(
                    "SELECT i.scope FROM batch_compact_outbox o JOIN items i\n\
                     ON i.item_id=o.item_id JOIN batch_item_representations r\n\
                     ON r.item_id=i.item_id AND r.representation=1\n\
                     JOIN batch_proof_peer_receipts p\n\
                     ON p.peer=?1 AND p.proof_envelope_id=r.proof_envelope_id\n\
                     WHERE o.item_id=?2",
                    params![peer.as_slice(), item_id.as_slice()],
                    |row| row.get(0),
                )
                .optional()?;
            let scope = scope.ok_or(StoreError::NotFound(
                "compact outbox proof receipt dependency",
            ))?;
            scopes
                .insert(Scope::new(scope).map_err(|error| StoreError::Corrupt(error.to_string()))?);
            transaction.execute(
                "INSERT INTO batch_compact_peer_receipts(peer,item_id,acknowledged_at_ms)\n\
                 VALUES(?1,?2,?3) ON CONFLICT(peer,item_id) DO UPDATE SET\n\
                   acknowledged_at_ms=excluded.acknowledged_at_ms",
                params![
                    peer.as_slice(),
                    item_id.as_slice(),
                    now_ms
                        .map(|value| sql_u64(value, "compact batch acknowledgement time"))
                        .transpose()?
                ],
            )?;
        }
        let usage = committed_usage_tx(&transaction, None)?;
        if usage.items > self.config.max_items || usage.bytes > committed_byte_limit(&self.config) {
            return Err(StoreError::QuotaExceeded);
        }
        for scope in &scopes {
            ensure_scope_quota_tx(&transaction, scope)?;
        }
        transaction.commit()?;
        Ok(())
    }

    pub(crate) fn read_batch_compact_range(
        &self,
        item_id: &ItemId,
        range: ChunkRange,
        max_bytes: usize,
        custody_sample: Option<CustodySample>,
    ) -> Result<Vec<u8>, StoreError> {
        let item = self
            .connection
            .query_row(
                &format!("SELECT {ITEM_COLUMNS} FROM items WHERE item_id=?1"),
                params![item_id.as_slice()],
                decode_item_row,
            )
            .optional()?
            .ok_or(StoreError::NotFound("compact batch item"))?;
        if !item.is_forwardable_at(custody_sample) {
            return Err(StoreError::NotFound("live compact batch item"));
        }
        let representation = self
            .stored_item_representation(item_id, 2)?
            .filter(|value| value.proof_envelope_id.is_some())
            .ok_or(StoreError::NotFound(
                "process-verified compact representation",
            ))?;
        if range.is_empty() || max_bytes == 0 {
            return Ok(Vec::new());
        }
        let start = usize::try_from(range.start)
            .unwrap_or(usize::MAX)
            .min(representation.exact_bytes.len());
        let requested_end = range.end.min(range.start.saturating_add(max_bytes as u64));
        let end = usize::try_from(requested_end)
            .unwrap_or(usize::MAX)
            .min(representation.exact_bytes.len());
        Ok(representation.exact_bytes[start.min(end)..end].to_vec())
    }

    pub(crate) fn filter_unacknowledged_batch_compacts(
        &self,
        peer: NodeId,
        candidates: &[ItemId],
        limit: usize,
    ) -> Result<Vec<ItemId>, StoreError> {
        if candidates.len() > MAX_BATCH_STORE_PAGE {
            return Err(StoreError::Invalid(
                "compact batch candidate page exceeds bound".into(),
            ));
        }
        let limit = limit.min(MAX_BATCH_STORE_PAGE);
        if limit == 0 {
            return Ok(Vec::new());
        }
        let mut selected = Vec::new();
        for candidate in candidates {
            let proof_id: Option<Vec<u8>> = self
                .connection
                .query_row(
                    "SELECT r.proof_envelope_id FROM batch_compact_outbox o\n\
                     JOIN batch_item_representations r\n\
                       ON r.item_id=o.item_id AND r.representation=1\n\
                     JOIN batch_proof_peer_receipts p\n\
                       ON p.peer=?1 AND p.proof_envelope_id=r.proof_envelope_id\n\
                     LEFT JOIN batch_compact_peer_receipts c\n\
                       ON c.peer=?1 AND c.item_id=o.item_id\n\
                     WHERE o.item_id=?2 AND c.item_id IS NULL",
                    params![peer.as_slice(), candidate.as_slice()],
                    |row| row.get(0),
                )
                .optional()?;
            let Some(proof_id) = proof_id else {
                continue;
            };
            let proof_id = item_from_vec(proof_id, "compact candidate proof")?;
            if !self.verified_batch_proofs.contains(&proof_id) {
                continue;
            }
            selected.push(*candidate);
            if selected.len() == limit {
                break;
            }
        }
        Ok(selected)
    }

    /// Batch Blob carriers are eligible only after this peer acknowledged both
    /// the exact shared proof and the exact compact manifest representation.
    pub(crate) fn filter_batch_blob_ready(
        &self,
        peer: NodeId,
        candidates: &[ItemId],
        limit: usize,
    ) -> Result<Vec<ItemId>, StoreError> {
        if candidates.len() > MAX_BATCH_STORE_PAGE {
            return Err(StoreError::Invalid(
                "batch Blob readiness candidate page exceeds bound".into(),
            ));
        }
        let limit = limit.min(MAX_BATCH_STORE_PAGE);
        if limit == 0 {
            return Ok(Vec::new());
        }
        let mut selected = Vec::new();
        for candidate in candidates {
            let proof_id: Option<Vec<u8>> = self
                .connection
                .query_row(
                    "SELECT r.proof_envelope_id FROM batch_item_representations r\n\
                     JOIN batch_proof_peer_receipts p\n\
                       ON p.peer=?1 AND p.proof_envelope_id=r.proof_envelope_id\n\
                     JOIN batch_compact_peer_receipts c\n\
                       ON c.peer=?1 AND c.item_id=r.item_id\n\
                     WHERE r.item_id=?2 AND r.representation=1",
                    params![peer.as_slice(), candidate.as_slice()],
                    |row| row.get(0),
                )
                .optional()?;
            let Some(proof_id) = proof_id else {
                continue;
            };
            let proof_id = item_from_vec(proof_id, "batch Blob readiness proof")?;
            if !self.verified_batch_proofs.contains(&proof_id) {
                continue;
            }
            selected.push(*candidate);
            if selected.len() == limit {
                break;
            }
        }
        Ok(selected)
    }

    pub(crate) fn is_batch_proof_rejected(
        &self,
        proof_envelope_id: &EnvelopeId,
    ) -> Result<bool, StoreError> {
        Ok(self.connection.query_row(
            "SELECT EXISTS(SELECT 1 FROM rejected_batch_proofs WHERE proof_envelope_id=?1)",
            params![proof_envelope_id.as_slice()],
            |row| row.get(0),
        )?)
    }

    /// Records a provider's terminal authentication failure for one complete,
    /// hash-matching proof carrier. Transfer digest failures must never call
    /// this method because they have not established this exact identity.
    pub(crate) fn reject_batch_proof(
        &mut self,
        proof_envelope_id: EnvelopeId,
        exact_bytes: &[u8],
    ) -> Result<bool, StoreError> {
        if exact_bytes.is_empty() || exact_object_id(exact_bytes) != proof_envelope_id {
            return Err(StoreError::Invalid(
                "rejected proof bytes do not match the complete proof identity".into(),
            ));
        }
        let config = self.config.clone();
        let transaction = self.connection.transaction()?;
        let already_rejected: bool = transaction.query_row(
            "SELECT EXISTS(SELECT 1 FROM rejected_batch_proofs WHERE proof_envelope_id=?1)",
            params![proof_envelope_id.as_slice()],
            |row| row.get(0),
        )?;
        let stored_proof: Option<Vec<u8>> = transaction
            .query_row(
                "SELECT exact_bytes FROM batch_proofs WHERE proof_envelope_id=?1",
                params![proof_envelope_id.as_slice()],
                |row| row.get(0),
            )
            .optional()?;
        if stored_proof
            .as_ref()
            .is_some_and(|stored| stored.as_slice() != exact_bytes)
        {
            return Err(StoreError::Corrupt(
                "rejected proof identity maps to different durable bytes".into(),
            ));
        }

        let representations = {
            let mut statement = transaction.prepare(
                "SELECT item_id,canonical FROM batch_item_representations\n\
                 WHERE representation=1 AND proof_envelope_id=?1 ORDER BY inserted_order",
            )?;
            statement
                .query_map(params![proof_envelope_id.as_slice()], |row| {
                    Ok((row.get::<_, Vec<u8>>(0)?, row.get::<_, i64>(1)? != 0))
                })?
                .collect::<Result<Vec<_>, _>>()?
        };
        for (item_id, compact_canonical) in representations {
            let item_id = item_from_vec(item_id, "rejected proof dependent")?;
            if compact_canonical {
                let singleton: Option<(Vec<u8>, Vec<u8>)> = transaction
                    .query_row(
                        "SELECT envelope_id,exact_bytes FROM batch_item_representations\n\
                         WHERE item_id=?1 AND representation=0 AND exact_bytes IS NOT NULL",
                        params![item_id.as_slice()],
                        |row| Ok((row.get(0)?, row.get(1)?)),
                    )
                    .optional()?;
                if let Some((singleton_envelope, singleton_bytes)) = singleton {
                    let mut retained = load_item_tx(&transaction, &item_id)?.ok_or_else(|| {
                        StoreError::Corrupt("batch representation has no semantic item".into())
                    })?;
                    let singleton_envelope =
                        item_from_vec(singleton_envelope, "singleton envelope id")?;
                    if exact_object_id(&singleton_bytes) != singleton_envelope {
                        return Err(StoreError::Corrupt(
                            "singleton fallback bytes do not match their identity".into(),
                        ));
                    }
                    retained.envelope_id = singleton_envelope;
                    retained.sealed = singleton_bytes;
                    let accounted = retained.accounted_bytes();
                    transaction.execute(
                        "UPDATE items SET envelope_id=?1,sealed=?2,accounted_bytes=?3\n\
                         WHERE item_id=?4",
                        params![
                            retained.envelope_id.as_slice(),
                            retained.sealed,
                            sql_u64(accounted, "singleton fallback bytes")?,
                            item_id.as_slice()
                        ],
                    )?;
                    transaction.execute(
                        "UPDATE batch_item_representations SET canonical=1,exact_bytes=NULL,\n\
                           accounted_bytes=96 WHERE item_id=?1 AND representation=0",
                        params![item_id.as_slice()],
                    )?;
                    transaction.execute(
                        "DELETE FROM batch_item_representations\n\
                         WHERE item_id=?1 AND representation=1",
                        params![item_id.as_slice()],
                    )?;
                    transaction.execute(
                        "INSERT INTO outbox(item_id,enqueued_order) VALUES(?1,?2)\n\
                         ON CONFLICT(item_id) DO NOTHING",
                        params![
                            item_id.as_slice(),
                            sql_u64(next_order(&transaction)?, "singleton outbox order")?
                        ],
                    )?;
                } else {
                    delete_item_tx(&transaction, item_id)?;
                }
            } else {
                transaction.execute(
                    "DELETE FROM batch_item_representations\n\
                     WHERE item_id=?1 AND representation=1",
                    params![item_id.as_slice()],
                )?;
            }
            transaction.execute(
                "DELETE FROM batch_compact_outbox WHERE item_id=?1",
                params![item_id.as_slice()],
            )?;
            transaction.execute(
                "DELETE FROM batch_compact_peer_receipts WHERE item_id=?1",
                params![item_id.as_slice()],
            )?;
            transaction.execute(
                "DELETE FROM batch_compact_peer_attempts WHERE item_id=?1",
                params![item_id.as_slice()],
            )?;
        }
        transaction.execute(
            "DELETE FROM pending_batch_items WHERE proof_envelope_id=?1",
            params![proof_envelope_id.as_slice()],
        )?;
        transaction.execute(
            "DELETE FROM batch_proofs WHERE proof_envelope_id=?1",
            params![proof_envelope_id.as_slice()],
        )?;
        if !already_rejected {
            make_batch_staging_room_tx(&transaction, &config, 1, 96, Priority::Flash)?;
            let order = next_order(&transaction)?;
            transaction.execute(
                "INSERT INTO rejected_batch_proofs(\n\
                   proof_envelope_id,inserted_order,accounted_bytes) VALUES(?1,?2,96)",
                params![
                    proof_envelope_id.as_slice(),
                    sql_u64(order, "rejected proof order")?
                ],
            )?;
        }
        transaction.commit()?;
        self.verified_batch_proofs.remove(&proof_envelope_id);
        Ok(!already_rejected)
    }

    /// Crash-atomically stores one provider-authenticated bridge control in its
    /// independent semantic-v2 chain. Chain activation is performed separately
    /// so an out-of-order record cannot acquire authority merely by being stored.
    fn stage_bridge_authorization(
        &mut self,
        verified: &VerifiedBridgeAuthorization,
    ) -> Result<BridgeControlStage, StoreError> {
        let authorization_body = verified
            .authorization
            .encode()
            .map_err(|error| StoreError::Invalid(error.to_string()))?;
        let transaction = self.connection.transaction()?;
        if let Some((stored_body, stored_signer, stored_exact)) = transaction
            .query_row(
                "SELECT authorization_body,control_signer,exact_bytes\n\
                 FROM bridge_authorization_controls\n\
                 WHERE envelope_id=?1",
                params![verified.envelope_id.as_slice()],
                |row| {
                    Ok((
                        row.get::<_, Vec<u8>>(0)?,
                        row.get::<_, Vec<u8>>(1)?,
                        row.get::<_, Vec<u8>>(2)?,
                    ))
                },
            )
            .optional()?
        {
            if stored_body != authorization_body
                || node_from_vec(stored_signer, "bridge control signer")? != verified.control_signer
                || stored_exact != verified.exact_bytes
            {
                return Err(StoreError::Corrupt(
                    "bridge authorization identity maps to different bytes".into(),
                ));
            }
            transaction.commit()?;
            self.verified_bridge_authorizations
                .insert(verified.envelope_id);
            return Ok(BridgeControlStage::Duplicate);
        }
        if control_signer_revoked_tx(&transaction, verified.authorization.authority_id)?
            || control_signer_revoked_tx(&transaction, verified.control_signer)?
        {
            transaction.commit()?;
            return Ok(BridgeControlStage::Rejected(RejectedControl {
                envelope_id: verified.envelope_id,
                signer: verified.control_signer,
            }));
        }
        if transaction
            .query_row(
                "SELECT envelope_id FROM bridge_authorization_controls\n\
                 WHERE authority_id=?1 AND sequence=?2",
                params![
                    verified.authorization.authority_id.as_slice(),
                    sql_u64(
                        verified.authorization.control_sequence,
                        "bridge control sequence"
                    )?
                ],
                |row| row.get::<_, Vec<u8>>(0),
            )
            .optional()?
            .is_some_and(|existing_id| existing_id.as_slice() != verified.envelope_id)
        {
            return Err(StoreError::BridgeControlFork);
        }

        let topic_bytes = verified
            .authorization
            .enabled
            .as_ref()
            .map(|enabled| {
                enabled
                    .topics
                    .iter()
                    .map(|topic| topic.as_str().len() as u64 + 2)
                    .sum::<u64>()
            })
            .unwrap_or(0);
        let accounted_bytes = (verified.exact_bytes.len() as u64)
            .checked_add(authorization_body.len() as u64)
            .and_then(|value| value.checked_add(topic_bytes))
            .and_then(|value| value.checked_add(512))
            .ok_or(StoreError::QuotaExceeded)?;
        ensure_bridge_admission(&transaction, &self.config, 1, accounted_bytes)?;
        let inserted_order = next_order(&transaction)?;
        let enabled = verified.authorization.enabled.as_ref();
        transaction.execute(
            "INSERT INTO bridge_authorization_controls(\n\
               envelope_id,mission_id,authority_id,control_signer,sequence,previous_control_id,\n\
               authorization_key,generation,enabled,bridge_node_id,source_scope,target_scope,\n\
               source_route_epoch,target_route_epoch,source_route_commitment,target_route_commitment,\n\
               allowed_priority_mask,max_total_hops,authorization_body,exact_bytes,applied,\n\
               inserted_order,accounted_bytes)\n\
             VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14,?15,?16,?17,?18,\n\
                    ?19,?20,0,?21,?22)",
            params![
                verified.envelope_id.as_slice(),
                verified.authorization.mission_id.as_slice(),
                verified.authorization.authority_id.as_slice(),
                verified.control_signer.as_slice(),
                sql_u64(
                    verified.authorization.control_sequence,
                    "bridge control sequence"
                )?,
                verified
                    .authorization
                    .previous_control_id
                    .as_ref()
                    .map(<[u8; 32]>::as_slice),
                verified.authorization.authorization_key.as_slice(),
                sql_u64(
                    verified.authorization.generation,
                    "bridge authorization generation"
                )?,
                i64::from(enabled.is_some()),
                verified.authorization.bridge_node_id.as_slice(),
                verified.authorization.source_scope.as_str(),
                verified.authorization.target_scope.as_str(),
                enabled
                    .map(|value| sql_u64(value.source_route_epoch, "bridge source route epoch"))
                    .transpose()?,
                enabled
                    .map(|value| sql_u64(value.target_route_epoch, "bridge target route epoch"))
                    .transpose()?,
                enabled.map(|value| value.source_route_commitment.as_slice()),
                enabled.map(|value| value.target_route_commitment.as_slice()),
                enabled.map(|value| i64::from(value.allowed_priority_mask)),
                enabled.map(|value| i64::from(value.max_total_hops)),
                authorization_body,
                &verified.exact_bytes,
                sql_u64(inserted_order, "bridge authorization insertion order")?,
                sql_u64(accounted_bytes, "bridge authorization accounted bytes")?,
            ],
        )?;
        if let Some(enabled) = enabled {
            for (index, topic) in enabled.topics.iter().enumerate() {
                transaction.execute(
                    "INSERT INTO bridge_authorization_topics(envelope_id,topic,topic_order)\n\
                     VALUES(?1,?2,?3)",
                    params![
                        verified.envelope_id.as_slice(),
                        topic.as_str(),
                        i64::try_from(index).map_err(|_| StoreError::QuotaExceeded)?
                    ],
                )?;
            }
        }
        ensure_scope_quota_tx(&transaction, &verified.authorization.source_scope)?;
        if verified.authorization.target_scope != verified.authorization.source_scope {
            ensure_scope_quota_tx(&transaction, &verified.authorization.target_scope)?;
        }
        transaction.commit()?;
        self.verified_bridge_authorizations
            .insert(verified.envelope_id);
        Ok(BridgeControlStage::Inserted)
    }

    #[cfg(test)]
    pub(crate) fn stage_bridge_authorization_without_activation_for_test(
        &mut self,
        verified: &VerifiedBridgeAuthorization,
    ) -> Result<(), StoreError> {
        match self.stage_bridge_authorization(verified)? {
            BridgeControlStage::Inserted | BridgeControlStage::Duplicate => Ok(()),
            BridgeControlStage::Rejected(_) => Err(StoreError::Invalid(
                "test fixture bridge control signer was already revoked".into(),
            )),
        }
    }

    /// Stores a provider-verified bridge control and advances only the
    /// contiguous, process-reverified prefix of its independent authority
    /// chain. Pending records are durable but confer no authority.
    pub(crate) fn ingest_bridge_authorization(
        &mut self,
        verified: &VerifiedBridgeAuthorization,
    ) -> Result<BridgeControlOutcome, StoreError> {
        let staged = self.stage_bridge_authorization(verified)?;
        let mut activation =
            self.activate_bridge_authorization_prefix(verified.authorization.authority_id)?;
        if let BridgeControlStage::Rejected(rejected) = staged
            && !activation.rejected.contains(&rejected)
        {
            activation.rejected.push(rejected);
        }
        if !activation.activated.is_empty() {
            return Ok(BridgeControlOutcome::Applied {
                envelope_id: verified.envelope_id,
                activated: activation.activated,
                rejected: activation.rejected,
            });
        }
        if let Some(rejected) = activation
            .rejected
            .iter()
            .find(|rejected| rejected.envelope_id == verified.envelope_id)
            .copied()
        {
            return Ok(BridgeControlOutcome::Rejected {
                envelope_id: rejected.envelope_id,
                signer: rejected.signer,
                rejected: activation.rejected,
            });
        }
        match staged {
            BridgeControlStage::Inserted => Ok(BridgeControlOutcome::Pending {
                envelope_id: verified.envelope_id,
            }),
            BridgeControlStage::Duplicate => Ok(BridgeControlOutcome::Duplicate {
                envelope_id: verified.envelope_id,
            }),
            BridgeControlStage::Rejected(_) => unreachable!("rejected stage handled above"),
        }
    }

    fn activate_bridge_authorization_prefix(
        &mut self,
        authority: NodeId,
    ) -> Result<BridgeControlActivation, StoreError> {
        let transaction = self.connection.transaction()?;
        let head = transaction
            .query_row(
                "SELECT sequence,envelope_id FROM bridge_authorization_heads\n\
                 WHERE authority_id=?1",
                params![authority.as_slice()],
                |row| Ok((row.get::<_, i64>(0)?, row.get::<_, Vec<u8>>(1)?)),
            )
            .optional()?;
        let (mut sequence, mut predecessor) = match head {
            Some((sequence, envelope_id)) => (
                from_sql_u64(sequence, "bridge control head sequence")?,
                Some(node_from_vec(envelope_id, "bridge control head envelope")?),
            ),
            None => (0, None),
        };
        let mut activated_ids = Vec::new();
        let mut rejected_ids = Vec::new();
        let mut result = BridgeControlActivation::default();
        loop {
            let next_sequence = sequence
                .checked_add(1)
                .ok_or(StoreError::BridgeControlRollback)?;
            let candidate = transaction
                .query_row(
                    "SELECT envelope_id,control_signer,previous_control_id,authorization_key,generation,enabled,\n\
                            applied,authorization_body\n\
                     FROM bridge_authorization_controls\n\
                     WHERE authority_id=?1 AND sequence=?2",
                    params![
                        authority.as_slice(),
                        sql_u64(next_sequence, "bridge control sequence")?
                    ],
                    |row| {
                        Ok((
                            row.get::<_, Vec<u8>>(0)?,
                            row.get::<_, Vec<u8>>(1)?,
                            row.get::<_, Option<Vec<u8>>>(2)?,
                            row.get::<_, Vec<u8>>(3)?,
                            row.get::<_, i64>(4)?,
                            row.get::<_, i64>(5)?,
                            row.get::<_, i64>(6)?,
                            row.get::<_, Vec<u8>>(7)?,
                        ))
                    },
                )
                .optional()?;
            let Some((envelope_id, signer, previous, key, generation, enabled, applied, body)) =
                candidate
            else {
                break;
            };
            let envelope_id = node_from_vec(envelope_id, "bridge control envelope")?;
            let signer = node_from_vec(signer, "bridge control signer")?;
            if !self.verified_bridge_authorizations.contains(&envelope_id) {
                break;
            }
            let previous = previous
                .map(|value| node_from_vec(value, "bridge control predecessor"))
                .transpose()?;
            if previous != predecessor || applied != 0 {
                return Err(StoreError::BridgeControlFork);
            }
            if control_signer_revoked_tx(&transaction, authority)?
                || control_signer_revoked_tx(&transaction, signer)?
            {
                let rejected =
                    purge_pending_bridge_control_suffix_tx(&transaction, authority, next_sequence)?;
                rejected_ids.extend(rejected.iter().map(|control| control.envelope_id));
                result.rejected.extend(rejected);
                break;
            }
            let key = node_from_vec(key, "bridge authorization key")?;
            let generation = from_sql_u64(generation, "bridge authorization generation")?;
            let enabled = match enabled {
                0 => false,
                1 => true,
                _ => {
                    return Err(StoreError::Corrupt(
                        "bridge authorization enabled state is invalid".into(),
                    ));
                }
            };
            let decoded = BridgeAuthorization::decode(&body)
                .map_err(|error| StoreError::Corrupt(error.to_string()))?;
            if decoded.authority_id != authority
                || decoded.control_sequence != next_sequence
                || decoded.previous_control_id != previous
                || decoded.authorization_key != key
                || decoded.generation != generation
                || decoded.enabled.is_some() != enabled
            {
                return Err(StoreError::Corrupt(
                    "normalized bridge authorization metadata differs from exact body".into(),
                ));
            }
            let prior_generation = transaction
                .query_row(
                    "SELECT generation FROM bridge_authorization_highwater\n\
                     WHERE authorization_key=?1",
                    params![key.as_slice()],
                    |row| row.get::<_, i64>(0),
                )
                .optional()?;
            if prior_generation
                .map(|value| from_sql_u64(value, "bridge authorization high-water"))
                .transpose()?
                .is_some_and(|prior| prior >= generation)
            {
                return Err(StoreError::BridgeControlRollback);
            }
            if prior_generation.is_none() {
                let active_count: i64 = transaction.query_row(
                    "SELECT count(*) FROM bridge_authorization_highwater",
                    [],
                    |row| row.get(0),
                )?;
                if from_sql_u64(active_count, "active bridge authorization count")?
                    >= MAX_ACTIVE_BRIDGE_AUTHORIZATIONS
                {
                    return Err(StoreError::QuotaExceeded);
                }
            }
            transaction.execute(
                "UPDATE bridge_authorization_controls SET applied=1 WHERE envelope_id=?1",
                params![envelope_id.as_slice()],
            )?;
            transaction.execute(
                "INSERT INTO bridge_authorization_highwater(\n\
                   authorization_key,generation,enabled,envelope_id) VALUES(?1,?2,?3,?4)\n\
                 ON CONFLICT(authorization_key) DO UPDATE SET\n\
                   generation=excluded.generation,enabled=excluded.enabled,envelope_id=excluded.envelope_id",
                params![
                    key.as_slice(),
                    sql_u64(generation, "bridge authorization generation")?,
                    i64::from(enabled),
                    envelope_id.as_slice()
                ],
            )?;
            transaction.execute(
                "DELETE FROM bridge_route_outbox WHERE wrapper_envelope_id IN (\n\
                   SELECT d.wrapper_envelope_id FROM bridge_wrapper_authorizations d\n\
                   JOIN bridge_authorization_controls c\n\
                     ON c.envelope_id=d.authorization_envelope_id\n\
                   WHERE c.authorization_key=?1\n\
                     AND (?2=0 OR d.authorization_envelope_id<>?3)\n\
                 )",
                params![key.as_slice(), i64::from(enabled), envelope_id.as_slice()],
            )?;
            transaction.execute(
                "DELETE FROM bridge_active_routes WHERE wrapper_envelope_id IN (\n\
                   SELECT d.wrapper_envelope_id FROM bridge_wrapper_authorizations d\n\
                   JOIN bridge_authorization_controls c\n\
                     ON c.envelope_id=d.authorization_envelope_id\n\
                   WHERE c.authorization_key=?1\n\
                     AND (?2=0 OR d.authorization_envelope_id<>?3)\n\
                 )",
                params![key.as_slice(), i64::from(enabled), envelope_id.as_slice()],
            )?;
            let enqueued_order = next_order(&transaction)?;
            transaction.execute(
                "INSERT INTO bridge_authorization_outbox(envelope_id,enqueued_order)\n\
                 VALUES(?1,?2) ON CONFLICT(envelope_id) DO NOTHING",
                params![
                    envelope_id.as_slice(),
                    sql_u64(enqueued_order, "bridge control outbox order")?
                ],
            )?;
            transaction.execute(
                "INSERT INTO bridge_authorization_heads(authority_id,sequence,envelope_id)\n\
                 VALUES(?1,?2,?3)\n\
                 ON CONFLICT(authority_id) DO UPDATE SET\n\
                   sequence=excluded.sequence,envelope_id=excluded.envelope_id",
                params![
                    authority.as_slice(),
                    sql_u64(next_sequence, "bridge control head sequence")?,
                    envelope_id.as_slice()
                ],
            )?;
            activated_ids.push(envelope_id);
            sequence = next_sequence;
            predecessor = Some(envelope_id);
        }
        transaction.commit()?;
        let mut activated = Vec::with_capacity(activated_ids.len());
        for envelope_id in activated_ids {
            activated.push(
                self.stored_bridge_authorization(&envelope_id)?
                    .ok_or(StoreError::NotFound("activated bridge authorization"))?,
            );
        }
        if !activated.is_empty() {
            self.verified_bridge_routes.clear();
            self.verified_pending_bridge_wrappers.clear();
            self.verified_bridge_sources.clear();
        }
        for envelope_id in rejected_ids {
            self.verified_bridge_authorizations.remove(&envelope_id);
        }
        result.activated = activated;
        Ok(result)
    }

    /// Returns the persisted generation high-water. The caller must still
    /// re-authenticate its exact bytes after process restart.
    pub(crate) fn active_bridge_authorization(
        &self,
        authorization_key: &[u8; 32],
    ) -> Result<Option<StoredBridgeAuthorization>, StoreError> {
        let envelope_id = self
            .connection
            .query_row(
                "SELECT envelope_id FROM bridge_authorization_highwater\n\
                 WHERE authorization_key=?1",
                params![authorization_key.as_slice()],
                |row| row.get::<_, Vec<u8>>(0),
            )
            .optional()?
            .map(|value| node_from_vec(value, "active bridge authorization envelope"))
            .transpose()?;
        envelope_id
            .map(|value| self.stored_bridge_authorization(&value))
            .transpose()
            .map(Option::flatten)
    }

    fn bridge_authorization_is_live(&self, envelope_id: &EnvelopeId) -> Result<bool, StoreError> {
        if !self.verified_bridge_authorizations.contains(envelope_id) {
            return Ok(false);
        }
        Ok(self.connection.query_row(
            "SELECT EXISTS(\n\
               SELECT 1 FROM bridge_authorization_highwater h\n\
               JOIN bridge_authorization_controls c ON c.envelope_id=h.envelope_id\n\
               WHERE h.envelope_id=?1 AND h.enabled=1 AND c.applied=1\n\
                 AND NOT EXISTS(SELECT 1 FROM revocations r\n\
                                WHERE r.subject IN\n\
                                  (c.authority_id,c.control_signer,c.bridge_node_id))\n\
             )",
            params![envelope_id.as_slice()],
            |row| row.get::<_, i64>(0),
        )? == 1)
    }

    /// Durably stages a route wrapper after provider verification of its outer
    /// protection and route structure. No source semantics are accepted here,
    /// and the record confers no bridge authority.
    pub(crate) fn stage_verified_pending_bridge_wrapper(
        &mut self,
        verified: &VerifiedPendingBridgeWrapper,
        sample: Option<CustodySample>,
    ) -> Result<bool, StoreError> {
        if let Some(existing) = self.stored_pending_bridge_wrapper(&verified.wrapper_envelope_id)? {
            if existing.route != verified.route
                || existing.exact_wrapper_bytes != verified.exact_wrapper_bytes
            {
                return Err(StoreError::Corrupt(
                    "pending bridge wrapper identity maps to different exact content".into(),
                ));
            }
            self.connection.execute(
                "UPDATE bridge_pending_wrappers SET\n\
                   cumulative_custody_age_ms=max(cumulative_custody_age_ms,?1),\n\
                   forwarding_custody_age_ms=max(forwarding_custody_age_ms,?1)\n\
                 WHERE wrapper_envelope_id=?2",
                params![
                    sql_u64(
                        verified.authenticated_forwarding_age_ms,
                        "authenticated wrapper forwarding age"
                    )?,
                    verified.wrapper_envelope_id.as_slice()
                ],
            )?;
            self.verified_pending_bridge_wrappers
                .insert(verified.wrapper_envelope_id);
            return Ok(false);
        }
        if let Some(existing) = self.stored_bridge_route(&verified.wrapper_envelope_id)? {
            if existing.bridge_route_id != verified.route.bridge_route_id
                || existing.origin_envelope_id != verified.route.origin_envelope_id
                || existing.source_item_id != verified.route.source_item_id
                || existing.exact_wrapper_bytes != verified.exact_wrapper_bytes
            {
                return Err(StoreError::Corrupt(
                    "bridge wrapper identity maps to different exact content".into(),
                ));
            }
            return Ok(false);
        }
        let route_body = verified
            .route
            .encode()
            .map_err(|error| StoreError::Invalid(error.to_string()))?;
        let dependency_bytes = (verified.route.hops.len() as u64)
            .checked_mul(80)
            .ok_or(StoreError::QuotaExceeded)?;
        let accounted_bytes = (verified.exact_wrapper_bytes.len() as u64)
            .checked_add(route_body.len() as u64)
            .and_then(|value| value.checked_add(dependency_bytes))
            .and_then(|value| value.checked_add(512))
            .ok_or(StoreError::QuotaExceeded)?;
        let final_hop = verified
            .route
            .hops
            .last()
            .ok_or(StoreError::BridgeDependencyMissing)?;
        let elapsed_available = !final_hop.age_continuity_unknown && sample.is_some();
        let transaction = self.connection.transaction()?;
        ensure_bridge_admission(&transaction, &self.config, 1, accounted_bytes)?;
        let inserted_order = next_order(&transaction)?;
        transaction.execute(
            "INSERT INTO bridge_pending_wrappers(\n\
               wrapper_envelope_id,bridge_route_id,origin_envelope_id,source_item_id,\n\
               origin_scope,origin_route_epoch,current_scope,current_route_epoch,hop_count,\n\
               cumulative_custody_age_ms,forwarding_custody_age_ms,age_continuity_unknown,\n\
               custody_clock_id,custody_tick_ms,\n\
               custody_elapsed_available,route_body,exact_bytes,inserted_order,accounted_bytes)\n\
             VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14,?15,?16,?17,?18,?19)",
            params![
                verified.wrapper_envelope_id.as_slice(),
                verified.route.bridge_route_id.as_slice(),
                verified.route.origin_envelope_id.as_slice(),
                verified.route.source_item_id.as_slice(),
                verified.route.origin_scope.as_str(),
                sql_u64(
                    verified.route.origin_route_epoch,
                    "pending bridge origin epoch"
                )?,
                verified.route.current_scope.as_str(),
                sql_u64(
                    verified.route.current_route_epoch,
                    "pending bridge current epoch"
                )?,
                i64::try_from(verified.route.hops.len()).map_err(|_| StoreError::QuotaExceeded)?,
                sql_u64(
                    final_hop
                        .cumulative_custody_age_ms
                        .max(verified.authenticated_forwarding_age_ms),
                    "pending bridge custody age"
                )?,
                sql_u64(
                    verified.authenticated_forwarding_age_ms,
                    "authenticated wrapper forwarding age"
                )?,
                i64::from(final_hop.age_continuity_unknown),
                sample
                    .filter(|_| elapsed_available)
                    .map(|value| value.clock_id),
                sample
                    .filter(|_| elapsed_available)
                    .map(|value| sql_u64(value.tick_ms, "pending bridge custody tick"))
                    .transpose()?,
                i64::from(elapsed_available),
                route_body,
                &verified.exact_wrapper_bytes,
                sql_u64(inserted_order, "pending bridge wrapper order")?,
                sql_u64(accounted_bytes, "pending bridge wrapper bytes")?
            ],
        )?;
        for (index, hop) in verified.route.hops.iter().enumerate() {
            transaction.execute(
                "INSERT INTO bridge_pending_wrapper_authorizations(\n\
                   wrapper_envelope_id,hop_index,authorization_envelope_id) VALUES(?1,?2,?3)",
                params![
                    verified.wrapper_envelope_id.as_slice(),
                    i64::try_from(index + 1).map_err(|_| StoreError::QuotaExceeded)?,
                    hop.authorization_envelope_id.as_slice()
                ],
            )?;
        }
        transaction.commit()?;
        self.verified_pending_bridge_wrappers
            .insert(verified.wrapper_envelope_id);
        Ok(true)
    }

    /// Atomically converts a complete typed wrapper transfer into private
    /// dependency-pending state. A reopened exact pending duplicate is
    /// idempotent even though its transfer rows were already retired.
    pub(crate) fn defer_verified_pending_bridge_wrapper_transfer(
        &mut self,
        verified: &VerifiedPendingBridgeWrapper,
        sample: Option<CustodySample>,
    ) -> Result<bool, StoreError> {
        let existing = self.stored_pending_bridge_wrapper(&verified.wrapper_envelope_id)?;
        let committed = self.stored_bridge_route(&verified.wrapper_envelope_id)?;
        if existing.is_some() && committed.is_some() {
            return Err(StoreError::Corrupt(
                "bridge wrapper exists in committed and pending state".into(),
            ));
        }
        if let Some(existing) = &existing
            && (existing.route != verified.route
                || existing.exact_wrapper_bytes != verified.exact_wrapper_bytes)
        {
            return Err(StoreError::Corrupt(
                "pending bridge wrapper identity maps to different exact content".into(),
            ));
        }
        if let Some(committed) = &committed {
            let authorization_ids = {
                let mut statement = self.connection.prepare(
                    "SELECT authorization_envelope_id FROM bridge_wrapper_authorizations\n\
                     WHERE wrapper_envelope_id=?1 ORDER BY hop_index",
                )?;
                statement
                    .query_map(params![verified.wrapper_envelope_id.as_slice()], |row| {
                        row.get::<_, Vec<u8>>(0)
                    })?
                    .collect::<Result<Vec<_>, _>>()?
            };
            let exact_match = committed.bridge_route_id == verified.route.bridge_route_id
                && committed.origin_envelope_id == verified.route.origin_envelope_id
                && committed.source_item_id == verified.route.source_item_id
                && committed.origin_scope == verified.route.origin_scope
                && committed.origin_route_epoch == verified.route.origin_route_epoch
                && committed.current_scope == verified.route.current_scope
                && committed.current_route_epoch == verified.route.current_route_epoch
                && usize::from(committed.hop_count) == verified.route.hops.len()
                && committed.exact_wrapper_bytes == verified.exact_wrapper_bytes
                && authorization_ids.len() == verified.route.hops.len()
                && authorization_ids
                    .iter()
                    .zip(&verified.route.hops)
                    .all(|(stored, hop)| {
                        stored.as_slice() == hop.authorization_envelope_id.as_slice()
                    });
            if !exact_match {
                return Err(StoreError::Corrupt(
                    "committed bridge wrapper identity maps to different exact content".into(),
                ));
            }
        }
        let object_id = ObjectId::new(ObjectKind::BridgeRouteWrapper, verified.wrapper_envelope_id);
        let storage_key = transfer_storage_key(object_id);
        let has_transfer: i64 = self.connection.query_row(
            "SELECT EXISTS(SELECT 1 FROM transfer_identities WHERE storage_key=?1)",
            params![storage_key.as_slice()],
            |row| row.get(0),
        )?;
        if let Some(committed) = &committed {
            let source = self
                .stored_bridge_source(&committed.origin_envelope_id)?
                .ok_or(StoreError::Corrupt(
                    "committed bridge wrapper source is missing".into(),
                ))?;
            let final_hop = verified
                .route
                .hops
                .last()
                .ok_or(StoreError::BridgeDependencyMissing)?;
            let checkpoint = checkpoint_bridge_route_custody(committed, sample);
            let cumulative_age = checkpoint
                .0
                .max(final_hop.cumulative_custody_age_ms)
                .max(verified.authenticated_forwarding_age_ms);
            let continuity_unknown = checkpoint.1
                || final_hop.age_continuity_unknown
                || sample.is_none()
                || source.age_continuity_unknown
                || bridge_source_custody_age_at(&source, sample).is_none();
            let continuity = if continuity_unknown {
                (None, None, false)
            } else {
                (checkpoint.2, checkpoint.3, checkpoint.4)
            };
            let live = bridge_custody_is_live(
                committed.ttl_ms,
                source.metadata.tombstone,
                cumulative_age,
                continuity_unknown,
                continuity.0,
                continuity.1,
                continuity.2,
                sample,
            ) && bridge_custody_is_live(
                source.metadata.ttl_ms,
                source.metadata.tombstone,
                source.cumulative_custody_age_ms,
                false,
                source.custody_clock_id,
                source.custody_tick_ms,
                source.custody_elapsed_available,
                sample,
            );
            let transaction = self.connection.transaction()?;
            if has_transfer != 0 {
                exact_typed_transfer_bytes_tx(
                    &transaction,
                    object_id,
                    &verified.exact_wrapper_bytes,
                )?;
            }
            transaction.execute(
                "UPDATE bridge_route_wrappers SET\n\
                   cumulative_custody_age_ms=max(cumulative_custody_age_ms,?1),\n\
                   forwarding_custody_age_ms=max(forwarding_custody_age_ms,?2),\n\
                   age_continuity_unknown=?3,custody_clock_id=?4,custody_tick_ms=?5,\n\
                   custody_elapsed_available=?6 WHERE wrapper_envelope_id=?7",
                params![
                    sql_u64(cumulative_age, "duplicate bridge wrapper custody age")?,
                    sql_u64(
                        verified.authenticated_forwarding_age_ms,
                        "duplicate bridge wrapper forwarding age"
                    )?,
                    i64::from(continuity_unknown),
                    continuity.0.map(|value| value.to_vec()),
                    continuity
                        .1
                        .map(|value| sql_u64(value, "duplicate bridge wrapper custody tick"))
                        .transpose()?,
                    i64::from(continuity.2),
                    verified.wrapper_envelope_id.as_slice()
                ],
            )?;
            if !live {
                transaction.execute(
                    "DELETE FROM bridge_route_outbox WHERE wrapper_envelope_id=?1",
                    params![verified.wrapper_envelope_id.as_slice()],
                )?;
                transaction.execute(
                    "DELETE FROM bridge_active_routes WHERE wrapper_envelope_id=?1",
                    params![verified.wrapper_envelope_id.as_slice()],
                )?;
            }
            if has_transfer != 0 {
                retire_typed_transfer_tx(&transaction, object_id)?;
            }
            transaction.commit()?;
            if !live {
                self.verified_bridge_routes
                    .remove(&verified.wrapper_envelope_id);
                return Err(StoreError::BridgeRouteIneligible);
            }
            return Ok(false);
        }
        if has_transfer == 0 {
            if existing.is_some() {
                self.verified_pending_bridge_wrappers
                    .extend(existing.as_ref().map(|_| verified.wrapper_envelope_id));
                return Ok(false);
            }
            return Err(StoreError::NotFound("typed bridge wrapper transfer"));
        }
        let transaction = self.connection.transaction()?;
        exact_typed_transfer_bytes_tx(&transaction, object_id, &verified.exact_wrapper_bytes)?;
        if existing.is_none() {
            insert_pending_bridge_wrapper_tx(&transaction, &self.config, verified, sample)?;
        } else {
            transaction.execute(
                "UPDATE bridge_pending_wrappers SET\n\
                   cumulative_custody_age_ms=max(cumulative_custody_age_ms,?1),\n\
                   forwarding_custody_age_ms=max(forwarding_custody_age_ms,?1)\n\
                 WHERE wrapper_envelope_id=?2",
                params![
                    sql_u64(
                        verified.authenticated_forwarding_age_ms,
                        "authenticated wrapper forwarding age"
                    )?,
                    verified.wrapper_envelope_id.as_slice()
                ],
            )?;
        }
        retire_typed_transfer_tx(&transaction, object_id)?;
        transaction.commit()?;
        self.verified_pending_bridge_wrappers
            .insert(verified.wrapper_envelope_id);
        Ok(existing.is_none())
    }

    pub(crate) fn stored_pending_bridge_wrapper(
        &self,
        wrapper_envelope_id: &EnvelopeId,
    ) -> Result<Option<StoredPendingBridgeWrapper>, StoreError> {
        let row = self
            .connection
            .query_row(
                "SELECT bridge_route_id,origin_envelope_id,source_item_id,origin_scope,\n\
                        origin_route_epoch,current_scope,current_route_epoch,hop_count,\n\
                        cumulative_custody_age_ms,forwarding_custody_age_ms,age_continuity_unknown,\n\
                        custody_clock_id,custody_tick_ms,custody_elapsed_available,route_body,\n\
                        exact_bytes,inserted_order\n\
                 FROM bridge_pending_wrappers WHERE wrapper_envelope_id=?1",
                params![wrapper_envelope_id.as_slice()],
                |row| {
                    Ok((
                        row.get::<_, Vec<u8>>(0)?,
                        row.get::<_, Vec<u8>>(1)?,
                        row.get::<_, Vec<u8>>(2)?,
                        row.get::<_, String>(3)?,
                        row.get::<_, i64>(4)?,
                        row.get::<_, String>(5)?,
                        row.get::<_, i64>(6)?,
                        row.get::<_, i64>(7)?,
                        row.get::<_, i64>(8)?,
                        row.get::<_, i64>(9)?,
                        row.get::<_, i64>(10)?,
                        row.get::<_, Option<Vec<u8>>>(11)?,
                        row.get::<_, Option<i64>>(12)?,
                        row.get::<_, i64>(13)?,
                        row.get::<_, Vec<u8>>(14)?,
                        row.get::<_, Vec<u8>>(15)?,
                        row.get::<_, i64>(16)?,
                    ))
                },
            )
            .optional()?;
        let Some((
            route_id,
            origin_id,
            source_item_id,
            origin_scope,
            origin_epoch,
            current_scope,
            current_epoch,
            hop_count,
            custody_age,
            forwarding_age,
            custody_unknown,
            clock_id,
            tick_ms,
            elapsed_available,
            route_body,
            exact_bytes,
            inserted_order,
        )) = row
        else {
            return Ok(None);
        };
        if exact_object_id(&exact_bytes) != *wrapper_envelope_id {
            return Err(StoreError::Corrupt(
                "stored pending bridge wrapper identity is invalid".into(),
            ));
        }
        let route = BridgeRoute::decode(&route_body)
            .map_err(|error| StoreError::Corrupt(error.to_string()))?;
        if route
            .encode()
            .map_err(|error| StoreError::Corrupt(error.to_string()))?
            != route_body
            || route.bridge_route_id != node_from_vec(route_id, "pending bridge route id")?
            || route.origin_envelope_id != node_from_vec(origin_id, "pending bridge origin")?
            || route.source_item_id != item_from_vec(source_item_id, "pending bridge source item")?
            || route.origin_scope.as_str() != origin_scope
            || route.origin_route_epoch
                != from_sql_u64(origin_epoch, "pending bridge origin epoch")?
            || route.current_scope.as_str() != current_scope
            || route.current_route_epoch
                != from_sql_u64(current_epoch, "pending bridge current epoch")?
            || route.hops.len() as u64 != from_sql_u64(hop_count, "pending bridge hop count")?
        {
            return Err(StoreError::Corrupt(
                "pending bridge normalized metadata differs from exact route".into(),
            ));
        }
        let dependencies = {
            let mut statement = self.connection.prepare(
                "SELECT authorization_envelope_id FROM bridge_pending_wrapper_authorizations\n\
                 WHERE wrapper_envelope_id=?1 ORDER BY hop_index",
            )?;
            statement
                .query_map(params![wrapper_envelope_id.as_slice()], |row| {
                    row.get::<_, Vec<u8>>(0)
                })?
                .collect::<Result<Vec<_>, _>>()?
        };
        if dependencies.len() != route.hops.len()
            || dependencies
                .iter()
                .zip(&route.hops)
                .any(|(stored, hop)| stored.as_slice() != hop.authorization_envelope_id.as_slice())
        {
            return Err(StoreError::Corrupt(
                "pending bridge authorization edges differ from exact route".into(),
            ));
        }
        let final_hop = route.hops.last().ok_or(StoreError::Corrupt(
            "pending bridge route has no hop".into(),
        ))?;
        let forwarding_age = from_sql_u64(forwarding_age, "pending bridge forwarding age")?;
        let stored_unknown = sql_bool(custody_unknown, "custody unknown")?;
        if final_hop.cumulative_custody_age_ms.max(forwarding_age)
            > from_sql_u64(custody_age, "pending bridge custody age")?
            || (final_hop.age_continuity_unknown && !stored_unknown)
        {
            return Err(StoreError::Corrupt(
                "pending bridge custody metadata differs from exact route".into(),
            ));
        }
        let custody_clock_id = clock_id
            .map(|value| clock_from_vec(value, "pending bridge custody clock"))
            .transpose()?;
        let custody_tick_ms = tick_ms
            .map(|value| from_sql_u64(value, "pending bridge custody tick"))
            .transpose()?;
        let custody_elapsed_available = sql_bool(elapsed_available, "custody availability")?;
        if custody_elapsed_available != (custody_clock_id.is_some() && custody_tick_ms.is_some()) {
            return Err(StoreError::Corrupt(
                "pending bridge custody continuity tuple is inconsistent".into(),
            ));
        }
        Ok(Some(StoredPendingBridgeWrapper {
            wrapper_envelope_id: *wrapper_envelope_id,
            route,
            exact_wrapper_bytes: exact_bytes,
            cumulative_custody_age_ms: from_sql_u64(custody_age, "pending bridge custody age")?,
            authenticated_forwarding_age_ms: forwarding_age,
            age_continuity_unknown: stored_unknown,
            custody_clock_id,
            custody_tick_ms,
            custody_elapsed_available,
            inserted_order: from_sql_u64(inserted_order, "pending bridge wrapper order")?,
        }))
    }

    /// Bounded restart reload. Returned bytes and metadata remain untrusted
    /// until the provider reconstructs a verification token in this process.
    pub(crate) fn pending_bridge_wrappers(
        &self,
        limit: usize,
    ) -> Result<Vec<StoredPendingBridgeWrapper>, StoreError> {
        self.pending_bridge_wrappers_after(None, limit)
    }

    pub(crate) fn pending_bridge_wrappers_after(
        &self,
        after_inserted_order: Option<u64>,
        limit: usize,
    ) -> Result<Vec<StoredPendingBridgeWrapper>, StoreError> {
        let limit = limit.min(MAX_BRIDGE_STORE_BATCH);
        if limit == 0 {
            return Ok(Vec::new());
        }
        let ids = {
            let mut statement = self.connection.prepare(
                "SELECT wrapper_envelope_id FROM bridge_pending_wrappers\n\
                 WHERE inserted_order>?1 ORDER BY inserted_order LIMIT ?2",
            )?;
            statement
                .query_map(
                    params![
                        sql_u64(
                            after_inserted_order.unwrap_or(0),
                            "pending bridge wrapper cursor"
                        )?,
                        i64::try_from(limit).map_err(|_| StoreError::QuotaExceeded)?
                    ],
                    |row| row.get::<_, Vec<u8>>(0),
                )?
                .collect::<Result<Vec<_>, _>>()?
        };
        ids.into_iter()
            .map(|id| {
                let id = node_from_vec(id, "pending bridge wrapper")?;
                self.stored_pending_bridge_wrapper(&id)?
                    .ok_or(StoreError::Corrupt(
                        "pending bridge wrapper disappeared".into(),
                    ))
            })
            .collect()
    }

    /// Bounded, canonical dependency enumeration. Missing authorizations are
    /// listed in hop order, followed by the exact source-carrier dependency.
    pub(crate) fn missing_bridge_dependencies(
        &self,
        wrapper_envelope_id: &EnvelopeId,
        limit: usize,
    ) -> Result<Vec<ObjectId>, StoreError> {
        let limit = limit.min(MAX_BRIDGE_STORE_BATCH);
        if limit == 0 {
            return Ok(Vec::new());
        }
        let pending = self
            .stored_pending_bridge_wrapper(wrapper_envelope_id)?
            .ok_or(StoreError::NotFound("pending bridge wrapper"))?;
        let mut missing = Vec::new();
        for hop in &pending.route.hops {
            if let Some(dependency) =
                self.missing_bridge_authorization_dependency(&pending.route, hop)?
            {
                missing.push(ObjectId::new(ObjectKind::BridgeAuthorization, dependency));
                if missing.len() == limit {
                    return Ok(missing);
                }
            }
        }
        let durable_bridge_source_present: i64 = self.connection.query_row(
            "SELECT EXISTS(SELECT 1 FROM bridge_pending_sources WHERE origin_envelope_id=?1)\n\
             OR EXISTS(SELECT 1 FROM bridge_source_objects\n\
                       WHERE origin_envelope_id=?1 AND reused_item_id IS NULL)",
            params![pending.route.origin_envelope_id.as_slice()],
            |row| row.get(0),
        )?;
        let verified_ordinary_present = self
            .verified_bridge_sources
            .contains(&pending.route.origin_envelope_id)
            && self.connection.query_row(
                "SELECT EXISTS(SELECT 1 FROM items WHERE envelope_id=?1)",
                params![pending.route.origin_envelope_id.as_slice()],
                |row| row.get::<_, i64>(0),
            )? == 1;
        if durable_bridge_source_present == 0 && !verified_ordinary_present && missing.len() < limit
        {
            missing.push(ObjectId::new(
                ObjectKind::SourceEnvelope,
                pending.route.origin_envelope_id,
            ));
        }
        Ok(missing)
    }

    fn missing_bridge_authorization_dependency(
        &self,
        route: &BridgeRoute,
        hop: &crate::bridge::BridgeHop,
    ) -> Result<Option<EnvelopeId>, StoreError> {
        let Some(target) = self.stored_bridge_authorization(&hop.authorization_envelope_id)? else {
            return Ok(Some(hop.authorization_envelope_id));
        };
        let Some(enabled) = target.authorization.enabled.as_ref() else {
            return Ok(None);
        };
        let superseding: Option<(i64, Vec<u8>)> = self
            .connection
            .query_row(
                "SELECT generation,envelope_id FROM bridge_authorization_highwater\n\
                 WHERE authorization_key=?1",
                params![target.authorization.authorization_key.as_slice()],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .optional()?;
        if superseding
            .map(|(generation, envelope_id)| {
                Ok::<_, StoreError>(
                    from_sql_u64(generation, "bridge authorization high-water")?
                        >= target.authorization.generation
                        && envelope_id.as_slice() != target.envelope_id.as_slice(),
                )
            })
            .transpose()?
            .unwrap_or(false)
        {
            return Ok(None);
        }
        let source_epoch = self
            .connection
            .query_row(
                "SELECT epoch FROM scope_epochs WHERE scope=?1",
                params![hop.from_scope.as_str()],
                |row| row.get::<_, i64>(0),
            )
            .optional()?
            .map(|value| from_sql_u64(value, "bridge source scope epoch"))
            .transpose()?;
        let target_epoch = self
            .connection
            .query_row(
                "SELECT epoch FROM scope_epochs WHERE scope=?1",
                params![hop.to_scope.as_str()],
                |row| row.get::<_, i64>(0),
            )
            .optional()?
            .map(|value| from_sql_u64(value, "bridge target scope epoch"))
            .transpose()?;
        let revoked: i64 = self.connection.query_row(
            "SELECT EXISTS(SELECT 1 FROM revocations WHERE subject IN (?1,?2,?3))",
            params![
                target.authorization.authority_id.as_slice(),
                target.control_signer.as_slice(),
                target.authorization.bridge_node_id.as_slice()
            ],
            |row| row.get(0),
        )?;
        if target.authorization.mission_id != route.mission_id
            || target.authorization.bridge_node_id != hop.bridge_node_id
            || target.authorization.source_scope != hop.from_scope
            || target.authorization.target_scope != hop.to_scope
            || enabled.source_route_epoch != hop.from_route_epoch
            || enabled.target_route_epoch != hop.to_route_epoch
            || route.hops.len() > usize::from(enabled.max_total_hops)
            || source_epoch != Some(hop.from_route_epoch)
            || target_epoch != Some(hop.to_route_epoch)
            || revoked != 0
        {
            return Ok(None);
        }
        if target.applied {
            return Ok(None);
        }

        let mut current = target;
        let mut visited = BTreeSet::new();
        loop {
            if !visited.insert(current.envelope_id) || visited.len() > MAX_BRIDGE_STORE_BATCH {
                return Err(StoreError::BridgeControlFork);
            }
            let Some(predecessor_id) = current.authorization.previous_control_id else {
                return if current.authorization.control_sequence == 1 {
                    Ok(None)
                } else {
                    Err(StoreError::BridgeControlFork)
                };
            };
            let Some(predecessor) = self.stored_bridge_authorization(&predecessor_id)? else {
                return Ok(Some(predecessor_id));
            };
            if predecessor.authorization.authority_id != current.authorization.authority_id
                || predecessor.authorization.control_sequence.checked_add(1)
                    != Some(current.authorization.control_sequence)
                || predecessor.envelope_id != predecessor_id
            {
                return Err(StoreError::BridgeControlFork);
            }
            if predecessor.applied {
                return Ok(None);
            }
            current = predecessor;
        }
    }

    /// Atomically converts a complete source transfer into bounded,
    /// semantics-free private state. No wrapper, ItemID, publisher, scope,
    /// topic, inventory, or application claim is attached at this stage.
    pub(crate) fn defer_verified_unresolved_bridge_source_transfer(
        &mut self,
        verified: &VerifiedUnresolvedBridgeSource,
        sample: Option<CustodySample>,
    ) -> Result<bool, StoreError> {
        let existing = self.stored_unresolved_bridge_source(&verified.origin_envelope_id)?;
        if let Some(existing) = &existing
            && existing.exact_bytes != verified.exact_bytes
        {
            return Err(StoreError::Corrupt(
                "unresolved bridge source identity maps to different exact content".into(),
            ));
        }
        if self
            .stored_pending_bridge_source(&verified.origin_envelope_id)?
            .is_some()
            || self
                .stored_bridge_source(&verified.origin_envelope_id)?
                .is_some()
        {
            return Err(StoreError::Corrupt(
                "resolved bridge source also exists in unresolved state".into(),
            ));
        }
        let object_id = ObjectId::new(ObjectKind::SourceEnvelope, verified.origin_envelope_id);
        let custody = merged_bridge_source_custody(
            existing.as_ref(),
            verified.authenticated_forwarding_age_ms,
            sample,
        );
        let storage_key = transfer_storage_key(object_id);
        let has_transfer: i64 = self.connection.query_row(
            "SELECT EXISTS(SELECT 1 FROM transfer_identities WHERE storage_key=?1)",
            params![storage_key.as_slice()],
            |row| row.get(0),
        )?;
        if has_transfer == 0 {
            if existing.is_some() {
                self.connection.execute(
                    "UPDATE bridge_unresolved_sources SET\n\
                       cumulative_custody_age_ms=?1,\n\
                       forwarding_custody_age_ms=max(forwarding_custody_age_ms,?2),\n\
                       age_continuity_unknown=?3,custody_clock_id=?4,custody_tick_ms=?5,\n\
                       custody_elapsed_available=?6 WHERE origin_envelope_id=?7",
                    params![
                        sql_u64(custody.0, "unresolved source custody age")?,
                        sql_u64(
                            verified.authenticated_forwarding_age_ms,
                            "unresolved source forwarding age"
                        )?,
                        i64::from(custody.1),
                        custody.2.map(|value| value.to_vec()),
                        custody
                            .3
                            .map(|value| sql_u64(value, "unresolved source custody tick"))
                            .transpose()?,
                        i64::from(custody.4),
                        verified.origin_envelope_id.as_slice()
                    ],
                )?;
                return Ok(false);
            }
            return Err(StoreError::NotFound(
                "typed unresolved bridge source transfer",
            ));
        }
        let transaction = self.connection.transaction()?;
        exact_typed_transfer_bytes_tx(&transaction, object_id, &verified.exact_bytes)?;
        if existing.is_none() {
            let accounted_bytes = (verified.exact_bytes.len() as u64)
                .checked_add(96)
                .ok_or(StoreError::QuotaExceeded)?;
            ensure_bridge_admission(&transaction, &self.config, 1, accounted_bytes)?;
            let inserted_order = next_order(&transaction)?;
            transaction.execute(
                "INSERT INTO bridge_unresolved_sources(\n\
                   origin_envelope_id,cumulative_custody_age_ms,forwarding_custody_age_ms,\n\
                   age_continuity_unknown,custody_clock_id,custody_tick_ms,\n\
                   custody_elapsed_available,exact_bytes,inserted_order,accounted_bytes)\n\
                 VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10)",
                params![
                    verified.origin_envelope_id.as_slice(),
                    sql_u64(custody.0, "unresolved source custody age")?,
                    sql_u64(
                        verified.authenticated_forwarding_age_ms,
                        "unresolved source forwarding age"
                    )?,
                    i64::from(custody.1),
                    custody.2.map(|value| value.to_vec()),
                    custody
                        .3
                        .map(|value| sql_u64(value, "unresolved source custody tick"))
                        .transpose()?,
                    i64::from(custody.4),
                    &verified.exact_bytes,
                    sql_u64(inserted_order, "unresolved source order")?,
                    sql_u64(accounted_bytes, "unresolved source bytes")?
                ],
            )?;
        } else {
            transaction.execute(
                "UPDATE bridge_unresolved_sources SET\n\
                   cumulative_custody_age_ms=?1,\n\
                   forwarding_custody_age_ms=max(forwarding_custody_age_ms,?2),\n\
                   age_continuity_unknown=?3,custody_clock_id=?4,custody_tick_ms=?5,\n\
                   custody_elapsed_available=?6 WHERE origin_envelope_id=?7",
                params![
                    sql_u64(custody.0, "unresolved source custody age")?,
                    sql_u64(
                        verified.authenticated_forwarding_age_ms,
                        "unresolved source forwarding age"
                    )?,
                    i64::from(custody.1),
                    custody.2.map(|value| value.to_vec()),
                    custody
                        .3
                        .map(|value| sql_u64(value, "unresolved source custody tick"))
                        .transpose()?,
                    i64::from(custody.4),
                    verified.origin_envelope_id.as_slice()
                ],
            )?;
        }
        retire_typed_transfer_tx(&transaction, object_id)?;
        transaction.commit()?;
        Ok(existing.is_none())
    }

    pub(crate) fn stored_unresolved_bridge_source(
        &self,
        origin_envelope_id: &EnvelopeId,
    ) -> Result<Option<StoredUnresolvedBridgeSource>, StoreError> {
        let row = self
            .connection
            .query_row(
                "SELECT cumulative_custody_age_ms,forwarding_custody_age_ms,\n\
                        age_continuity_unknown,custody_clock_id,custody_tick_ms,\n\
                        custody_elapsed_available,exact_bytes,inserted_order\n\
                 FROM bridge_unresolved_sources WHERE origin_envelope_id=?1",
                params![origin_envelope_id.as_slice()],
                |row| {
                    Ok((
                        row.get::<_, i64>(0)?,
                        row.get::<_, i64>(1)?,
                        row.get::<_, i64>(2)?,
                        row.get::<_, Option<Vec<u8>>>(3)?,
                        row.get::<_, Option<i64>>(4)?,
                        row.get::<_, i64>(5)?,
                        row.get::<_, Vec<u8>>(6)?,
                        row.get::<_, i64>(7)?,
                    ))
                },
            )
            .optional()?;
        let Some((
            custody_age,
            forwarding_age,
            continuity_unknown,
            clock_id,
            tick_ms,
            elapsed_available,
            exact_bytes,
            inserted_order,
        )) = row
        else {
            return Ok(None);
        };
        if exact_object_id(&exact_bytes) != *origin_envelope_id {
            return Err(StoreError::Corrupt(
                "stored unresolved bridge source identity is invalid".into(),
            ));
        }
        let custody_clock_id = clock_id
            .map(|value| clock_from_vec(value, "unresolved source custody clock"))
            .transpose()?;
        let custody_tick_ms = tick_ms
            .map(|value| from_sql_u64(value, "unresolved source custody tick"))
            .transpose()?;
        let custody_elapsed_available = sql_bool(elapsed_available, "unresolved source custody")?;
        if custody_elapsed_available != (custody_clock_id.is_some() && custody_tick_ms.is_some()) {
            return Err(StoreError::Corrupt(
                "unresolved source custody tuple is inconsistent".into(),
            ));
        }
        Ok(Some(StoredUnresolvedBridgeSource {
            origin_envelope_id: *origin_envelope_id,
            cumulative_custody_age_ms: from_sql_u64(custody_age, "unresolved source custody age")?,
            authenticated_forwarding_age_ms: from_sql_u64(
                forwarding_age,
                "unresolved source forwarding age",
            )?,
            age_continuity_unknown: sql_bool(continuity_unknown, "unresolved source continuity")?,
            custody_clock_id,
            custody_tick_ms,
            custody_elapsed_available,
            exact_bytes,
            inserted_order: from_sql_u64(inserted_order, "unresolved source order")?,
        }))
    }

    pub(crate) fn unresolved_bridge_sources_after(
        &self,
        after_inserted_order: Option<u64>,
        limit: usize,
    ) -> Result<Vec<StoredUnresolvedBridgeSource>, StoreError> {
        let limit = limit.min(MAX_BRIDGE_STORE_BATCH);
        if limit == 0 {
            return Ok(Vec::new());
        }
        let ids = {
            let mut statement = self.connection.prepare(
                "SELECT origin_envelope_id FROM bridge_unresolved_sources\n\
                 WHERE inserted_order>?1 ORDER BY inserted_order LIMIT ?2",
            )?;
            statement
                .query_map(
                    params![
                        sql_u64(
                            after_inserted_order.unwrap_or(0),
                            "unresolved source cursor"
                        )?,
                        i64::try_from(limit).map_err(|_| StoreError::QuotaExceeded)?
                    ],
                    |row| row.get::<_, Vec<u8>>(0),
                )?
                .collect::<Result<Vec<_>, _>>()?
        };
        ids.into_iter()
            .map(|id| {
                let id = node_from_vec(id, "unresolved source identity")?;
                self.stored_unresolved_bridge_source(&id)?
                    .ok_or(StoreError::Corrupt(
                        "unresolved bridge source disappeared".into(),
                    ))
            })
            .collect()
    }

    pub(crate) fn unresolved_bridge_sources(
        &self,
        limit: usize,
    ) -> Result<Vec<StoredUnresolvedBridgeSource>, StoreError> {
        self.unresolved_bridge_sources_after(None, limit)
    }

    pub(crate) fn delete_unresolved_bridge_source(
        &mut self,
        origin_envelope_id: &EnvelopeId,
    ) -> Result<bool, StoreError> {
        Ok(self.connection.execute(
            "DELETE FROM bridge_unresolved_sources WHERE origin_envelope_id=?1",
            params![origin_envelope_id.as_slice()],
        )? != 0)
    }

    /// Crash-atomically retires a complete typed Blob transfer into bounded,
    /// private carrier state. No inventory, semantic, or application row is
    /// created before an exact source manifest authorizes the route proof.
    pub(crate) fn defer_verified_pending_bridge_blob_carrier_transfer(
        &mut self,
        verified: &VerifiedPendingBridgeBlobCarrier,
    ) -> Result<bool, StoreError> {
        let key = verified.object_id.to_wire_bytes();
        let existing = self
            .connection
            .query_row(
                "SELECT exact_bytes FROM bridge_pending_blob_carriers\n\
                 WHERE object_id=?1 AND source_envelope_id=?2",
                params![key.as_slice(), verified.source_envelope_id.as_slice()],
                |row| row.get::<_, Vec<u8>>(0),
            )
            .optional()?;
        if existing
            .as_ref()
            .is_some_and(|bytes| bytes != &verified.exact_bytes)
        {
            return Err(StoreError::Corrupt(
                "pending bridge Blob carrier identity maps to different exact bytes".into(),
            ));
        }
        let committed: Option<Vec<u8>> = self
            .connection
            .query_row(
                "SELECT source_envelope_id FROM bridge_blob_carrier_commits WHERE object_id=?1",
                params![key.as_slice()],
                |row| row.get(0),
            )
            .optional()?;
        if let Some(source) = committed {
            if source.as_slice() != verified.source_envelope_id {
                return Err(StoreError::Corrupt(
                    "committed bridge Blob carrier identity maps to another source".into(),
                ));
            }
            let storage_key = transfer_storage_key(verified.object_id);
            let has_transfer: i64 = self.connection.query_row(
                "SELECT EXISTS(SELECT 1 FROM transfer_identities WHERE storage_key=?1)",
                params![storage_key.as_slice()],
                |row| row.get(0),
            )?;
            if has_transfer != 0 {
                let transaction = self.connection.transaction()?;
                exact_typed_transfer_bytes_tx(
                    &transaction,
                    verified.object_id,
                    &verified.exact_bytes,
                )?;
                retire_typed_transfer_tx(&transaction, verified.object_id)?;
                transaction.commit()?;
            }
            return Ok(false);
        }
        let storage_key = transfer_storage_key(verified.object_id);
        let has_transfer: i64 = self.connection.query_row(
            "SELECT EXISTS(SELECT 1 FROM transfer_identities WHERE storage_key=?1)",
            params![storage_key.as_slice()],
            |row| row.get(0),
        )?;
        if has_transfer == 0 {
            return if existing.is_some() {
                Ok(false)
            } else {
                Err(StoreError::NotFound("typed bridge Blob carrier transfer"))
            };
        }
        let accounted_bytes = (verified.exact_bytes.len() as u64)
            .checked_add(160)
            .ok_or(StoreError::QuotaExceeded)?;
        let transaction = self.connection.transaction()?;
        exact_typed_transfer_bytes_tx(&transaction, verified.object_id, &verified.exact_bytes)?;
        let inserted = if existing.is_none() {
            ensure_bridge_admission(&transaction, &self.config, 1, accounted_bytes)?;
            let inserted_order = next_order(&transaction)?;
            transaction.execute(
                "INSERT INTO bridge_pending_blob_carriers(\n\
                   object_id,source_envelope_id,exact_bytes,inserted_order,accounted_bytes)\n\
                 VALUES(?1,?2,?3,?4,?5)",
                params![
                    key.as_slice(),
                    verified.source_envelope_id.as_slice(),
                    &verified.exact_bytes,
                    sql_u64(inserted_order, "pending bridge Blob carrier order")?,
                    sql_u64(accounted_bytes, "pending bridge Blob carrier bytes")?
                ],
            )?;
            true
        } else {
            false
        };
        retire_typed_transfer_tx(&transaction, verified.object_id)?;
        transaction.commit()?;
        Ok(inserted)
    }

    pub(crate) fn stored_pending_bridge_blob_carrier(
        &self,
        object_id: ObjectId,
        source_envelope_id: EnvelopeId,
    ) -> Result<Option<StoredPendingBridgeBlobCarrier>, StoreError> {
        let key = object_id.to_wire_bytes();
        let row = self
            .connection
            .query_row(
                "SELECT object_id,source_envelope_id,exact_bytes,inserted_order\n\
                 FROM bridge_pending_blob_carriers\n\
                 WHERE object_id=?1 AND source_envelope_id=?2",
                params![key.as_slice(), source_envelope_id.as_slice()],
                |row| {
                    Ok((
                        row.get::<_, Vec<u8>>(0)?,
                        row.get::<_, Vec<u8>>(1)?,
                        row.get::<_, Vec<u8>>(2)?,
                        row.get::<_, i64>(3)?,
                    ))
                },
            )
            .optional()?;
        row.map(|(object, source, exact_bytes, order)| {
            Ok(StoredPendingBridgeBlobCarrier {
                object_id: object_id_from_vec(object, "pending bridge Blob carrier")?,
                source_envelope_id: node_from_vec(source, "pending bridge Blob source")?,
                exact_bytes,
                inserted_order: from_sql_u64(order, "pending bridge Blob carrier order")?,
            })
        })
        .transpose()
    }

    pub(crate) fn pending_bridge_blob_carriers_after(
        &self,
        after_inserted_order: Option<u64>,
        limit: usize,
    ) -> Result<Vec<StoredPendingBridgeBlobCarrier>, StoreError> {
        let limit = limit.min(MAX_BRIDGE_STORE_BATCH);
        if limit == 0 {
            return Ok(Vec::new());
        }
        let rows = {
            let mut statement = self.connection.prepare(
                "SELECT object_id,source_envelope_id FROM bridge_pending_blob_carriers\n\
                 WHERE inserted_order>?1 ORDER BY inserted_order LIMIT ?2",
            )?;
            statement
                .query_map(
                    params![
                        sql_u64(
                            after_inserted_order.unwrap_or(0),
                            "pending bridge Blob cursor"
                        )?,
                        i64::try_from(limit).map_err(|_| StoreError::QuotaExceeded)?
                    ],
                    |row| Ok((row.get::<_, Vec<u8>>(0)?, row.get::<_, Vec<u8>>(1)?)),
                )?
                .collect::<Result<Vec<_>, _>>()?
        };
        rows.into_iter()
            .map(|(object, source)| {
                let object = object_id_from_vec(object, "pending bridge Blob carrier")?;
                let source = node_from_vec(source, "pending bridge Blob source")?;
                self.stored_pending_bridge_blob_carrier(object, source)?
                    .ok_or(StoreError::Corrupt(
                        "pending bridge Blob carrier disappeared".into(),
                    ))
            })
            .collect()
    }

    /// Idempotently discards only the exact private row rejected by the
    /// provider. A same-key/different-byte request fails as durable corruption.
    pub(crate) fn discard_rejected_pending_bridge_blob_carrier(
        &mut self,
        rejected: &VerifiedRejectedBridgeBlobCarrier,
    ) -> Result<bool, StoreError> {
        let existing = self
            .stored_pending_bridge_blob_carrier(rejected.object_id, rejected.source_envelope_id)?;
        let Some(existing) = existing else {
            return Ok(false);
        };
        if existing.exact_bytes != rejected.exact_bytes {
            return Err(StoreError::Corrupt(
                "rejected bridge Blob carrier differs from pending exact bytes".into(),
            ));
        }
        let encoded = rejected.object_id.to_wire_bytes();
        let deleted = self.connection.execute(
            "DELETE FROM bridge_pending_blob_carriers\n\
             WHERE object_id=?1 AND source_envelope_id=?2 AND exact_bytes=?3",
            params![
                encoded.as_slice(),
                rejected.source_envelope_id.as_slice(),
                &rejected.exact_bytes
            ],
        )?;
        if deleted != 1 {
            return Err(StoreError::Corrupt(
                "rejected bridge Blob carrier changed during discard".into(),
            ));
        }
        Ok(true)
    }

    /// Completes the SQLite side of the idempotent Blob-store handoff only
    /// after the caller has committed the exact carrier to `BlobTransferStore`.
    /// A crash before this step replays that external idempotent commit.
    pub(crate) fn complete_verified_bridge_blob_carrier_commit(
        &mut self,
        verified: &VerifiedBridgeBlobCarrierCommit,
        sample: Option<CustodySample>,
    ) -> Result<bool, StoreError> {
        if !self
            .verified_bridge_sources
            .contains(&verified.source_envelope_id)
            || !self.bridge_source_is_servable_at(&verified.source_envelope_id, sample)?
        {
            return Err(StoreError::BridgeDependencyMissing);
        }
        let source = self
            .stored_bridge_source(&verified.source_envelope_id)?
            .ok_or(StoreError::BridgeDependencyMissing)?;
        if source.metadata.class != DataClass::Blob {
            return Err(StoreError::Invalid(
                "bridge Blob carrier source is not a Blob manifest".into(),
            ));
        }
        let key = verified.object_id.to_wire_bytes();
        let pending = self
            .stored_pending_bridge_blob_carrier(verified.object_id, verified.source_envelope_id)?;
        let Some(pending) = pending else {
            let committed: i64 = self.connection.query_row(
                "SELECT EXISTS(SELECT 1 FROM bridge_blob_carrier_commits\n\
                 WHERE object_id=?1 AND source_envelope_id=?2)",
                params![key.as_slice(), verified.source_envelope_id.as_slice()],
                |row| row.get(0),
            )?;
            return if committed == 1 {
                Ok(false)
            } else {
                Err(StoreError::NotFound("pending bridge Blob carrier"))
            };
        };
        if pending.exact_bytes != verified.exact_bytes {
            return Err(StoreError::Corrupt(
                "pending bridge Blob carrier differs from route-verified bytes".into(),
            ));
        }
        let transaction = self.connection.transaction()?;
        let deleted = transaction.execute(
            "DELETE FROM bridge_pending_blob_carriers\n\
             WHERE object_id=?1 AND source_envelope_id=?2 AND exact_bytes=?3",
            params![
                key.as_slice(),
                verified.source_envelope_id.as_slice(),
                &verified.exact_bytes
            ],
        )?;
        if deleted != 1 {
            return Err(StoreError::Corrupt(
                "pending bridge Blob carrier changed during commit".into(),
            ));
        }
        let committed_order = next_order(&transaction)?;
        transaction.execute(
            "INSERT INTO bridge_blob_carrier_commits(\n\
               object_id,source_envelope_id,committed_order,accounted_bytes)\n\
             VALUES(?1,?2,?3,96)",
            params![
                key.as_slice(),
                verified.source_envelope_id.as_slice(),
                sql_u64(committed_order, "bridge Blob carrier commit order")?
            ],
        )?;
        transaction.commit()?;
        Ok(true)
    }

    /// Non-mutating durable receipt filter for Blob carrier object IDs on one
    /// exact peer/source/wrapper path. Candidate IDs come from BlobTransferStore.
    pub(crate) fn filter_unacknowledged_bridge_blob_carriers(
        &self,
        peer: NodeId,
        wrapper_envelope_id: EnvelopeId,
        source_envelope_id: EnvelopeId,
        candidates: &[ObjectId],
        limit: usize,
        sample: Option<CustodySample>,
    ) -> Result<Vec<ObjectId>, StoreError> {
        if candidates.len() > MAX_BRIDGE_STORE_BATCH {
            return Err(StoreError::Invalid(
                "bridge Blob carrier candidate batch exceeds bound".into(),
            ));
        }
        let limit = limit.min(MAX_BRIDGE_STORE_BATCH);
        if limit == 0 || !self.bridge_route_is_live_at(&wrapper_envelope_id, sample)? {
            return Ok(Vec::new());
        }
        let route = self
            .stored_bridge_route(&wrapper_envelope_id)?
            .ok_or(StoreError::NotFound("active bridge Blob route"))?;
        if route.origin_envelope_id != source_envelope_id {
            return Err(StoreError::Invalid(
                "bridge Blob receipt path does not match route source".into(),
            ));
        }
        let mut unacknowledged = Vec::new();
        for object_id in candidates {
            if object_id.kind() != ObjectKind::BlobChunk {
                return Err(StoreError::Invalid(
                    "bridge Blob receipt candidate has wrong object kind".into(),
                ));
            }
            let encoded = object_id.to_wire_bytes();
            let acknowledged: i64 = self.connection.query_row(
                "SELECT EXISTS(SELECT 1 FROM bridge_blob_carrier_peer_possessions\n\
                   WHERE peer=?1 AND source_envelope_id=?3 AND object_id=?4)\n\
                 OR EXISTS(SELECT 1 FROM bridge_blob_carrier_peer_receipts\n\
                   WHERE peer=?1 AND wrapper_envelope_id=?2 AND source_envelope_id=?3\n\
                     AND object_id=?4)",
                params![
                    peer.as_slice(),
                    wrapper_envelope_id.as_slice(),
                    source_envelope_id.as_slice(),
                    encoded.as_slice()
                ],
                |row| row.get(0),
            )?;
            if acknowledged == 0 {
                unacknowledged.push(*object_id);
                if unacknowledged.len() == limit {
                    break;
                }
            }
        }
        Ok(unacknowledged)
    }

    pub(crate) fn filter_unacknowledged_bridge_routes(
        &self,
        peer: NodeId,
        candidates: &[EnvelopeId],
        limit: usize,
    ) -> Result<Vec<EnvelopeId>, StoreError> {
        if candidates.len() > MAX_BRIDGE_STORE_BATCH {
            return Err(StoreError::Invalid(
                "bridge route receipt candidate batch exceeds bound".into(),
            ));
        }
        let limit = limit.min(MAX_BRIDGE_STORE_BATCH);
        if limit == 0 {
            return Ok(Vec::new());
        }
        let mut selected = Vec::new();
        for candidate in candidates {
            let acknowledged: i64 = self.connection.query_row(
                "SELECT EXISTS(SELECT 1 FROM bridge_route_peer_receipts\n\
                 WHERE peer=?1 AND wrapper_envelope_id=?2)",
                params![peer.as_slice(), candidate.as_slice()],
                |row| row.get(0),
            )?;
            if acknowledged == 0 {
                selected.push(*candidate);
                if selected.len() == limit {
                    break;
                }
            }
        }
        Ok(selected)
    }

    pub(crate) fn filter_unacknowledged_bridge_authorizations(
        &self,
        peer: NodeId,
        candidates: &[EnvelopeId],
        limit: usize,
    ) -> Result<Vec<EnvelopeId>, StoreError> {
        if candidates.len() > MAX_BRIDGE_STORE_BATCH {
            return Err(StoreError::Invalid(
                "bridge authorization receipt candidate batch exceeds bound".into(),
            ));
        }
        let limit = limit.min(MAX_BRIDGE_STORE_BATCH);
        if limit == 0 {
            return Ok(Vec::new());
        }
        let mut selected = Vec::new();
        for candidate in candidates {
            let acknowledged: i64 = self.connection.query_row(
                "SELECT EXISTS(SELECT 1 FROM bridge_authorization_peer_receipts\n\
                 WHERE peer=?1 AND envelope_id=?2)",
                params![peer.as_slice(), candidate.as_slice()],
                |row| row.get(0),
            )?;
            if acknowledged == 0 {
                selected.push(*candidate);
                if selected.len() == limit {
                    break;
                }
            }
        }
        Ok(selected)
    }

    pub(crate) fn filter_unacknowledged_bridge_sources_for_path(
        &self,
        peer: NodeId,
        wrapper_envelope_id: EnvelopeId,
        candidates: &[EnvelopeId],
        limit: usize,
    ) -> Result<Vec<EnvelopeId>, StoreError> {
        if candidates.len() > MAX_BRIDGE_STORE_BATCH {
            return Err(StoreError::Invalid(
                "bridge source receipt candidate batch exceeds bound".into(),
            ));
        }
        let limit = limit.min(MAX_BRIDGE_STORE_BATCH);
        if limit == 0 {
            return Ok(Vec::new());
        }
        let route = self
            .stored_bridge_route(&wrapper_envelope_id)?
            .ok_or(StoreError::NotFound("bridge source receipt path"))?;
        let mut selected = Vec::new();
        for candidate in candidates {
            if candidate != &route.origin_envelope_id {
                return Err(StoreError::Invalid(
                    "bridge source receipt candidate does not match path".into(),
                ));
            }
            let acknowledged: i64 = self.connection.query_row(
                "SELECT EXISTS(SELECT 1 FROM bridge_source_peer_receipts\n\
                   WHERE peer=?1 AND origin_envelope_id=?3)\n\
                 OR EXISTS(SELECT 1 FROM bridge_source_path_peer_receipts\n\
                   WHERE peer=?1 AND wrapper_envelope_id=?2 AND origin_envelope_id=?3)",
                params![
                    peer.as_slice(),
                    wrapper_envelope_id.as_slice(),
                    candidate.as_slice()
                ],
                |row| row.get(0),
            )?;
            if acknowledged == 0 {
                selected.push(*candidate);
                if selected.len() == limit {
                    break;
                }
            }
        }
        Ok(selected)
    }

    pub(crate) fn acknowledge_bridge_blob_carrier_peer(
        &mut self,
        peer: NodeId,
        wrapper_envelope_id: EnvelopeId,
        source_envelope_id: EnvelopeId,
        object_ids: &[ObjectId],
        now_ms: Option<u64>,
        sample: Option<CustodySample>,
    ) -> Result<(), StoreError> {
        if object_ids.len() > MAX_BRIDGE_STORE_BATCH {
            return Err(StoreError::Invalid(
                "bridge Blob carrier receipt batch exceeds bound".into(),
            ));
        }
        if !self.bridge_route_is_live_at(&wrapper_envelope_id, sample)? {
            return Err(StoreError::NotFound("active bridge Blob route"));
        }
        let route = self
            .stored_bridge_route(&wrapper_envelope_id)?
            .ok_or(StoreError::NotFound("active bridge Blob route"))?;
        if route.origin_envelope_id != source_envelope_id {
            return Err(StoreError::Invalid(
                "bridge Blob receipt path does not match route source".into(),
            ));
        }
        if object_ids
            .iter()
            .any(|object_id| object_id.kind() != ObjectKind::BlobChunk)
        {
            return Err(StoreError::Invalid(
                "bridge Blob receipt has wrong object kind".into(),
            ));
        }
        let acknowledged_at_ms = now_ms
            .map(|value| sql_u64(value, "bridge Blob acknowledgement time"))
            .transpose()?;
        let transaction = self.connection.transaction()?;
        for object_id in object_ids {
            let encoded = object_id.to_wire_bytes();
            transaction.execute(
                "INSERT INTO bridge_blob_carrier_peer_possessions(\n\
                   peer,source_envelope_id,object_id,acknowledged_at_ms)\n\
                 VALUES(?1,?2,?3,?4)\n\
                 ON CONFLICT(peer,source_envelope_id,object_id) DO UPDATE SET\n\
                   acknowledged_at_ms=excluded.acknowledged_at_ms",
                params![
                    peer.as_slice(),
                    source_envelope_id.as_slice(),
                    encoded.as_slice(),
                    acknowledged_at_ms
                ],
            )?;
            transaction.execute(
                "INSERT INTO bridge_blob_carrier_peer_receipts(\n\
                   peer,wrapper_envelope_id,source_envelope_id,object_id,acknowledged_at_ms)\n\
                 VALUES(?1,?2,?3,?4,?5)\n\
                 ON CONFLICT(peer,wrapper_envelope_id,source_envelope_id,object_id) DO UPDATE SET\n\
                   acknowledged_at_ms=excluded.acknowledged_at_ms",
                params![
                    peer.as_slice(),
                    wrapper_envelope_id.as_slice(),
                    source_envelope_id.as_slice(),
                    encoded.as_slice(),
                    acknowledged_at_ms
                ],
            )?;
        }
        transaction.commit()?;
        Ok(())
    }

    /// Establishes a bridge-only reference to an already accepted ordinary
    /// source representation. The exact bytes remain owned by `items`; this
    /// record charges only bridge metadata and holds a restrictive foreign-key
    /// reference so ordinary GC cannot remove shared bytes prematurely.
    pub(crate) fn establish_verified_bridge_source_from_item(
        &mut self,
        verified: &VerifiedBridgeSource,
    ) -> Result<bool, StoreError> {
        self.establish_verified_bridge_source_from_item_at(verified, None)
    }

    pub(crate) fn establish_verified_bridge_source_from_item_at(
        &mut self,
        verified: &VerifiedBridgeSource,
        sample: Option<CustodySample>,
    ) -> Result<bool, StoreError> {
        if !self.bridge_source_has_verified_reference(verified)? {
            return Err(StoreError::BridgeDependencyMissing);
        }
        let item = self
            .ordinary_item_for_bridge_source(verified)?
            .ok_or(StoreError::NotFound("exact ordinary bridge source"))?;
        let source_custody = ordinary_item_bridge_custody(&item, sample);
        let pending = self.stored_pending_bridge_source(&verified.origin_envelope_id)?;
        let committed = self.stored_bridge_source(&verified.origin_envelope_id)?;
        let unresolved = self.stored_unresolved_bridge_source(&verified.origin_envelope_id)?;
        for source in pending.iter().chain(committed.iter()) {
            if source.metadata != verified.metadata || source.exact_bytes != verified.exact_bytes {
                return Err(StoreError::Corrupt(
                    "bridge source identity maps to different exact content".into(),
                ));
            }
        }
        if unresolved
            .as_ref()
            .is_some_and(|source| source.exact_bytes != verified.exact_bytes)
        {
            return Err(StoreError::Corrupt(
                "unresolved bridge source identity maps to different exact content".into(),
            ));
        }
        let already_reused: Option<Vec<u8>> = self
            .connection
            .query_row(
                "SELECT reused_item_id FROM bridge_source_objects\n\
                 WHERE origin_envelope_id=?1 AND reused_item_id IS NOT NULL",
                params![verified.origin_envelope_id.as_slice()],
                |row| row.get(0),
            )
            .optional()?;
        if let Some(reused) = already_reused
            && reused.as_slice() != item.id.as_slice()
        {
            return Err(StoreError::Corrupt(
                "bridge source references a different ordinary item".into(),
            ));
        }
        let metadata_bytes = bridge_source_metadata_accounted_bytes(verified)?;
        let insertion_order = pending
            .as_ref()
            .map(|source| source.inserted_order)
            .or_else(|| unresolved.as_ref().map(|source| source.inserted_order));
        let forwarding_age = verified
            .authenticated_forwarding_age_ms
            .max(source_custody.0)
            .max(
                pending
                    .as_ref()
                    .map(|source| source.authenticated_forwarding_age_ms)
                    .unwrap_or(0),
            )
            .max(
                committed
                    .as_ref()
                    .map(|source| source.authenticated_forwarding_age_ms)
                    .unwrap_or(0),
            )
            .max(
                unresolved
                    .as_ref()
                    .map(|source| source.authenticated_forwarding_age_ms)
                    .unwrap_or(0),
            );
        let transaction = self.connection.transaction()?;
        accept_bridge_source_semantics_tx(&transaction, verified)?;
        transaction.execute(
            "DELETE FROM bridge_unresolved_sources WHERE origin_envelope_id=?1",
            params![verified.origin_envelope_id.as_slice()],
        )?;
        transaction.execute(
            "DELETE FROM bridge_pending_sources WHERE origin_envelope_id=?1",
            params![verified.origin_envelope_id.as_slice()],
        )?;
        let inserted = if committed.is_some() {
            transaction.execute(
                "UPDATE bridge_source_objects SET exact_bytes=x'00',reused_item_id=?1,\n\
                   accounted_bytes=?2,forwarding_custody_age_ms=max(\n\
                     forwarding_custody_age_ms,?3),cumulative_custody_age_ms=max(\n\
                     cumulative_custody_age_ms,?4),source_age_continuity_unknown=?5,\n\
                   source_custody_clock_id=?6,source_custody_tick_ms=?7,\n\
                   source_custody_elapsed_available=?8 WHERE origin_envelope_id=?9",
                params![
                    item.id.as_slice(),
                    sql_u64(metadata_bytes, "shared bridge source metadata bytes")?,
                    sql_u64(forwarding_age, "shared bridge source forwarding age")?,
                    sql_u64(source_custody.0, "shared bridge source custody age")?,
                    i64::from(source_custody.1),
                    source_custody.2.map(|value| value.to_vec()),
                    source_custody
                        .3
                        .map(|value| sql_u64(value, "shared bridge source custody tick"))
                        .transpose()?,
                    i64::from(source_custody.4),
                    verified.origin_envelope_id.as_slice()
                ],
            )? == 0
        } else {
            ensure_bridge_admission(&transaction, &self.config, 1, metadata_bytes)?;
            true
        };
        if inserted {
            insert_reused_bridge_source_tx(
                &transaction,
                verified,
                item.id,
                insertion_order,
                forwarding_age,
                metadata_bytes,
                source_custody,
            )?;
        }
        transaction.commit()?;
        self.verified_bridge_sources
            .insert(verified.origin_envelope_id);
        Ok(inserted)
    }

    fn ordinary_item_for_bridge_source(
        &self,
        verified: &VerifiedBridgeSource,
    ) -> Result<Option<StoredItem>, StoreError> {
        let sql = format!("SELECT {ITEM_COLUMNS} FROM items WHERE envelope_id=?1");
        let item = self
            .connection
            .query_row(
                &sql,
                params![verified.origin_envelope_id.as_slice()],
                decode_item_row,
            )
            .optional()?;
        let Some(item) = item else { return Ok(None) };
        let metadata = &verified.metadata;
        if item.id != metadata.source_item_id
            || item.envelope_id != verified.origin_envelope_id
            || item.sealed != verified.exact_bytes
            || item.class != metadata.class
            || item.topic != metadata.topic
            || item.scope != metadata.origin_scope
            || item.priority != metadata.priority
            || item.stamp != metadata.stamp
            || item.event_sequence != metadata.event_sequence
            || item.logical_key != metadata.logical_key
            || item.ttl_ms != metadata.ttl_ms
            || item.content_len != metadata.content_len
            || item.tombstone != metadata.tombstone
            || item.key_epoch != metadata.origin_route_epoch
        {
            return Err(StoreError::Invalid(
                "ordinary item does not exactly match provider-verified bridge source".into(),
            ));
        }
        Ok(Some(item))
    }

    /// Stages an exact, provider-authenticated source carrier only when a
    /// process-reverified wrapper already names it. Unsolicited carriers are
    /// rejected before quota or durable state changes.
    pub(crate) fn stage_verified_bridge_source(
        &mut self,
        verified: &VerifiedBridgeSource,
    ) -> Result<bool, StoreError> {
        self.stage_verified_bridge_source_at(verified, None)
    }

    pub(crate) fn stage_verified_bridge_source_at(
        &mut self,
        verified: &VerifiedBridgeSource,
        sample: Option<CustodySample>,
    ) -> Result<bool, StoreError> {
        let metadata = &verified.metadata;
        let pending_references = {
            let mut statement = self.connection.prepare(
                "SELECT wrapper_envelope_id FROM bridge_pending_wrappers\n\
                 WHERE origin_envelope_id=?1 AND source_item_id=?2\n\
                   AND origin_scope=?3 AND origin_route_epoch=?4",
            )?;
            statement
                .query_map(
                    params![
                        verified.origin_envelope_id.as_slice(),
                        metadata.source_item_id.as_slice(),
                        metadata.origin_scope.as_str(),
                        sql_u64(metadata.origin_route_epoch, "bridge source origin epoch")?
                    ],
                    |row| row.get::<_, Vec<u8>>(0),
                )?
                .collect::<Result<Vec<_>, _>>()?
        };
        let pending_verified = pending_references.into_iter().try_fold(
            false,
            |found, value| -> Result<bool, StoreError> {
                let id = node_from_vec(value, "pending source wrapper reference")?;
                Ok(found || self.verified_pending_bridge_wrappers.contains(&id))
            },
        )?;
        let committed_references = {
            let mut statement = self.connection.prepare(
                "SELECT wrapper_envelope_id FROM bridge_route_wrappers\n\
                 WHERE origin_envelope_id=?1 AND source_item_id=?2 AND source_publisher=?3\n\
                   AND origin_scope=?4 AND origin_route_epoch=?5",
            )?;
            statement
                .query_map(
                    params![
                        verified.origin_envelope_id.as_slice(),
                        metadata.source_item_id.as_slice(),
                        metadata.stamp.dot.publisher.as_slice(),
                        metadata.origin_scope.as_str(),
                        sql_u64(metadata.origin_route_epoch, "bridge source origin epoch")?
                    ],
                    |row| row.get::<_, Vec<u8>>(0),
                )?
                .collect::<Result<Vec<_>, _>>()?
        };
        let committed_verified = committed_references.into_iter().try_fold(
            false,
            |found, value| -> Result<bool, StoreError> {
                let id = node_from_vec(value, "committed source wrapper reference")?;
                Ok(found || self.verified_bridge_routes.contains(&id))
            },
        )?;
        if !pending_verified && !committed_verified {
            return Err(StoreError::BridgeDependencyMissing);
        }
        if self.ordinary_item_for_bridge_source(verified)?.is_some() {
            return self.establish_verified_bridge_source_from_item_at(verified, sample);
        }
        if let Some(unresolved) =
            self.stored_unresolved_bridge_source(&verified.origin_envelope_id)?
        {
            if unresolved.exact_bytes != verified.exact_bytes {
                return Err(StoreError::Corrupt(
                    "unresolved bridge source identity maps to different exact content".into(),
                ));
            }
            if self
                .stored_pending_bridge_source(&verified.origin_envelope_id)?
                .is_some()
                || self
                    .stored_bridge_source(&verified.origin_envelope_id)?
                    .is_some()
            {
                return Err(StoreError::Corrupt(
                    "bridge source exists in unresolved and resolved state".into(),
                ));
            }
            let transaction = self.connection.transaction()?;
            let deleted = transaction.execute(
                "DELETE FROM bridge_unresolved_sources\n\
                 WHERE origin_envelope_id=?1 AND exact_bytes=?2",
                params![
                    verified.origin_envelope_id.as_slice(),
                    &verified.exact_bytes
                ],
            )?;
            if deleted != 1 {
                return Err(StoreError::Corrupt(
                    "unresolved bridge source changed during promotion".into(),
                ));
            }
            insert_pending_bridge_source_tx(
                &transaction,
                &self.config,
                verified,
                Some(&unresolved),
                sample,
            )?;
            transaction.commit()?;
            self.verified_bridge_sources
                .insert(verified.origin_envelope_id);
            return Ok(true);
        }
        if let Some(existing) = self.stored_pending_bridge_source(&verified.origin_envelope_id)? {
            if existing.metadata != verified.metadata
                || existing.exact_bytes != verified.exact_bytes
            {
                return Err(StoreError::Corrupt(
                    "pending bridge source identity maps to different exact content".into(),
                ));
            }
            let transaction = self.connection.transaction()?;
            merge_bridge_forwarding_age_tx(
                &transaction,
                verified.origin_envelope_id,
                verified.authenticated_forwarding_age_ms,
            )?;
            checkpoint_existing_bridge_source_tx(
                &transaction,
                &existing,
                verified.authenticated_forwarding_age_ms,
                sample,
            )?;
            transaction.commit()?;
            self.verified_bridge_sources
                .insert(verified.origin_envelope_id);
            return Ok(false);
        }
        if let Some(existing) = self.stored_bridge_source(&verified.origin_envelope_id)? {
            if existing.metadata != verified.metadata
                || existing.exact_bytes != verified.exact_bytes
            {
                return Err(StoreError::Corrupt(
                    "bridge source identity maps to different exact content".into(),
                ));
            }
            let transaction = self.connection.transaction()?;
            merge_bridge_forwarding_age_tx(
                &transaction,
                verified.origin_envelope_id,
                verified.authenticated_forwarding_age_ms,
            )?;
            checkpoint_existing_bridge_source_tx(
                &transaction,
                &existing,
                verified.authenticated_forwarding_age_ms,
                sample,
            )?;
            transaction.commit()?;
            self.verified_bridge_sources
                .insert(verified.origin_envelope_id);
            return Ok(false);
        }
        let transaction = self.connection.transaction()?;
        insert_pending_bridge_source_tx(&transaction, &self.config, verified, None, sample)?;
        transaction.commit()?;
        self.verified_bridge_sources
            .insert(verified.origin_envelope_id);
        Ok(true)
    }

    fn bridge_source_has_verified_reference(
        &self,
        verified: &VerifiedBridgeSource,
    ) -> Result<bool, StoreError> {
        let metadata = &verified.metadata;
        let rows = {
            let mut statement = self.connection.prepare(
                "SELECT wrapper_envelope_id,0 FROM bridge_pending_wrappers\n\
                 WHERE origin_envelope_id=?1 AND source_item_id=?2\n\
                   AND origin_scope=?3 AND origin_route_epoch=?4\n\
                 UNION ALL\n\
                 SELECT wrapper_envelope_id,1 FROM bridge_route_wrappers\n\
                 WHERE origin_envelope_id=?1 AND source_item_id=?2 AND source_publisher=?5\n\
                   AND origin_scope=?3 AND origin_route_epoch=?4",
            )?;
            statement
                .query_map(
                    params![
                        verified.origin_envelope_id.as_slice(),
                        metadata.source_item_id.as_slice(),
                        metadata.origin_scope.as_str(),
                        sql_u64(metadata.origin_route_epoch, "bridge source origin epoch")?,
                        metadata.stamp.dot.publisher.as_slice()
                    ],
                    |row| Ok((row.get::<_, Vec<u8>>(0)?, row.get::<_, i64>(1)?)),
                )?
                .collect::<Result<Vec<_>, _>>()?
        };
        for (id, committed) in rows {
            let id = node_from_vec(id, "bridge source wrapper reference")?;
            if (committed == 0 && self.verified_pending_bridge_wrappers.contains(&id))
                || (committed == 1 && self.verified_bridge_routes.contains(&id))
            {
                return Ok(true);
            }
        }
        Ok(false)
    }

    /// Atomically converts a complete typed source transfer into private
    /// referenced-source state. No ordinary item, inventory, or outbox row is
    /// created by this operation.
    pub(crate) fn defer_verified_bridge_source_transfer(
        &mut self,
        verified: &VerifiedBridgeSource,
        sample: Option<CustodySample>,
    ) -> Result<bool, StoreError> {
        if !self.bridge_source_has_verified_reference(verified)? {
            return Err(StoreError::BridgeDependencyMissing);
        }
        if let Some(unresolved) =
            self.stored_unresolved_bridge_source(&verified.origin_envelope_id)?
        {
            if unresolved.exact_bytes != verified.exact_bytes {
                return Err(StoreError::Corrupt(
                    "unresolved bridge source identity maps to different exact content".into(),
                ));
            }
            let object_id = ObjectId::new(ObjectKind::SourceEnvelope, verified.origin_envelope_id);
            let storage_key = transfer_storage_key(object_id);
            let has_transfer: i64 = self.connection.query_row(
                "SELECT EXISTS(SELECT 1 FROM transfer_identities WHERE storage_key=?1)",
                params![storage_key.as_slice()],
                |row| row.get(0),
            )?;
            let transaction = self.connection.transaction()?;
            if has_transfer != 0 {
                exact_typed_transfer_bytes_tx(&transaction, object_id, &verified.exact_bytes)?;
            }
            let deleted = transaction.execute(
                "DELETE FROM bridge_unresolved_sources\n\
                 WHERE origin_envelope_id=?1 AND exact_bytes=?2",
                params![
                    verified.origin_envelope_id.as_slice(),
                    &verified.exact_bytes
                ],
            )?;
            if deleted != 1 {
                return Err(StoreError::Corrupt(
                    "unresolved bridge source changed during promotion".into(),
                ));
            }
            insert_pending_bridge_source_tx(
                &transaction,
                &self.config,
                verified,
                Some(&unresolved),
                sample,
            )?;
            if has_transfer != 0 {
                retire_typed_transfer_tx(&transaction, object_id)?;
            }
            transaction.commit()?;
            self.verified_bridge_sources
                .insert(verified.origin_envelope_id);
            return Ok(true);
        }
        let pending = self.stored_pending_bridge_source(&verified.origin_envelope_id)?;
        let committed = self.stored_bridge_source(&verified.origin_envelope_id)?;
        if pending.is_some() && committed.is_some() {
            return Err(StoreError::Corrupt(
                "bridge source exists in committed and pending state".into(),
            ));
        }
        for source in pending.iter().chain(committed.iter()) {
            if source.metadata != verified.metadata || source.exact_bytes != verified.exact_bytes {
                return Err(StoreError::Corrupt(
                    "bridge source identity maps to different exact content".into(),
                ));
            }
        }
        let object_id = ObjectId::new(ObjectKind::SourceEnvelope, verified.origin_envelope_id);
        let storage_key = transfer_storage_key(object_id);
        let has_transfer: i64 = self.connection.query_row(
            "SELECT EXISTS(SELECT 1 FROM transfer_identities WHERE storage_key=?1)",
            params![storage_key.as_slice()],
            |row| row.get(0),
        )?;
        if has_transfer == 0 {
            if pending.is_none() && committed.is_none() {
                return Err(StoreError::NotFound("typed bridge source transfer"));
            }
            let transaction = self.connection.transaction()?;
            merge_bridge_forwarding_age_tx(
                &transaction,
                verified.origin_envelope_id,
                verified.authenticated_forwarding_age_ms,
            )?;
            let source = pending
                .as_ref()
                .or(committed.as_ref())
                .ok_or(StoreError::Corrupt(
                    "bridge source state disappeared during deferral".into(),
                ))?;
            checkpoint_existing_bridge_source_tx(
                &transaction,
                source,
                verified.authenticated_forwarding_age_ms,
                sample,
            )?;
            transaction.commit()?;
            self.verified_bridge_sources
                .insert(verified.origin_envelope_id);
            return Ok(false);
        }
        let transaction = self.connection.transaction()?;
        exact_typed_transfer_bytes_tx(&transaction, object_id, &verified.exact_bytes)?;
        if pending.is_none() && committed.is_none() {
            insert_pending_bridge_source_tx(&transaction, &self.config, verified, None, sample)?;
        } else {
            merge_bridge_forwarding_age_tx(
                &transaction,
                verified.origin_envelope_id,
                verified.authenticated_forwarding_age_ms,
            )?;
            let source = pending
                .as_ref()
                .or(committed.as_ref())
                .ok_or(StoreError::Corrupt(
                    "bridge source state disappeared during deferral".into(),
                ))?;
            checkpoint_existing_bridge_source_tx(
                &transaction,
                source,
                verified.authenticated_forwarding_age_ms,
                sample,
            )?;
        }
        retire_typed_transfer_tx(&transaction, object_id)?;
        transaction.commit()?;
        self.verified_bridge_sources
            .insert(verified.origin_envelope_id);
        Ok(pending.is_none() && committed.is_none())
    }

    pub(crate) fn stored_pending_bridge_source(
        &self,
        origin_envelope_id: &EnvelopeId,
    ) -> Result<Option<StoredBridgeSource>, StoreError> {
        self.connection
            .query_row(
                &bridge_source_select("bridge_pending_sources"),
                params![origin_envelope_id.as_slice()],
                decode_bridge_source_row,
            )
            .optional()
            .map_err(StoreError::from)
    }

    pub(crate) fn stored_bridge_source(
        &self,
        origin_envelope_id: &EnvelopeId,
    ) -> Result<Option<StoredBridgeSource>, StoreError> {
        let reused_item_id: Option<Option<Vec<u8>>> = self
            .connection
            .query_row(
                "SELECT reused_item_id FROM bridge_source_objects WHERE origin_envelope_id=?1",
                params![origin_envelope_id.as_slice()],
                |row| row.get(0),
            )
            .optional()?;
        let Some(reused_item_id) = reused_item_id else {
            return Ok(None);
        };
        let exact_override = if let Some(item_id) = reused_item_id {
            let item_id = item_from_vec(item_id, "reused bridge source item")?;
            let sql = format!("SELECT {ITEM_COLUMNS} FROM items WHERE item_id=?1");
            let item = self
                .connection
                .query_row(&sql, params![item_id.as_slice()], decode_item_row)
                .optional()?
                .ok_or(StoreError::Corrupt(
                    "reused bridge source item disappeared".into(),
                ))?;
            if item.envelope_id != *origin_envelope_id {
                return Err(StoreError::Corrupt(
                    "reused bridge source points to a different exact envelope".into(),
                ));
            }
            Some(item.sealed)
        } else {
            None
        };
        let sql = if exact_override.is_some() {
            bridge_source_select_with_exact("bridge_source_objects", "?2")
        } else {
            bridge_source_select("bridge_source_objects")
        };
        let source = if let Some(exact_bytes) = exact_override {
            self.connection
                .query_row(
                    &sql,
                    params![origin_envelope_id.as_slice(), exact_bytes],
                    decode_bridge_source_row,
                )
                .optional()?
        } else {
            self.connection
                .query_row(
                    &sql,
                    params![origin_envelope_id.as_slice()],
                    decode_bridge_source_row,
                )
                .optional()?
        };
        Ok(source)
    }

    /// Bounded restart reload of committed bridge-only source carriers. This
    /// read has no inventory, application, or liveness side effects.
    pub(crate) fn stored_bridge_sources(
        &self,
        limit: usize,
    ) -> Result<Vec<StoredBridgeSource>, StoreError> {
        self.stored_bridge_sources_after(None, limit)
    }

    pub(crate) fn stored_bridge_sources_after(
        &self,
        after_inserted_order: Option<u64>,
        limit: usize,
    ) -> Result<Vec<StoredBridgeSource>, StoreError> {
        let limit = limit.min(MAX_BRIDGE_STORE_BATCH);
        if limit == 0 {
            return Ok(Vec::new());
        }
        let ids = {
            let mut statement = self.connection.prepare(
                "SELECT origin_envelope_id FROM bridge_source_objects\n\
                 WHERE source_publisher IS NOT NULL AND data_class IS NOT NULL\n\
                   AND source_topic IS NOT NULL AND source_priority IS NOT NULL\n\
                   AND causal_counter IS NOT NULL AND causal_context IS NOT NULL\n\
                   AND logical_key IS NOT NULL AND content_len IS NOT NULL\n\
                   AND tombstone IS NOT NULL AND origin_scope IS NOT NULL\n\
                   AND origin_route_epoch IS NOT NULL\n\
                   AND forwarding_custody_age_ms IS NOT NULL\n\
                   AND inserted_order>?1\n\
                 ORDER BY inserted_order LIMIT ?2",
            )?;
            statement
                .query_map(
                    params![
                        sql_u64(
                            after_inserted_order.unwrap_or(0),
                            "stored bridge source cursor"
                        )?,
                        i64::try_from(limit).map_err(|_| StoreError::QuotaExceeded)?
                    ],
                    |row| row.get::<_, Vec<u8>>(0),
                )?
                .collect::<Result<Vec<_>, _>>()?
        };
        ids.into_iter()
            .map(|id| {
                let id = node_from_vec(id, "stored bridge source")?;
                self.stored_bridge_source(&id)?.ok_or(StoreError::Corrupt(
                    "stored bridge source disappeared".into(),
                ))
            })
            .collect()
    }

    /// Bounded restart reload of private source dependencies. Reload alone
    /// never makes a source eligible for promotion or serving.
    pub(crate) fn pending_bridge_sources(
        &self,
        limit: usize,
    ) -> Result<Vec<StoredBridgeSource>, StoreError> {
        self.pending_bridge_sources_after(None, limit)
    }

    pub(crate) fn pending_bridge_sources_after(
        &self,
        after_inserted_order: Option<u64>,
        limit: usize,
    ) -> Result<Vec<StoredBridgeSource>, StoreError> {
        let limit = limit.min(MAX_BRIDGE_STORE_BATCH);
        if limit == 0 {
            return Ok(Vec::new());
        }
        let ids = {
            let mut statement = self.connection.prepare(
                "SELECT origin_envelope_id FROM bridge_pending_sources\n\
                 WHERE inserted_order>?1 ORDER BY inserted_order LIMIT ?2",
            )?;
            statement
                .query_map(
                    params![
                        sql_u64(
                            after_inserted_order.unwrap_or(0),
                            "pending bridge source cursor"
                        )?,
                        i64::try_from(limit).map_err(|_| StoreError::QuotaExceeded)?
                    ],
                    |row| row.get::<_, Vec<u8>>(0),
                )?
                .collect::<Result<Vec<_>, _>>()?
        };
        ids.into_iter()
            .map(|id| {
                let id = node_from_vec(id, "pending bridge source")?;
                self.stored_pending_bridge_source(&id)?
                    .ok_or(StoreError::Corrupt(
                        "pending bridge source disappeared".into(),
                    ))
            })
            .collect()
    }

    pub(crate) fn verified_bridge_route_readiness(
        &self,
        verified: &VerifiedBridgeRoute,
    ) -> Result<BridgeRouteReadiness, StoreError> {
        match self.validate_live_bridge_route(verified) {
            Ok(()) => Ok(BridgeRouteReadiness::Eligible),
            Err(StoreError::BridgeDependencyMissing) => Ok(BridgeRouteReadiness::MissingDependency),
            Err(StoreError::BridgeRouteIneligible) => Ok(BridgeRouteReadiness::Ineligible),
            Err(error) => Err(error),
        }
    }

    fn validate_live_bridge_route(&self, verified: &VerifiedBridgeRoute) -> Result<(), StoreError> {
        let hop_count = verified.route.hops.len();
        let mut authorization_records = BTreeMap::new();
        let mut active_authorization_ids = BTreeMap::new();
        let last_hop = verified
            .route
            .hops
            .last()
            .ok_or(StoreError::BridgeDependencyMissing)?;
        let authenticated_age = last_hop
            .cumulative_custody_age_ms
            .max(verified.authenticated_forwarding_age_ms)
            .max(verified.source.authenticated_forwarding_age_ms);
        if !verified.source.metadata.tombstone
            && ((verified.source.metadata.ttl_ms.is_some() && last_hop.age_continuity_unknown)
                || verified
                    .source
                    .metadata
                    .ttl_ms
                    .is_some_and(|ttl| authenticated_age >= ttl))
        {
            return Err(StoreError::BridgeRouteIneligible);
        }
        let source_revoked: i64 = self.connection.query_row(
            "SELECT EXISTS(SELECT 1 FROM revocations WHERE subject=?1)",
            params![verified.source.metadata.stamp.dot.publisher.as_slice()],
            |row| row.get(0),
        )?;
        if source_revoked != 0 {
            return Err(StoreError::BridgeRouteIneligible);
        }
        for hop in &verified.route.hops {
            let stored = self
                .stored_bridge_authorization(&hop.authorization_envelope_id)?
                .ok_or(StoreError::BridgeDependencyMissing)?;
            if !stored.applied
                || !self
                    .verified_bridge_authorizations
                    .contains(&hop.authorization_envelope_id)
            {
                return Err(StoreError::BridgeDependencyMissing);
            }
            if !self.bridge_authorization_is_live(&hop.authorization_envelope_id)? {
                return Err(StoreError::BridgeRouteIneligible);
            }
            let control_signer = stored.control_signer;
            let authorization = stored.authorization;
            authorization_records.insert(
                hop.authorization_envelope_id,
                AuthorizationEnvelope {
                    envelope_id: hop.authorization_envelope_id,
                    authorization: authorization.clone(),
                },
            );
            active_authorization_ids.insert(
                authorization.authorization_key,
                hop.authorization_envelope_id,
            );
            let enabled = authorization
                .enabled
                .ok_or(StoreError::BridgeRouteIneligible)?;
            if authorization.mission_id != verified.route.mission_id
                || authorization.bridge_node_id != hop.bridge_node_id
                || authorization.source_scope != hop.from_scope
                || authorization.target_scope != hop.to_scope
                || enabled.source_route_epoch != hop.from_route_epoch
                || enabled.target_route_epoch != hop.to_route_epoch
                || hop_count > usize::from(enabled.max_total_hops)
                || enabled
                    .topics
                    .binary_search(&verified.source.metadata.topic)
                    .is_err()
                || !priority_allowed(
                    enabled.allowed_priority_mask,
                    verified.source.metadata.priority,
                )
            {
                return Err(StoreError::BridgeRouteIneligible);
            }
            let source_epoch = self
                .connection
                .query_row(
                    "SELECT epoch FROM scope_epochs WHERE scope=?1",
                    params![hop.from_scope.as_str()],
                    |row| row.get::<_, i64>(0),
                )
                .optional()?
                .map(|value| from_sql_u64(value, "bridge source scope epoch"))
                .transpose()?;
            let target_epoch = self
                .connection
                .query_row(
                    "SELECT epoch FROM scope_epochs WHERE scope=?1",
                    params![hop.to_scope.as_str()],
                    |row| row.get::<_, i64>(0),
                )
                .optional()?
                .map(|value| from_sql_u64(value, "bridge target scope epoch"))
                .transpose()?;
            if source_epoch != Some(hop.from_route_epoch)
                || target_epoch != Some(hop.to_route_epoch)
            {
                return Err(StoreError::BridgeRouteIneligible);
            }
            let revoked: i64 = self.connection.query_row(
                "SELECT EXISTS(SELECT 1 FROM revocations WHERE subject IN (?1,?2,?3))",
                params![
                    authorization.authority_id.as_slice(),
                    control_signer.as_slice(),
                    hop.bridge_node_id.as_slice()
                ],
                |row| row.get(0),
            )?;
            if revoked != 0 {
                return Err(StoreError::BridgeRouteIneligible);
            }
        }
        verified
            .route
            .validate_authority_path(
                &verified.source.metadata.topic,
                verified.source.metadata.priority,
                &authorization_records,
                &active_authorization_ids,
            )
            .map_err(|_| StoreError::BridgeRouteIneligible)?;
        Ok(())
    }

    /// Version-4 stores retained exact source/wrapper bytes but did not have
    /// the complete authenticated semantic columns. A newly provider-verified
    /// final route can fill those nullable migration columns once, atomically,
    /// without trusting the legacy normalized subset.
    fn hydrate_legacy_bridge_source(
        &mut self,
        verified: &VerifiedBridgeRoute,
        sample: Option<CustodySample>,
    ) -> Result<(), StoreError> {
        let legacy = self
            .connection
            .query_row(
                "SELECT source_item_id,exact_bytes,accounted_bytes,\n\
                        source_publisher IS NOT NULL AND data_class IS NOT NULL\n\
                        AND source_topic IS NOT NULL AND source_priority IS NOT NULL\n\
                        AND causal_counter IS NOT NULL AND causal_context IS NOT NULL\n\
                        AND logical_key IS NOT NULL AND content_len IS NOT NULL\n\
                        AND tombstone IS NOT NULL AND origin_scope IS NOT NULL\n\
                        AND origin_route_epoch IS NOT NULL\n\
                        AND forwarding_custody_age_ms IS NOT NULL\n\
                 FROM bridge_source_objects WHERE origin_envelope_id=?1",
                params![verified.route.origin_envelope_id.as_slice()],
                |row| {
                    Ok((
                        row.get::<_, Vec<u8>>(0)?,
                        row.get::<_, Vec<u8>>(1)?,
                        row.get::<_, i64>(2)?,
                        row.get::<_, i64>(3)?,
                    ))
                },
            )
            .optional()?;
        let Some((source_item_id, exact_bytes, old_accounted_bytes, complete)) = legacy else {
            return Ok(());
        };
        if complete == 1 {
            return Ok(());
        }
        if source_item_id.as_slice() != verified.route.source_item_id
            || exact_bytes != verified.source.exact_bytes
        {
            return Err(StoreError::Corrupt(
                "legacy bridge source differs from newly verified exact carrier".into(),
            ));
        }
        let final_hop = verified
            .route
            .hops
            .last()
            .ok_or(StoreError::BridgeDependencyMissing)?;
        let authenticated_age = final_hop
            .cumulative_custody_age_ms
            .max(verified.authenticated_forwarding_age_ms)
            .max(verified.source.authenticated_forwarding_age_ms);
        let available = !final_hop.age_continuity_unknown && sample.is_some();
        if !verified.source.metadata.tombstone
            && verified.source.metadata.ttl_ms.is_some()
            && !available
        {
            return Err(StoreError::BridgeRouteIneligible);
        }
        let new_accounted_bytes = bridge_source_accounted_bytes(&verified.source)?;
        let old_accounted_bytes = from_sql_u64(old_accounted_bytes, "legacy bridge source bytes")?;
        let additional_bytes = new_accounted_bytes.saturating_sub(old_accounted_bytes);
        let metadata = &verified.source.metadata;
        let transaction = self.connection.transaction()?;
        ensure_bridge_admission(&transaction, &self.config, 0, additional_bytes)?;
        accept_bridge_source_semantics_tx(&transaction, &verified.source)?;
        let context = encode_context(&metadata.stamp.context);
        transaction.execute(
            "UPDATE bridge_source_objects SET\n\
               source_publisher=?1,data_class=?2,source_topic=?3,source_priority=?4,\n\
               causal_counter=?5,causal_context=?6,event_sequence=?7,logical_key=?8,\n\
               source_ttl_ms=?9,blob_id=?10,blob_chunk_count=?11,blob_merkle_root=?12,\n\
               content_len=?13,tombstone=?14,origin_scope=?15,origin_route_epoch=?16,\n\
               forwarding_custody_age_ms=?17,accounted_bytes=max(accounted_bytes,?18),\n\
               cumulative_custody_age_ms=max(cumulative_custody_age_ms,?19),\n\
               source_age_continuity_unknown=?20,source_custody_clock_id=?21,\n\
               source_custody_tick_ms=?22,source_custody_elapsed_available=?23\n\
             WHERE origin_envelope_id=?24",
            params![
                metadata.stamp.dot.publisher.as_slice(),
                class_to_i64(metadata.class),
                metadata.topic.as_str(),
                i64::from(metadata.priority as u8),
                sql_u64(metadata.stamp.dot.counter, "bridge source causal counter")?,
                context,
                metadata
                    .event_sequence
                    .map(|value| sql_u64(value, "bridge source event sequence"))
                    .transpose()?,
                &metadata.logical_key,
                metadata
                    .ttl_ms
                    .map(|value| sql_u64(value, "bridge source TTL"))
                    .transpose()?,
                metadata
                    .blob_route
                    .as_ref()
                    .map(|blob| blob.blob_id.as_slice()),
                metadata
                    .blob_route
                    .as_ref()
                    .map(|blob| sql_u64(blob.chunk_count, "bridge blob chunk count"))
                    .transpose()?,
                metadata
                    .blob_route
                    .as_ref()
                    .map(|blob| blob.merkle_root.as_slice()),
                sql_u64(metadata.content_len, "bridge source content length")?,
                i64::from(metadata.tombstone),
                metadata.origin_scope.as_str(),
                sql_u64(metadata.origin_route_epoch, "bridge source origin epoch")?,
                sql_u64(
                    verified.source.authenticated_forwarding_age_ms,
                    "authenticated source forwarding age"
                )?,
                sql_u64(new_accounted_bytes, "bridge source accounted bytes")?,
                sql_u64(authenticated_age, "bridge source custody age")?,
                i64::from(!available),
                sample.filter(|_| available).map(|value| value.clock_id),
                sample
                    .filter(|_| available)
                    .map(|value| sql_u64(value.tick_ms, "bridge source custody tick"))
                    .transpose()?,
                i64::from(available),
                verified.route.origin_envelope_id.as_slice()
            ],
        )?;
        transaction.execute(
            "UPDATE bridge_route_wrappers SET\n\
               cumulative_custody_age_ms=max(cumulative_custody_age_ms,?1),\n\
               forwarding_custody_age_ms=max(forwarding_custody_age_ms,?2),\n\
               custody_clock_id=?3,custody_tick_ms=?4,custody_elapsed_available=?5\n\
             WHERE wrapper_envelope_id=?6",
            params![
                sql_u64(authenticated_age, "bridge cumulative custody age")?,
                sql_u64(
                    verified
                        .authenticated_forwarding_age_ms
                        .max(verified.source.authenticated_forwarding_age_ms),
                    "authenticated bridge forwarding age"
                )?,
                sample.filter(|_| available).map(|value| value.clock_id),
                sample
                    .filter(|_| available)
                    .map(|value| sql_u64(value.tick_ms, "bridge custody tick"))
                    .transpose()?,
                i64::from(available),
                verified.wrapper_envelope_id.as_slice()
            ],
        )?;
        transaction.commit()?;
        Ok(())
    }

    /// Atomically commits an exact provider-verified target wrapper, its exact
    /// source dependency, authorization edges, deterministic active mapping,
    /// and active-route outbox row.
    pub(crate) fn promote_verified_bridge_route(
        &mut self,
        verified: &VerifiedBridgeRoute,
    ) -> Result<BridgeRouteOutcome, StoreError> {
        self.promote_verified_bridge_route_at(verified, None)
    }

    /// Promotion and active selection use the same elapsed-clock sample. A
    /// finite-TTL route without continuous elapsed time fails closed and its
    /// pending records remain intact.
    pub(crate) fn promote_verified_bridge_route_at(
        &mut self,
        verified: &VerifiedBridgeRoute,
        sample: Option<CustodySample>,
    ) -> Result<BridgeRouteOutcome, StoreError> {
        if self
            .stored_bridge_route(&verified.wrapper_envelope_id)?
            .is_some()
        {
            return self.revalidate_committed_bridge_route_at(verified, sample);
        }
        self.validate_live_bridge_route(verified)?;
        self.hydrate_legacy_bridge_source(verified, sample)?;
        let metadata = &verified.source.metadata;

        let pending_wrapper = self.stored_pending_bridge_wrapper(&verified.wrapper_envelope_id)?;
        if let Some(pending) = &pending_wrapper
            && (pending.route != verified.route
                || pending.exact_wrapper_bytes != verified.exact_wrapper_bytes)
        {
            return Err(StoreError::Corrupt(
                "pending bridge wrapper differs from final verified route".into(),
            ));
        }
        let committed_source = self.stored_bridge_source(&verified.route.origin_envelope_id)?;
        let pending_source =
            self.stored_pending_bridge_source(&verified.route.origin_envelope_id)?;
        if committed_source.is_some() && pending_source.is_some() {
            return Err(StoreError::Corrupt(
                "bridge source exists in committed and pending state".into(),
            ));
        }
        for source in committed_source.iter().chain(pending_source.iter()) {
            if source.metadata != *metadata || source.exact_bytes != verified.source.exact_bytes {
                return Err(StoreError::Corrupt(
                    "bridge source identity maps to different exact content".into(),
                ));
            }
        }

        let final_hop = verified
            .route
            .hops
            .last()
            .ok_or(StoreError::BridgeDependencyMissing)?;
        let wrapper_checkpoint = pending_wrapper
            .as_ref()
            .map(|wrapper| checkpoint_pending_bridge_wrapper_custody(wrapper, sample))
            .unwrap_or_else(|| match sample {
                Some(sample) if !final_hop.age_continuity_unknown => (
                    final_hop
                        .cumulative_custody_age_ms
                        .max(verified.authenticated_forwarding_age_ms),
                    false,
                    Some(sample.clock_id),
                    Some(sample.tick_ms),
                    true,
                ),
                _ => (
                    final_hop
                        .cumulative_custody_age_ms
                        .max(verified.authenticated_forwarding_age_ms),
                    true,
                    None,
                    None,
                    false,
                ),
            });
        let source_checkpoint = pending_source
            .as_ref()
            .or(committed_source.as_ref())
            .map(|source| checkpoint_bridge_source_custody(source, sample))
            .unwrap_or_else(|| match sample {
                Some(sample) => (
                    verified.source.authenticated_forwarding_age_ms,
                    false,
                    Some(sample.clock_id),
                    Some(sample.tick_ms),
                    true,
                ),
                None => (
                    verified.source.authenticated_forwarding_age_ms,
                    true,
                    None,
                    None,
                    false,
                ),
            });
        let current = self.current_bridge_route_rank(
            verified.route.origin_envelope_id,
            &verified.route.current_scope,
            verified.route.current_route_epoch,
        )?;
        let current_is_live = match &current {
            Some((wrapper, _, _)) => self.bridge_route_is_live_at(wrapper, sample)?,
            None => false,
        };
        let active_checkpoint = current
            .as_ref()
            .map(|(wrapper, _, _)| {
                self.stored_bridge_route(wrapper)?
                    .ok_or(StoreError::Corrupt(
                        "active bridge route disappeared during promotion".into(),
                    ))
            })
            .transpose()?
            .as_ref()
            .map(|route| checkpoint_bridge_route_custody(route, sample));
        let cumulative_custody_age_ms = final_hop
            .cumulative_custody_age_ms
            .max(verified.authenticated_forwarding_age_ms)
            .max(verified.source.authenticated_forwarding_age_ms)
            .max(wrapper_checkpoint.0)
            .max(source_checkpoint.0)
            .max(active_checkpoint.map_or(0, |checkpoint| checkpoint.0));
        let combined_continuity_unknown = final_hop.age_continuity_unknown
            || wrapper_checkpoint.1
            || source_checkpoint.1
            || active_checkpoint.is_some_and(|checkpoint| checkpoint.1)
            || sample.is_none();
        let (custody_clock_id, custody_tick_ms, custody_elapsed_available) =
            if combined_continuity_unknown {
                (None, None, false)
            } else {
                (
                    wrapper_checkpoint.2,
                    wrapper_checkpoint.3,
                    wrapper_checkpoint.4,
                )
            };
        if !bridge_custody_is_live(
            metadata.ttl_ms,
            metadata.tombstone,
            cumulative_custody_age_ms,
            combined_continuity_unknown,
            custody_clock_id,
            custody_tick_ms,
            custody_elapsed_available,
            sample,
        ) {
            return Err(StoreError::BridgeRouteIneligible);
        }

        let source_accounted_bytes = bridge_source_accounted_bytes(&verified.source)?;
        let dependency_bytes = (verified.route.hops.len() as u64)
            .checked_mul(80)
            .ok_or(StoreError::QuotaExceeded)?;
        let wrapper_accounted_bytes = (verified.exact_wrapper_bytes.len() as u64)
            .checked_add(512)
            .and_then(|value| value.checked_add(dependency_bytes))
            .ok_or(StoreError::QuotaExceeded)?;
        let pending_wrapper_accounted_bytes = pending_wrapper
            .as_ref()
            .map(|_| {
                self.connection.query_row(
                    "SELECT accounted_bytes FROM bridge_pending_wrappers WHERE wrapper_envelope_id=?1",
                    params![verified.wrapper_envelope_id.as_slice()],
                    |row| row.get::<_, i64>(0),
                )
            })
            .transpose()?
            .map(|value| from_sql_u64(value, "pending bridge wrapper bytes"))
            .transpose()?;
        let pending_source_accounted_bytes = pending_source
            .as_ref()
            .map(|_| {
                self.connection.query_row(
                    "SELECT accounted_bytes FROM bridge_pending_sources WHERE origin_envelope_id=?1",
                    params![verified.route.origin_envelope_id.as_slice()],
                    |row| row.get::<_, i64>(0),
                )
            })
            .transpose()?
            .map(|value| from_sql_u64(value, "pending bridge source bytes"))
            .transpose()?;
        let transaction = self.connection.transaction()?;
        let source_is_new = committed_source.is_none();
        let additional_objects = u64::from(pending_wrapper.is_none())
            .checked_add(u64::from(source_is_new && pending_source.is_none()))
            .ok_or(StoreError::QuotaExceeded)?;
        let additional_bytes = if pending_wrapper.is_none() {
            wrapper_accounted_bytes
        } else {
            0
        }
        .checked_add(if source_is_new && pending_source.is_none() {
            source_accounted_bytes
        } else {
            0
        })
        .ok_or(StoreError::QuotaExceeded)?;
        ensure_bridge_admission(
            &transaction,
            &self.config,
            additional_objects,
            additional_bytes,
        )?;
        accept_bridge_source_semantics_tx(&transaction, &verified.source)?;
        if let Some(source) = &committed_source {
            merge_bridge_forwarding_age_tx(
                &transaction,
                verified.route.origin_envelope_id,
                verified.source.authenticated_forwarding_age_ms,
            )?;
            checkpoint_existing_bridge_source_tx(
                &transaction,
                source,
                verified.source.authenticated_forwarding_age_ms,
                sample,
            )?;
        }
        if source_is_new {
            let source_order = pending_source
                .as_ref()
                .map(|source| source.inserted_order)
                .unwrap_or(next_order(&transaction)?);
            let persisted_source_bytes =
                pending_source_accounted_bytes.unwrap_or(source_accounted_bytes);
            if pending_source.is_some() {
                transaction.execute(
                    "DELETE FROM bridge_pending_sources WHERE origin_envelope_id=?1",
                    params![verified.route.origin_envelope_id.as_slice()],
                )?;
            }
            let context = encode_context(&metadata.stamp.context);
            transaction.execute(
                "INSERT INTO bridge_source_objects(\n\
                   origin_envelope_id,source_item_id,exact_bytes,inserted_order,accounted_bytes,\n\
                   source_publisher,data_class,source_topic,source_priority,causal_counter,\n\
                   causal_context,event_sequence,logical_key,source_ttl_ms,blob_id,blob_chunk_count,\n\
                   blob_merkle_root,content_len,tombstone,origin_scope,origin_route_epoch,\n\
                   forwarding_custody_age_ms,cumulative_custody_age_ms,\n\
                   source_age_continuity_unknown,source_custody_clock_id,\n\
                   source_custody_tick_ms,source_custody_elapsed_available)\n\
                 VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14,?15,?16,?17,?18,?19,?20,?21,?22,?23,?24,?25,?26,?27)",
                params![
                    verified.route.origin_envelope_id.as_slice(),
                    verified.route.source_item_id.as_slice(),
                    &verified.source.exact_bytes,
                    sql_u64(source_order, "bridge source insertion order")?,
                    sql_u64(persisted_source_bytes, "bridge source accounted bytes")?,
                    metadata.stamp.dot.publisher.as_slice(),
                    class_to_i64(metadata.class),
                    metadata.topic.as_str(),
                    i64::from(metadata.priority as u8),
                    sql_u64(metadata.stamp.dot.counter, "bridge source causal counter")?,
                    context,
                    metadata
                        .event_sequence
                        .map(|value| sql_u64(value, "bridge source event sequence"))
                        .transpose()?,
                    &metadata.logical_key,
                    metadata
                        .ttl_ms
                        .map(|value| sql_u64(value, "bridge source TTL"))
                        .transpose()?,
                    metadata.blob_route.as_ref().map(|blob| blob.blob_id.as_slice()),
                    metadata
                        .blob_route
                        .as_ref()
                        .map(|blob| sql_u64(blob.chunk_count, "bridge blob chunk count"))
                        .transpose()?,
                    metadata
                        .blob_route
                        .as_ref()
                        .map(|blob| blob.merkle_root.as_slice()),
                    sql_u64(metadata.content_len, "bridge source content length")?,
                    i64::from(metadata.tombstone),
                    metadata.origin_scope.as_str(),
                    sql_u64(metadata.origin_route_epoch, "bridge source origin epoch")?,
                    sql_u64(
                        verified.source.authenticated_forwarding_age_ms,
                        "authenticated source forwarding age"
                    )?,
                    sql_u64(source_checkpoint.0, "bridge source custody age")?,
                    i64::from(source_checkpoint.1),
                    source_checkpoint.2.map(|value| value.to_vec()),
                    source_checkpoint
                        .3
                        .map(|value| sql_u64(value, "bridge source custody tick"))
                        .transpose()?,
                    i64::from(source_checkpoint.4)
                ],
            )?;
        }
        let wrapper_order = pending_wrapper
            .as_ref()
            .map(|wrapper| wrapper.inserted_order)
            .unwrap_or(next_order(&transaction)?);
        let persisted_wrapper_bytes =
            pending_wrapper_accounted_bytes.unwrap_or(wrapper_accounted_bytes);
        if pending_wrapper.is_some() {
            transaction.execute(
                "DELETE FROM bridge_pending_wrapper_authorizations WHERE wrapper_envelope_id=?1",
                params![verified.wrapper_envelope_id.as_slice()],
            )?;
            transaction.execute(
                "DELETE FROM bridge_pending_wrappers WHERE wrapper_envelope_id=?1",
                params![verified.wrapper_envelope_id.as_slice()],
            )?;
        }
        transaction.execute(
            "INSERT INTO bridge_route_wrappers(\n\
               wrapper_envelope_id,bridge_route_id,origin_envelope_id,source_item_id,source_publisher,\n\
               origin_scope,origin_route_epoch,current_scope,current_route_epoch,\n\
               source_topic,source_priority,source_ttl_ms,hop_count,\n\
               cumulative_custody_age_ms,forwarding_custody_age_ms,age_continuity_unknown,\n\
               custody_clock_id,custody_tick_ms,\n\
               custody_elapsed_available,exact_bytes,inserted_order,accounted_bytes)\n\
             VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14,?15,?16,?17,?18,?19,?20,?21,?22)",
            params![
                verified.wrapper_envelope_id.as_slice(),
                verified.route.bridge_route_id.as_slice(),
                verified.route.origin_envelope_id.as_slice(),
                verified.route.source_item_id.as_slice(),
                metadata.stamp.dot.publisher.as_slice(),
                verified.route.origin_scope.as_str(),
                sql_u64(
                    verified.route.origin_route_epoch,
                    "bridge origin route epoch"
                )?,
                verified.route.current_scope.as_str(),
                sql_u64(
                    verified.route.current_route_epoch,
                    "bridge current route epoch"
                )?,
                metadata.topic.as_str(),
                i64::from(metadata.priority as u8),
                metadata
                    .ttl_ms
                    .map(|value| sql_u64(value, "bridge source TTL"))
                    .transpose()?,
                i64::try_from(verified.route.hops.len()).map_err(|_| StoreError::QuotaExceeded)?,
                sql_u64(
                    cumulative_custody_age_ms,
                    "bridge cumulative custody age"
                )?,
                sql_u64(
                    verified
                        .authenticated_forwarding_age_ms
                        .max(verified.source.authenticated_forwarding_age_ms),
                    "authenticated bridge forwarding age"
                )?,
                i64::from(combined_continuity_unknown),
                custody_clock_id,
                custody_tick_ms
                    .map(|value| sql_u64(value, "bridge custody tick"))
                    .transpose()?,
                i64::from(custody_elapsed_available),
                &verified.exact_wrapper_bytes,
                sql_u64(wrapper_order, "bridge wrapper insertion order")?,
                sql_u64(persisted_wrapper_bytes, "bridge wrapper accounted bytes")?
            ],
        )?;
        for (index, hop) in verified.route.hops.iter().enumerate() {
            transaction.execute(
                "INSERT INTO bridge_wrapper_authorizations(\n\
                   wrapper_envelope_id,hop_index,authorization_envelope_id) VALUES(?1,?2,?3)",
                params![
                    verified.wrapper_envelope_id.as_slice(),
                    i64::try_from(index + 1).map_err(|_| StoreError::QuotaExceeded)?,
                    hop.authorization_envelope_id.as_slice()
                ],
            )?;
        }
        let candidate_rank = (
            verified.route.hops.len() as u64,
            verified.route.bridge_route_id,
        );
        let candidate_wins = !current_is_live
            || current
                .as_ref()
                .is_none_or(|(_, hops, route_id)| candidate_rank < (*hops, *route_id));
        let outcome = if candidate_wins {
            if let Some((old_wrapper, _, _)) = current {
                transaction.execute(
                    "DELETE FROM bridge_route_outbox WHERE wrapper_envelope_id=?1",
                    params![old_wrapper.as_slice()],
                )?;
            }
            transaction.execute(
                "INSERT INTO bridge_active_routes(\n\
                   origin_envelope_id,current_scope,current_route_epoch,wrapper_envelope_id)\n\
                 VALUES(?1,?2,?3,?4)\n\
                 ON CONFLICT(origin_envelope_id,current_scope,current_route_epoch) DO UPDATE SET\n\
                   wrapper_envelope_id=excluded.wrapper_envelope_id",
                params![
                    verified.route.origin_envelope_id.as_slice(),
                    verified.route.current_scope.as_str(),
                    sql_u64(
                        verified.route.current_route_epoch,
                        "bridge current route epoch"
                    )?,
                    verified.wrapper_envelope_id.as_slice()
                ],
            )?;
            transaction.execute(
                "INSERT INTO bridge_target_projection(\n\
                   wrapper_envelope_id,source_item_id,target_scope,target_route_epoch,version_status)\n\
                 VALUES(?1,?2,?3,?4,?5)",
                params![
                    verified.wrapper_envelope_id.as_slice(),
                    metadata.source_item_id.as_slice(),
                    verified.route.current_scope.as_str(),
                    sql_u64(
                        verified.route.current_route_epoch,
                        "bridge target projection epoch"
                    )?,
                    VersionStatus::Current as u8 as i64
                ],
            )?;
            recompute_bridge_projection_group_tx(
                &transaction,
                metadata,
                &verified.route.current_scope,
                verified.route.current_route_epoch,
                self.config.max_items,
            )?;
            let outbox_order = next_order(&transaction)?;
            transaction.execute(
                "INSERT INTO bridge_route_outbox(wrapper_envelope_id,enqueued_order)\n\
                 VALUES(?1,?2) ON CONFLICT(wrapper_envelope_id) DO NOTHING",
                params![
                    verified.wrapper_envelope_id.as_slice(),
                    sql_u64(outbox_order, "bridge route outbox order")?
                ],
            )?;
            BridgeRouteOutcome::Active {
                wrapper_envelope_id: verified.wrapper_envelope_id,
                replaced: current.map(|value| value.0),
            }
        } else {
            BridgeRouteOutcome::RetainedAlternate {
                wrapper_envelope_id: verified.wrapper_envelope_id,
                active_wrapper_envelope_id: current
                    .map(|value| value.0)
                    .ok_or(StoreError::Corrupt("missing active bridge route".into()))?,
            }
        };
        ensure_scope_quota_tx(&transaction, &verified.route.origin_scope)?;
        if verified.route.current_scope != verified.route.origin_scope {
            ensure_scope_quota_tx(&transaction, &verified.route.current_scope)?;
        }
        transaction.commit()?;
        self.verified_bridge_routes
            .insert(verified.wrapper_envelope_id);
        self.verified_bridge_sources
            .insert(verified.route.origin_envelope_id);
        self.verified_pending_bridge_wrappers
            .remove(&verified.wrapper_envelope_id);
        Ok(outcome)
    }

    /// Re-authenticates a committed exact wrapper/source pair after restart or
    /// control refresh and deterministically restores its live mapping. Merely
    /// loading the durable normalized rows never confers process liveness.
    pub(crate) fn revalidate_committed_bridge_route(
        &mut self,
        verified: &VerifiedBridgeRoute,
    ) -> Result<BridgeRouteOutcome, StoreError> {
        self.revalidate_committed_bridge_route_at(verified, None)
    }

    pub(crate) fn revalidate_committed_bridge_route_at(
        &mut self,
        verified: &VerifiedBridgeRoute,
        sample: Option<CustodySample>,
    ) -> Result<BridgeRouteOutcome, StoreError> {
        self.validate_live_bridge_route(verified)?;
        self.hydrate_legacy_bridge_source(verified, sample)?;
        let existing = self
            .stored_bridge_route(&verified.wrapper_envelope_id)?
            .ok_or(StoreError::NotFound("committed bridge route"))?;
        let source = self
            .stored_bridge_source(&verified.route.origin_envelope_id)?
            .ok_or(StoreError::Corrupt("bridge route source is missing".into()))?;
        let authorization_ids = {
            let mut statement = self.connection.prepare(
                "SELECT authorization_envelope_id FROM bridge_wrapper_authorizations\n\
                 WHERE wrapper_envelope_id=?1 ORDER BY hop_index",
            )?;
            statement
                .query_map(params![verified.wrapper_envelope_id.as_slice()], |row| {
                    row.get::<_, Vec<u8>>(0)
                })?
                .collect::<Result<Vec<_>, _>>()?
        };
        let metadata = &verified.source.metadata;
        let exact_match = existing.bridge_route_id == verified.route.bridge_route_id
            && existing.origin_envelope_id == verified.route.origin_envelope_id
            && existing.source_item_id == verified.route.source_item_id
            && existing.source_publisher == metadata.stamp.dot.publisher
            && existing.origin_scope == verified.route.origin_scope
            && existing.origin_route_epoch == verified.route.origin_route_epoch
            && existing.current_scope == verified.route.current_scope
            && existing.current_route_epoch == verified.route.current_route_epoch
            && existing.topic == metadata.topic
            && existing.priority == metadata.priority
            && existing.ttl_ms == metadata.ttl_ms
            && existing.tombstone == metadata.tombstone
            && usize::from(existing.hop_count) == verified.route.hops.len()
            && existing.exact_wrapper_bytes == verified.exact_wrapper_bytes
            && existing.exact_source_bytes == verified.source.exact_bytes
            && source.metadata == *metadata
            && source.exact_bytes == verified.source.exact_bytes
            && authorization_ids.len() == verified.route.hops.len()
            && authorization_ids
                .iter()
                .zip(&verified.route.hops)
                .all(|(stored, hop)| stored.as_slice() == hop.authorization_envelope_id.as_slice());
        if !exact_match {
            return Err(StoreError::Corrupt(
                "committed bridge route differs from provider-verified exact content".into(),
            ));
        }

        let final_hop = verified
            .route
            .hops
            .last()
            .ok_or(StoreError::BridgeDependencyMissing)?;
        let current = self.current_bridge_route_rank(
            verified.route.origin_envelope_id,
            &verified.route.current_scope,
            verified.route.current_route_epoch,
        )?;
        let current_is_live = match &current {
            Some((wrapper, _, _)) => self.bridge_route_is_live_at(wrapper, sample)?,
            None => false,
        };
        let active_route = current
            .as_ref()
            .map(|(wrapper, _, _)| {
                self.stored_bridge_route(wrapper)?
                    .ok_or(StoreError::Corrupt(
                        "active bridge route disappeared during revalidation".into(),
                    ))
            })
            .transpose()?;
        let active_checkpoint = active_route
            .as_ref()
            .map(|route| checkpoint_bridge_route_custody(route, sample));
        let source_checkpoint = checkpoint_bridge_source_custody(&source, sample);
        let route_checkpoint = checkpoint_bridge_route_custody(&existing, sample);
        let cumulative_custody_age_ms = route_checkpoint
            .0
            .max(source_checkpoint.0)
            .max(final_hop.cumulative_custody_age_ms)
            .max(verified.authenticated_forwarding_age_ms)
            .max(verified.source.authenticated_forwarding_age_ms)
            .max(active_checkpoint.map_or(0, |checkpoint| checkpoint.0));
        let age_continuity_unknown = route_checkpoint.1
            || source_checkpoint.1
            || final_hop.age_continuity_unknown
            || active_checkpoint.is_some_and(|checkpoint| checkpoint.1);
        let continuity = if age_continuity_unknown {
            (None, None, false)
        } else {
            (route_checkpoint.2, route_checkpoint.3, route_checkpoint.4)
        };
        if !bridge_custody_is_live(
            metadata.ttl_ms,
            metadata.tombstone,
            cumulative_custody_age_ms,
            age_continuity_unknown,
            continuity.0,
            continuity.1,
            continuity.2,
            sample,
        ) {
            return Err(StoreError::BridgeRouteIneligible);
        }

        let candidate_rank = (
            verified.route.hops.len() as u64,
            verified.route.bridge_route_id,
        );
        let candidate_wins = !current_is_live
            || current
                .as_ref()
                .is_none_or(|(_, hops, route_id)| candidate_rank < (*hops, *route_id));

        let source_age = source_checkpoint
            .0
            .max(verified.source.authenticated_forwarding_age_ms);
        let transaction = self.connection.transaction()?;
        transaction.execute(
            "UPDATE bridge_source_objects SET\n\
               forwarding_custody_age_ms=max(coalesce(forwarding_custody_age_ms,0),?1),\n\
               cumulative_custody_age_ms=max(cumulative_custody_age_ms,?2),\n\
               source_age_continuity_unknown=?3,source_custody_clock_id=?4,\n\
               source_custody_tick_ms=?5,source_custody_elapsed_available=?6\n\
             WHERE origin_envelope_id=?7",
            params![
                sql_u64(
                    verified.source.authenticated_forwarding_age_ms,
                    "authenticated source forwarding age"
                )?,
                sql_u64(source_age, "bridge source custody age")?,
                i64::from(source_checkpoint.1),
                source_checkpoint.2.map(|value| value.to_vec()),
                source_checkpoint
                    .3
                    .map(|value| sql_u64(value, "bridge source custody tick"))
                    .transpose()?,
                i64::from(source_checkpoint.4),
                verified.route.origin_envelope_id.as_slice()
            ],
        )?;
        transaction.execute(
            "UPDATE bridge_route_wrappers SET\n\
               cumulative_custody_age_ms=max(cumulative_custody_age_ms,?1),\n\
               forwarding_custody_age_ms=max(forwarding_custody_age_ms,?2),\n\
               age_continuity_unknown=?3,custody_clock_id=?4,custody_tick_ms=?5,\n\
               custody_elapsed_available=?6\n\
             WHERE wrapper_envelope_id=?7",
            params![
                sql_u64(cumulative_custody_age_ms, "bridge cumulative custody age")?,
                sql_u64(
                    verified
                        .authenticated_forwarding_age_ms
                        .max(verified.source.authenticated_forwarding_age_ms),
                    "authenticated bridge forwarding age"
                )?,
                i64::from(age_continuity_unknown),
                continuity.0.map(|value| value.to_vec()),
                continuity
                    .1
                    .map(|value| sql_u64(value, "bridge custody tick"))
                    .transpose()?,
                i64::from(continuity.2),
                verified.wrapper_envelope_id.as_slice()
            ],
        )?;

        let outcome = if candidate_wins {
            let replaced = current
                .as_ref()
                .map(|value| value.0)
                .filter(|wrapper| wrapper != &verified.wrapper_envelope_id);
            if let Some(old_wrapper) = replaced {
                transaction.execute(
                    "DELETE FROM bridge_route_outbox WHERE wrapper_envelope_id=?1",
                    params![old_wrapper.as_slice()],
                )?;
            }
            transaction.execute(
                "INSERT INTO bridge_active_routes(\n\
                   origin_envelope_id,current_scope,current_route_epoch,wrapper_envelope_id)\n\
                 VALUES(?1,?2,?3,?4)\n\
                 ON CONFLICT(origin_envelope_id,current_scope,current_route_epoch) DO UPDATE SET\n\
                   wrapper_envelope_id=excluded.wrapper_envelope_id",
                params![
                    verified.route.origin_envelope_id.as_slice(),
                    verified.route.current_scope.as_str(),
                    sql_u64(
                        verified.route.current_route_epoch,
                        "bridge current route epoch"
                    )?,
                    verified.wrapper_envelope_id.as_slice()
                ],
            )?;
            transaction.execute(
                "INSERT INTO bridge_target_projection(\n\
                   wrapper_envelope_id,source_item_id,target_scope,target_route_epoch,version_status)\n\
                 VALUES(?1,?2,?3,?4,?5)\n\
                 ON CONFLICT(wrapper_envelope_id) DO UPDATE SET\n\
                   source_item_id=excluded.source_item_id,target_scope=excluded.target_scope,\n\
                   target_route_epoch=excluded.target_route_epoch",
                params![
                    verified.wrapper_envelope_id.as_slice(),
                    metadata.source_item_id.as_slice(),
                    verified.route.current_scope.as_str(),
                    sql_u64(
                        verified.route.current_route_epoch,
                        "bridge target projection epoch"
                    )?,
                    VersionStatus::Current as u8 as i64
                ],
            )?;
            recompute_bridge_projection_group_tx(
                &transaction,
                metadata,
                &verified.route.current_scope,
                verified.route.current_route_epoch,
                self.config.max_items,
            )?;
            let outbox_order = next_order(&transaction)?;
            transaction.execute(
                "INSERT INTO bridge_route_outbox(wrapper_envelope_id,enqueued_order)\n\
                 VALUES(?1,?2) ON CONFLICT(wrapper_envelope_id) DO NOTHING",
                params![
                    verified.wrapper_envelope_id.as_slice(),
                    sql_u64(outbox_order, "bridge route outbox order")?
                ],
            )?;
            if current
                .as_ref()
                .is_some_and(|value| value.0 == verified.wrapper_envelope_id)
            {
                BridgeRouteOutcome::Duplicate {
                    wrapper_envelope_id: verified.wrapper_envelope_id,
                    active: true,
                }
            } else {
                BridgeRouteOutcome::Active {
                    wrapper_envelope_id: verified.wrapper_envelope_id,
                    replaced,
                }
            }
        } else {
            BridgeRouteOutcome::RetainedAlternate {
                wrapper_envelope_id: verified.wrapper_envelope_id,
                active_wrapper_envelope_id: current
                    .map(|value| value.0)
                    .ok_or(StoreError::Corrupt("missing active bridge route".into()))?,
            }
        };
        transaction.commit()?;
        self.verified_bridge_routes
            .insert(verified.wrapper_envelope_id);
        self.verified_bridge_sources
            .insert(verified.route.origin_envelope_id);
        Ok(outcome)
    }

    fn current_bridge_route_rank(
        &self,
        origin_envelope_id: EnvelopeId,
        current_scope: &Scope,
        current_route_epoch: u64,
    ) -> Result<Option<(EnvelopeId, u64, [u8; 32])>, StoreError> {
        self.connection
            .query_row(
                "SELECT a.wrapper_envelope_id,w.hop_count,w.bridge_route_id\n\
                 FROM bridge_active_routes a JOIN bridge_route_wrappers w\n\
                   ON w.wrapper_envelope_id=a.wrapper_envelope_id\n\
                 WHERE a.origin_envelope_id=?1 AND a.current_scope=?2 AND a.current_route_epoch=?3",
                params![
                    origin_envelope_id.as_slice(),
                    current_scope.as_str(),
                    sql_u64(current_route_epoch, "bridge current route epoch")?
                ],
                |row| {
                    Ok((
                        row.get::<_, Vec<u8>>(0)?,
                        row.get::<_, i64>(1)?,
                        row.get::<_, Vec<u8>>(2)?,
                    ))
                },
            )
            .optional()?
            .map(|(wrapper, hops, route)| {
                Ok((
                    node_from_vec(wrapper, "active bridge wrapper")?,
                    from_sql_u64(hops, "active bridge hop count")?,
                    node_from_vec(route, "active bridge route identifier")?,
                ))
            })
            .transpose()
    }

    pub(crate) fn stored_bridge_route(
        &self,
        wrapper_envelope_id: &EnvelopeId,
    ) -> Result<Option<StoredBridgeRoute>, StoreError> {
        let row = self
            .connection
            .query_row(
                "SELECT w.bridge_route_id,w.origin_envelope_id,w.source_item_id,w.source_publisher,\n\
                        w.origin_scope,w.origin_route_epoch,w.current_scope,w.current_route_epoch,\n\
                        w.source_topic,w.source_priority,w.source_ttl_ms,coalesce(s.tombstone,0),w.hop_count,\n\
                        w.cumulative_custody_age_ms,w.forwarding_custody_age_ms,\n\
                        w.age_continuity_unknown,\n\
                        w.custody_clock_id,w.custody_tick_ms,w.custody_elapsed_available,w.exact_bytes,\n\
                        CASE WHEN s.reused_item_id IS NULL THEN s.exact_bytes ELSE i.sealed END,\n\
                        w.inserted_order,\n\
                        EXISTS(SELECT 1 FROM bridge_active_routes a\n\
                               WHERE a.wrapper_envelope_id=w.wrapper_envelope_id)\n\
                 FROM bridge_route_wrappers w JOIN bridge_source_objects s\n\
                   ON s.origin_envelope_id=w.origin_envelope_id\n\
                 LEFT JOIN items i ON i.item_id=s.reused_item_id\n\
                   AND i.envelope_id=s.origin_envelope_id\n\
                 WHERE w.wrapper_envelope_id=?1",
                params![wrapper_envelope_id.as_slice()],
                |row| {
                    Ok((
                        row.get::<_, Vec<u8>>(0)?,
                        row.get::<_, Vec<u8>>(1)?,
                        row.get::<_, Vec<u8>>(2)?,
                        row.get::<_, Vec<u8>>(3)?,
                        row.get::<_, String>(4)?,
                        row.get::<_, i64>(5)?,
                        row.get::<_, String>(6)?,
                        row.get::<_, i64>(7)?,
                        row.get::<_, String>(8)?,
                        row.get::<_, i64>(9)?,
                        row.get::<_, Option<i64>>(10)?,
                        row.get::<_, i64>(11)?,
                        row.get::<_, i64>(12)?,
                        row.get::<_, i64>(13)?,
                        row.get::<_, i64>(14)?,
                        row.get::<_, i64>(15)?,
                        row.get::<_, Option<Vec<u8>>>(16)?,
                        row.get::<_, Option<i64>>(17)?,
                        row.get::<_, i64>(18)?,
                        row.get::<_, Vec<u8>>(19)?,
                        row.get::<_, Vec<u8>>(20)?,
                        row.get::<_, i64>(21)?,
                        row.get::<_, i64>(22)?,
                    ))
                },
            )
            .optional()?;
        let Some((
            route_id,
            origin_envelope_id,
            source_item_id,
            source_publisher,
            origin_scope,
            origin_epoch,
            current_scope,
            current_epoch,
            topic,
            priority,
            ttl,
            tombstone,
            hop_count,
            custody_age,
            forwarding_age,
            custody_unknown,
            custody_clock_id,
            custody_tick_ms,
            custody_elapsed_available,
            exact_wrapper_bytes,
            exact_source_bytes,
            inserted_order,
            active,
        )) = row
        else {
            return Ok(None);
        };
        if exact_object_id(&exact_wrapper_bytes) != *wrapper_envelope_id {
            return Err(StoreError::Corrupt(
                "stored bridge wrapper identity is invalid".into(),
            ));
        }
        let origin_envelope_id = node_from_vec(origin_envelope_id, "bridge source envelope")?;
        if exact_object_id(&exact_source_bytes) != origin_envelope_id {
            return Err(StoreError::Corrupt(
                "stored bridge source identity is invalid".into(),
            ));
        }
        let cumulative_custody_age_ms = from_sql_u64(custody_age, "bridge cumulative custody age")?;
        let authenticated_forwarding_age_ms =
            from_sql_u64(forwarding_age, "bridge authenticated forwarding age")?;
        let custody_clock_id = custody_clock_id
            .map(|value| clock_from_vec(value, "bridge custody clock"))
            .transpose()?;
        let custody_tick_ms = custody_tick_ms
            .map(|value| from_sql_u64(value, "bridge custody tick"))
            .transpose()?;
        let custody_elapsed_available = sql_bool(
            custody_elapsed_available,
            "bridge custody elapsed availability",
        )?;
        if cumulative_custody_age_ms < authenticated_forwarding_age_ms
            || custody_elapsed_available
                != (custody_clock_id.is_some() && custody_tick_ms.is_some())
        {
            return Err(StoreError::Corrupt(
                "bridge custody continuity tuple is inconsistent".into(),
            ));
        }
        Ok(Some(StoredBridgeRoute {
            wrapper_envelope_id: *wrapper_envelope_id,
            bridge_route_id: node_from_vec(route_id, "bridge route identifier")?,
            origin_envelope_id,
            source_item_id: item_from_vec(source_item_id, "bridge source item")?,
            source_publisher: node_from_vec(source_publisher, "bridge source publisher")?,
            origin_scope: Scope::new(origin_scope)
                .map_err(|error| StoreError::Corrupt(error.to_string()))?,
            origin_route_epoch: from_sql_u64(origin_epoch, "bridge origin route epoch")?,
            current_scope: Scope::new(current_scope)
                .map_err(|error| StoreError::Corrupt(error.to_string()))?,
            current_route_epoch: from_sql_u64(current_epoch, "bridge current route epoch")?,
            topic: Topic::new(topic).map_err(|error| StoreError::Corrupt(error.to_string()))?,
            priority: priority_from_i64(priority)?,
            ttl_ms: ttl
                .map(|value| from_sql_u64(value, "bridge source TTL"))
                .transpose()?,
            tombstone: sql_bool(tombstone, "bridge source tombstone")?,
            hop_count: u8::try_from(from_sql_u64(hop_count, "bridge hop count")?)
                .map_err(|_| StoreError::Corrupt("bridge hop count outside byte range".into()))?,
            cumulative_custody_age_ms,
            authenticated_forwarding_age_ms,
            age_continuity_unknown: match custody_unknown {
                0 => false,
                1 => true,
                _ => {
                    return Err(StoreError::Corrupt(
                        "bridge custody continuity state is invalid".into(),
                    ));
                }
            },
            custody_clock_id,
            custody_tick_ms,
            custody_elapsed_available,
            exact_wrapper_bytes,
            exact_source_bytes,
            active: match active {
                0 => false,
                1 => true,
                _ => {
                    return Err(StoreError::Corrupt(
                        "bridge active route state is invalid".into(),
                    ));
                }
            },
            inserted_order: from_sql_u64(inserted_order, "bridge wrapper insertion order")?,
        }))
    }

    /// Bounded restart reload in durable insertion order. Returned routes are
    /// not made live; the provider must reconstruct verification tokens.
    pub(crate) fn stored_bridge_routes(
        &self,
        limit: usize,
    ) -> Result<Vec<StoredBridgeRoute>, StoreError> {
        self.stored_bridge_routes_after(None, limit)
    }

    pub(crate) fn stored_bridge_routes_after(
        &self,
        after_inserted_order: Option<u64>,
        limit: usize,
    ) -> Result<Vec<StoredBridgeRoute>, StoreError> {
        let limit = limit.min(MAX_BRIDGE_STORE_BATCH);
        if limit == 0 {
            return Ok(Vec::new());
        }
        let ids = {
            let mut statement = self.connection.prepare(
                "SELECT wrapper_envelope_id FROM bridge_route_wrappers\n\
                 WHERE inserted_order>?1 ORDER BY inserted_order LIMIT ?2",
            )?;
            statement
                .query_map(
                    params![
                        sql_u64(
                            after_inserted_order.unwrap_or(0),
                            "stored bridge route cursor"
                        )?,
                        i64::try_from(limit).map_err(|_| StoreError::QuotaExceeded)?
                    ],
                    |row| row.get::<_, Vec<u8>>(0),
                )?
                .collect::<Result<Vec<_>, _>>()?
        };
        ids.into_iter()
            .map(|id| {
                let id = node_from_vec(id, "stored bridge route")?;
                self.stored_bridge_route(&id)?.ok_or(StoreError::Corrupt(
                    "stored bridge route disappeared".into(),
                ))
            })
            .collect()
    }

    /// Queries only the provider-revalidated active target projection. An
    /// ordinary item with the same ItemID wins de-duplication, so applications
    /// never observe the same semantic item through both representations.
    pub(crate) fn query_active_bridge_projection(
        &self,
        query: &BridgeProjectionQuery,
    ) -> Result<Vec<StoredBridgeProjection>, StoreError> {
        let requested_limit = query
            .limit
            .unwrap_or(MAX_BRIDGE_PROJECTION_RESULTS)
            .min(MAX_BRIDGE_PROJECTION_RESULTS);
        if requested_limit == 0 {
            return Ok(Vec::new());
        }
        let mut entries = Vec::new();
        let mut cursor = None;
        let mut inspected = 0u64;
        while entries.len() < requested_limit {
            let mut page_query = query.clone();
            page_query.limit = Some(requested_limit - entries.len());
            let page = self.query_active_bridge_projection_page(&page_query, cursor)?;
            inspected = inspected
                .checked_add(MAX_BRIDGE_STORE_BATCH as u64)
                .ok_or(StoreError::QuotaExceeded)?;
            entries.extend(page.entries);
            let Some(next) = page.next_cursor else { break };
            if Some(next) == cursor || inspected > self.config.max_items {
                return Err(StoreError::Corrupt(
                    "bridge projection scan exceeded configured object bound".into(),
                ));
            }
            cursor = Some(next);
        }
        entries.truncate(requested_limit);
        Ok(entries)
    }

    /// One bounded page after SQL de-duplication. A supplied bridge scope is
    /// always an opaque exact match, independent of ordinary descendant-query
    /// behavior.
    pub(crate) fn query_active_bridge_projection_page(
        &self,
        query: &BridgeProjectionQuery,
        after: Option<BridgeProjectionCursor>,
    ) -> Result<BridgeProjectionPage, StoreError> {
        use rusqlite::types::Value;

        let requested_limit = query
            .limit
            .unwrap_or(MAX_BRIDGE_STORE_BATCH)
            .min(MAX_BRIDGE_STORE_BATCH);
        if requested_limit == 0 {
            return Ok(BridgeProjectionPage {
                entries: Vec::new(),
                next_cursor: None,
            });
        }
        let mut sql = String::from(
            "SELECT p.wrapper_envelope_id,p.version_status,w.source_priority,w.inserted_order\n\
             FROM bridge_target_projection p\n\
             JOIN bridge_active_routes a ON a.wrapper_envelope_id=p.wrapper_envelope_id\n\
             JOIN bridge_route_wrappers w ON w.wrapper_envelope_id=p.wrapper_envelope_id\n\
             JOIN bridge_source_objects s ON s.origin_envelope_id=w.origin_envelope_id\n\
             WHERE NOT EXISTS(SELECT 1 FROM items i WHERE i.item_id=p.source_item_id\n\
               AND i.scope=p.target_scope AND i.key_epoch=p.target_route_epoch)",
        );
        let mut values = Vec::<Value>::new();
        if let Some(scope) = &query.target_scope {
            sql.push_str(" AND p.target_scope=?");
            values.push(scope.as_str().to_owned().into());
        }
        if let Some(epoch) = query.target_route_epoch {
            sql.push_str(" AND p.target_route_epoch=?");
            values.push(sql_u64(epoch, "bridge projection target epoch")?.into());
        }
        if let Some(topic) = &query.topic {
            sql.push_str(" AND w.source_topic=?");
            values.push(topic.as_str().to_owned().into());
        }
        if let Some(class) = query.class {
            sql.push_str(" AND s.data_class=?");
            values.push(class_to_i64(class).into());
        } else if query.mutable_classes_only {
            sql.push_str(" AND s.data_class IN (?,?)");
            values.push(class_to_i64(DataClass::State).into());
            values.push(class_to_i64(DataClass::Record).into());
        }
        if let Some(key) = &query.logical_key {
            sql.push_str(" AND s.logical_key=?");
            values.push(key.clone().into());
        }
        if let Some(status) = query.version_status {
            sql.push_str(" AND p.version_status=?");
            values.push((status as u8 as i64).into());
        }
        if let Some(subscription) = query.acknowledged_subscription {
            sql.push_str(
                " AND EXISTS(SELECT 1 FROM semantic_app_deliveries d\n\
                   WHERE d.subscription_id=? AND d.item_id=p.source_item_id\n\
                     AND d.acked_at_ms IS NOT NULL)",
            );
            values.push(sql_u64(subscription.0, "subscription id")?.into());
        }
        if !query.include_tombstones {
            sql.push_str(" AND s.tombstone=0");
        }
        if let Some(cursor) = after {
            sql.push_str(
                " AND (w.source_priority<? OR\n\
                   (w.source_priority=? AND w.inserted_order>?))",
            );
            values.push((cursor.source_priority as u8 as i64).into());
            values.push((cursor.source_priority as u8 as i64).into());
            values.push(sql_u64(cursor.inserted_order, "bridge projection cursor")?.into());
        }
        sql.push_str(" ORDER BY w.source_priority DESC,w.inserted_order ASC LIMIT ?");
        values.push(
            i64::try_from(MAX_BRIDGE_STORE_BATCH)
                .map_err(|_| StoreError::QuotaExceeded)?
                .into(),
        );
        let rows = {
            let mut statement = self.connection.prepare(&sql)?;
            statement
                .query_map(rusqlite::params_from_iter(values), |row| {
                    Ok((
                        row.get::<_, Vec<u8>>(0)?,
                        row.get::<_, i64>(1)?,
                        row.get::<_, i64>(2)?,
                        row.get::<_, i64>(3)?,
                    ))
                })?
                .collect::<Result<Vec<_>, _>>()?
        };
        let mut projection = Vec::new();
        let row_count = rows.len();
        let mut next_cursor = None;
        for (wrapper, status, priority, inserted_order) in rows {
            next_cursor = Some(BridgeProjectionCursor {
                source_priority: priority_from_i64(priority)?,
                inserted_order: from_sql_u64(inserted_order, "bridge projection order")?,
            });
            let wrapper = node_from_vec(wrapper, "active bridge projection wrapper")?;
            if !self.bridge_route_is_live_at(&wrapper, query.custody_sample)? {
                continue;
            }
            let route = self
                .stored_bridge_route(&wrapper)?
                .ok_or(StoreError::Corrupt(
                    "active bridge projection route disappeared".into(),
                ))?;
            let source = self
                .stored_bridge_source(&route.origin_envelope_id)?
                .ok_or(StoreError::Corrupt(
                    "active bridge projection source disappeared".into(),
                ))?;
            projection.push(StoredBridgeProjection {
                route,
                source,
                version_status: status_from_i64(status)?,
            });
            if projection.len() == requested_limit {
                return Ok(BridgeProjectionPage {
                    entries: projection,
                    next_cursor,
                });
            }
        }
        Ok(BridgeProjectionPage {
            entries: projection,
            next_cursor: (row_count == MAX_BRIDGE_STORE_BATCH)
                .then_some(next_cursor)
                .flatten(),
        })
    }

    /// Returns one non-mutating candidate page for an existing subscription.
    /// The engine may skip route-only entries and continue with `next_cursor`
    /// before committing only provider-opened content as application delivery.
    pub(crate) fn peek_bridge_projection_subscription_page(
        &self,
        id: SubscriptionId,
        after: Option<BridgeProjectionCursor>,
        custody_sample: Option<CustodySample>,
    ) -> Result<BridgeProjectionPage, StoreError> {
        self.bridge_projection_subscription_page(id, after, custody_sample, false)
    }

    /// Returns acknowledged State/Record bridge candidates. Application
    /// projection combines these with the ordinary unacknowledged page before
    /// reduction so an acknowledged current head still suppresses its ancestors.
    pub(crate) fn peek_acknowledged_bridge_projection_subscription_page(
        &self,
        id: SubscriptionId,
        after: Option<BridgeProjectionCursor>,
        custody_sample: Option<CustodySample>,
    ) -> Result<BridgeProjectionPage, StoreError> {
        self.bridge_projection_subscription_page(id, after, custody_sample, true)
    }

    fn bridge_projection_subscription_page(
        &self,
        id: SubscriptionId,
        after: Option<BridgeProjectionCursor>,
        custody_sample: Option<CustodySample>,
        include_acknowledged: bool,
    ) -> Result<BridgeProjectionPage, StoreError> {
        let subscription: Option<(String, String, Option<i64>)> = self
            .connection
            .query_row(
                "SELECT topic,scope,data_class FROM subscriptions WHERE subscription_id=?1",
                params![sql_u64(id.0, "subscription id")?],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .optional()?;
        let Some((topic, scope, class)) = subscription else {
            return Err(StoreError::NotFound("subscription"));
        };
        let class = class.map(class_from_i64).transpose()?;
        if include_acknowledged
            && class.is_some_and(|class| !matches!(class, DataClass::State | DataClass::Record))
        {
            return Ok(BridgeProjectionPage {
                entries: Vec::new(),
                next_cursor: None,
            });
        }
        let query = BridgeProjectionQuery {
            target_scope: Some(
                Scope::new(scope).map_err(|error| StoreError::Corrupt(error.to_string()))?,
            ),
            topic: Some(Topic::new(topic).map_err(|error| StoreError::Corrupt(error.to_string()))?),
            class,
            mutable_classes_only: include_acknowledged,
            acknowledged_subscription: include_acknowledged.then_some(id),
            // Subscription reduction is performed over the combined ordinary
            // and bridge candidate set; a representation-local Current bit
            // must not hide the live fallback after another path expires.
            version_status: None,
            include_tombstones: true,
            custody_sample,
            limit: Some(MAX_BRIDGE_STORE_BATCH),
            ..BridgeProjectionQuery::default()
        };
        let mut page = self.query_active_bridge_projection_page(&query, after)?;
        if include_acknowledged {
            return Ok(page);
        }
        let mut retained = Vec::with_capacity(page.entries.len());
        for projection in page.entries {
            let acknowledged: i64 = self.connection.query_row(
                "SELECT EXISTS(SELECT 1 FROM semantic_app_deliveries\n\
                 WHERE subscription_id=?1 AND item_id=?2 AND acked_at_ms IS NOT NULL)",
                params![
                    sql_u64(id.0, "subscription id")?,
                    projection.source.metadata.source_item_id.as_slice()
                ],
                |row| row.get(0),
            )?;
            if acknowledged == 0 {
                retained.push(projection);
            }
        }
        page.entries = retained;
        Ok(page)
    }

    /// Returns acknowledged ordinary State/Record candidates that still match
    /// one durable subscription. Immutable Event/Blob history remains on the
    /// existing unacknowledged-only scan and is not rematerialized on every poll.
    pub(crate) fn acknowledged_subscription_projection_items(
        &self,
        id: SubscriptionId,
        custody_sample: Option<CustodySample>,
    ) -> Result<Vec<StoredItem>, StoreError> {
        let columns = ITEM_COLUMNS
            .split(',')
            .map(|column| format!("i.{column}"))
            .collect::<Vec<_>>()
            .join(",");
        let sql = format!(
            "SELECT {columns} FROM semantic_app_deliveries d\n\
             JOIN subscriptions s ON s.subscription_id=d.subscription_id\n\
             JOIN items i ON i.item_id=d.item_id\n\
             WHERE d.subscription_id=?1 AND d.acked_at_ms IS NOT NULL\n\
               AND i.data_class IN (?2,?3)\n\
               AND i.topic=s.topic\n\
               AND (i.scope=s.scope OR (s.descendants<>0 AND i.scope LIKE s.scope || '/%'))\n\
               AND (s.data_class IS NULL OR i.data_class=s.data_class)\n\
             ORDER BY i.priority DESC,i.inserted_order ASC"
        );
        let mut statement = self.connection.prepare(&sql)?;
        let rows = statement.query_map(
            params![
                sql_u64(id.0, "subscription id")?,
                class_to_i64(DataClass::State),
                class_to_i64(DataClass::Record)
            ],
            decode_item_row,
        )?;
        let max_items =
            usize::try_from(self.config.max_items).map_err(|_| StoreError::QuotaExceeded)?;
        let scan_limit = max_items.checked_add(1).ok_or(StoreError::QuotaExceeded)?;
        let items = rows
            .take(scan_limit)
            .filter(|row| {
                row.as_ref()
                    .map_or(true, |item| !item.is_expired_at(custody_sample))
            })
            .collect::<Result<Vec<_>, _>>()?;
        if items.len() > max_items {
            return Err(StoreError::Corrupt(
                "acknowledged subscription projection exceeds configured object bound".into(),
            ));
        }
        Ok(items)
    }

    /// Crash-atomically records attempts only for candidates whose content was
    /// provider-opened. Route-only entries never consume delivery attempts or
    /// application limits.
    pub(crate) fn record_bridge_projection_deliveries(
        &mut self,
        id: SubscriptionId,
        opened: &[ProviderOpenedBridgeProjection],
        now_ms: Option<u64>,
        custody_sample: Option<CustodySample>,
    ) -> Result<Vec<BridgeProjectionDelivery>, StoreError> {
        if opened.len() > MAX_BRIDGE_PROJECTION_RESULTS {
            return Err(StoreError::Invalid(
                "bridge projection delivery batch exceeds bound".into(),
            ));
        }
        let subscription: Option<(String, String, Option<i64>)> = self
            .connection
            .query_row(
                "SELECT topic,scope,data_class FROM subscriptions WHERE subscription_id=?1",
                params![sql_u64(id.0, "subscription id")?],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .optional()?;
        let Some((topic, scope, class)) = subscription else {
            return Err(StoreError::NotFound("subscription"));
        };
        let class = class.map(class_from_i64).transpose()?;
        let mut candidates = BTreeMap::new();
        for capability in opened {
            let projection = &capability.projection;
            if projection.route.current_scope.as_str() != scope
                || projection.source.metadata.topic.as_str() != topic
                || class.is_some_and(|wanted| wanted != projection.source.metadata.class)
                || !self.bridge_route_is_live_at(
                    &projection.route.wrapper_envelope_id,
                    custody_sample,
                )?
            {
                return Err(StoreError::NotFound(
                    "active bridge subscription projection",
                ));
            }
            let current = self
                .stored_bridge_route(&projection.route.wrapper_envelope_id)?
                .ok_or(StoreError::NotFound(
                    "active bridge subscription projection",
                ))?;
            let source = self
                .stored_bridge_source(&current.origin_envelope_id)?
                .ok_or(StoreError::NotFound(
                    "active bridge subscription projection",
                ))?;
            if current != projection.route || source != projection.source {
                return Err(StoreError::Invalid(
                    "provider-opened bridge projection changed before delivery".into(),
                ));
            }
            let ordinary_wins: i64 = self.connection.query_row(
                "SELECT EXISTS(SELECT 1 FROM items WHERE item_id=?1 AND scope=?2 AND key_epoch=?3)",
                params![
                    source.metadata.source_item_id.as_slice(),
                    current.current_scope.as_str(),
                    sql_u64(current.current_route_epoch, "bridge target route epoch")?
                ],
                |row| row.get(0),
            )?;
            if ordinary_wins != 0 {
                return Err(StoreError::NotFound(
                    "ordinary subscription representation wins",
                ));
            }
            candidates
                .entry(source.metadata.source_item_id)
                .or_insert_with(|| projection.clone());
        }
        let delivery_time = now_ms
            .map(|value| sql_u64(value, "bridge delivery time"))
            .transpose()?;
        let transaction = self.connection.transaction()?;
        let mut deliveries = Vec::with_capacity(candidates.len());
        for (item_id, projection) in candidates {
            transaction.execute(
                "INSERT INTO semantic_app_deliveries(\n\
                   subscription_id,item_id,target_scope,representation,wrapper_envelope_id)\n\
                 VALUES(?1,?2,?3,1,?4)\n\
                 ON CONFLICT(subscription_id,item_id) DO UPDATE SET\n\
                   target_scope=excluded.target_scope,representation=1,\n\
                   wrapper_envelope_id=excluded.wrapper_envelope_id\n\
                 WHERE semantic_app_deliveries.acked_at_ms IS NULL",
                params![
                    sql_u64(id.0, "subscription id")?,
                    item_id.as_slice(),
                    projection.route.current_scope.as_str(),
                    projection.route.wrapper_envelope_id.as_slice()
                ],
            )?;
            let changed = transaction.execute(
                "UPDATE semantic_app_deliveries SET\n\
                   attempts=attempts+1,last_delivery_ms=?1\n\
                 WHERE subscription_id=?2 AND item_id=?3 AND acked_at_ms IS NULL",
                params![
                    delivery_time,
                    sql_u64(id.0, "subscription id")?,
                    item_id.as_slice()
                ],
            )?;
            if changed == 0 {
                continue;
            }
            let attempts: i64 = transaction.query_row(
                "SELECT attempts FROM semantic_app_deliveries\n\
                 WHERE subscription_id=?1 AND item_id=?2",
                params![sql_u64(id.0, "subscription id")?, item_id.as_slice()],
                |row| row.get(0),
            )?;
            deliveries.push(BridgeProjectionDelivery {
                subscription: id,
                projection,
                delivery_attempt: from_sql_u64(attempts, "bridge delivery attempts")?,
            });
        }
        transaction.commit()?;
        Ok(deliveries)
    }

    pub(crate) fn acknowledge_bridge_projection_delivery(
        &mut self,
        id: SubscriptionId,
        item_id: ItemId,
        now_ms: Option<u64>,
    ) -> Result<(), StoreError> {
        let changed = self.connection.execute(
            "UPDATE semantic_app_deliveries SET acked_at_ms=?1\n\
             WHERE subscription_id=?2 AND item_id=?3",
            params![
                now_ms
                    .map(|value| sql_u64(value, "bridge delivery acknowledgement time"))
                    .transpose()?,
                sql_u64(id.0, "subscription id")?,
                item_id.as_slice()
            ],
        )?;
        if changed == 0 {
            return Err(StoreError::NotFound("bridge application delivery"));
        }
        Ok(())
    }

    pub(crate) fn active_bridge_route(
        &self,
        origin_envelope_id: &EnvelopeId,
        current_scope: &Scope,
        current_route_epoch: u64,
    ) -> Result<Option<StoredBridgeRoute>, StoreError> {
        self.active_bridge_route_at(origin_envelope_id, current_scope, current_route_epoch, None)
    }

    pub(crate) fn active_bridge_route_at(
        &self,
        origin_envelope_id: &EnvelopeId,
        current_scope: &Scope,
        current_route_epoch: u64,
        sample: Option<CustodySample>,
    ) -> Result<Option<StoredBridgeRoute>, StoreError> {
        let wrapper = self
            .connection
            .query_row(
                "SELECT wrapper_envelope_id FROM bridge_active_routes\n\
                 WHERE origin_envelope_id=?1 AND current_scope=?2 AND current_route_epoch=?3",
                params![
                    origin_envelope_id.as_slice(),
                    current_scope.as_str(),
                    sql_u64(current_route_epoch, "bridge current route epoch")?
                ],
                |row| row.get::<_, Vec<u8>>(0),
            )
            .optional()?
            .map(|value| node_from_vec(value, "active bridge wrapper"))
            .transpose()?;
        let Some(wrapper) = wrapper else {
            return Ok(None);
        };
        if !self.bridge_route_is_live_at(&wrapper, sample)? {
            return Ok(None);
        }
        self.stored_bridge_route(&wrapper)
    }

    pub(crate) fn bridge_route_is_live(
        &self,
        wrapper_envelope_id: &EnvelopeId,
    ) -> Result<bool, StoreError> {
        self.bridge_route_is_live_at(wrapper_envelope_id, None)
    }

    pub(crate) fn bridge_route_is_live_at(
        &self,
        wrapper_envelope_id: &EnvelopeId,
        sample: Option<CustodySample>,
    ) -> Result<bool, StoreError> {
        self.bridge_route_candidate_is_live_at(wrapper_envelope_id, sample, true)
    }

    fn bridge_route_candidate_is_live_at(
        &self,
        wrapper_envelope_id: &EnvelopeId,
        sample: Option<CustodySample>,
        require_active: bool,
    ) -> Result<bool, StoreError> {
        if !self.verified_bridge_routes.contains(wrapper_envelope_id) {
            return Ok(false);
        }
        if require_active {
            let active: i64 = self.connection.query_row(
                "SELECT EXISTS(SELECT 1 FROM bridge_active_routes WHERE wrapper_envelope_id=?1)",
                params![wrapper_envelope_id.as_slice()],
                |row| row.get(0),
            )?;
            if active == 0 {
                return Ok(false);
            }
        }
        let Some(route) = self.stored_bridge_route(wrapper_envelope_id)? else {
            return Err(StoreError::Corrupt("active bridge route is missing".into()));
        };
        if !self
            .verified_bridge_sources
            .contains(&route.origin_envelope_id)
        {
            return Ok(false);
        }
        let source = self
            .stored_bridge_source(&route.origin_envelope_id)?
            .ok_or(StoreError::Corrupt(
                "active bridge source is missing".into(),
            ))?;
        if source.metadata.source_item_id != route.source_item_id
            || source.metadata.stamp.dot.publisher != route.source_publisher
            || source.metadata.topic != route.topic
            || source.metadata.priority != route.priority
            || source.metadata.ttl_ms != route.ttl_ms
            || source.metadata.origin_scope != route.origin_scope
            || source.metadata.origin_route_epoch != route.origin_route_epoch
            || !bridge_custody_is_live(
                route.ttl_ms,
                source.metadata.tombstone,
                route.cumulative_custody_age_ms,
                route.age_continuity_unknown,
                route.custody_clock_id,
                route.custody_tick_ms,
                route.custody_elapsed_available,
                sample,
            )
            || !bridge_custody_is_live(
                source.metadata.ttl_ms,
                source.metadata.tombstone,
                source.cumulative_custody_age_ms,
                source.age_continuity_unknown,
                source.custody_clock_id,
                source.custody_tick_ms,
                source.custody_elapsed_available,
                sample,
            )
        {
            return Ok(false);
        }
        let revoked: i64 = self.connection.query_row(
            "SELECT EXISTS(SELECT 1 FROM revocations WHERE subject=?1)",
            params![route.source_publisher.as_slice()],
            |row| row.get(0),
        )?;
        if revoked != 0 {
            return Ok(false);
        }
        let dependencies = {
            let mut statement = self.connection.prepare(
                "SELECT authorization_envelope_id FROM bridge_wrapper_authorizations\n\
                 WHERE wrapper_envelope_id=?1 ORDER BY hop_index",
            )?;
            statement
                .query_map(params![wrapper_envelope_id.as_slice()], |row| {
                    row.get::<_, Vec<u8>>(0)
                })?
                .collect::<Result<Vec<_>, _>>()?
        };
        for dependency in dependencies {
            let dependency = node_from_vec(dependency, "bridge authorization dependency")?;
            if !self.bridge_authorization_is_live(&dependency)? {
                return Ok(false);
            }
        }
        Ok(true)
    }

    pub(crate) fn next_bridge_route_outbound(
        &mut self,
        peer: NodeId,
        limit: usize,
        byte_budget: u64,
        now_ms: Option<u64>,
        sample: Option<CustodySample>,
    ) -> Result<Vec<StoredBridgeRoute>, StoreError> {
        let selected = self.peek_bridge_route_outbound(peer, limit, byte_budget, sample)?;
        self.record_bridge_route_attempts(peer, &selected, now_ms)?;
        Ok(selected)
    }

    /// Non-mutating route selection. Attempt counters move only after the
    /// runtime confirms that it actually scheduled these rows.
    pub(crate) fn peek_bridge_route_outbound(
        &mut self,
        peer: NodeId,
        limit: usize,
        byte_budget: u64,
        sample: Option<CustodySample>,
    ) -> Result<Vec<StoredBridgeRoute>, StoreError> {
        let limit = limit.min(MAX_BRIDGE_STORE_BATCH);
        if limit == 0 || byte_budget == 0 || self.is_zeroized()? || self.is_revoked(&peer)? {
            return Ok(Vec::new());
        }
        let ids = {
            let mut statement = self.connection.prepare(
                "SELECT w.wrapper_envelope_id FROM bridge_route_outbox o\n\
                 JOIN bridge_route_wrappers w ON w.wrapper_envelope_id=o.wrapper_envelope_id\n\
                 JOIN bridge_active_routes a ON a.wrapper_envelope_id=w.wrapper_envelope_id\n\
                 LEFT JOIN bridge_route_peer_receipts r\n\
                   ON r.peer=?1 AND r.wrapper_envelope_id=w.wrapper_envelope_id\n\
                 LEFT JOIN bridge_route_peer_attempts x\n\
                   ON x.peer=?1 AND x.wrapper_envelope_id=w.wrapper_envelope_id\n\
                 WHERE r.wrapper_envelope_id IS NULL\n\
                 ORDER BY w.source_priority DESC,coalesce(x.attempts,0),o.enqueued_order\n\
                 LIMIT ?2",
            )?;
            statement
                .query_map(
                    params![peer.as_slice(), i64::from(MAX_BRIDGE_STORE_BATCH as u16)],
                    |row| row.get::<_, Vec<u8>>(0),
                )?
                .collect::<Result<Vec<_>, _>>()?
        };
        let mut selected = Vec::new();
        let mut used = 0u64;
        for id in ids {
            let id = node_from_vec(id, "bridge route outbox")?;
            if !self.bridge_route_is_live_at(&id, sample)? {
                continue;
            }
            let route = self.stored_bridge_route(&id)?.ok_or(StoreError::Corrupt(
                "bridge route outbox is dangling".into(),
            ))?;
            let size = route.exact_wrapper_bytes.len() as u64;
            if used.saturating_add(size) <= byte_budget {
                used = used.saturating_add(size);
                selected.push(route);
                if selected.len() == limit {
                    break;
                }
            }
        }
        Ok(selected)
    }

    pub(crate) fn record_bridge_route_attempts(
        &mut self,
        peer: NodeId,
        routes: &[StoredBridgeRoute],
        now_ms: Option<u64>,
    ) -> Result<(), StoreError> {
        if routes.len() > MAX_BRIDGE_STORE_BATCH {
            return Err(StoreError::Invalid(
                "bridge route attempt batch exceeds bound".into(),
            ));
        }
        let transaction = self.connection.transaction()?;
        for route in routes {
            transaction.execute(
                "INSERT INTO bridge_route_peer_attempts(\n\
                   peer,wrapper_envelope_id,attempts,last_attempt_ms) VALUES(?1,?2,1,?3)\n\
                 ON CONFLICT(peer,wrapper_envelope_id) DO UPDATE SET\n\
                   attempts=attempts+1,last_attempt_ms=excluded.last_attempt_ms",
                params![
                    peer.as_slice(),
                    route.wrapper_envelope_id.as_slice(),
                    now_ms
                        .map(|value| sql_u64(value, "bridge route emission time"))
                        .transpose()?
                ],
            )?;
        }
        transaction.commit()?;
        Ok(())
    }

    pub(crate) fn read_bridge_wrapper_range(
        &self,
        wrapper_envelope_id: &EnvelopeId,
        range: ChunkRange,
        max_bytes: usize,
        sample: Option<CustodySample>,
    ) -> Result<Vec<u8>, StoreError> {
        if range.is_empty() || max_bytes == 0 {
            return Ok(Vec::new());
        }
        if !self.bridge_route_is_live_at(wrapper_envelope_id, sample)? {
            return Err(StoreError::NotFound("active bridge route outbox object"));
        }
        let bytes = self
            .connection
            .query_row(
                "SELECT substr(w.exact_bytes,?2,?3) FROM bridge_route_wrappers w\n\
                 JOIN bridge_route_outbox o ON o.wrapper_envelope_id=w.wrapper_envelope_id\n\
                 WHERE w.wrapper_envelope_id=?1",
                params![
                    wrapper_envelope_id.as_slice(),
                    sql_u64(range.start.saturating_add(1), "bridge wrapper read offset")?,
                    sql_u64(
                        range.len().min(max_bytes as u64),
                        "bridge wrapper read length"
                    )?
                ],
                |row| row.get::<_, Vec<u8>>(0),
            )
            .optional()?;
        bytes.ok_or(StoreError::NotFound("active bridge route outbox object"))
    }

    pub(crate) fn acknowledge_bridge_route_peer(
        &mut self,
        peer: NodeId,
        wrapper_envelope_ids: &[EnvelopeId],
        now_ms: Option<u64>,
        sample: Option<CustodySample>,
    ) -> Result<(), StoreError> {
        if wrapper_envelope_ids.len() > MAX_BRIDGE_STORE_BATCH {
            return Err(StoreError::Invalid(
                "bridge route receipt batch exceeds bound".into(),
            ));
        }
        for id in wrapper_envelope_ids {
            if !self.bridge_route_is_live_at(id, sample)? {
                return Err(StoreError::NotFound("active bridge route outbox object"));
            }
        }
        let transaction = self.connection.transaction()?;
        for id in wrapper_envelope_ids {
            let inserted = transaction.execute(
                "INSERT INTO bridge_route_peer_receipts(peer,wrapper_envelope_id,acknowledged_at_ms)\n\
                 SELECT ?1,w.wrapper_envelope_id,?3 FROM bridge_route_wrappers w\n\
                 JOIN bridge_route_outbox o ON o.wrapper_envelope_id=w.wrapper_envelope_id\n\
                 JOIN bridge_active_routes a ON a.wrapper_envelope_id=w.wrapper_envelope_id\n\
                 WHERE w.wrapper_envelope_id=?2\n\
                 ON CONFLICT(peer,wrapper_envelope_id) DO UPDATE SET\n\
                   acknowledged_at_ms=excluded.acknowledged_at_ms",
                params![
                    peer.as_slice(),
                    id.as_slice(),
                    now_ms
                        .map(|value| sql_u64(value, "bridge route acknowledgement time"))
                        .transpose()?
                ],
            )?;
            if inserted == 0 {
                return Err(StoreError::NotFound("active bridge route outbox object"));
            }
            transaction.execute(
                "INSERT INTO bridge_source_path_peer_receipts(\n\
                   peer,wrapper_envelope_id,origin_envelope_id,acknowledged_at_ms)\n\
                 SELECT ?1,w.wrapper_envelope_id,w.origin_envelope_id,g.acknowledged_at_ms\n\
                 FROM bridge_route_wrappers w JOIN bridge_source_peer_receipts g\n\
                   ON g.peer=?1 AND g.origin_envelope_id=w.origin_envelope_id\n\
                 WHERE w.wrapper_envelope_id=?2\n\
                 ON CONFLICT(peer,wrapper_envelope_id,origin_envelope_id) DO UPDATE SET\n\
                   acknowledged_at_ms=excluded.acknowledged_at_ms",
                params![peer.as_slice(), id.as_slice()],
            )?;
            transaction.execute(
                "INSERT INTO bridge_blob_carrier_peer_receipts(\n\
                   peer,wrapper_envelope_id,source_envelope_id,object_id,acknowledged_at_ms)\n\
                 SELECT ?1,w.wrapper_envelope_id,w.origin_envelope_id,g.object_id,\n\
                        g.acknowledged_at_ms\n\
                 FROM bridge_route_wrappers w JOIN bridge_blob_carrier_peer_possessions g\n\
                   ON g.peer=?1 AND g.source_envelope_id=w.origin_envelope_id\n\
                 WHERE w.wrapper_envelope_id=?2\n\
                 ON CONFLICT(peer,wrapper_envelope_id,source_envelope_id,object_id) DO UPDATE SET\n\
                   acknowledged_at_ms=excluded.acknowledged_at_ms",
                params![peer.as_slice(), id.as_slice()],
            )?;
            transaction.execute(
                "DELETE FROM bridge_route_peer_attempts\n\
                 WHERE peer=?1 AND wrapper_envelope_id=?2",
                params![peer.as_slice(), id.as_slice()],
            )?;
        }
        transaction.commit()?;
        Ok(())
    }

    fn bridge_source_is_servable_at(
        &self,
        origin_envelope_id: &EnvelopeId,
        sample: Option<CustodySample>,
    ) -> Result<bool, StoreError> {
        if !self.verified_bridge_sources.contains(origin_envelope_id) {
            return Ok(false);
        }
        let mut cursor = 0u64;
        let mut inspected = 0u64;
        loop {
            let rows = {
                let mut statement = self.connection.prepare(
                    "SELECT w.wrapper_envelope_id,w.inserted_order\n\
                     FROM bridge_route_wrappers w\n\
                     JOIN bridge_active_routes a ON a.wrapper_envelope_id=w.wrapper_envelope_id\n\
                     JOIN bridge_route_outbox o ON o.wrapper_envelope_id=w.wrapper_envelope_id\n\
                     WHERE w.origin_envelope_id=?1 AND w.inserted_order>?2\n\
                     ORDER BY w.inserted_order LIMIT ?3",
                )?;
                statement
                    .query_map(
                        params![
                            origin_envelope_id.as_slice(),
                            sql_u64(cursor, "bridge source route cursor")?,
                            i64::from(MAX_BRIDGE_STORE_BATCH as u16)
                        ],
                        |row| Ok((row.get::<_, Vec<u8>>(0)?, row.get::<_, i64>(1)?)),
                    )?
                    .collect::<Result<Vec<_>, _>>()?
            };
            if rows.is_empty() {
                return Ok(false);
            }
            let page_len = rows.len();
            for (id, order) in rows {
                let id = node_from_vec(id, "bridge source route reference")?;
                cursor = from_sql_u64(order, "bridge source route cursor")?;
                inspected = inspected.checked_add(1).ok_or(StoreError::QuotaExceeded)?;
                if inspected > self.config.max_items {
                    return Err(StoreError::Corrupt(
                        "bridge source route references exceed configured object bound".into(),
                    ));
                }
                if self.bridge_route_is_live_at(&id, sample)? {
                    return Ok(true);
                }
            }
            if page_len < MAX_BRIDGE_STORE_BATCH {
                return Ok(false);
            }
        }
    }

    pub(crate) fn next_bridge_source_outbound(
        &mut self,
        peer: NodeId,
        limit: usize,
        byte_budget: u64,
        sample: Option<CustodySample>,
    ) -> Result<Vec<StoredBridgeSource>, StoreError> {
        let selected = self.peek_bridge_source_outbound(peer, limit, byte_budget, sample)?;
        self.record_bridge_source_attempts(peer, &selected, None)?;
        Ok(selected)
    }

    /// Selects source envelopes only after this peer has acknowledged at least
    /// one live wrapper on the exact source path.
    pub(crate) fn peek_bridge_source_outbound(
        &mut self,
        peer: NodeId,
        limit: usize,
        byte_budget: u64,
        sample: Option<CustodySample>,
    ) -> Result<Vec<StoredBridgeSource>, StoreError> {
        let limit = limit.min(MAX_BRIDGE_STORE_BATCH);
        if limit == 0 || byte_budget == 0 || self.is_zeroized()? || self.is_revoked(&peer)? {
            return Ok(Vec::new());
        }
        let ids = {
            let mut statement = self.connection.prepare(
                "SELECT DISTINCT s.origin_envelope_id,MIN(o.enqueued_order) AS first_order\n\
                 FROM bridge_source_objects s\n\
                 JOIN bridge_route_wrappers w ON w.origin_envelope_id=s.origin_envelope_id\n\
                 JOIN bridge_active_routes a ON a.wrapper_envelope_id=w.wrapper_envelope_id\n\
                 JOIN bridge_route_outbox o ON o.wrapper_envelope_id=w.wrapper_envelope_id\n\
                 JOIN bridge_route_peer_receipts q\n\
                   ON q.peer=?1 AND q.wrapper_envelope_id=w.wrapper_envelope_id\n\
                 LEFT JOIN bridge_source_path_peer_receipts r\n\
                   ON r.peer=?1 AND r.wrapper_envelope_id=w.wrapper_envelope_id\n\
                  AND r.origin_envelope_id=s.origin_envelope_id\n\
                 LEFT JOIN bridge_source_peer_receipts g\n\
                   ON g.peer=?1 AND g.origin_envelope_id=s.origin_envelope_id\n\
                 LEFT JOIN bridge_source_peer_attempts x\n\
                   ON x.peer=?1 AND x.origin_envelope_id=s.origin_envelope_id\n\
                 WHERE r.origin_envelope_id IS NULL AND g.origin_envelope_id IS NULL\n\
                 GROUP BY s.origin_envelope_id\n\
                 ORDER BY coalesce(x.attempts,0),first_order LIMIT ?2",
            )?;
            statement
                .query_map(
                    params![peer.as_slice(), i64::from(MAX_BRIDGE_STORE_BATCH as u16)],
                    |row| row.get::<_, Vec<u8>>(0),
                )?
                .collect::<Result<Vec<_>, _>>()?
        };
        let mut selected = Vec::new();
        let mut used = 0u64;
        for id in ids {
            let id = node_from_vec(id, "bridge source outbox")?;
            if !self.bridge_source_is_servable_at(&id, sample)? {
                continue;
            }
            let source = self.stored_bridge_source(&id)?.ok_or(StoreError::Corrupt(
                "bridge source outbox is dangling".into(),
            ))?;
            let size = source.exact_bytes.len() as u64;
            if used.saturating_add(size) <= byte_budget {
                used = used.saturating_add(size);
                selected.push(source);
                if selected.len() == limit {
                    break;
                }
            }
        }
        Ok(selected)
    }

    pub(crate) fn record_bridge_source_attempts(
        &mut self,
        peer: NodeId,
        sources: &[StoredBridgeSource],
        now_ms: Option<u64>,
    ) -> Result<(), StoreError> {
        if sources.len() > MAX_BRIDGE_STORE_BATCH {
            return Err(StoreError::Invalid(
                "bridge source attempt batch exceeds bound".into(),
            ));
        }
        let transaction = self.connection.transaction()?;
        for source in sources {
            transaction.execute(
                "INSERT INTO bridge_source_peer_attempts(\n\
                   peer,origin_envelope_id,attempts,last_attempt_ms) VALUES(?1,?2,1,?3)\n\
                 ON CONFLICT(peer,origin_envelope_id) DO UPDATE SET\n\
                   attempts=attempts+1,last_attempt_ms=excluded.last_attempt_ms",
                params![
                    peer.as_slice(),
                    source.origin_envelope_id.as_slice(),
                    now_ms
                        .map(|value| sql_u64(value, "bridge source emission time"))
                        .transpose()?
                ],
            )?;
        }
        transaction.commit()?;
        Ok(())
    }

    pub(crate) fn read_bridge_source_range(
        &self,
        origin_envelope_id: &EnvelopeId,
        range: ChunkRange,
        max_bytes: usize,
        sample: Option<CustodySample>,
    ) -> Result<Vec<u8>, StoreError> {
        if range.is_empty() || max_bytes == 0 {
            return Ok(Vec::new());
        }
        if !self.bridge_source_is_servable_at(origin_envelope_id, sample)? {
            return Err(StoreError::NotFound("active bridge source object"));
        }
        let bytes = self
            .connection
            .query_row(
                "SELECT substr(CASE WHEN s.reused_item_id IS NULL THEN s.exact_bytes ELSE i.sealed END,?2,?3)\n\
                 FROM bridge_source_objects s LEFT JOIN items i\n\
                   ON i.item_id=s.reused_item_id AND i.envelope_id=s.origin_envelope_id\n\
                 WHERE s.origin_envelope_id=?1",
                params![
                    origin_envelope_id.as_slice(),
                    sql_u64(range.start.saturating_add(1), "bridge source read offset")?,
                    sql_u64(
                        range.len().min(max_bytes as u64),
                        "bridge source read length"
                    )?
                ],
                |row| row.get::<_, Vec<u8>>(0),
            )
            .optional()?;
        bytes.ok_or(StoreError::NotFound("active bridge source object"))
    }

    /// Records a source receipt for the exact active wrapper path that served
    /// it. This does not depend on wrapper-receipt arrival order: inventory may
    /// advertise the wrapper and source concurrently, while the active route,
    /// authorization chain, and custody clocks still have to be live.
    pub(crate) fn acknowledge_bridge_source_path_peer(
        &mut self,
        peer: NodeId,
        wrapper_envelope_id: EnvelopeId,
        origin_envelope_ids: &[EnvelopeId],
        now_ms: Option<u64>,
        sample: Option<CustodySample>,
    ) -> Result<(), StoreError> {
        if origin_envelope_ids.len() > MAX_BRIDGE_STORE_BATCH {
            return Err(StoreError::Invalid(
                "bridge source path receipt batch exceeds bound".into(),
            ));
        }
        if origin_envelope_ids.is_empty() {
            return Ok(());
        }
        if !self.bridge_route_is_live_at(&wrapper_envelope_id, sample)? {
            return Err(StoreError::NotFound("active bridge source receipt path"));
        }
        let route = self
            .stored_bridge_route(&wrapper_envelope_id)?
            .ok_or(StoreError::NotFound("active bridge source receipt path"))?;
        if origin_envelope_ids
            .iter()
            .any(|id| id != &route.origin_envelope_id)
        {
            return Err(StoreError::Invalid(
                "bridge source receipt does not match active wrapper path".into(),
            ));
        }
        let acknowledged_at_ms = now_ms
            .map(|value| sql_u64(value, "bridge source acknowledgement time"))
            .transpose()?;
        let transaction = self.connection.transaction()?;
        for id in origin_envelope_ids {
            transaction.execute(
                "INSERT INTO bridge_source_peer_receipts(\n\
                   peer,origin_envelope_id,acknowledged_at_ms) VALUES(?1,?2,?3)\n\
                 ON CONFLICT(peer,origin_envelope_id) DO UPDATE SET\n\
                   acknowledged_at_ms=excluded.acknowledged_at_ms",
                params![peer.as_slice(), id.as_slice(), acknowledged_at_ms],
            )?;
            let inserted = transaction.execute(
                "INSERT INTO bridge_source_path_peer_receipts(\n\
                   peer,wrapper_envelope_id,origin_envelope_id,acknowledged_at_ms)\n\
                 SELECT ?1,w.wrapper_envelope_id,w.origin_envelope_id,?4\n\
                 FROM bridge_route_wrappers w\n\
                 JOIN bridge_active_routes a ON a.wrapper_envelope_id=w.wrapper_envelope_id\n\
                 WHERE w.wrapper_envelope_id=?2 AND w.origin_envelope_id=?3\n\
                 ON CONFLICT(peer,wrapper_envelope_id,origin_envelope_id) DO UPDATE SET\n\
                   acknowledged_at_ms=excluded.acknowledged_at_ms",
                params![
                    peer.as_slice(),
                    wrapper_envelope_id.as_slice(),
                    id.as_slice(),
                    acknowledged_at_ms
                ],
            )?;
            if inserted == 0 {
                return Err(StoreError::NotFound("active bridge source receipt path"));
            }
            transaction.execute(
                "DELETE FROM bridge_source_peer_attempts\n\
                 WHERE peer=?1 AND origin_envelope_id=?2",
                params![peer.as_slice(), id.as_slice()],
            )?;
        }
        transaction.commit()?;
        Ok(())
    }

    pub(crate) fn acknowledge_bridge_source_peer(
        &mut self,
        peer: NodeId,
        origin_envelope_ids: &[EnvelopeId],
        now_ms: Option<u64>,
        sample: Option<CustodySample>,
    ) -> Result<(), StoreError> {
        if origin_envelope_ids.len() > MAX_BRIDGE_STORE_BATCH {
            return Err(StoreError::Invalid(
                "bridge source receipt batch exceeds bound".into(),
            ));
        }
        for id in origin_envelope_ids {
            if !self.bridge_source_is_servable_at(id, sample)? {
                return Err(StoreError::NotFound("active bridge source object"));
            }
        }
        let transaction = self.connection.transaction()?;
        for id in origin_envelope_ids {
            let inserted = transaction.execute(
                "INSERT INTO bridge_source_peer_receipts(peer,origin_envelope_id,acknowledged_at_ms)\n\
                 SELECT ?1,s.origin_envelope_id,?3 FROM bridge_source_objects s\n\
                 WHERE s.origin_envelope_id=?2 AND EXISTS(\n\
                   SELECT 1 FROM bridge_route_wrappers w\n\
                   JOIN bridge_active_routes a ON a.wrapper_envelope_id=w.wrapper_envelope_id\n\
                   JOIN bridge_route_outbox o ON o.wrapper_envelope_id=w.wrapper_envelope_id\n\
                   JOIN bridge_route_peer_receipts q\n\
                     ON q.peer=?1 AND q.wrapper_envelope_id=w.wrapper_envelope_id\n\
                   WHERE w.origin_envelope_id=s.origin_envelope_id)\n\
                 ON CONFLICT(peer,origin_envelope_id) DO UPDATE SET\n\
                   acknowledged_at_ms=excluded.acknowledged_at_ms",
                params![
                    peer.as_slice(),
                    id.as_slice(),
                    now_ms
                        .map(|value| sql_u64(value, "bridge source acknowledgement time"))
                        .transpose()?
                ],
            )?;
            if inserted == 0 {
                return Err(StoreError::NotFound("active bridge source object"));
            }
            transaction.execute(
                "INSERT INTO bridge_source_path_peer_receipts(\n\
                   peer,wrapper_envelope_id,origin_envelope_id,acknowledged_at_ms)\n\
                 SELECT ?1,w.wrapper_envelope_id,w.origin_envelope_id,?3\n\
                 FROM bridge_route_wrappers w\n\
                 JOIN bridge_active_routes a ON a.wrapper_envelope_id=w.wrapper_envelope_id\n\
                 JOIN bridge_route_peer_receipts q\n\
                   ON q.peer=?1 AND q.wrapper_envelope_id=w.wrapper_envelope_id\n\
                 WHERE w.origin_envelope_id=?2\n\
                 ON CONFLICT(peer,wrapper_envelope_id,origin_envelope_id) DO UPDATE SET\n\
                   acknowledged_at_ms=excluded.acknowledged_at_ms",
                params![
                    peer.as_slice(),
                    id.as_slice(),
                    now_ms
                        .map(|value| sql_u64(value, "bridge source acknowledgement time"))
                        .transpose()?
                ],
            )?;
            transaction.execute(
                "DELETE FROM bridge_source_peer_attempts\n\
                 WHERE peer=?1 AND origin_envelope_id=?2",
                params![peer.as_slice(), id.as_slice()],
            )?;
        }
        transaction.commit()?;
        Ok(())
    }

    fn bridge_route_persistently_eligible_at(
        &self,
        wrapper_envelope_id: &EnvelopeId,
        sample: Option<CustodySample>,
    ) -> Result<bool, StoreError> {
        let Some(route) = self.stored_bridge_route(wrapper_envelope_id)? else {
            return Err(StoreError::Corrupt("bridge route is missing".into()));
        };
        let Some(source) = self.stored_bridge_source(&route.origin_envelope_id)? else {
            return Err(StoreError::Corrupt("bridge source is missing".into()));
        };
        // Bridge source metadata has no trustworthy wall-clock observation
        // timestamp from which to prove the configured tombstone-retention
        // interval. Preserve it conservatively instead of evicting early.
        if source.metadata.tombstone {
            return Ok(true);
        }
        if let Some(sample) = sample
            && (!bridge_custody_is_live(
                route.ttl_ms,
                source.metadata.tombstone,
                route.cumulative_custody_age_ms,
                route.age_continuity_unknown,
                route.custody_clock_id,
                route.custody_tick_ms,
                route.custody_elapsed_available,
                Some(sample),
            ) || !bridge_custody_is_live(
                source.metadata.ttl_ms,
                source.metadata.tombstone,
                source.cumulative_custody_age_ms,
                source.age_continuity_unknown,
                source.custody_clock_id,
                source.custody_tick_ms,
                source.custody_elapsed_available,
                Some(sample),
            ))
        {
            return Ok(false);
        }
        let epochs_live: i64 = self.connection.query_row(
            "SELECT EXISTS(SELECT 1 FROM scope_epochs WHERE scope=?1 AND epoch=?2)\n\
             AND EXISTS(SELECT 1 FROM scope_epochs WHERE scope=?3 AND epoch=?4)",
            params![
                route.origin_scope.as_str(),
                sql_u64(route.origin_route_epoch, "bridge origin route epoch")?,
                route.current_scope.as_str(),
                sql_u64(route.current_route_epoch, "bridge current route epoch")?
            ],
            |row| row.get(0),
        )?;
        if epochs_live == 0 {
            return Ok(false);
        }
        let source_revoked: i64 = self.connection.query_row(
            "SELECT EXISTS(SELECT 1 FROM revocations WHERE subject=?1)",
            params![route.source_publisher.as_slice()],
            |row| row.get(0),
        )?;
        if source_revoked != 0 {
            return Ok(false);
        }
        let (dependency_count, live_count): (i64, i64) = self.connection.query_row(
            "SELECT count(*),coalesce(sum(CASE WHEN EXISTS(\n\
                 SELECT 1 FROM bridge_authorization_highwater h\n\
                 JOIN bridge_authorization_controls c ON c.envelope_id=h.envelope_id\n\
                 WHERE h.envelope_id=e.authorization_envelope_id AND h.enabled=1\n\
                   AND c.applied=1 AND NOT EXISTS(SELECT 1 FROM revocations r\n\
                     WHERE r.subject IN\n\
                       (c.authority_id,c.control_signer,c.bridge_node_id)))\n\
               THEN 1 ELSE 0 END),0)\n\
             FROM bridge_wrapper_authorizations e WHERE e.wrapper_envelope_id=?1",
            params![wrapper_envelope_id.as_slice()],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )?;
        Ok(
            from_sql_u64(dependency_count, "bridge dependency count")?
                == u64::from(route.hop_count)
                && dependency_count == live_count,
        )
    }

    /// Bounded reference-safe bridge lifecycle collection. Historical
    /// authority heads/high-water and latest disable evidence are never
    /// candidates.
    pub(crate) fn collect_bridge_garbage(
        &mut self,
        sample: Option<CustodySample>,
        limit: usize,
    ) -> Result<BridgeGcReport, StoreError> {
        let limit = limit.min(MAX_BRIDGE_STORE_BATCH);
        if limit == 0 {
            return Ok(BridgeGcReport::default());
        }
        let mut victims = Vec::new();
        let mut priority_cursor = -1i64;
        let mut order_cursor = 0u64;
        let mut inspected = 0u64;
        while victims.len() < limit {
            let rows = {
                let mut statement = self.connection.prepare(
                    "SELECT wrapper_envelope_id,source_priority,inserted_order\n\
                     FROM bridge_route_wrappers\n\
                     WHERE source_priority>?1 OR\n\
                       (source_priority=?1 AND inserted_order>?2)\n\
                     ORDER BY source_priority ASC,inserted_order LIMIT ?3",
                )?;
                statement
                    .query_map(
                        params![
                            priority_cursor,
                            sql_u64(order_cursor, "bridge GC cursor")?,
                            i64::from(MAX_BRIDGE_STORE_BATCH as u16)
                        ],
                        |row| {
                            Ok((
                                row.get::<_, Vec<u8>>(0)?,
                                row.get::<_, i64>(1)?,
                                row.get::<_, i64>(2)?,
                            ))
                        },
                    )?
                    .collect::<Result<Vec<_>, _>>()?
            };
            if rows.is_empty() {
                break;
            }
            let page_len = rows.len();
            for (wrapper, priority, order) in rows {
                let wrapper = node_from_vec(wrapper, "bridge GC wrapper")?;
                priority_cursor = priority;
                order_cursor = from_sql_u64(order, "bridge GC order")?;
                inspected = inspected.checked_add(1).ok_or(StoreError::QuotaExceeded)?;
                if inspected > self.config.max_items {
                    return Err(StoreError::Corrupt(
                        "bridge GC scan exceeded configured object bound".into(),
                    ));
                }
                if !self.bridge_route_persistently_eligible_at(&wrapper, sample)? {
                    victims.push(wrapper);
                    if victims.len() == limit {
                        break;
                    }
                }
            }
            if page_len < MAX_BRIDGE_STORE_BATCH {
                break;
            }
        }
        let mut victim_routes = Vec::with_capacity(victims.len());
        for wrapper in &victims {
            let route = self
                .stored_bridge_route(wrapper)?
                .ok_or(StoreError::Corrupt("bridge GC victim disappeared".into()))?;
            let was_active: i64 = self.connection.query_row(
                "SELECT EXISTS(SELECT 1 FROM bridge_active_routes\n\
                 WHERE wrapper_envelope_id=?1)",
                params![wrapper.as_slice()],
                |row| row.get(0),
            )?;
            victim_routes.push((route, was_active != 0));
        }
        let transaction = self.connection.transaction()?;
        let mut report = BridgeGcReport::default();
        for wrapper in victims {
            let removed = evict_bridge_mapping_tx(&transaction, wrapper)?;
            report.mappings = report.mappings.saturating_add(removed.mappings);
            report.wrappers = report.wrappers.saturating_add(removed.wrappers);
            report.sources = report.sources.saturating_add(removed.sources);
            report.metadata_rows = report.metadata_rows.saturating_add(removed.metadata_rows);
        }
        let remaining = limit.saturating_sub(report.wrappers as usize);
        let authorization_cleanup =
            cleanup_unreferenced_bridge_authorizations_tx(&transaction, remaining)?;
        report.authorizations = authorization_cleanup.0;
        report.metadata_rows = report.metadata_rows.saturating_add(authorization_cleanup.1);
        transaction.commit()?;
        for (route, _) in &victim_routes {
            self.verified_bridge_routes
                .remove(&route.wrapper_envelope_id);
            if self
                .stored_bridge_source(&route.origin_envelope_id)?
                .is_none()
            {
                self.verified_bridge_sources
                    .remove(&route.origin_envelope_id);
            }
        }
        for (route, was_active) in victim_routes {
            if was_active {
                self.activate_best_live_bridge_alternate(
                    route.origin_envelope_id,
                    &route.current_scope,
                    route.current_route_epoch,
                    sample,
                )?;
            }
        }
        Ok(report)
    }

    fn activate_best_live_bridge_alternate(
        &mut self,
        origin_envelope_id: EnvelopeId,
        current_scope: &Scope,
        current_route_epoch: u64,
        sample: Option<CustodySample>,
    ) -> Result<bool, StoreError> {
        let candidates = {
            let mut statement = self.connection.prepare(
                "SELECT wrapper_envelope_id FROM bridge_route_wrappers\n\
                 WHERE origin_envelope_id=?1 AND current_scope=?2 AND current_route_epoch=?3\n\
                 ORDER BY hop_count ASC,bridge_route_id ASC",
            )?;
            statement
                .query_map(
                    params![
                        origin_envelope_id.as_slice(),
                        current_scope.as_str(),
                        sql_u64(current_route_epoch, "bridge alternate route epoch")?
                    ],
                    |row| row.get::<_, Vec<u8>>(0),
                )?
                .collect::<Result<Vec<_>, _>>()?
        };
        let mut selected = None;
        for candidate in candidates {
            let candidate = node_from_vec(candidate, "bridge alternate wrapper")?;
            if self.bridge_route_candidate_is_live_at(&candidate, sample, false)? {
                selected = Some(candidate);
                break;
            }
        }
        let Some(selected) = selected else {
            return Ok(false);
        };
        let route = self
            .stored_bridge_route(&selected)?
            .ok_or(StoreError::Corrupt("bridge alternate disappeared".into()))?;
        let source = self
            .stored_bridge_source(&route.origin_envelope_id)?
            .ok_or(StoreError::Corrupt(
                "bridge alternate source disappeared".into(),
            ))?;
        let transaction = self.connection.transaction()?;
        transaction.execute(
            "INSERT INTO bridge_active_routes(\n\
               origin_envelope_id,current_scope,current_route_epoch,wrapper_envelope_id)\n\
             VALUES(?1,?2,?3,?4)\n\
             ON CONFLICT(origin_envelope_id,current_scope,current_route_epoch) DO UPDATE SET\n\
               wrapper_envelope_id=excluded.wrapper_envelope_id",
            params![
                origin_envelope_id.as_slice(),
                current_scope.as_str(),
                sql_u64(current_route_epoch, "bridge alternate route epoch")?,
                selected.as_slice()
            ],
        )?;
        transaction.execute(
            "INSERT INTO bridge_target_projection(\n\
               wrapper_envelope_id,source_item_id,target_scope,target_route_epoch,version_status)\n\
             VALUES(?1,?2,?3,?4,?5)\n\
             ON CONFLICT(wrapper_envelope_id) DO UPDATE SET\n\
               source_item_id=excluded.source_item_id,target_scope=excluded.target_scope,\n\
               target_route_epoch=excluded.target_route_epoch",
            params![
                selected.as_slice(),
                source.metadata.source_item_id.as_slice(),
                current_scope.as_str(),
                sql_u64(current_route_epoch, "bridge alternate projection epoch")?,
                VersionStatus::Current as u8 as i64
            ],
        )?;
        recompute_bridge_projection_group_tx(
            &transaction,
            &source.metadata,
            current_scope,
            current_route_epoch,
            self.config.max_items,
        )?;
        let order = next_order(&transaction)?;
        transaction.execute(
            "INSERT INTO bridge_route_outbox(wrapper_envelope_id,enqueued_order)\n\
             VALUES(?1,?2) ON CONFLICT(wrapper_envelope_id) DO NOTHING",
            params![
                selected.as_slice(),
                sql_u64(order, "bridge alternate outbox order")?
            ],
        )?;
        transaction.commit()?;
        Ok(true)
    }

    pub(crate) fn delete_bridge_wrapper(
        &mut self,
        wrapper_envelope_id: &EnvelopeId,
    ) -> Result<bool, StoreError> {
        let transaction = self.connection.transaction()?;
        let referenced: i64 = transaction.query_row(
            "SELECT EXISTS(SELECT 1 FROM bridge_active_routes WHERE wrapper_envelope_id=?1)\n\
             OR EXISTS(SELECT 1 FROM bridge_route_outbox WHERE wrapper_envelope_id=?1)\n\
             OR EXISTS(SELECT 1 FROM bridge_route_peer_receipts WHERE wrapper_envelope_id=?1)",
            params![wrapper_envelope_id.as_slice()],
            |row| row.get(0),
        )?;
        if referenced != 0 {
            return Err(StoreError::BridgeObjectReferenced);
        }
        transaction.execute(
            "DELETE FROM bridge_wrapper_authorizations WHERE wrapper_envelope_id=?1",
            params![wrapper_envelope_id.as_slice()],
        )?;
        let deleted = transaction.execute(
            "DELETE FROM bridge_route_wrappers WHERE wrapper_envelope_id=?1",
            params![wrapper_envelope_id.as_slice()],
        )?;
        transaction.commit()?;
        self.verified_bridge_routes.remove(wrapper_envelope_id);
        Ok(deleted == 1)
    }

    pub(crate) fn delete_bridge_source(
        &mut self,
        origin_envelope_id: &EnvelopeId,
    ) -> Result<bool, StoreError> {
        let referenced: i64 = self.connection.query_row(
            "SELECT EXISTS(SELECT 1 FROM bridge_route_wrappers WHERE origin_envelope_id=?1)\n\
             OR EXISTS(SELECT 1 FROM bridge_source_peer_receipts WHERE origin_envelope_id=?1)",
            params![origin_envelope_id.as_slice()],
            |row| row.get(0),
        )?;
        if referenced != 0 {
            return Err(StoreError::BridgeObjectReferenced);
        }
        Ok(self.connection.execute(
            "DELETE FROM bridge_source_objects WHERE origin_envelope_id=?1",
            params![origin_envelope_id.as_slice()],
        )? == 1)
    }

    pub(crate) fn delete_bridge_authorization(
        &mut self,
        envelope_id: &EnvelopeId,
    ) -> Result<bool, StoreError> {
        let transaction = self.connection.transaction()?;
        let referenced: i64 = transaction.query_row(
            "SELECT EXISTS(SELECT 1 FROM bridge_authorization_heads WHERE envelope_id=?1)\n\
             OR EXISTS(SELECT 1 FROM bridge_authorization_highwater WHERE envelope_id=?1)\n\
             OR EXISTS(SELECT 1 FROM bridge_authorization_outbox WHERE envelope_id=?1)\n\
             OR EXISTS(SELECT 1 FROM bridge_authorization_peer_receipts WHERE envelope_id=?1)\n\
             OR EXISTS(SELECT 1 FROM bridge_wrapper_authorizations\n\
                       WHERE authorization_envelope_id=?1)\n\
             OR EXISTS(SELECT 1 FROM bridge_authorization_controls\n\
                       WHERE previous_control_id=?1)",
            params![envelope_id.as_slice()],
            |row| row.get(0),
        )?;
        if referenced != 0 {
            return Err(StoreError::BridgeObjectReferenced);
        }
        transaction.execute(
            "DELETE FROM bridge_authorization_topics WHERE envelope_id=?1",
            params![envelope_id.as_slice()],
        )?;
        let deleted = transaction.execute(
            "DELETE FROM bridge_authorization_controls WHERE envelope_id=?1",
            params![envelope_id.as_slice()],
        )?;
        transaction.commit()?;
        self.verified_bridge_authorizations.remove(envelope_id);
        Ok(deleted == 1)
    }

    /// Returns the exact unacknowledged authorization predecessor chain needed
    /// by one route and peer. Each authority chain is earliest-first; durable
    /// rows that were not provider-reverified in this process are withheld.
    pub(crate) fn peek_bridge_authorization_chain_for_route(
        &self,
        peer: NodeId,
        wrapper_envelope_id: EnvelopeId,
        limit: usize,
        byte_budget: u64,
        sample: Option<CustodySample>,
    ) -> Result<Vec<StoredBridgeAuthorization>, StoreError> {
        let limit = limit.min(MAX_BRIDGE_STORE_BATCH);
        if limit == 0
            || byte_budget == 0
            || !self.bridge_route_is_live_at(&wrapper_envelope_id, sample)?
        {
            return Ok(Vec::new());
        }
        let dependencies = {
            let mut statement = self.connection.prepare(
                "SELECT authorization_envelope_id FROM bridge_wrapper_authorizations\n\
                 WHERE wrapper_envelope_id=?1 ORDER BY hop_index",
            )?;
            statement
                .query_map(params![wrapper_envelope_id.as_slice()], |row| {
                    row.get::<_, Vec<u8>>(0)
                })?
                .collect::<Result<Vec<_>, _>>()?
        };
        let mut ordered = Vec::new();
        let mut seen = BTreeSet::new();
        for dependency in dependencies {
            let mut cursor = Some(node_from_vec(
                dependency,
                "bridge route authorization dependency",
            )?);
            let mut reverse_chain = Vec::new();
            let mut traversed = 0u64;
            while let Some(envelope_id) = cursor {
                traversed = traversed.checked_add(1).ok_or(StoreError::QuotaExceeded)?;
                if traversed > MAX_ACTIVE_BRIDGE_AUTHORIZATIONS {
                    return Err(StoreError::Corrupt(
                        "bridge authorization predecessor chain exceeds bound".into(),
                    ));
                }
                let acknowledged: i64 = self.connection.query_row(
                    "SELECT EXISTS(SELECT 1 FROM bridge_authorization_peer_receipts\n\
                     WHERE peer=?1 AND envelope_id=?2)",
                    params![peer.as_slice(), envelope_id.as_slice()],
                    |row| row.get(0),
                )?;
                if acknowledged == 1 {
                    break;
                }
                let stored = self
                    .stored_bridge_authorization(&envelope_id)?
                    .ok_or(StoreError::BridgeDependencyMissing)?;
                if !stored.applied
                    || !self
                        .verified_bridge_authorizations
                        .contains(&stored.envelope_id)
                {
                    return Ok(Vec::new());
                }
                cursor = stored.authorization.previous_control_id;
                reverse_chain.push(stored);
            }
            reverse_chain.reverse();
            for authorization in reverse_chain {
                if seen.insert(authorization.envelope_id) {
                    ordered.push(authorization);
                }
            }
        }
        let mut selected = Vec::new();
        let mut used = 0u64;
        for authorization in ordered {
            let size = authorization.exact_bytes.len() as u64;
            if used.saturating_add(size) > byte_budget {
                break;
            }
            used = used.saturating_add(size);
            selected.push(authorization);
            if selected.len() == limit {
                break;
            }
        }
        Ok(selected)
    }

    pub(crate) fn next_bridge_authorization_outbound(
        &mut self,
        peer: NodeId,
        limit: usize,
        byte_budget: u64,
        now_ms: Option<u64>,
    ) -> Result<Vec<StoredBridgeAuthorization>, StoreError> {
        let selected = self.peek_bridge_authorization_outbound(peer, limit, byte_budget)?;
        self.record_bridge_authorization_attempts(peer, &selected, now_ms)?;
        Ok(selected)
    }

    pub(crate) fn peek_bridge_authorization_outbound(
        &mut self,
        peer: NodeId,
        limit: usize,
        byte_budget: u64,
    ) -> Result<Vec<StoredBridgeAuthorization>, StoreError> {
        let limit = limit.min(MAX_BRIDGE_STORE_BATCH);
        if limit == 0 || byte_budget == 0 || self.is_zeroized()? || self.is_revoked(&peer)? {
            return Ok(Vec::new());
        }
        let ids = {
            let mut statement = self.connection.prepare(
                "SELECT c.envelope_id FROM bridge_authorization_outbox o\n\
                 JOIN bridge_authorization_controls c ON c.envelope_id=o.envelope_id\n\
                 LEFT JOIN bridge_authorization_peer_receipts r\n\
                   ON r.peer=?1 AND r.envelope_id=c.envelope_id\n\
                 LEFT JOIN bridge_authorization_peer_attempts x\n\
                   ON x.peer=?1 AND x.envelope_id=c.envelope_id\n\
                 WHERE c.applied=1 AND r.envelope_id IS NULL\n\
                 ORDER BY coalesce(x.attempts,0),o.enqueued_order LIMIT ?2",
            )?;
            statement
                .query_map(
                    params![peer.as_slice(), i64::from(MAX_BRIDGE_STORE_BATCH as u16)],
                    |row| row.get::<_, Vec<u8>>(0),
                )?
                .collect::<Result<Vec<_>, _>>()?
        };
        let mut selected = Vec::new();
        let mut used = 0u64;
        for id in ids {
            let id = node_from_vec(id, "bridge authorization outbox")?;
            if !self.verified_bridge_authorizations.contains(&id) {
                continue;
            }
            let authorization =
                self.stored_bridge_authorization(&id)?
                    .ok_or(StoreError::Corrupt(
                        "bridge authorization outbox is dangling".into(),
                    ))?;
            let size = authorization.exact_bytes.len() as u64;
            if used.saturating_add(size) <= byte_budget {
                used = used.saturating_add(size);
                selected.push(authorization);
                if selected.len() == limit {
                    break;
                }
            }
        }
        Ok(selected)
    }

    pub(crate) fn record_bridge_authorization_attempts(
        &mut self,
        peer: NodeId,
        authorizations: &[StoredBridgeAuthorization],
        now_ms: Option<u64>,
    ) -> Result<(), StoreError> {
        if authorizations.len() > MAX_BRIDGE_STORE_BATCH {
            return Err(StoreError::Invalid(
                "bridge authorization attempt batch exceeds bound".into(),
            ));
        }
        let transaction = self.connection.transaction()?;
        for authorization in authorizations {
            transaction.execute(
                "INSERT INTO bridge_authorization_peer_attempts(\n\
                   peer,envelope_id,attempts,last_attempt_ms) VALUES(?1,?2,1,?3)\n\
                 ON CONFLICT(peer,envelope_id) DO UPDATE SET\n\
                   attempts=attempts+1,last_attempt_ms=excluded.last_attempt_ms",
                params![
                    peer.as_slice(),
                    authorization.envelope_id.as_slice(),
                    now_ms
                        .map(|value| sql_u64(value, "bridge authorization emission time"))
                        .transpose()?
                ],
            )?;
        }
        transaction.commit()?;
        Ok(())
    }

    pub(crate) fn read_bridge_authorization_range(
        &self,
        envelope_id: &EnvelopeId,
        range: ChunkRange,
        max_bytes: usize,
    ) -> Result<Vec<u8>, StoreError> {
        if range.is_empty() || max_bytes == 0 {
            return Ok(Vec::new());
        }
        if !self.verified_bridge_authorizations.contains(envelope_id) {
            return Err(StoreError::NotFound(
                "process-verified bridge authorization outbox object",
            ));
        }
        let bytes = self
            .connection
            .query_row(
                "SELECT substr(c.exact_bytes,?2,?3)\n\
                 FROM bridge_authorization_controls c JOIN bridge_authorization_outbox o\n\
                   ON o.envelope_id=c.envelope_id\n\
                 WHERE c.envelope_id=?1 AND c.applied=1",
                params![
                    envelope_id.as_slice(),
                    sql_u64(
                        range.start.saturating_add(1),
                        "bridge authorization read offset"
                    )?,
                    sql_u64(
                        range.len().min(max_bytes as u64),
                        "bridge authorization read length"
                    )?
                ],
                |row| row.get::<_, Vec<u8>>(0),
            )
            .optional()?;
        bytes.ok_or(StoreError::NotFound(
            "active bridge authorization outbox object",
        ))
    }

    pub(crate) fn acknowledge_bridge_authorization_peer(
        &mut self,
        peer: NodeId,
        envelope_ids: &[EnvelopeId],
        now_ms: Option<u64>,
    ) -> Result<(), StoreError> {
        if envelope_ids.len() > MAX_BRIDGE_STORE_BATCH {
            return Err(StoreError::Invalid(
                "bridge authorization receipt batch exceeds bound".into(),
            ));
        }
        if envelope_ids
            .iter()
            .any(|id| !self.verified_bridge_authorizations.contains(id))
        {
            return Err(StoreError::NotFound(
                "process-verified bridge authorization outbox object",
            ));
        }
        let transaction = self.connection.transaction()?;
        for envelope_id in envelope_ids {
            let inserted = transaction.execute(
                "INSERT INTO bridge_authorization_peer_receipts(peer,envelope_id,acknowledged_at_ms)\n\
                 SELECT ?1,c.envelope_id,?3 FROM bridge_authorization_controls c\n\
                 JOIN bridge_authorization_outbox o ON o.envelope_id=c.envelope_id\n\
                 WHERE c.envelope_id=?2 AND c.applied=1\n\
                 ON CONFLICT(peer,envelope_id) DO UPDATE SET\n\
                   acknowledged_at_ms=excluded.acknowledged_at_ms",
                params![
                    peer.as_slice(),
                    envelope_id.as_slice(),
                    now_ms
                        .map(|value| sql_u64(value, "bridge authorization acknowledgement time"))
                        .transpose()?
                ],
            )?;
            if inserted == 0 {
                return Err(StoreError::NotFound(
                    "active bridge authorization outbox object",
                ));
            }
            transaction.execute(
                "DELETE FROM bridge_authorization_peer_attempts\n\
                 WHERE peer=?1 AND envelope_id=?2",
                params![peer.as_slice(), envelope_id.as_slice()],
            )?;
        }
        transaction.commit()?;
        Ok(())
    }

    /// Reads exact durable bytes and canonical metadata without treating a
    /// reopened record as cryptographically live.
    pub(crate) fn stored_bridge_authorization(
        &self,
        envelope_id: &EnvelopeId,
    ) -> Result<Option<StoredBridgeAuthorization>, StoreError> {
        let row = self
            .connection
            .query_row(
                "SELECT authorization_body,control_signer,exact_bytes,applied,inserted_order\n\
                 FROM bridge_authorization_controls WHERE envelope_id=?1",
                params![envelope_id.as_slice()],
                |row| {
                    Ok((
                        row.get::<_, Vec<u8>>(0)?,
                        row.get::<_, Vec<u8>>(1)?,
                        row.get::<_, Vec<u8>>(2)?,
                        row.get::<_, i64>(3)?,
                        row.get::<_, i64>(4)?,
                    ))
                },
            )
            .optional()?;
        let Some((body, control_signer, exact_bytes, applied, inserted_order)) = row else {
            return Ok(None);
        };
        if exact_object_id(&exact_bytes) != *envelope_id {
            return Err(StoreError::Corrupt(
                "stored bridge authorization identity is invalid".into(),
            ));
        }
        let authorization = BridgeAuthorization::decode(&body)
            .map_err(|error| StoreError::Corrupt(error.to_string()))?;
        if authorization
            .encode()
            .map_err(|error| StoreError::Corrupt(error.to_string()))?
            != body
        {
            return Err(StoreError::Corrupt(
                "stored bridge authorization is not canonical".into(),
            ));
        }
        Ok(Some(StoredBridgeAuthorization {
            envelope_id: *envelope_id,
            authorization,
            control_signer: node_from_vec(control_signer, "bridge control signer")?,
            exact_bytes,
            applied: match applied {
                0 => false,
                1 => true,
                _ => {
                    return Err(StoreError::Corrupt(
                        "stored bridge authorization has invalid applied state".into(),
                    ));
                }
            },
            inserted_order: from_sql_u64(inserted_order, "bridge insertion order")?,
        }))
    }

    /// Bounded restart reload in independent authority-chain order. Reading
    /// controls never populates the process-local verified set.
    pub(crate) fn stored_bridge_authorizations(
        &self,
        limit: usize,
    ) -> Result<Vec<StoredBridgeAuthorization>, StoreError> {
        self.stored_bridge_authorizations_after(None, limit)
    }

    pub(crate) fn stored_bridge_authorizations_after(
        &self,
        after: Option<BridgeAuthorizationCursor>,
        limit: usize,
    ) -> Result<Vec<StoredBridgeAuthorization>, StoreError> {
        let limit = limit.min(MAX_BRIDGE_STORE_BATCH);
        if limit == 0 {
            return Ok(Vec::new());
        }
        let ids = if let Some(after) = after {
            let mut statement = self.connection.prepare(
                "SELECT envelope_id FROM bridge_authorization_controls\n\
                 WHERE authority_id>?1 OR (authority_id=?1 AND sequence>?2)\n\
                 ORDER BY authority_id,sequence LIMIT ?3",
            )?;
            statement
                .query_map(
                    params![
                        after.authority_id.as_slice(),
                        sql_u64(after.sequence, "bridge authorization cursor sequence")?,
                        i64::try_from(limit).map_err(|_| StoreError::QuotaExceeded)?
                    ],
                    |row| row.get::<_, Vec<u8>>(0),
                )?
                .collect::<Result<Vec<_>, _>>()?
        } else {
            let mut statement = self.connection.prepare(
                "SELECT envelope_id FROM bridge_authorization_controls\n\
                 ORDER BY authority_id,sequence LIMIT ?1",
            )?;
            statement
                .query_map(
                    params![i64::try_from(limit).map_err(|_| StoreError::QuotaExceeded)?],
                    |row| row.get::<_, Vec<u8>>(0),
                )?
                .collect::<Result<Vec<_>, _>>()?
        };
        ids.into_iter()
            .map(|id| {
                let id = node_from_vec(id, "stored bridge authorization")?;
                self.stored_bridge_authorization(&id)?
                    .ok_or(StoreError::Corrupt(
                        "stored bridge authorization disappeared".into(),
                    ))
            })
            .collect()
    }
}

#[allow(dead_code)]
fn bridge_source_select(table: &str) -> String {
    bridge_source_select_with_exact(table, "exact_bytes")
}

#[allow(dead_code)]
fn bridge_source_select_with_exact(table: &str, exact_expression: &str) -> String {
    format!(
        "SELECT origin_envelope_id,source_item_id,source_publisher,data_class,source_topic,\
         source_priority,causal_counter,causal_context,event_sequence,logical_key,source_ttl_ms,\
         blob_id,blob_chunk_count,blob_merkle_root,content_len,tombstone,origin_scope,\
         origin_route_epoch,forwarding_custody_age_ms,cumulative_custody_age_ms,\
         source_age_continuity_unknown,source_custody_clock_id,source_custody_tick_ms,\
         source_custody_elapsed_available,{exact_expression},inserted_order \
         FROM {table} WHERE origin_envelope_id=?1"
    )
}

#[allow(dead_code)]
fn insert_pending_bridge_wrapper_tx(
    transaction: &Transaction<'_>,
    config: &StoreConfig,
    verified: &VerifiedPendingBridgeWrapper,
    sample: Option<CustodySample>,
) -> Result<(), StoreError> {
    let route_body = verified
        .route
        .encode()
        .map_err(|error| StoreError::Invalid(error.to_string()))?;
    let dependency_bytes = (verified.route.hops.len() as u64)
        .checked_mul(80)
        .ok_or(StoreError::QuotaExceeded)?;
    let accounted_bytes = (verified.exact_wrapper_bytes.len() as u64)
        .checked_add(route_body.len() as u64)
        .and_then(|value| value.checked_add(dependency_bytes))
        .and_then(|value| value.checked_add(512))
        .ok_or(StoreError::QuotaExceeded)?;
    let final_hop = verified
        .route
        .hops
        .last()
        .ok_or(StoreError::BridgeDependencyMissing)?;
    let elapsed_available = !final_hop.age_continuity_unknown && sample.is_some();
    ensure_bridge_admission(transaction, config, 1, accounted_bytes)?;
    let inserted_order = next_order(transaction)?;
    transaction.execute(
        "INSERT INTO bridge_pending_wrappers(\n\
           wrapper_envelope_id,bridge_route_id,origin_envelope_id,source_item_id,\n\
           origin_scope,origin_route_epoch,current_scope,current_route_epoch,hop_count,\n\
           cumulative_custody_age_ms,forwarding_custody_age_ms,age_continuity_unknown,\n\
           custody_clock_id,custody_tick_ms,custody_elapsed_available,route_body,exact_bytes,\n\
           inserted_order,accounted_bytes)\n\
         VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14,?15,?16,?17,?18,?19)",
        params![
            verified.wrapper_envelope_id.as_slice(),
            verified.route.bridge_route_id.as_slice(),
            verified.route.origin_envelope_id.as_slice(),
            verified.route.source_item_id.as_slice(),
            verified.route.origin_scope.as_str(),
            sql_u64(
                verified.route.origin_route_epoch,
                "pending bridge origin epoch"
            )?,
            verified.route.current_scope.as_str(),
            sql_u64(
                verified.route.current_route_epoch,
                "pending bridge current epoch"
            )?,
            i64::try_from(verified.route.hops.len()).map_err(|_| StoreError::QuotaExceeded)?,
            sql_u64(
                final_hop
                    .cumulative_custody_age_ms
                    .max(verified.authenticated_forwarding_age_ms),
                "pending bridge custody age"
            )?,
            sql_u64(
                verified.authenticated_forwarding_age_ms,
                "authenticated wrapper forwarding age"
            )?,
            i64::from(final_hop.age_continuity_unknown),
            sample
                .filter(|_| elapsed_available)
                .map(|value| value.clock_id),
            sample
                .filter(|_| elapsed_available)
                .map(|value| sql_u64(value.tick_ms, "pending bridge custody tick"))
                .transpose()?,
            i64::from(elapsed_available),
            route_body,
            &verified.exact_wrapper_bytes,
            sql_u64(inserted_order, "pending bridge wrapper order")?,
            sql_u64(accounted_bytes, "pending bridge wrapper bytes")?
        ],
    )?;
    for (index, hop) in verified.route.hops.iter().enumerate() {
        transaction.execute(
            "INSERT INTO bridge_pending_wrapper_authorizations(\n\
               wrapper_envelope_id,hop_index,authorization_envelope_id) VALUES(?1,?2,?3)",
            params![
                verified.wrapper_envelope_id.as_slice(),
                i64::try_from(index + 1).map_err(|_| StoreError::QuotaExceeded)?,
                hop.authorization_envelope_id.as_slice()
            ],
        )?;
    }
    ensure_scope_quota_tx(transaction, &verified.route.current_scope)?;
    Ok(())
}

#[allow(dead_code)]
fn insert_pending_bridge_source_tx(
    transaction: &Transaction<'_>,
    config: &StoreConfig,
    verified: &VerifiedBridgeSource,
    replacement: Option<&StoredUnresolvedBridgeSource>,
    sample: Option<CustodySample>,
) -> Result<(), StoreError> {
    let metadata = &verified.metadata;
    let context = encode_context(&metadata.stamp.context);
    let accounted_bytes = bridge_source_accounted_bytes(verified)?;
    // A replacement unresolved row is removed before this helper runs, so the
    // admission check charges exactly one resolved record without a transient
    // double charge.
    ensure_bridge_admission(transaction, config, 1, accounted_bytes)?;
    let inserted_order = match replacement {
        Some(source) => source.inserted_order,
        None => next_order(transaction)?,
    };
    let forwarding_age = replacement
        .map(|source| source.authenticated_forwarding_age_ms)
        .unwrap_or(0)
        .max(verified.authenticated_forwarding_age_ms);
    let custody = match (replacement, sample) {
        (Some(source), None) => (
            source.cumulative_custody_age_ms.max(forwarding_age),
            source.age_continuity_unknown,
            source.custody_clock_id,
            source.custody_tick_ms,
            source.custody_elapsed_available,
        ),
        _ => merged_bridge_source_custody(replacement, forwarding_age, sample),
    };
    transaction.execute(
        "INSERT INTO bridge_pending_sources(\n\
           origin_envelope_id,source_item_id,source_publisher,data_class,source_topic,\n\
           source_priority,causal_counter,causal_context,event_sequence,logical_key,\n\
           source_ttl_ms,blob_id,blob_chunk_count,blob_merkle_root,content_len,tombstone,\n\
           origin_scope,origin_route_epoch,forwarding_custody_age_ms,exact_bytes,inserted_order,\n\
           accounted_bytes,cumulative_custody_age_ms,source_age_continuity_unknown,\n\
           source_custody_clock_id,source_custody_tick_ms,source_custody_elapsed_available)\n\
         VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14,?15,?16,?17,?18,?19,?20,?21,?22,?23,?24,?25,?26,?27)",
        params![
            verified.origin_envelope_id.as_slice(),
            metadata.source_item_id.as_slice(),
            metadata.stamp.dot.publisher.as_slice(),
            class_to_i64(metadata.class),
            metadata.topic.as_str(),
            i64::from(metadata.priority as u8),
            sql_u64(metadata.stamp.dot.counter, "bridge source causal counter")?,
            context,
            metadata
                .event_sequence
                .map(|value| sql_u64(value, "bridge source event sequence"))
                .transpose()?,
            &metadata.logical_key,
            metadata
                .ttl_ms
                .map(|value| sql_u64(value, "bridge source TTL"))
                .transpose()?,
            metadata
                .blob_route
                .as_ref()
                .map(|blob| blob.blob_id.as_slice()),
            metadata
                .blob_route
                .as_ref()
                .map(|blob| sql_u64(blob.chunk_count, "bridge blob chunk count"))
                .transpose()?,
            metadata
                .blob_route
                .as_ref()
                .map(|blob| blob.merkle_root.as_slice()),
            sql_u64(metadata.content_len, "bridge source content length")?,
            i64::from(metadata.tombstone),
            metadata.origin_scope.as_str(),
            sql_u64(metadata.origin_route_epoch, "bridge source origin epoch")?,
            sql_u64(forwarding_age, "authenticated source forwarding age")?,
            &verified.exact_bytes,
            sql_u64(inserted_order, "pending bridge source order")?,
            sql_u64(accounted_bytes, "pending bridge source bytes")?,
            sql_u64(custody.0, "pending bridge source custody age")?,
            i64::from(custody.1),
            custody.2.map(|value| value.to_vec()),
            custody.3
                .map(|value| sql_u64(value, "pending bridge source custody tick"))
                .transpose()?,
            i64::from(custody.4)
        ],
    )?;
    merge_bridge_forwarding_age_tx(transaction, verified.origin_envelope_id, forwarding_age)?;
    ensure_scope_quota_tx(transaction, &metadata.origin_scope)?;
    Ok(())
}

#[allow(dead_code)]
fn checkpoint_existing_bridge_source_tx(
    transaction: &Transaction<'_>,
    source: &StoredBridgeSource,
    authenticated_age_ms: u64,
    sample: Option<CustodySample>,
) -> Result<(), StoreError> {
    let mut custody = checkpoint_bridge_source_custody(source, sample);
    custody.0 = custody.0.max(authenticated_age_ms);
    for table in ["bridge_pending_sources", "bridge_source_objects"] {
        transaction.execute(
            &format!(
                "UPDATE {table} SET\n\
                   cumulative_custody_age_ms=max(cumulative_custody_age_ms,?1),\n\
                   source_age_continuity_unknown=?2,source_custody_clock_id=?3,\n\
                   source_custody_tick_ms=?4,source_custody_elapsed_available=?5\n\
                 WHERE origin_envelope_id=?6"
            ),
            params![
                sql_u64(custody.0, "bridge source custody age")?,
                i64::from(custody.1),
                custody.2.map(|value| value.to_vec()),
                custody
                    .3
                    .map(|value| sql_u64(value, "bridge source custody tick"))
                    .transpose()?,
                i64::from(custody.4),
                source.origin_envelope_id.as_slice()
            ],
        )?;
    }
    transaction.execute(
        "UPDATE bridge_route_wrappers SET\n\
           cumulative_custody_age_ms=max(cumulative_custody_age_ms,?1),\n\
           age_continuity_unknown=max(age_continuity_unknown,?2),\n\
           custody_clock_id=CASE WHEN ?2=1 THEN NULL ELSE custody_clock_id END,\n\
           custody_tick_ms=CASE WHEN ?2=1 THEN NULL ELSE custody_tick_ms END,\n\
           custody_elapsed_available=CASE WHEN ?2=1 THEN 0 ELSE custody_elapsed_available END\n\
         WHERE origin_envelope_id=?3",
        params![
            sql_u64(custody.0, "bridge source custody age")?,
            i64::from(custody.1),
            source.origin_envelope_id.as_slice()
        ],
    )?;
    transaction.execute(
        "UPDATE bridge_pending_wrappers SET\n\
           cumulative_custody_age_ms=max(cumulative_custody_age_ms,?1),\n\
           age_continuity_unknown=max(age_continuity_unknown,?2),\n\
           custody_clock_id=CASE WHEN ?2=1 THEN NULL ELSE custody_clock_id END,\n\
           custody_tick_ms=CASE WHEN ?2=1 THEN NULL ELSE custody_tick_ms END,\n\
           custody_elapsed_available=CASE WHEN ?2=1 THEN 0 ELSE custody_elapsed_available END\n\
         WHERE origin_envelope_id=?3",
        params![
            sql_u64(custody.0, "bridge source custody age")?,
            i64::from(custody.1),
            source.origin_envelope_id.as_slice()
        ],
    )?;
    Ok(())
}

#[allow(dead_code)]
fn exact_typed_transfer_bytes_tx(
    transaction: &Transaction<'_>,
    object_id: ObjectId,
    expected: &[u8],
) -> Result<(), StoreError> {
    let storage_key = transfer_storage_key(object_id);
    let stored = transaction
        .query_row(
            "SELECT i.object_id,w.total_len FROM transfer_identities i\n\
             JOIN wants w ON w.object_id=i.storage_key WHERE i.storage_key=?1",
            params![storage_key.as_slice()],
            |row| Ok((row.get::<_, Vec<u8>>(0)?, row.get::<_, i64>(1)?)),
        )
        .optional()?
        .ok_or(StoreError::NotFound("typed bridge transfer"))?;
    if stored.0.as_slice() != object_id.to_wire_bytes()
        || from_sql_u64(stored.1, "typed bridge transfer length")? != expected.len() as u64
    {
        return Err(StoreError::Invalid(
            "typed bridge transfer identity or length differs from verified object".into(),
        ));
    }
    let remaining: i64 = transaction.query_row(
        "SELECT count(*) FROM want_ranges WHERE object_id=?1",
        params![storage_key.as_slice()],
        |row| row.get(0),
    )?;
    if remaining != 0 {
        return Err(StoreError::BridgeDependencyMissing);
    }
    let mut bytes = Vec::with_capacity(expected.len());
    let mut statement = transaction.prepare(
        "SELECT start_offset,end_offset,bytes FROM sealed_chunks\n\
         WHERE object_id=?1 ORDER BY start_offset",
    )?;
    let rows = statement.query_map(params![storage_key.as_slice()], |row| {
        Ok((
            row.get::<_, i64>(0)?,
            row.get::<_, i64>(1)?,
            row.get::<_, Vec<u8>>(2)?,
        ))
    })?;
    let mut cursor = 0u64;
    for row in rows {
        let (start, end, chunk) = row?;
        let start = from_sql_u64(start, "typed bridge chunk start")?;
        let end = from_sql_u64(end, "typed bridge chunk end")?;
        if start != cursor || end.saturating_sub(start) != chunk.len() as u64 {
            return Err(StoreError::Corrupt(
                "typed bridge transfer chunks are not contiguous".into(),
            ));
        }
        if bytes.len().saturating_add(chunk.len()) > expected.len() {
            return Err(StoreError::Invalid(
                "typed bridge transfer exceeds verified object".into(),
            ));
        }
        bytes.extend_from_slice(&chunk);
        cursor = end;
    }
    drop(statement);
    if bytes != expected {
        return Err(StoreError::Invalid(
            "typed bridge transfer bytes differ from provider-verified object".into(),
        ));
    }
    Ok(())
}

#[allow(dead_code)]
fn retire_typed_transfer_tx(
    transaction: &Transaction<'_>,
    object_id: ObjectId,
) -> Result<(), StoreError> {
    let storage_key = transfer_storage_key(object_id);
    transaction.execute(
        "DELETE FROM wants WHERE object_id=?1",
        params![storage_key.as_slice()],
    )?;
    Ok(())
}

#[allow(dead_code)]
fn decode_bridge_source_row(row: &Row<'_>) -> rusqlite::Result<StoredBridgeSource> {
    fn conversion(error: StoreError) -> rusqlite::Error {
        rusqlite::Error::FromSqlConversionFailure(0, rusqlite::types::Type::Blob, Box::new(error))
    }
    let origin_envelope_id =
        node_from_vec(row.get(0)?, "bridge source envelope").map_err(conversion)?;
    let blob_id = row.get::<_, Option<Vec<u8>>>(11)?;
    let blob_chunk_count = row.get::<_, Option<i64>>(12)?;
    let blob_merkle_root = row.get::<_, Option<Vec<u8>>>(13)?;
    let blob_route = match (blob_id, blob_chunk_count, blob_merkle_root) {
        (None, None, None) => None,
        (Some(blob_id), Some(chunk_count), Some(merkle_root)) => Some(VerifiedBlobRouteMetadata {
            blob_id: node_from_vec(blob_id, "bridge blob id").map_err(conversion)?,
            chunk_count: from_sql_u64(chunk_count, "bridge blob chunk count")
                .map_err(conversion)?,
            merkle_root: node_from_vec(merkle_root, "bridge blob Merkle root")
                .map_err(conversion)?,
        }),
        _ => {
            return Err(conversion(StoreError::Corrupt(
                "bridge blob route metadata is incomplete".into(),
            )));
        }
    };
    let metadata = VerifiedBridgeSourceMetadata {
        source_item_id: item_from_vec(row.get(1)?, "bridge source item").map_err(conversion)?,
        class: class_from_i64(row.get(3)?).map_err(conversion)?,
        topic: Topic::new(row.get::<_, String>(4)?)
            .map_err(|error| conversion(StoreError::Corrupt(error.to_string())))?,
        priority: priority_from_i64(row.get(5)?).map_err(conversion)?,
        stamp: CausalStamp {
            dot: Dot {
                publisher: node_from_vec(row.get(2)?, "bridge source publisher")
                    .map_err(conversion)?,
                counter: from_sql_u64(row.get(6)?, "bridge source causal counter")
                    .map_err(conversion)?,
            },
            context: decode_context(&row.get::<_, Vec<u8>>(7)?).map_err(conversion)?,
        },
        event_sequence: row
            .get::<_, Option<i64>>(8)?
            .map(|value| from_sql_u64(value, "bridge source event sequence"))
            .transpose()
            .map_err(conversion)?,
        logical_key: row.get(9)?,
        ttl_ms: row
            .get::<_, Option<i64>>(10)?
            .map(|value| from_sql_u64(value, "bridge source TTL"))
            .transpose()
            .map_err(conversion)?,
        blob_route,
        content_len: from_sql_u64(row.get(14)?, "bridge source content length")
            .map_err(conversion)?,
        tombstone: sql_bool(row.get(15)?, "bridge source tombstone").map_err(conversion)?,
        origin_scope: Scope::new(row.get::<_, String>(16)?)
            .map_err(|error| conversion(StoreError::Corrupt(error.to_string())))?,
        origin_route_epoch: from_sql_u64(row.get(17)?, "bridge source origin epoch")
            .map_err(conversion)?,
    };
    let authenticated_forwarding_age_ms =
        from_sql_u64(row.get(18)?, "bridge source forwarding age").map_err(conversion)?;
    let cumulative_custody_age_ms =
        from_sql_u64(row.get(19)?, "bridge source custody age").map_err(conversion)?;
    let age_continuity_unknown =
        sql_bool(row.get(20)?, "bridge source continuity").map_err(conversion)?;
    let custody_clock_id = row
        .get::<_, Option<Vec<u8>>>(21)?
        .map(|value| clock_from_vec(value, "bridge source custody clock"))
        .transpose()
        .map_err(conversion)?;
    let custody_tick_ms = row
        .get::<_, Option<i64>>(22)?
        .map(|value| from_sql_u64(value, "bridge source custody tick"))
        .transpose()
        .map_err(conversion)?;
    let custody_elapsed_available =
        sql_bool(row.get(23)?, "bridge source custody availability").map_err(conversion)?;
    if custody_elapsed_available != (custody_clock_id.is_some() && custody_tick_ms.is_some()) {
        return Err(conversion(StoreError::Corrupt(
            "bridge source custody tuple is inconsistent".into(),
        )));
    }
    let exact_bytes: Vec<u8> = row.get(24)?;
    let verified = VerifiedBridgeSource::from_provider(
        origin_envelope_id,
        metadata.clone(),
        exact_bytes.clone(),
        authenticated_forwarding_age_ms,
    )
    .map_err(conversion)?;
    Ok(StoredBridgeSource {
        origin_envelope_id: verified.origin_envelope_id,
        metadata,
        exact_bytes,
        cumulative_custody_age_ms,
        authenticated_forwarding_age_ms,
        age_continuity_unknown,
        custody_clock_id,
        custody_tick_ms,
        custody_elapsed_available,
        inserted_order: from_sql_u64(row.get(25)?, "bridge source order").map_err(conversion)?,
    })
}

#[allow(dead_code)]
fn bridge_source_accounted_bytes(source: &VerifiedBridgeSource) -> Result<u64, StoreError> {
    let metadata = &source.metadata;
    (source.exact_bytes.len() as u64)
        .checked_add(encode_context(&metadata.stamp.context).len() as u64)
        .and_then(|value| value.checked_add(metadata.logical_key.len() as u64))
        .and_then(|value| value.checked_add(metadata.topic.as_str().len() as u64))
        .and_then(|value| value.checked_add(metadata.origin_scope.as_str().len() as u64))
        .and_then(|value| value.checked_add(256))
        .ok_or(StoreError::QuotaExceeded)
}

#[allow(dead_code)]
fn bridge_source_metadata_accounted_bytes(
    source: &VerifiedBridgeSource,
) -> Result<u64, StoreError> {
    bridge_source_accounted_bytes(source)?
        .checked_sub(source.exact_bytes.len() as u64)
        .filter(|value| *value > 0)
        .ok_or(StoreError::QuotaExceeded)
}

#[allow(dead_code)]
fn insert_reused_bridge_source_tx(
    transaction: &Transaction<'_>,
    verified: &VerifiedBridgeSource,
    reused_item_id: ItemId,
    insertion_order: Option<u64>,
    forwarding_age: u64,
    accounted_bytes: u64,
    custody: (u64, bool, Option<[u8; 16]>, Option<u64>, bool),
) -> Result<(), StoreError> {
    let metadata = &verified.metadata;
    let order = match insertion_order {
        Some(order) => order,
        None => next_order(transaction)?,
    };
    transaction.execute(
        "INSERT INTO bridge_source_objects(\n\
           origin_envelope_id,source_item_id,exact_bytes,inserted_order,accounted_bytes,\n\
           source_publisher,data_class,source_topic,source_priority,causal_counter,\n\
           causal_context,event_sequence,logical_key,source_ttl_ms,blob_id,blob_chunk_count,\n\
           blob_merkle_root,content_len,tombstone,origin_scope,origin_route_epoch,\n\
           forwarding_custody_age_ms,reused_item_id,cumulative_custody_age_ms,\n\
           source_age_continuity_unknown,source_custody_clock_id,source_custody_tick_ms,\n\
           source_custody_elapsed_available)\n\
         VALUES(?1,?2,x'00',?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14,?15,?16,?17,?18,?19,?20,?21,?22,?23,?24,?25,?26,?27)",
        params![
            verified.origin_envelope_id.as_slice(),
            metadata.source_item_id.as_slice(),
            sql_u64(order, "shared bridge source order")?,
            sql_u64(accounted_bytes, "shared bridge source metadata bytes")?,
            metadata.stamp.dot.publisher.as_slice(),
            class_to_i64(metadata.class),
            metadata.topic.as_str(),
            i64::from(metadata.priority as u8),
            sql_u64(metadata.stamp.dot.counter, "shared bridge source causal counter")?,
            encode_context(&metadata.stamp.context),
            metadata
                .event_sequence
                .map(|value| sql_u64(value, "shared bridge source event sequence"))
                .transpose()?,
            &metadata.logical_key,
            metadata
                .ttl_ms
                .map(|value| sql_u64(value, "shared bridge source TTL"))
                .transpose()?,
            metadata
                .blob_route
                .as_ref()
                .map(|blob| blob.blob_id.as_slice()),
            metadata
                .blob_route
                .as_ref()
                .map(|blob| sql_u64(blob.chunk_count, "shared bridge blob chunk count"))
                .transpose()?,
            metadata
                .blob_route
                .as_ref()
                .map(|blob| blob.merkle_root.as_slice()),
            sql_u64(metadata.content_len, "shared bridge source content length")?,
            i64::from(metadata.tombstone),
            metadata.origin_scope.as_str(),
            sql_u64(metadata.origin_route_epoch, "shared bridge source origin epoch")?,
            sql_u64(forwarding_age, "shared bridge source forwarding age")?,
            reused_item_id.as_slice(),
            sql_u64(custody.0, "shared bridge source custody age")?,
            i64::from(custody.1),
            custody.2.map(|value| value.to_vec()),
            custody
                .3
                .map(|value| sql_u64(value, "shared bridge source custody tick"))
                .transpose()?,
            i64::from(custody.4)
        ],
    )?;
    ensure_scope_quota_tx(transaction, &metadata.origin_scope)?;
    Ok(())
}

#[allow(dead_code)]
fn merged_bridge_source_custody(
    existing: Option<&StoredUnresolvedBridgeSource>,
    authenticated_age_ms: u64,
    sample: Option<CustodySample>,
) -> (u64, bool, Option<[u8; 16]>, Option<u64>, bool) {
    merge_authenticated_custody_fields(
        existing.map(|value| {
            (
                value.cumulative_custody_age_ms,
                value.age_continuity_unknown,
                value.custody_clock_id,
                value.custody_tick_ms,
                value.custody_elapsed_available,
            )
        }),
        authenticated_age_ms,
        sample,
    )
}

#[allow(dead_code)]
fn ordinary_item_bridge_custody(
    item: &StoredItem,
    sample: Option<CustodySample>,
) -> (u64, bool, Option<[u8; 16]>, Option<u64>, bool) {
    let mut age = custody_age_from_legacy_fields(
        item.custody_age_ms,
        !item.custody_elapsed_available,
        item.custody_clock_id,
        item.custody_tick_ms,
        item.custody_elapsed_available,
    );
    let _ = age.checkpoint(sample);
    custody_fields_from_age(age)
}

#[allow(dead_code)]
fn bridge_source_custody_age_at(
    source: &StoredBridgeSource,
    sample: Option<CustodySample>,
) -> Option<u64> {
    let mut age = custody_age_from_legacy_fields(
        source.cumulative_custody_age_ms,
        source.age_continuity_unknown,
        source.custody_clock_id,
        source.custody_tick_ms,
        source.custody_elapsed_available,
    );
    age.effective_age(sample).ok()
}

#[allow(dead_code)]
fn checkpoint_bridge_source_custody(
    source: &StoredBridgeSource,
    sample: Option<CustodySample>,
) -> (u64, bool, Option<[u8; 16]>, Option<u64>, bool) {
    let mut age = custody_age_from_legacy_fields(
        source.cumulative_custody_age_ms,
        source.age_continuity_unknown,
        source.custody_clock_id,
        source.custody_tick_ms,
        source.custody_elapsed_available,
    );
    let _ = age.checkpoint(sample);
    custody_fields_from_age(age)
}

#[allow(dead_code)]
fn checkpoint_bridge_route_custody(
    route: &StoredBridgeRoute,
    sample: Option<CustodySample>,
) -> (u64, bool, Option<[u8; 16]>, Option<u64>, bool) {
    let mut age = custody_age_from_legacy_fields(
        route.cumulative_custody_age_ms,
        route.age_continuity_unknown,
        route.custody_clock_id,
        route.custody_tick_ms,
        route.custody_elapsed_available,
    );
    let _ = age.checkpoint(sample);
    custody_fields_from_age(age)
}

#[allow(dead_code)]
fn checkpoint_pending_bridge_wrapper_custody(
    wrapper: &StoredPendingBridgeWrapper,
    sample: Option<CustodySample>,
) -> (u64, bool, Option<[u8; 16]>, Option<u64>, bool) {
    let mut age = custody_age_from_legacy_fields(
        wrapper.cumulative_custody_age_ms,
        wrapper.age_continuity_unknown,
        wrapper.custody_clock_id,
        wrapper.custody_tick_ms,
        wrapper.custody_elapsed_available,
    );
    let _ = age.checkpoint(sample);
    custody_fields_from_age(age)
}

#[allow(dead_code)]
fn merge_bridge_forwarding_age_tx(
    transaction: &Transaction<'_>,
    origin_envelope_id: EnvelopeId,
    authenticated_age_ms: u64,
) -> Result<(), StoreError> {
    let age = sql_u64(authenticated_age_ms, "authenticated bridge forwarding age")?;
    transaction.execute(
        "UPDATE bridge_pending_sources SET\n\
           forwarding_custody_age_ms=max(forwarding_custody_age_ms,?1),\n\
           cumulative_custody_age_ms=max(cumulative_custody_age_ms,?1)\n\
         WHERE origin_envelope_id=?2",
        params![age, origin_envelope_id.as_slice()],
    )?;
    transaction.execute(
        "UPDATE bridge_source_objects SET\n\
           forwarding_custody_age_ms=max(coalesce(forwarding_custody_age_ms,0),?1),\n\
           cumulative_custody_age_ms=max(cumulative_custody_age_ms,?1)\n\
         WHERE origin_envelope_id=?2",
        params![age, origin_envelope_id.as_slice()],
    )?;
    transaction.execute(
        "UPDATE bridge_pending_wrappers SET\n\
           cumulative_custody_age_ms=max(cumulative_custody_age_ms,?1),\n\
           forwarding_custody_age_ms=max(forwarding_custody_age_ms,?1)\n\
         WHERE origin_envelope_id=?2",
        params![age, origin_envelope_id.as_slice()],
    )?;
    transaction.execute(
        "UPDATE bridge_route_wrappers SET\n\
           cumulative_custody_age_ms=max(cumulative_custody_age_ms,?1),\n\
           forwarding_custody_age_ms=max(forwarding_custody_age_ms,?1)\n\
         WHERE origin_envelope_id=?2",
        params![age, origin_envelope_id.as_slice()],
    )?;
    Ok(())
}

#[allow(dead_code)]
fn accept_bridge_source_semantics_tx(
    transaction: &Transaction<'_>,
    source: &VerifiedBridgeSource,
) -> Result<(), StoreError> {
    let metadata = &source.metadata;
    if let Some(existing) = load_item_tx(transaction, &metadata.source_item_id)?
        && (existing.envelope_id != source.origin_envelope_id
            || existing.class != metadata.class
            || existing.topic != metadata.topic
            || existing.priority != metadata.priority
            || existing.stamp != metadata.stamp
            || existing.event_sequence != metadata.event_sequence
            || existing.logical_key != metadata.logical_key
            || existing.ttl_ms != metadata.ttl_ms
            || existing.content_len != metadata.content_len
            || existing.tombstone != metadata.tombstone
            || existing.sealed != source.exact_bytes)
    {
        return Err(StoreError::Invalid(
            "bridge source ItemID conflicts with an accepted source representation".into(),
        ));
    }
    let accepted_dot = transaction
        .query_row(
            "SELECT item_id FROM accepted_dots WHERE publisher=?1 AND counter=?2",
            params![
                metadata.stamp.dot.publisher.as_slice(),
                sql_u64(metadata.stamp.dot.counter, "bridge source causal counter")?
            ],
            |row| row.get::<_, Vec<u8>>(0),
        )
        .optional()?;
    if let Some(existing) = accepted_dot
        && existing.as_slice() != metadata.source_item_id.as_slice()
    {
        return Err(StoreError::Equivocation {
            publisher: metadata.stamp.dot.publisher,
            counter: metadata.stamp.dot.counter,
        });
    }
    transaction.execute(
        "INSERT INTO accepted_dots(publisher,counter,item_id) VALUES(?1,?2,?3)\n\
         ON CONFLICT(publisher,counter) DO NOTHING",
        params![
            metadata.stamp.dot.publisher.as_slice(),
            sql_u64(metadata.stamp.dot.counter, "bridge source causal counter")?,
            metadata.source_item_id.as_slice()
        ],
    )?;
    if let Some(sequence) = metadata.event_sequence {
        let accepted_event = transaction
            .query_row(
                "SELECT item_id FROM accepted_events\n\
                 WHERE publisher=?1 AND topic=?2 AND scope=?3 AND sequence=?4",
                params![
                    metadata.stamp.dot.publisher.as_slice(),
                    metadata.topic.as_str(),
                    metadata.origin_scope.as_str(),
                    sql_u64(sequence, "bridge source event sequence")?
                ],
                |row| row.get::<_, Vec<u8>>(0),
            )
            .optional()?;
        if let Some(existing) = accepted_event
            && existing.as_slice() != metadata.source_item_id.as_slice()
        {
            return Err(StoreError::EventEquivocation {
                publisher: metadata.stamp.dot.publisher,
                sequence,
            });
        }
        transaction.execute(
            "INSERT INTO accepted_events(publisher,topic,scope,sequence,item_id)\n\
             VALUES(?1,?2,?3,?4,?5)\n\
             ON CONFLICT(publisher,topic,scope,sequence) DO NOTHING",
            params![
                metadata.stamp.dot.publisher.as_slice(),
                metadata.topic.as_str(),
                metadata.origin_scope.as_str(),
                sql_u64(sequence, "bridge source event sequence")?,
                metadata.source_item_id.as_slice()
            ],
        )?;
    }
    let other_origin = transaction
        .query_row(
            "SELECT origin_envelope_id FROM bridge_source_objects\n\
             WHERE source_item_id=?1 AND data_class IS NOT NULL",
            params![metadata.source_item_id.as_slice()],
            |row| row.get::<_, Vec<u8>>(0),
        )
        .optional()?;
    if other_origin.is_some_and(|id| id.as_slice() != source.origin_envelope_id) {
        return Err(StoreError::Invalid(
            "bridge source ItemID maps to a different exact carrier".into(),
        ));
    }
    record_accepted_frontier_dot_tx(
        transaction,
        &metadata.topic,
        &metadata.origin_scope,
        metadata.stamp.dot,
    )?;
    Ok(())
}

/// A permanent causal acceptance is not itself an ordinary scope view. When
/// the exact provider-authenticated bridge source is still retained, that
/// source may materialize an authenticated ordinary origin or currently active
/// target-scope view later without being mistaken for replay resurrection.
fn matches_retained_bridge_origin_tx(
    transaction: &Transaction<'_>,
    item: &StoredItem,
) -> Result<bool, StoreError> {
    let origin: Option<Vec<u8>> = transaction
        .query_row(
            "SELECT origin_envelope_id FROM bridge_source_objects WHERE source_item_id=?1",
            params![item.id.as_slice()],
            |row| row.get(0),
        )
        .optional()?;
    let Some(origin) = origin else {
        return Ok(false);
    };
    let origin = node_from_vec(origin, "retained bridge origin")?;
    let source = transaction
        .query_row(
            &bridge_source_select("bridge_source_objects"),
            params![origin.as_slice()],
            decode_bridge_source_row,
        )
        .optional()?
        .ok_or(StoreError::Corrupt(
            "retained bridge origin disappeared".into(),
        ))?;
    let metadata = &source.metadata;
    let scope_is_permitted = (item.scope == metadata.origin_scope
        && item.key_epoch == metadata.origin_route_epoch)
        || transaction.query_row(
            "SELECT EXISTS(SELECT 1 FROM bridge_route_wrappers w\n\
               JOIN bridge_active_routes a ON a.wrapper_envelope_id=w.wrapper_envelope_id\n\
               WHERE w.origin_envelope_id=?1 AND w.current_scope=?2\n\
                 AND w.current_route_epoch=?3)",
            params![
                source.origin_envelope_id.as_slice(),
                item.scope.as_str(),
                sql_u64(item.key_epoch, "materialized bridge-view epoch")?
            ],
            |row| row.get::<_, i64>(0),
        )? != 0;
    Ok(item.id == metadata.source_item_id
        && item.envelope_id == source.origin_envelope_id
        && item.sealed == source.exact_bytes
        && item.class == metadata.class
        && item.topic == metadata.topic
        && scope_is_permitted
        && item.priority == metadata.priority
        && item.stamp == metadata.stamp
        && item.event_sequence == metadata.event_sequence
        && item.logical_key == metadata.logical_key
        && item.ttl_ms == metadata.ttl_ms
        && item.content_len == metadata.content_len
        && item.tombstone == metadata.tombstone)
}

#[allow(dead_code)]
fn recompute_bridge_projection_group_tx(
    transaction: &Transaction<'_>,
    metadata: &VerifiedBridgeSourceMetadata,
    target_scope: &Scope,
    target_route_epoch: u64,
    max_items: u64,
) -> Result<(), StoreError> {
    let rows = {
        let mut statement = transaction.prepare(
            "SELECT p.wrapper_envelope_id,s.source_item_id,s.source_publisher,s.causal_counter,\n\
                    s.causal_context\n\
             FROM bridge_target_projection p\n\
             JOIN bridge_route_wrappers w ON w.wrapper_envelope_id=p.wrapper_envelope_id\n\
             JOIN bridge_source_objects s ON s.origin_envelope_id=w.origin_envelope_id\n\
             WHERE p.target_scope=?1 AND p.target_route_epoch=?2 AND s.data_class=?3\n\
               AND s.source_topic=?4 AND s.logical_key=?5\n\
             ORDER BY s.source_item_id LIMIT ?6",
        )?;
        statement
            .query_map(
                params![
                    target_scope.as_str(),
                    sql_u64(target_route_epoch, "bridge target projection epoch")?,
                    class_to_i64(metadata.class),
                    metadata.topic.as_str(),
                    &metadata.logical_key,
                    sql_u64(max_items, "bridge target projection scan bound")?
                ],
                |row| {
                    Ok((
                        row.get::<_, Vec<u8>>(0)?,
                        row.get::<_, Vec<u8>>(1)?,
                        row.get::<_, Vec<u8>>(2)?,
                        row.get::<_, i64>(3)?,
                        row.get::<_, Vec<u8>>(4)?,
                    ))
                },
            )?
            .collect::<Result<Vec<_>, _>>()?
    };
    if rows.len() as u64 > max_items {
        return Err(StoreError::QuotaExceeded);
    }
    let mut entries = Vec::with_capacity(rows.len());
    for (wrapper, item, publisher, counter, context) in rows {
        entries.push((
            node_from_vec(wrapper, "bridge target projection wrapper")?,
            item_from_vec(item, "bridge target projection item")?,
            Dot {
                publisher: node_from_vec(publisher, "bridge target projection publisher")?,
                counter: from_sql_u64(counter, "bridge target projection counter")?,
            },
            decode_context(&context)?,
        ));
    }
    if !matches!(metadata.class, DataClass::State | DataClass::Record) {
        for (wrapper, _, _, _) in entries {
            transaction.execute(
                "UPDATE bridge_target_projection SET version_status=?1\n\
                 WHERE wrapper_envelope_id=?2",
                params![VersionStatus::Current as u8 as i64, wrapper.as_slice()],
            )?;
        }
        return Ok(());
    }
    let mut maximal = Vec::new();
    for (index, (_, item, dot, _)) in entries.iter().enumerate() {
        let dominated = entries
            .iter()
            .enumerate()
            .any(|(other_index, (_, _, _, context))| {
                other_index != index && context.observes(*dot)
            });
        if !dominated {
            maximal.push(*item);
        }
    }
    let winner = maximal.iter().max().copied();
    let maximal: BTreeSet<_> = maximal.into_iter().collect();
    for (wrapper, item, _, _) in entries {
        let status = if Some(item) == winner {
            VersionStatus::Current
        } else if maximal.contains(&item) {
            VersionStatus::Concurrent
        } else {
            VersionStatus::Superseded
        };
        transaction.execute(
            "UPDATE bridge_target_projection SET version_status=?1 WHERE wrapper_envelope_id=?2",
            params![status as u8 as i64, wrapper.as_slice()],
        )?;
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
#[allow(dead_code)]
fn bridge_custody_is_live(
    ttl_ms: Option<u64>,
    tombstone: bool,
    cumulative_age_ms: u64,
    age_continuity_unknown: bool,
    custody_clock_id: Option<[u8; 16]>,
    custody_tick_ms: Option<u64>,
    custody_elapsed_available: bool,
    sample: Option<CustodySample>,
) -> bool {
    let mut age = custody_age_from_legacy_fields(
        cumulative_age_ms,
        age_continuity_unknown,
        custody_clock_id,
        custody_tick_ms,
        custody_elapsed_available,
    );
    evaluate_custody(ttl_ms, tombstone, &mut age, sample).is_forwardable()
}

#[allow(dead_code)]
fn ensure_bridge_admission(
    transaction: &Transaction<'_>,
    config: &StoreConfig,
    additional_objects: u64,
    additional_bytes: u64,
) -> Result<(), StoreError> {
    let allowed_items = config
        .max_items
        .checked_sub(additional_objects)
        .ok_or(StoreError::QuotaExceeded)?;
    let allowed_bytes = committed_byte_limit(config)
        .checked_sub(additional_bytes)
        .ok_or(StoreError::QuotaExceeded)?;
    evict_bridge_mappings_for_quota_tx(transaction, None, allowed_items, allowed_bytes)?;
    let usage = committed_usage_tx(transaction, None)?;
    if usage
        .items
        .checked_add(additional_objects)
        .is_none_or(|value| value > config.max_items)
        || usage
            .bytes
            .checked_add(additional_bytes)
            .is_none_or(|value| value > committed_byte_limit(config))
    {
        return Err(StoreError::QuotaExceeded);
    }
    Ok(())
}

#[allow(dead_code)]
fn ensure_scope_quota_tx(transaction: &Transaction<'_>, scope: &Scope) -> Result<(), StoreError> {
    let quota = transaction
        .query_row(
            "SELECT max_items,max_bytes FROM quotas WHERE scope=?1",
            params![scope.as_str()],
            |row| Ok((row.get::<_, i64>(0)?, row.get::<_, i64>(1)?)),
        )
        .optional()?;
    let Some((max_items, max_bytes)) = quota else {
        return Ok(());
    };
    let usage = committed_usage_tx(transaction, Some(scope))?;
    if usage.items > from_sql_u64(max_items, "scope max items")?
        || usage.bytes > from_sql_u64(max_bytes, "scope max bytes")?
    {
        return Err(StoreError::QuotaExceeded);
    }
    Ok(())
}

fn validate_config(config: &StoreConfig) -> Result<(), StoreError> {
    if config.max_items == 0 || config.max_bytes == 0 {
        return Err(StoreError::Invalid("storage quotas must be nonzero".into()));
    }
    sql_u64(config.max_items, "max_items")?;
    sql_u64(config.max_bytes, "max_bytes")?;
    sql_u64(config.tombstone_retention_ms, "tombstone_retention_ms")?;
    sql_u64(config.superseded_retention_ms, "superseded_retention_ms")?;
    Ok(())
}

fn staging_byte_limit(config: &StoreConfig) -> u64 {
    let reserved = (config.max_bytes / 4).max(1);
    reserved
        .min(MAX_STAGING_BYTES)
        .min(config.max_bytes.saturating_sub(1))
}

fn committed_byte_limit(config: &StoreConfig) -> u64 {
    config.max_bytes.saturating_sub(staging_byte_limit(config))
}

fn staged_object_byte_limit(config: &StoreConfig) -> u64 {
    staging_byte_limit(config).min(MAX_STAGED_OBJECT_BYTES)
}

fn staging_object_limit(config: &StoreConfig) -> u64 {
    config.max_items.min(MAX_STAGING_OBJECTS)
}

fn create_schema(connection: &Connection) -> Result<(), StoreError> {
    connection.execute_batch(
        "BEGIN IMMEDIATE;\n\
         CREATE TABLE IF NOT EXISTS store_meta (\n\
           key TEXT PRIMARY KEY, value INTEGER NOT NULL\n\
         ) STRICT;\n\
         CREATE TABLE IF NOT EXISTS publisher_counters (\n\
           publisher BLOB PRIMARY KEY CHECK(length(publisher)=32),\n\
           counter INTEGER NOT NULL CHECK(counter>=0)\n\
         ) STRICT;\n\
         CREATE TABLE IF NOT EXISTS event_counters (\n\
           publisher BLOB NOT NULL CHECK(length(publisher)=32),\n\
           topic TEXT NOT NULL, scope TEXT NOT NULL,\n\
           counter INTEGER NOT NULL CHECK(counter>=0),\n\
           PRIMARY KEY(publisher, topic, scope)\n\
         ) STRICT;\n\
         CREATE TABLE IF NOT EXISTS causal_frontier (\n\
           publisher BLOB PRIMARY KEY CHECK(length(publisher)=32),\n\
           counter INTEGER NOT NULL CHECK(counter>0)\n\
         ) STRICT;\n\
         CREATE TABLE IF NOT EXISTS accepted_dots (\n\
           publisher BLOB NOT NULL CHECK(length(publisher)=32),\n\
           counter INTEGER NOT NULL CHECK(counter>0),\n\
           item_id BLOB NOT NULL CHECK(length(item_id)=32),\n\
           PRIMARY KEY(publisher,counter)\n\
         ) STRICT;\n\
         CREATE TABLE IF NOT EXISTS accepted_events (\n\
           publisher BLOB NOT NULL CHECK(length(publisher)=32),topic TEXT NOT NULL,scope TEXT NOT NULL,\n\
           sequence INTEGER NOT NULL CHECK(sequence>0),item_id BLOB NOT NULL CHECK(length(item_id)=32),\n\
           PRIMARY KEY(publisher,topic,scope,sequence)\n\
         ) STRICT;\n\
         CREATE TABLE IF NOT EXISTS items (\n\
           item_id BLOB PRIMARY KEY CHECK(length(item_id)=32),\n\
           envelope_id BLOB NOT NULL UNIQUE CHECK(length(envelope_id)=32),\n\
           data_class INTEGER NOT NULL CHECK(data_class BETWEEN 0 AND 3),\n\
           topic TEXT NOT NULL, scope TEXT NOT NULL,\n\
           priority INTEGER NOT NULL CHECK(priority BETWEEN 0 AND 3),\n\
           publisher BLOB NOT NULL CHECK(length(publisher)=32),\n\
           causal_counter INTEGER NOT NULL CHECK(causal_counter>0),\n\
           causal_context BLOB NOT NULL,\n\
           event_sequence INTEGER, logical_key BLOB NOT NULL,\n\
           ttl_ms INTEGER, observed_at_ms INTEGER,\n\
           sealed BLOB NOT NULL, content_len INTEGER NOT NULL CHECK(content_len>=0),\n\
           tombstone INTEGER NOT NULL CHECK(tombstone IN (0,1)),\n\
           key_epoch INTEGER NOT NULL CHECK(key_epoch>=0),\n\
           custody_age_ms INTEGER NOT NULL CHECK(custody_age_ms>=0),\n\
           custody_clock_id BLOB CHECK(custody_clock_id IS NULL OR length(custody_clock_id)=16),\n\
           custody_tick_ms INTEGER,\n\
           custody_elapsed_available INTEGER NOT NULL CHECK(custody_elapsed_available IN (0,1)),\n\
           version_status INTEGER NOT NULL CHECK(version_status BETWEEN 0 AND 2),\n\
           inserted_order INTEGER NOT NULL UNIQUE,\n\
           accounted_bytes INTEGER NOT NULL CHECK(accounted_bytes>=0),\n\
           UNIQUE(publisher, causal_counter)\n\
         ) STRICT;\n\
         CREATE UNIQUE INDEX IF NOT EXISTS event_sequence_unique\n\
           ON items(publisher, topic, scope, event_sequence)\n\
           WHERE data_class=1;\n\
         CREATE INDEX IF NOT EXISTS items_projection\n\
           ON items(topic, scope, data_class, logical_key, version_status);\n\
         CREATE INDEX IF NOT EXISTS items_eviction\n\
           ON items(priority, version_status DESC, inserted_order);\n\
         CREATE INDEX IF NOT EXISTS items_expiry ON items(observed_at_ms, ttl_ms);\n\
         CREATE TABLE IF NOT EXISTS tombstones (\n\
           item_id BLOB PRIMARY KEY REFERENCES items(item_id) ON DELETE CASCADE,\n\
           retain_until_ms INTEGER\n\
         ) STRICT;\n\
         CREATE TABLE IF NOT EXISTS conflict_siblings (\n\
           topic TEXT NOT NULL, scope TEXT NOT NULL, logical_key BLOB NOT NULL,\n\
           item_id BLOB NOT NULL REFERENCES items(item_id) ON DELETE CASCADE,\n\
           PRIMARY KEY(topic, scope, logical_key, item_id)\n\
         ) STRICT;\n\
         CREATE TABLE IF NOT EXISTS outbox (\n\
           item_id BLOB PRIMARY KEY REFERENCES items(item_id) ON DELETE CASCADE,\n\
           enqueued_order INTEGER NOT NULL, attempts INTEGER NOT NULL DEFAULT 0,\n\
           last_attempt_ms INTEGER\n\
         ) STRICT;\n\
         CREATE TABLE IF NOT EXISTS peer_receipts (\n\
           peer BLOB NOT NULL CHECK(length(peer)=32),\n\
           item_id BLOB NOT NULL REFERENCES items(item_id) ON DELETE CASCADE,\n\
           acknowledged_at_ms INTEGER, PRIMARY KEY(peer,item_id)\n\
         ) STRICT;\n\
         CREATE TABLE IF NOT EXISTS subscriptions (\n\
           subscription_id INTEGER PRIMARY KEY AUTOINCREMENT, topic TEXT NOT NULL,\n\
           scope TEXT NOT NULL, descendants INTEGER NOT NULL CHECK(descendants IN (0,1)),\n\
           data_class INTEGER\n\
         ) STRICT;\n\
         CREATE TABLE IF NOT EXISTS app_deliveries (\n\
           subscription_id INTEGER NOT NULL REFERENCES subscriptions(subscription_id) ON DELETE CASCADE,\n\
           item_id BLOB NOT NULL REFERENCES items(item_id) ON DELETE CASCADE,\n\
           attempts INTEGER NOT NULL DEFAULT 0, last_delivery_ms INTEGER, acked_at_ms INTEGER,\n\
           PRIMARY KEY(subscription_id,item_id)\n\
         ) STRICT;\n\
         CREATE TABLE IF NOT EXISTS wants (\n\
           object_id BLOB PRIMARY KEY CHECK(length(object_id)=32),\n\
           total_len INTEGER NOT NULL CHECK(total_len>0),\n\
           priority INTEGER NOT NULL CHECK(priority BETWEEN 0 AND 3),\n\
           updated_at_ms INTEGER\n\
         ) STRICT;\n\
         CREATE TABLE IF NOT EXISTS transfer_identities (\n\
           storage_key BLOB PRIMARY KEY REFERENCES wants(object_id) ON DELETE CASCADE\n\
             CHECK(length(storage_key)=32),\n\
           object_id BLOB NOT NULL UNIQUE CHECK(length(object_id)=33)\n\
         ) STRICT;\n\
         CREATE TABLE IF NOT EXISTS want_ranges (\n\
           object_id BLOB NOT NULL REFERENCES wants(object_id) ON DELETE CASCADE,\n\
           start_offset INTEGER NOT NULL, end_offset INTEGER NOT NULL,\n\
           CHECK(start_offset>=0 AND end_offset>start_offset),\n\
           PRIMARY KEY(object_id,start_offset)\n\
         ) STRICT;\n\
         CREATE TABLE IF NOT EXISTS sealed_chunks (\n\
           object_id BLOB NOT NULL REFERENCES wants(object_id) ON DELETE CASCADE,\n\
           start_offset INTEGER NOT NULL, end_offset INTEGER NOT NULL, bytes BLOB NOT NULL,\n\
           CHECK(start_offset>=0 AND end_offset>start_offset),\n\
           PRIMARY KEY(object_id,start_offset)\n\
         ) STRICT;\n\
         CREATE TABLE IF NOT EXISTS revocations (\n\
           subject BLOB PRIMARY KEY CHECK(length(subject)=32),\n\
           authority BLOB NOT NULL CHECK(length(authority)=32), generation INTEGER NOT NULL,\n\
           sealed_notice BLOB NOT NULL, observed_at_ms INTEGER\n\
         ) STRICT;\n\
         CREATE TABLE IF NOT EXISTS scope_epochs (\n\
           scope TEXT PRIMARY KEY, epoch INTEGER NOT NULL, sealed_notice BLOB NOT NULL\n\
         ) STRICT;\n\
         CREATE TABLE IF NOT EXISTS quotas (\n\
           scope TEXT PRIMARY KEY, max_items INTEGER NOT NULL, max_bytes INTEGER NOT NULL\n\
         ) STRICT;\n\
         CREATE TABLE IF NOT EXISTS peers (\n\
           node_id BLOB PRIMARY KEY CHECK(length(node_id)=32),\n\
           peer_status INTEGER NOT NULL, sync_status INTEGER NOT NULL,\n\
           last_change_ms INTEGER, detail TEXT\n\
         ) STRICT;\n\
         CREATE TABLE IF NOT EXISTS bridge_filters (\n\
           from_scope TEXT NOT NULL, to_scope TEXT NOT NULL,\n\
           topic TEXT NOT NULL, minimum_priority INTEGER NOT NULL,\n\
           PRIMARY KEY(from_scope,to_scope,topic)\n\
         ) STRICT;\n\
         CREATE TABLE IF NOT EXISTS controls (\n\
           envelope_id BLOB PRIMARY KEY CHECK(length(envelope_id)=32),\n\
           authority BLOB NOT NULL CHECK(length(authority)=32),\n\
           sequence INTEGER NOT NULL CHECK(sequence>0),\n\
           previous_control BLOB CHECK(previous_control IS NULL OR length(previous_control)=32),\n\
           kind INTEGER NOT NULL CHECK(kind IN (1,2)), sealed BLOB NOT NULL,\n\
           subject BLOB CHECK(subject IS NULL OR length(subject)=32),generation INTEGER,\n\
           scope TEXT,epoch INTEGER,observed_at_ms INTEGER,\n\
           applied INTEGER NOT NULL CHECK(applied IN (0,1)), inserted_order INTEGER NOT NULL UNIQUE,\n\
           UNIQUE(authority,sequence)\n\
         ) STRICT;\n\
         CREATE TABLE IF NOT EXISTS control_heads (\n\
           authority BLOB PRIMARY KEY CHECK(length(authority)=32),\n\
           sequence INTEGER NOT NULL CHECK(sequence>0),\n\
           envelope_id BLOB NOT NULL REFERENCES controls(envelope_id)\n\
         ) STRICT;\n\
         CREATE TABLE IF NOT EXISTS control_outbox (\n\
           envelope_id BLOB PRIMARY KEY REFERENCES controls(envelope_id) ON DELETE CASCADE,\n\
           enqueued_order INTEGER NOT NULL,attempts INTEGER NOT NULL DEFAULT 0,last_attempt_ms INTEGER\n\
         ) STRICT;\n\
         CREATE TABLE IF NOT EXISTS control_peer_receipts (\n\
           peer BLOB NOT NULL CHECK(length(peer)=32),\n\
           envelope_id BLOB NOT NULL REFERENCES controls(envelope_id) ON DELETE CASCADE,\n\
           acknowledged_at_ms INTEGER,PRIMARY KEY(peer,envelope_id)\n\
         ) STRICT;\n\
         CREATE INDEX IF NOT EXISTS controls_chain ON controls(authority,sequence);\n\
         CREATE INDEX IF NOT EXISTS control_outbox_order ON control_outbox(enqueued_order);\n\
         PRAGMA user_version=3;\n\
         COMMIT;",
    )?;
    migrate_v3_to_v4(connection)?;
    migrate_v4_to_v5(connection)?;
    migrate_v5_to_v6(connection)?;
    migrate_v6_to_v7(connection)?;
    migrate_v7_to_v8(connection)?;
    migrate_v8_to_v9(connection)?;
    migrate_v9_to_v10(connection)?;
    migrate_v10_to_v11(connection)?;
    migrate_v11_to_v12(connection)?;
    migrate_v12_to_v13(connection)?;
    migrate_v13_to_v14(connection)?;
    migrate_v14_to_v15(connection)?;
    migrate_v15_to_v16(connection)
}

fn migrate_v1_to_v2(connection: &Connection) -> Result<(), StoreError> {
    let transaction = connection.unchecked_transaction()?;
    transaction.execute_batch(
        "ALTER TABLE items ADD COLUMN envelope_id BLOB;\n\
         ALTER TABLE items ADD COLUMN custody_age_ms INTEGER NOT NULL DEFAULT 0;\n\
         ALTER TABLE items ADD COLUMN custody_clock_id BLOB;\n\
         ALTER TABLE items ADD COLUMN custody_tick_ms INTEGER;\n\
         ALTER TABLE items ADD COLUMN custody_elapsed_available INTEGER NOT NULL DEFAULT 0;\n\
         CREATE TABLE accepted_dots (\n\
           publisher BLOB NOT NULL CHECK(length(publisher)=32),counter INTEGER NOT NULL CHECK(counter>0),\n\
           item_id BLOB NOT NULL CHECK(length(item_id)=32),PRIMARY KEY(publisher,counter)\n\
         ) STRICT;\n\
         CREATE TABLE accepted_events (\n\
           publisher BLOB NOT NULL CHECK(length(publisher)=32),topic TEXT NOT NULL,scope TEXT NOT NULL,\n\
           sequence INTEGER NOT NULL CHECK(sequence>0),item_id BLOB NOT NULL CHECK(length(item_id)=32),\n\
           PRIMARY KEY(publisher,topic,scope,sequence)\n\
         ) STRICT;\n\
         CREATE TABLE controls (\n\
           envelope_id BLOB PRIMARY KEY CHECK(length(envelope_id)=32),\n\
           authority BLOB NOT NULL CHECK(length(authority)=32),\n\
           sequence INTEGER NOT NULL CHECK(sequence>0),\n\
           previous_control BLOB CHECK(previous_control IS NULL OR length(previous_control)=32),\n\
           kind INTEGER NOT NULL CHECK(kind IN (1,2)), sealed BLOB NOT NULL,\n\
           subject BLOB CHECK(subject IS NULL OR length(subject)=32),generation INTEGER,\n\
           scope TEXT,epoch INTEGER,observed_at_ms INTEGER,\n\
           applied INTEGER NOT NULL CHECK(applied IN (0,1)), inserted_order INTEGER NOT NULL UNIQUE,\n\
           UNIQUE(authority,sequence)\n\
         ) STRICT;\n\
         CREATE TABLE control_heads (\n\
           authority BLOB PRIMARY KEY CHECK(length(authority)=32),\n\
           sequence INTEGER NOT NULL CHECK(sequence>0),\n\
           envelope_id BLOB NOT NULL REFERENCES controls(envelope_id)\n\
         ) STRICT;\n\
         CREATE TABLE control_outbox (\n\
           envelope_id BLOB PRIMARY KEY REFERENCES controls(envelope_id) ON DELETE CASCADE,\n\
           enqueued_order INTEGER NOT NULL,attempts INTEGER NOT NULL DEFAULT 0,last_attempt_ms INTEGER\n\
         ) STRICT;\n\
         CREATE TABLE control_peer_receipts (\n\
           peer BLOB NOT NULL CHECK(length(peer)=32),\n\
           envelope_id BLOB NOT NULL REFERENCES controls(envelope_id) ON DELETE CASCADE,\n\
           acknowledged_at_ms INTEGER,PRIMARY KEY(peer,envelope_id)\n\
         ) STRICT;",
    )?;
    let migrated = {
        let mut statement = transaction.prepare("SELECT item_id,sealed FROM items")?;
        statement
            .query_map([], |row| {
                Ok((row.get::<_, Vec<u8>>(0)?, row.get::<_, Vec<u8>>(1)?))
            })?
            .collect::<Result<Vec<_>, _>>()?
    };
    for (item_id, sealed) in migrated {
        let envelope_id: EnvelopeId = Sha256::digest(&sealed).into();
        transaction.execute(
            "UPDATE items SET envelope_id=?1 WHERE item_id=?2",
            params![envelope_id.as_slice(), item_id],
        )?;
    }
    transaction.execute(
        "INSERT INTO accepted_dots(publisher,counter,item_id)\n\
         SELECT publisher,causal_counter,item_id FROM items",
        [],
    )?;
    transaction.execute(
        "INSERT INTO accepted_events(publisher,topic,scope,sequence,item_id)\n\
         SELECT publisher,topic,scope,event_sequence,item_id FROM items WHERE data_class=1",
        [],
    )?;
    transaction.execute_batch(
        "CREATE UNIQUE INDEX items_envelope_id ON items(envelope_id);\n\
         CREATE INDEX controls_chain ON controls(authority,sequence);\n\
         CREATE INDEX control_outbox_order ON control_outbox(enqueued_order);\n\
         PRAGMA user_version=2;",
    )?;
    transaction.commit()?;
    Ok(())
}

fn migrate_v2_to_v3(connection: &Connection) -> Result<(), StoreError> {
    connection.execute_batch(
        "BEGIN IMMEDIATE;\n\
         CREATE TABLE transfer_identities (\n\
           storage_key BLOB PRIMARY KEY REFERENCES wants(object_id) ON DELETE CASCADE\n\
             CHECK(length(storage_key)=32),\n\
           object_id BLOB NOT NULL UNIQUE CHECK(length(object_id)=33)\n\
         ) STRICT;\n\
         PRAGMA user_version=3;\n\
         COMMIT;",
    )?;
    Ok(())
}

fn migrate_v3_to_v4(connection: &Connection) -> Result<(), StoreError> {
    connection.execute_batch(
        "BEGIN IMMEDIATE;\n\
         CREATE TABLE bridge_authorization_controls (\n\
           envelope_id BLOB PRIMARY KEY CHECK(length(envelope_id)=32),\n\
           mission_id BLOB NOT NULL CHECK(length(mission_id)=32),\n\
           authority_id BLOB NOT NULL CHECK(length(authority_id)=32),\n\
           sequence INTEGER NOT NULL CHECK(sequence>0),\n\
           previous_control_id BLOB CHECK(previous_control_id IS NULL OR length(previous_control_id)=32),\n\
           authorization_key BLOB NOT NULL CHECK(length(authorization_key)=32),\n\
           generation INTEGER NOT NULL CHECK(generation>0),\n\
           enabled INTEGER NOT NULL CHECK(enabled IN (0,1)),\n\
           bridge_node_id BLOB NOT NULL CHECK(length(bridge_node_id)=32),\n\
           source_scope TEXT NOT NULL, target_scope TEXT NOT NULL,\n\
           source_route_epoch INTEGER, target_route_epoch INTEGER,\n\
           source_route_commitment BLOB, target_route_commitment BLOB,\n\
           allowed_priority_mask INTEGER, max_total_hops INTEGER,\n\
           authorization_body BLOB NOT NULL\n\
             CHECK(length(authorization_body) BETWEEN 1 AND 65536),\n\
           exact_bytes BLOB NOT NULL CHECK(length(exact_bytes) BETWEEN 1 AND 65536),\n\
           applied INTEGER NOT NULL CHECK(applied IN (0,1)),\n\
           inserted_order INTEGER NOT NULL UNIQUE,\n\
           accounted_bytes INTEGER NOT NULL CHECK(accounted_bytes>0),\n\
           UNIQUE(authority_id,sequence),\n\
           CHECK((sequence=1 AND previous_control_id IS NULL) OR\n\
                 (sequence>1 AND previous_control_id IS NOT NULL)),\n\
           CHECK((enabled=0 AND source_route_epoch IS NULL AND target_route_epoch IS NULL AND\n\
                  source_route_commitment IS NULL AND target_route_commitment IS NULL AND\n\
                  allowed_priority_mask IS NULL AND max_total_hops IS NULL) OR\n\
                 (enabled=1 AND source_route_epoch>0 AND target_route_epoch>0 AND\n\
                  length(source_route_commitment)=32 AND length(target_route_commitment)=32 AND\n\
                  allowed_priority_mask BETWEEN 1 AND 15 AND max_total_hops BETWEEN 1 AND 8))\n\
         ) STRICT;\n\
         CREATE TABLE bridge_authorization_topics (\n\
           envelope_id BLOB NOT NULL REFERENCES bridge_authorization_controls(envelope_id),\n\
           topic TEXT NOT NULL, topic_order INTEGER NOT NULL CHECK(topic_order BETWEEN 0 AND 127),\n\
           PRIMARY KEY(envelope_id,topic), UNIQUE(envelope_id,topic_order)\n\
         ) STRICT;\n\
         CREATE TABLE bridge_authorization_heads (\n\
           authority_id BLOB PRIMARY KEY CHECK(length(authority_id)=32),\n\
           sequence INTEGER NOT NULL CHECK(sequence>0),\n\
           envelope_id BLOB NOT NULL UNIQUE\n\
             REFERENCES bridge_authorization_controls(envelope_id)\n\
         ) STRICT;\n\
         CREATE TABLE bridge_authorization_highwater (\n\
           authorization_key BLOB PRIMARY KEY CHECK(length(authorization_key)=32),\n\
           generation INTEGER NOT NULL CHECK(generation>0),\n\
           enabled INTEGER NOT NULL CHECK(enabled IN (0,1)),\n\
           envelope_id BLOB NOT NULL UNIQUE\n\
             REFERENCES bridge_authorization_controls(envelope_id)\n\
         ) STRICT;\n\
         CREATE TABLE bridge_authorization_outbox (\n\
           envelope_id BLOB PRIMARY KEY\n\
             REFERENCES bridge_authorization_controls(envelope_id),\n\
           enqueued_order INTEGER NOT NULL UNIQUE, attempts INTEGER NOT NULL DEFAULT 0,\n\
           last_attempt_ms INTEGER\n\
         ) STRICT;\n\
         CREATE TABLE bridge_source_objects (\n\
           origin_envelope_id BLOB PRIMARY KEY CHECK(length(origin_envelope_id)=32),\n\
           source_item_id BLOB NOT NULL CHECK(length(source_item_id)=32),\n\
           exact_bytes BLOB NOT NULL CHECK(length(exact_bytes)>0),\n\
           inserted_order INTEGER NOT NULL UNIQUE,\n\
           accounted_bytes INTEGER NOT NULL CHECK(accounted_bytes>0)\n\
         ) STRICT;\n\
         CREATE TABLE bridge_route_wrappers (\n\
           wrapper_envelope_id BLOB PRIMARY KEY CHECK(length(wrapper_envelope_id)=32),\n\
           bridge_route_id BLOB NOT NULL CHECK(length(bridge_route_id)=32),\n\
           origin_envelope_id BLOB NOT NULL REFERENCES bridge_source_objects(origin_envelope_id),\n\
           source_item_id BLOB NOT NULL CHECK(length(source_item_id)=32),\n\
           source_publisher BLOB NOT NULL CHECK(length(source_publisher)=32),\n\
           origin_scope TEXT NOT NULL, origin_route_epoch INTEGER NOT NULL CHECK(origin_route_epoch>0),\n\
           current_scope TEXT NOT NULL, current_route_epoch INTEGER NOT NULL CHECK(current_route_epoch>0),\n\
           source_topic TEXT NOT NULL, source_priority INTEGER NOT NULL CHECK(source_priority BETWEEN 0 AND 3),\n\
           source_ttl_ms INTEGER, hop_count INTEGER NOT NULL CHECK(hop_count BETWEEN 1 AND 8),\n\
           cumulative_custody_age_ms INTEGER NOT NULL CHECK(cumulative_custody_age_ms>=0),\n\
           age_continuity_unknown INTEGER NOT NULL CHECK(age_continuity_unknown IN (0,1)),\n\
           exact_bytes BLOB NOT NULL CHECK(length(exact_bytes) BETWEEN 1 AND 524322),\n\
           inserted_order INTEGER NOT NULL UNIQUE,\n\
           accounted_bytes INTEGER NOT NULL CHECK(accounted_bytes>0),\n\
           UNIQUE(origin_envelope_id,current_scope,current_route_epoch,bridge_route_id)\n\
         ) STRICT;\n\
         CREATE TABLE bridge_wrapper_authorizations (\n\
           wrapper_envelope_id BLOB NOT NULL REFERENCES bridge_route_wrappers(wrapper_envelope_id),\n\
           hop_index INTEGER NOT NULL CHECK(hop_index BETWEEN 1 AND 8),\n\
           authorization_envelope_id BLOB NOT NULL\n\
             REFERENCES bridge_authorization_controls(envelope_id),\n\
           PRIMARY KEY(wrapper_envelope_id,hop_index)\n\
         ) STRICT;\n\
         CREATE TABLE bridge_active_routes (\n\
           origin_envelope_id BLOB NOT NULL CHECK(length(origin_envelope_id)=32),\n\
           current_scope TEXT NOT NULL, current_route_epoch INTEGER NOT NULL CHECK(current_route_epoch>0),\n\
           wrapper_envelope_id BLOB NOT NULL UNIQUE\n\
             REFERENCES bridge_route_wrappers(wrapper_envelope_id),\n\
           PRIMARY KEY(origin_envelope_id,current_scope,current_route_epoch)\n\
         ) STRICT;\n\
         CREATE TABLE bridge_route_outbox (\n\
           wrapper_envelope_id BLOB PRIMARY KEY REFERENCES bridge_route_wrappers(wrapper_envelope_id),\n\
           enqueued_order INTEGER NOT NULL UNIQUE, attempts INTEGER NOT NULL DEFAULT 0,\n\
           last_attempt_ms INTEGER\n\
         ) STRICT;\n\
         CREATE TABLE bridge_route_peer_receipts (\n\
           peer BLOB NOT NULL CHECK(length(peer)=32),\n\
           wrapper_envelope_id BLOB NOT NULL REFERENCES bridge_route_wrappers(wrapper_envelope_id),\n\
           acknowledged_at_ms INTEGER, PRIMARY KEY(peer,wrapper_envelope_id)\n\
         ) STRICT;\n\
         CREATE INDEX bridge_authorization_chain\n\
           ON bridge_authorization_controls(authority_id,sequence);\n\
         CREATE INDEX bridge_authorization_key_generation\n\
           ON bridge_authorization_controls(authorization_key,generation);\n\
         CREATE INDEX bridge_route_selection\n\
           ON bridge_route_wrappers(origin_envelope_id,current_scope,current_route_epoch,hop_count,bridge_route_id);\n\
         PRAGMA user_version=4;\n\
         COMMIT;",
    )?;
    Ok(())
}

fn migrate_v4_to_v5(connection: &Connection) -> Result<(), StoreError> {
    connection.execute_batch(
        "BEGIN IMMEDIATE;\n\
         ALTER TABLE bridge_source_objects ADD COLUMN source_publisher BLOB\n\
           CHECK(source_publisher IS NULL OR length(source_publisher)=32);\n\
         ALTER TABLE bridge_source_objects ADD COLUMN data_class INTEGER\n\
           CHECK(data_class IS NULL OR data_class BETWEEN 0 AND 3);\n\
         ALTER TABLE bridge_source_objects ADD COLUMN source_topic TEXT;\n\
         ALTER TABLE bridge_source_objects ADD COLUMN source_priority INTEGER\n\
           CHECK(source_priority IS NULL OR source_priority BETWEEN 0 AND 3);\n\
         ALTER TABLE bridge_source_objects ADD COLUMN causal_counter INTEGER\n\
           CHECK(causal_counter IS NULL OR causal_counter>0);\n\
         ALTER TABLE bridge_source_objects ADD COLUMN causal_context BLOB;\n\
         ALTER TABLE bridge_source_objects ADD COLUMN event_sequence INTEGER;\n\
         ALTER TABLE bridge_source_objects ADD COLUMN logical_key BLOB;\n\
         ALTER TABLE bridge_source_objects ADD COLUMN source_ttl_ms INTEGER;\n\
         ALTER TABLE bridge_source_objects ADD COLUMN blob_id BLOB\n\
           CHECK(blob_id IS NULL OR length(blob_id)=32);\n\
         ALTER TABLE bridge_source_objects ADD COLUMN blob_chunk_count INTEGER\n\
           CHECK(blob_chunk_count IS NULL OR blob_chunk_count>0);\n\
         ALTER TABLE bridge_source_objects ADD COLUMN blob_merkle_root BLOB\n\
           CHECK(blob_merkle_root IS NULL OR length(blob_merkle_root)=32);\n\
         ALTER TABLE bridge_source_objects ADD COLUMN forwarding_custody_age_ms INTEGER\n\
           CHECK(forwarding_custody_age_ms IS NULL OR forwarding_custody_age_ms>=0);\n\
         ALTER TABLE bridge_source_objects ADD COLUMN content_len INTEGER\n\
           CHECK(content_len IS NULL OR content_len>=0);\n\
         ALTER TABLE bridge_source_objects ADD COLUMN tombstone INTEGER\n\
           CHECK(tombstone IS NULL OR tombstone IN (0,1));\n\
         ALTER TABLE bridge_source_objects ADD COLUMN origin_scope TEXT;\n\
         ALTER TABLE bridge_source_objects ADD COLUMN origin_route_epoch INTEGER\n\
           CHECK(origin_route_epoch IS NULL OR origin_route_epoch>0);\n\
         UPDATE bridge_source_objects SET source_publisher=(\n\
           SELECT w.source_publisher FROM bridge_route_wrappers w\n\
           WHERE w.origin_envelope_id=bridge_source_objects.origin_envelope_id\n\
           ORDER BY w.inserted_order LIMIT 1\n\
         );\n\
         ALTER TABLE bridge_route_wrappers ADD COLUMN custody_clock_id BLOB\n\
           CHECK(custody_clock_id IS NULL OR length(custody_clock_id)=16);\n\
         ALTER TABLE bridge_route_wrappers ADD COLUMN custody_tick_ms INTEGER;\n\
         ALTER TABLE bridge_route_wrappers ADD COLUMN custody_elapsed_available INTEGER NOT NULL DEFAULT 0\n\
           CHECK(custody_elapsed_available IN (0,1));\n\
         ALTER TABLE bridge_route_wrappers ADD COLUMN forwarding_custody_age_ms INTEGER NOT NULL DEFAULT 0\n\
           CHECK(forwarding_custody_age_ms>=0);\n\
         CREATE TABLE bridge_pending_wrappers (\n\
           wrapper_envelope_id BLOB PRIMARY KEY CHECK(length(wrapper_envelope_id)=32),\n\
           bridge_route_id BLOB NOT NULL CHECK(length(bridge_route_id)=32),\n\
           origin_envelope_id BLOB NOT NULL CHECK(length(origin_envelope_id)=32),\n\
           source_item_id BLOB NOT NULL CHECK(length(source_item_id)=32),\n\
           origin_scope TEXT NOT NULL, origin_route_epoch INTEGER NOT NULL CHECK(origin_route_epoch>0),\n\
           current_scope TEXT NOT NULL, current_route_epoch INTEGER NOT NULL CHECK(current_route_epoch>0),\n\
           hop_count INTEGER NOT NULL CHECK(hop_count BETWEEN 1 AND 8),\n\
           cumulative_custody_age_ms INTEGER NOT NULL CHECK(cumulative_custody_age_ms>=0),\n\
           forwarding_custody_age_ms INTEGER NOT NULL CHECK(forwarding_custody_age_ms>=0),\n\
           age_continuity_unknown INTEGER NOT NULL CHECK(age_continuity_unknown IN (0,1)),\n\
           custody_clock_id BLOB CHECK(custody_clock_id IS NULL OR length(custody_clock_id)=16),\n\
           custody_tick_ms INTEGER,\n\
           custody_elapsed_available INTEGER NOT NULL CHECK(custody_elapsed_available IN (0,1)),\n\
           route_body BLOB NOT NULL CHECK(length(route_body)>0),\n\
           exact_bytes BLOB NOT NULL CHECK(length(exact_bytes) BETWEEN 1 AND 524322),\n\
           inserted_order INTEGER NOT NULL UNIQUE,\n\
           accounted_bytes INTEGER NOT NULL CHECK(accounted_bytes>0),\n\
           UNIQUE(origin_envelope_id,current_scope,current_route_epoch,bridge_route_id),\n\
           CHECK((custody_elapsed_available=0 AND custody_clock_id IS NULL AND custody_tick_ms IS NULL) OR\n\
                 (custody_elapsed_available=1 AND length(custody_clock_id)=16 AND custody_tick_ms>=0))\n\
         ) STRICT;\n\
         CREATE TABLE bridge_pending_wrapper_authorizations (\n\
           wrapper_envelope_id BLOB NOT NULL REFERENCES bridge_pending_wrappers(wrapper_envelope_id),\n\
           hop_index INTEGER NOT NULL CHECK(hop_index BETWEEN 1 AND 8),\n\
           authorization_envelope_id BLOB NOT NULL CHECK(length(authorization_envelope_id)=32),\n\
           PRIMARY KEY(wrapper_envelope_id,hop_index)\n\
         ) STRICT;\n\
         CREATE TABLE bridge_pending_sources (\n\
           origin_envelope_id BLOB PRIMARY KEY CHECK(length(origin_envelope_id)=32),\n\
           source_item_id BLOB NOT NULL CHECK(length(source_item_id)=32),\n\
           source_publisher BLOB NOT NULL CHECK(length(source_publisher)=32),\n\
           data_class INTEGER NOT NULL CHECK(data_class BETWEEN 0 AND 3),\n\
           source_topic TEXT NOT NULL, source_priority INTEGER NOT NULL CHECK(source_priority BETWEEN 0 AND 3),\n\
           causal_counter INTEGER NOT NULL CHECK(causal_counter>0), causal_context BLOB NOT NULL,\n\
           event_sequence INTEGER, logical_key BLOB NOT NULL, source_ttl_ms INTEGER,\n\
           blob_id BLOB CHECK(blob_id IS NULL OR length(blob_id)=32),\n\
           blob_chunk_count INTEGER CHECK(blob_chunk_count IS NULL OR blob_chunk_count>0),\n\
           blob_merkle_root BLOB CHECK(blob_merkle_root IS NULL OR length(blob_merkle_root)=32),\n\
           forwarding_custody_age_ms INTEGER NOT NULL CHECK(forwarding_custody_age_ms>=0),\n\
           content_len INTEGER NOT NULL CHECK(content_len>=0),\n\
           tombstone INTEGER NOT NULL CHECK(tombstone IN (0,1)),\n\
           origin_scope TEXT NOT NULL, origin_route_epoch INTEGER NOT NULL CHECK(origin_route_epoch>0),\n\
           exact_bytes BLOB NOT NULL CHECK(length(exact_bytes)>0),\n\
           inserted_order INTEGER NOT NULL UNIQUE,\n\
           accounted_bytes INTEGER NOT NULL CHECK(accounted_bytes>0),\n\
           CHECK((data_class=1 AND event_sequence IS NOT NULL AND event_sequence>0) OR\n\
                 (data_class<>1 AND event_sequence IS NULL)),\n\
           CHECK((data_class=3 AND blob_id IS NOT NULL AND length(blob_id)=32 AND\n\
                    blob_chunk_count IS NOT NULL AND blob_chunk_count>0 AND\n\
                    blob_merkle_root IS NOT NULL AND length(blob_merkle_root)=32) OR\n\
                 (data_class<>3 AND blob_id IS NULL AND blob_chunk_count IS NULL AND\n\
                    blob_merkle_root IS NULL))\n\
         ) STRICT;\n\
         CREATE TABLE bridge_authorization_peer_receipts (\n\
           peer BLOB NOT NULL CHECK(length(peer)=32),\n\
           envelope_id BLOB NOT NULL REFERENCES bridge_authorization_controls(envelope_id),\n\
           acknowledged_at_ms INTEGER, PRIMARY KEY(peer,envelope_id)\n\
         ) STRICT;\n\
         CREATE TABLE bridge_source_peer_receipts (\n\
           peer BLOB NOT NULL CHECK(length(peer)=32),\n\
           origin_envelope_id BLOB NOT NULL REFERENCES bridge_source_objects(origin_envelope_id),\n\
           acknowledged_at_ms INTEGER, PRIMARY KEY(peer,origin_envelope_id)\n\
         ) STRICT;\n\
         CREATE TABLE bridge_target_projection (\n\
           wrapper_envelope_id BLOB PRIMARY KEY\n\
             REFERENCES bridge_route_wrappers(wrapper_envelope_id),\n\
           source_item_id BLOB NOT NULL CHECK(length(source_item_id)=32),\n\
           target_scope TEXT NOT NULL, target_route_epoch INTEGER NOT NULL CHECK(target_route_epoch>0),\n\
           version_status INTEGER NOT NULL CHECK(version_status BETWEEN 0 AND 2),\n\
           UNIQUE(source_item_id,target_scope,target_route_epoch)\n\
         ) STRICT;\n\
         CREATE TRIGGER bridge_active_route_projection_delete\n\
           AFTER DELETE ON bridge_active_routes BEGIN\n\
             DELETE FROM bridge_target_projection WHERE wrapper_envelope_id=OLD.wrapper_envelope_id;\n\
           END;\n\
         CREATE TRIGGER bridge_active_route_projection_update\n\
           AFTER UPDATE OF wrapper_envelope_id ON bridge_active_routes BEGIN\n\
             DELETE FROM bridge_target_projection WHERE wrapper_envelope_id=OLD.wrapper_envelope_id;\n\
           END;\n\
         CREATE UNIQUE INDEX bridge_source_item_identity ON bridge_source_objects(source_item_id)\n\
           WHERE data_class IS NOT NULL;\n\
         CREATE INDEX bridge_pending_wrapper_order ON bridge_pending_wrappers(inserted_order);\n\
         CREATE INDEX bridge_pending_source_order ON bridge_pending_sources(inserted_order);\n\
         PRAGMA user_version=5;\n\
         COMMIT;",
    )?;
    Ok(())
}

fn migrate_v5_to_v6(connection: &Connection) -> Result<(), StoreError> {
    connection.execute_batch(
        "BEGIN IMMEDIATE;\n\
         ALTER TABLE bridge_source_objects ADD COLUMN reused_item_id BLOB\n\
           REFERENCES items(item_id) ON DELETE RESTRICT\n\
           CHECK(reused_item_id IS NULL OR length(reused_item_id)=32);\n\
         ALTER TABLE bridge_source_objects ADD COLUMN cumulative_custody_age_ms INTEGER\n\
           NOT NULL DEFAULT 0 CHECK(cumulative_custody_age_ms>=0);\n\
         ALTER TABLE bridge_source_objects ADD COLUMN source_age_continuity_unknown INTEGER\n\
           NOT NULL DEFAULT 1 CHECK(source_age_continuity_unknown IN (0,1));\n\
         ALTER TABLE bridge_source_objects ADD COLUMN source_custody_clock_id BLOB\n\
           CHECK(source_custody_clock_id IS NULL OR length(source_custody_clock_id)=16);\n\
         ALTER TABLE bridge_source_objects ADD COLUMN source_custody_tick_ms INTEGER;\n\
         ALTER TABLE bridge_source_objects ADD COLUMN source_custody_elapsed_available INTEGER\n\
           NOT NULL DEFAULT 0 CHECK(source_custody_elapsed_available IN (0,1));\n\
         ALTER TABLE bridge_pending_sources ADD COLUMN cumulative_custody_age_ms INTEGER\n\
           NOT NULL DEFAULT 0 CHECK(cumulative_custody_age_ms>=0);\n\
         ALTER TABLE bridge_pending_sources ADD COLUMN source_age_continuity_unknown INTEGER\n\
           NOT NULL DEFAULT 1 CHECK(source_age_continuity_unknown IN (0,1));\n\
         ALTER TABLE bridge_pending_sources ADD COLUMN source_custody_clock_id BLOB\n\
           CHECK(source_custody_clock_id IS NULL OR length(source_custody_clock_id)=16);\n\
         ALTER TABLE bridge_pending_sources ADD COLUMN source_custody_tick_ms INTEGER;\n\
         ALTER TABLE bridge_pending_sources ADD COLUMN source_custody_elapsed_available INTEGER\n\
           NOT NULL DEFAULT 0 CHECK(source_custody_elapsed_available IN (0,1));\n\
         CREATE TABLE bridge_unresolved_sources (\n\
           origin_envelope_id BLOB PRIMARY KEY CHECK(length(origin_envelope_id)=32),\n\
           cumulative_custody_age_ms INTEGER NOT NULL CHECK(cumulative_custody_age_ms>=0),\n\
           forwarding_custody_age_ms INTEGER NOT NULL CHECK(forwarding_custody_age_ms>=0),\n\
           age_continuity_unknown INTEGER NOT NULL CHECK(age_continuity_unknown IN (0,1)),\n\
           custody_clock_id BLOB CHECK(custody_clock_id IS NULL OR length(custody_clock_id)=16),\n\
           custody_tick_ms INTEGER, custody_elapsed_available INTEGER NOT NULL\n\
             CHECK(custody_elapsed_available IN (0,1)),\n\
           exact_bytes BLOB NOT NULL CHECK(length(exact_bytes)>0),\n\
           inserted_order INTEGER NOT NULL UNIQUE,\n\
           accounted_bytes INTEGER NOT NULL CHECK(accounted_bytes>0),\n\
           CHECK((custody_elapsed_available=0 AND custody_clock_id IS NULL AND custody_tick_ms IS NULL) OR\n\
                 (custody_elapsed_available=1 AND length(custody_clock_id)=16 AND custody_tick_ms>=0))\n\
         ) STRICT;\n\
         CREATE INDEX bridge_unresolved_source_order\n\
           ON bridge_unresolved_sources(inserted_order);\n\
         CREATE INDEX bridge_reused_source_item\n\
           ON bridge_source_objects(reused_item_id);\n\
         PRAGMA user_version=6;\n\
         COMMIT;",
    )?;
    Ok(())
}

fn migrate_v6_to_v7(connection: &Connection) -> Result<(), StoreError> {
    connection.execute_batch(
        "BEGIN IMMEDIATE;\n\
         CREATE TABLE bridge_pending_blob_carriers (\n\
           object_id BLOB NOT NULL CHECK(length(object_id)=33),\n\
           source_envelope_id BLOB NOT NULL CHECK(length(source_envelope_id)=32),\n\
           exact_bytes BLOB NOT NULL CHECK(length(exact_bytes)>0),\n\
           inserted_order INTEGER NOT NULL UNIQUE,\n\
           accounted_bytes INTEGER NOT NULL CHECK(accounted_bytes>0),\n\
           PRIMARY KEY(object_id,source_envelope_id)\n\
         ) STRICT;\n\
         CREATE TABLE bridge_blob_carrier_commits (\n\
           object_id BLOB NOT NULL CHECK(length(object_id)=33),\n\
           source_envelope_id BLOB NOT NULL CHECK(length(source_envelope_id)=32),\n\
           committed_order INTEGER NOT NULL UNIQUE,\n\
           accounted_bytes INTEGER NOT NULL CHECK(accounted_bytes>0),\n\
           PRIMARY KEY(object_id,source_envelope_id)\n\
         ) STRICT;\n\
         CREATE TABLE bridge_blob_carrier_peer_receipts (\n\
           peer BLOB NOT NULL CHECK(length(peer)=32),\n\
           wrapper_envelope_id BLOB NOT NULL REFERENCES bridge_route_wrappers(wrapper_envelope_id)\n\
             ON DELETE CASCADE CHECK(length(wrapper_envelope_id)=32),\n\
           source_envelope_id BLOB NOT NULL REFERENCES bridge_source_objects(origin_envelope_id)\n\
             ON DELETE CASCADE CHECK(length(source_envelope_id)=32),\n\
           object_id BLOB NOT NULL CHECK(length(object_id)=33),\n\
           acknowledged_at_ms INTEGER,\n\
           PRIMARY KEY(peer,wrapper_envelope_id,source_envelope_id,object_id)\n\
         ) STRICT;\n\
         CREATE TABLE bridge_authorization_peer_attempts (\n\
           peer BLOB NOT NULL CHECK(length(peer)=32),\n\
           envelope_id BLOB NOT NULL REFERENCES bridge_authorization_controls(envelope_id)\n\
             ON DELETE CASCADE,\n\
           attempts INTEGER NOT NULL DEFAULT 0 CHECK(attempts>=0),last_attempt_ms INTEGER,\n\
           PRIMARY KEY(peer,envelope_id)\n\
         ) STRICT;\n\
         CREATE TABLE bridge_route_peer_attempts (\n\
           peer BLOB NOT NULL CHECK(length(peer)=32),\n\
           wrapper_envelope_id BLOB NOT NULL REFERENCES bridge_route_wrappers(wrapper_envelope_id)\n\
             ON DELETE CASCADE,\n\
           attempts INTEGER NOT NULL DEFAULT 0 CHECK(attempts>=0),last_attempt_ms INTEGER,\n\
           PRIMARY KEY(peer,wrapper_envelope_id)\n\
         ) STRICT;\n\
         CREATE TABLE bridge_source_peer_attempts (\n\
           peer BLOB NOT NULL CHECK(length(peer)=32),\n\
           origin_envelope_id BLOB NOT NULL REFERENCES bridge_source_objects(origin_envelope_id)\n\
             ON DELETE CASCADE,\n\
           attempts INTEGER NOT NULL DEFAULT 0 CHECK(attempts>=0),last_attempt_ms INTEGER,\n\
           PRIMARY KEY(peer,origin_envelope_id)\n\
         ) STRICT;\n\
         CREATE TABLE bridge_source_path_peer_receipts (\n\
           peer BLOB NOT NULL CHECK(length(peer)=32),\n\
           wrapper_envelope_id BLOB NOT NULL REFERENCES bridge_route_wrappers(wrapper_envelope_id)\n\
             ON DELETE CASCADE,\n\
           origin_envelope_id BLOB NOT NULL REFERENCES bridge_source_objects(origin_envelope_id)\n\
             ON DELETE CASCADE,acknowledged_at_ms INTEGER,\n\
           PRIMARY KEY(peer,wrapper_envelope_id,origin_envelope_id)\n\
         ) STRICT;\n\
         CREATE INDEX bridge_pending_blob_carrier_order\n\
           ON bridge_pending_blob_carriers(inserted_order);\n\
         CREATE INDEX bridge_blob_carrier_source_receipts\n\
           ON bridge_blob_carrier_peer_receipts(peer,source_envelope_id,wrapper_envelope_id);\n\
         PRAGMA user_version=7;\n\
         COMMIT;",
    )?;
    Ok(())
}

fn migrate_v7_to_v8(connection: &Connection) -> Result<(), StoreError> {
    connection.execute_batch(
        "BEGIN IMMEDIATE;\n\
         ALTER TABLE transfer_identities ADD COLUMN origin_semantic_version INTEGER\n\
           CHECK(origin_semantic_version IS NULL OR origin_semantic_version IN (1,2));\n\
         CREATE TABLE bridge_blob_carrier_peer_possessions (\n\
           peer BLOB NOT NULL CHECK(length(peer)=32),\n\
           source_envelope_id BLOB NOT NULL REFERENCES bridge_source_objects(origin_envelope_id)\n\
             ON DELETE CASCADE CHECK(length(source_envelope_id)=32),\n\
           object_id BLOB NOT NULL CHECK(length(object_id)=33),\n\
           acknowledged_at_ms INTEGER,\n\
           PRIMARY KEY(peer,source_envelope_id,object_id)\n\
         ) STRICT;\n\
         CREATE TABLE bridge_projection_deliveries (\n\
           subscription_id INTEGER NOT NULL REFERENCES subscriptions(subscription_id)\n\
             ON DELETE CASCADE,\n\
           source_item_id BLOB NOT NULL CHECK(length(source_item_id)=32),\n\
           wrapper_envelope_id BLOB NOT NULL\n\
             REFERENCES bridge_route_wrappers(wrapper_envelope_id) ON DELETE CASCADE,\n\
           attempts INTEGER NOT NULL DEFAULT 0 CHECK(attempts>=0),\n\
           last_delivery_ms INTEGER,acked_at_ms INTEGER,\n\
           PRIMARY KEY(subscription_id,source_item_id)\n\
         ) STRICT;\n\
         CREATE TABLE semantic_app_deliveries (\n\
           subscription_id INTEGER NOT NULL REFERENCES subscriptions(subscription_id)\n\
             ON DELETE CASCADE,\n\
           item_id BLOB NOT NULL CHECK(length(item_id)=32),\n\
           target_scope TEXT NOT NULL,\n\
           representation INTEGER NOT NULL CHECK(representation IN (0,1)),\n\
           wrapper_envelope_id BLOB\n\
             REFERENCES bridge_route_wrappers(wrapper_envelope_id) ON DELETE SET NULL\n\
             CHECK(wrapper_envelope_id IS NULL OR length(wrapper_envelope_id)=32),\n\
           attempts INTEGER NOT NULL DEFAULT 0 CHECK(attempts>=0),\n\
           last_delivery_ms INTEGER,acked_at_ms INTEGER,\n\
           PRIMARY KEY(subscription_id,item_id),\n\
           CHECK((representation=0 AND wrapper_envelope_id IS NULL) OR representation=1)\n\
         ) STRICT;\n\
         INSERT INTO semantic_app_deliveries(\n\
           subscription_id,item_id,target_scope,representation,attempts,last_delivery_ms,acked_at_ms)\n\
         SELECT d.subscription_id,d.item_id,i.scope,0,d.attempts,d.last_delivery_ms,d.acked_at_ms\n\
         FROM app_deliveries d JOIN items i ON i.item_id=d.item_id;\n\
         PRAGMA user_version=8;\n\
         COMMIT;",
    )?;
    Ok(())
}

fn migrate_v8_to_v9(connection: &Connection) -> Result<(), StoreError> {
    connection.execute_batch(
        "BEGIN IMMEDIATE;\n\
         CREATE TABLE batch_proofs (\n\
           proof_envelope_id BLOB PRIMARY KEY CHECK(length(proof_envelope_id)=32),\n\
           batch_id BLOB NOT NULL UNIQUE CHECK(length(batch_id)=32),\n\
           scope TEXT NOT NULL,\n\
           exact_bytes BLOB NOT NULL CHECK(length(exact_bytes)>0),\n\
           inserted_order INTEGER NOT NULL UNIQUE,\n\
           accounted_bytes INTEGER NOT NULL CHECK(accounted_bytes>0)\n\
         ) STRICT;\n\
         CREATE TABLE rejected_batch_proofs (\n\
           proof_envelope_id BLOB PRIMARY KEY CHECK(length(proof_envelope_id)=32),\n\
           inserted_order INTEGER NOT NULL UNIQUE,\n\
           accounted_bytes INTEGER NOT NULL CHECK(accounted_bytes>0)\n\
         ) STRICT;\n\
         CREATE TABLE pending_batch_items (\n\
           envelope_id BLOB PRIMARY KEY CHECK(length(envelope_id)=32),\n\
           item_id BLOB NOT NULL CHECK(length(item_id)=32),\n\
           proof_envelope_id BLOB NOT NULL CHECK(length(proof_envelope_id)=32),\n\
           scope TEXT NOT NULL,priority INTEGER NOT NULL CHECK(priority BETWEEN 0 AND 3),\n\
           publisher BLOB NOT NULL CHECK(length(publisher)=32),\n\
           key_epoch INTEGER NOT NULL CHECK(key_epoch>=0),\n\
           ttl_ms INTEGER,cumulative_custody_age_ms INTEGER NOT NULL CHECK(cumulative_custody_age_ms>=0),\n\
           forwarding_custody_age_ms INTEGER NOT NULL CHECK(forwarding_custody_age_ms>=0),\n\
           age_continuity_unknown INTEGER NOT NULL CHECK(age_continuity_unknown IN (0,1)),\n\
           custody_clock_id BLOB CHECK(custody_clock_id IS NULL OR length(custody_clock_id)=16),\n\
           custody_tick_ms INTEGER,custody_elapsed_available INTEGER NOT NULL\n\
             CHECK(custody_elapsed_available IN (0,1)),\n\
           exact_bytes BLOB NOT NULL CHECK(length(exact_bytes)>0),\n\
           inserted_order INTEGER NOT NULL UNIQUE,\n\
           accounted_bytes INTEGER NOT NULL CHECK(accounted_bytes>0),\n\
           UNIQUE(item_id,proof_envelope_id)\n\
         ) STRICT;\n\
         CREATE TABLE batch_item_representations (\n\
           item_id BLOB NOT NULL REFERENCES items(item_id) ON DELETE CASCADE\n\
             CHECK(length(item_id)=32),\n\
           representation INTEGER NOT NULL CHECK(representation IN (0,1)),\n\
           envelope_id BLOB NOT NULL UNIQUE CHECK(length(envelope_id)=32),\n\
           proof_envelope_id BLOB REFERENCES batch_proofs(proof_envelope_id)\n\
             ON DELETE RESTRICT CHECK(proof_envelope_id IS NULL OR length(proof_envelope_id)=32),\n\
           exact_bytes BLOB,canonical INTEGER NOT NULL CHECK(canonical IN (0,1)),\n\
           inserted_order INTEGER NOT NULL UNIQUE,\n\
           accounted_bytes INTEGER NOT NULL CHECK(accounted_bytes>0),\n\
           PRIMARY KEY(item_id,representation),\n\
           CHECK((representation=0 AND proof_envelope_id IS NULL) OR\n\
                 (representation=1 AND proof_envelope_id IS NOT NULL)),\n\
           CHECK((canonical=1 AND exact_bytes IS NULL) OR\n\
                 (canonical=0 AND exact_bytes IS NOT NULL AND length(exact_bytes)>0))\n\
         ) STRICT;\n\
         CREATE TABLE batch_proof_outbox (\n\
           proof_envelope_id BLOB PRIMARY KEY REFERENCES batch_proofs(proof_envelope_id)\n\
             ON DELETE CASCADE,\n\
           enqueued_order INTEGER NOT NULL UNIQUE,attempts INTEGER NOT NULL DEFAULT 0\n\
             CHECK(attempts>=0),last_attempt_ms INTEGER\n\
         ) STRICT;\n\
         CREATE TABLE batch_proof_peer_receipts (\n\
           peer BLOB NOT NULL CHECK(length(peer)=32),\n\
           proof_envelope_id BLOB NOT NULL REFERENCES batch_proofs(proof_envelope_id)\n\
             ON DELETE CASCADE,acknowledged_at_ms INTEGER,\n\
           PRIMARY KEY(peer,proof_envelope_id)\n\
         ) STRICT;\n\
         CREATE TABLE batch_proof_peer_attempts (\n\
           peer BLOB NOT NULL CHECK(length(peer)=32),\n\
           proof_envelope_id BLOB NOT NULL REFERENCES batch_proofs(proof_envelope_id)\n\
             ON DELETE CASCADE,attempts INTEGER NOT NULL CHECK(attempts>0),\n\
           last_attempt_ms INTEGER,PRIMARY KEY(peer,proof_envelope_id)\n\
         ) STRICT;\n\
         CREATE TABLE batch_compact_outbox (\n\
           item_id BLOB PRIMARY KEY REFERENCES items(item_id) ON DELETE CASCADE,\n\
           enqueued_order INTEGER NOT NULL UNIQUE,attempts INTEGER NOT NULL DEFAULT 0\n\
             CHECK(attempts>=0),last_attempt_ms INTEGER\n\
         ) STRICT;\n\
         CREATE TABLE batch_compact_peer_receipts (\n\
           peer BLOB NOT NULL CHECK(length(peer)=32),\n\
           item_id BLOB NOT NULL REFERENCES items(item_id) ON DELETE CASCADE,\n\
           acknowledged_at_ms INTEGER,PRIMARY KEY(peer,item_id)\n\
         ) STRICT;\n\
         CREATE TABLE batch_compact_peer_attempts (\n\
           peer BLOB NOT NULL CHECK(length(peer)=32),\n\
           item_id BLOB NOT NULL REFERENCES items(item_id) ON DELETE CASCADE,\n\
           attempts INTEGER NOT NULL CHECK(attempts>0),last_attempt_ms INTEGER,\n\
           PRIMARY KEY(peer,item_id)\n\
         ) STRICT;\n\
         CREATE INDEX pending_batch_items_by_proof\n\
           ON pending_batch_items(proof_envelope_id,inserted_order);\n\
         CREATE INDEX batch_representations_by_proof\n\
           ON batch_item_representations(proof_envelope_id);\n\
         PRAGMA user_version=9;\n\
         COMMIT;",
    )?;
    Ok(())
}

fn migrate_v9_to_v10(connection: &Connection) -> Result<(), StoreError> {
    let transaction = connection.unchecked_transaction()?;
    // Schema 9 admitted every assertion in a received causal context into the
    // context of future local publications. Rebuild exclusively from dots for
    // items that this store actually accepted, so a signed remote assertion is
    // not laundered into a local causal claim.
    transaction.execute("DELETE FROM causal_frontier", [])?;
    transaction.execute(
        "INSERT INTO causal_frontier(publisher,counter)\n\
         SELECT publisher,max(counter) FROM accepted_dots GROUP BY publisher",
        [],
    )?;
    let publisher_count: i64 =
        transaction.query_row("SELECT count(*) FROM causal_frontier", [], |row| row.get(0))?;
    if publisher_count > MAX_CAUSAL_CONTEXT_ENTRIES as i64 {
        return Err(StoreError::Corrupt(
            "directly observed causal frontier exceeds the protocol bound".into(),
        ));
    }
    transaction.execute_batch("PRAGMA user_version=10;")?;
    transaction.commit()?;
    Ok(())
}

fn migrate_v10_to_v11(connection: &Connection) -> Result<(), StoreError> {
    let transaction = connection.unchecked_transaction()?;
    let legacy_controls: i64 = transaction.query_row(
        "SELECT (SELECT count(*) FROM controls) +
                (SELECT count(*) FROM bridge_authorization_controls)",
        [],
        |row| row.get(0),
    )?;
    if legacy_controls != 0 {
        return Err(StoreError::LegacyControlMigrationRequired);
    }
    transaction.execute_batch(
        "ALTER TABLE controls ADD COLUMN signer BLOB CHECK(length(signer)=32);\n\
         ALTER TABLE bridge_authorization_controls ADD COLUMN control_signer BLOB\n\
           CHECK(length(control_signer)=32);\n\
         CREATE TRIGGER controls_require_signer_insert\n\
           BEFORE INSERT ON controls WHEN NEW.signer IS NULL BEGIN\n\
             SELECT RAISE(ABORT,'control signer is required');\n\
           END;\n\
         CREATE TRIGGER controls_require_signer_update\n\
           BEFORE UPDATE OF signer ON controls WHEN NEW.signer IS NULL BEGIN\n\
             SELECT RAISE(ABORT,'control signer is required');\n\
           END;\n\
         CREATE TRIGGER bridge_controls_require_signer_insert\n\
           BEFORE INSERT ON bridge_authorization_controls\n\
           WHEN NEW.control_signer IS NULL BEGIN\n\
             SELECT RAISE(ABORT,'bridge control signer is required');\n\
           END;\n\
         CREATE TRIGGER bridge_controls_require_signer_update\n\
           BEFORE UPDATE OF control_signer ON bridge_authorization_controls\n\
           WHEN NEW.control_signer IS NULL BEGIN\n\
             SELECT RAISE(ABORT,'bridge control signer is required');\n\
           END;\n\
         CREATE INDEX controls_signer ON controls(signer,applied,sequence);\n\
         CREATE INDEX bridge_controls_signer\n\
           ON bridge_authorization_controls(control_signer,applied,sequence);\n\
         PRAGMA user_version=11;",
    )?;
    transaction.commit()?;
    Ok(())
}

fn migrate_v11_to_v12(connection: &Connection) -> Result<(), StoreError> {
    let transaction =
        Transaction::new_unchecked(connection, rusqlite::TransactionBehavior::Immediate)?;
    let legacy_count: i64 =
        transaction.query_row("SELECT count(*) FROM causal_frontier", [], |row| row.get(0))?;
    if legacy_count > MAX_CAUSAL_CONTEXT_ENTRIES as i64 {
        return Err(StoreError::Corrupt(
            "legacy causal frontier exceeds the protocol bound".into(),
        ));
    }
    transaction.execute_batch(
        "ALTER TABLE causal_frontier RENAME TO causal_frontier_v11;\n\
         CREATE TABLE causal_frontier (\n\
           topic TEXT NOT NULL,scope TEXT NOT NULL,\n\
           publisher BLOB NOT NULL CHECK(length(publisher)=32),\n\
           counter INTEGER NOT NULL CHECK(counter>0),\n\
           CHECK((topic='' AND scope='') OR (topic<>'' AND scope<>'')),\n\
           PRIMARY KEY(topic,scope,publisher)\n\
         ) STRICT;",
    )?;
    transaction.execute(
        "INSERT INTO causal_frontier(topic,scope,publisher,counter)\n\
         SELECT ?1,?2,publisher,counter FROM causal_frontier_v11",
        params![LEGACY_CAUSAL_TOPIC, LEGACY_CAUSAL_SCOPE],
    )?;
    let migrated_count: i64 = transaction.query_row(
        "SELECT count(*) FROM causal_frontier WHERE topic=?1 AND scope=?2",
        params![LEGACY_CAUSAL_TOPIC, LEGACY_CAUSAL_SCOPE],
        |row| row.get(0),
    )?;
    if migrated_count != legacy_count {
        return Err(StoreError::Corrupt(
            "legacy causal frontier migration lost rows".into(),
        ));
    }
    transaction.execute_batch(
        "DROP TABLE causal_frontier_v11;\n\
         PRAGMA user_version=12;",
    )?;
    transaction.commit()?;
    Ok(())
}

fn migrate_v12_to_v13(connection: &Connection) -> Result<(), StoreError> {
    connection.execute_batch(
        "BEGIN IMMEDIATE;\n\
         ALTER TABLE transfer_identities RENAME TO transfer_identities_v12;\n\
         CREATE TABLE transfer_identities (\n\
           storage_key BLOB PRIMARY KEY REFERENCES wants(object_id) ON DELETE CASCADE\n\
             CHECK(length(storage_key)=32),\n\
           object_id BLOB NOT NULL UNIQUE CHECK(length(object_id)=33),\n\
           origin_semantic_version INTEGER\n\
             CHECK(origin_semantic_version IS NULL OR origin_semantic_version IN (1,2,3))\n\
         ) STRICT;\n\
         INSERT INTO transfer_identities(storage_key,object_id,origin_semantic_version)\n\
           SELECT storage_key,object_id,origin_semantic_version FROM transfer_identities_v12;\n\
         DROP TABLE transfer_identities_v12;\n\
         PRAGMA user_version=13;\n\
         COMMIT;",
    )?;
    Ok(())
}

fn migrate_v13_to_v14(connection: &Connection) -> Result<(), StoreError> {
    connection.execute_batch(
        "BEGIN IMMEDIATE;\n\
         ALTER TABLE transfer_identities RENAME TO transfer_identities_v13;\n\
         CREATE TABLE transfer_identities (\n\
           storage_key BLOB PRIMARY KEY REFERENCES wants(object_id) ON DELETE CASCADE\n\
             CHECK(length(storage_key)=32),\n\
           object_id BLOB NOT NULL UNIQUE CHECK(length(object_id)=33),\n\
           origin_semantic_version INTEGER\n\
             CHECK(origin_semantic_version IS NULL OR origin_semantic_version IN (1,2,3,4))\n\
         ) STRICT;\n\
         INSERT INTO transfer_identities(storage_key,object_id,origin_semantic_version)\n\
           SELECT storage_key,object_id,origin_semantic_version FROM transfer_identities_v13;\n\
         DROP TABLE transfer_identities_v13;\n\
         PRAGMA user_version=14;\n\
         COMMIT;",
    )?;
    Ok(())
}

fn migrate_v14_to_v15(connection: &Connection) -> Result<(), StoreError> {
    connection.execute_batch(
        "BEGIN IMMEDIATE;\n\
         ALTER TABLE transfer_identities RENAME TO transfer_identities_v14;\n\
         CREATE TABLE transfer_identities (\n\
           storage_key BLOB PRIMARY KEY REFERENCES wants(object_id) ON DELETE CASCADE\n\
             CHECK(length(storage_key)=32),\n\
           object_id BLOB NOT NULL UNIQUE CHECK(length(object_id)=33),\n\
           origin_semantic_version INTEGER\n\
             CHECK(origin_semantic_version IS NULL OR origin_semantic_version IN (1,2,3,4,5))\n\
         ) STRICT;\n\
         INSERT INTO transfer_identities(storage_key,object_id,origin_semantic_version)\n\
           SELECT storage_key,object_id,origin_semantic_version FROM transfer_identities_v14;\n\
         DROP TABLE transfer_identities_v14;\n\
         PRAGMA user_version=15;\n\
         COMMIT;",
    )?;
    Ok(())
}

fn migrate_v15_to_v16(connection: &Connection) -> Result<(), StoreError> {
    connection.execute_batch(
        "BEGIN IMMEDIATE;\n\
         ALTER TABLE transfer_identities RENAME TO transfer_identities_v15;\n\
         CREATE TABLE transfer_identities (\n\
           storage_key BLOB PRIMARY KEY REFERENCES wants(object_id) ON DELETE CASCADE\n\
             CHECK(length(storage_key)=32),\n\
           object_id BLOB NOT NULL UNIQUE CHECK(length(object_id)=33),\n\
           origin_semantic_version INTEGER\n\
             CHECK(origin_semantic_version IS NULL OR origin_semantic_version IN (1,2,3,4,5,6,7))\n\
         ) STRICT;\n\
         INSERT INTO transfer_identities(storage_key,object_id,origin_semantic_version)\n\
           SELECT storage_key,object_id,origin_semantic_version FROM transfer_identities_v15;\n\
         DROP TABLE transfer_identities_v15;\n\
         PRAGMA user_version=16;\n\
         COMMIT;",
    )?;
    Ok(())
}

fn persist_config(connection: &Connection, config: &StoreConfig) -> Result<(), StoreError> {
    let values = [
        ("max_items", config.max_items),
        ("max_bytes", config.max_bytes),
        ("tombstone_retention_ms", config.tombstone_retention_ms),
        ("superseded_retention_ms", config.superseded_retention_ms),
    ];
    let transaction = connection.unchecked_transaction()?;
    for (key, value) in values {
        transaction.execute(
            "INSERT INTO store_meta(key,value) VALUES(?1,?2)\n\
             ON CONFLICT(key) DO UPDATE SET value=excluded.value",
            params![key, sql_u64(value, key)?],
        )?;
    }
    transaction.commit()?;
    Ok(())
}

fn next_order(transaction: &Transaction<'_>) -> Result<u64, StoreError> {
    let value: i64 = transaction.query_row(
        "INSERT INTO store_meta(key,value) VALUES('next_order',1)\n\
         ON CONFLICT(key) DO UPDATE SET value=CAST(value AS INTEGER)+1\n\
         RETURNING CAST(value AS INTEGER)",
        [],
        |row| row.get(0),
    )?;
    from_sql_u64(value, "inserted order")
}

fn decode_item_row(row: &Row<'_>) -> rusqlite::Result<StoredItem> {
    fn conversion(error: StoreError) -> rusqlite::Error {
        rusqlite::Error::FromSqlConversionFailure(0, rusqlite::types::Type::Blob, Box::new(error))
    }
    let id = item_from_vec(row.get(0)?, "item id").map_err(conversion)?;
    let class = class_from_i64(row.get(1)?).map_err(conversion)?;
    let topic = Topic::new(row.get::<_, String>(2)?)
        .map_err(|error| conversion(StoreError::Corrupt(error.to_string())))?;
    let scope = Scope::new(row.get::<_, String>(3)?)
        .map_err(|error| conversion(StoreError::Corrupt(error.to_string())))?;
    let priority = priority_from_i64(row.get(4)?).map_err(conversion)?;
    let publisher = node_from_vec(row.get(5)?, "publisher").map_err(conversion)?;
    let counter = from_sql_u64(row.get(6)?, "causal counter").map_err(conversion)?;
    let context = decode_context(&row.get::<_, Vec<u8>>(7)?).map_err(conversion)?;
    let event_sequence = row
        .get::<_, Option<i64>>(8)?
        .map(|value| from_sql_u64(value, "event sequence"))
        .transpose()
        .map_err(conversion)?;
    let ttl_ms = row
        .get::<_, Option<i64>>(10)?
        .map(|value| from_sql_u64(value, "ttl"))
        .transpose()
        .map_err(conversion)?;
    let observed_at_ms = row
        .get::<_, Option<i64>>(11)?
        .map(|value| from_sql_u64(value, "observation time"))
        .transpose()
        .map_err(conversion)?;
    let content_len = from_sql_u64(row.get(13)?, "content length").map_err(conversion)?;
    let key_epoch = from_sql_u64(row.get(15)?, "key epoch").map_err(conversion)?;
    let status = status_from_i64(row.get(16)?).map_err(conversion)?;
    let inserted_order = from_sql_u64(row.get(17)?, "inserted order").map_err(conversion)?;
    let envelope_id = item_from_vec(row.get(18)?, "envelope id").map_err(conversion)?;
    let custody_age_ms = from_sql_u64(row.get(19)?, "custody age").map_err(conversion)?;
    let custody_clock_id = row
        .get::<_, Option<Vec<u8>>>(20)?
        .map(|value| {
            value
                .try_into()
                .map_err(|_| StoreError::Corrupt("custody clock id is not 16 bytes".into()))
        })
        .transpose()
        .map_err(conversion)?;
    let custody_tick_ms = row
        .get::<_, Option<i64>>(21)?
        .map(|value| from_sql_u64(value, "custody tick"))
        .transpose()
        .map_err(conversion)?;
    Ok(StoredItem {
        id,
        envelope_id,
        class,
        topic,
        scope,
        priority,
        stamp: CausalStamp {
            dot: Dot { publisher, counter },
            context,
        },
        event_sequence,
        logical_key: row.get(9)?,
        ttl_ms,
        observed_at_ms,
        sealed: row.get(12)?,
        content_len,
        tombstone: row.get::<_, i64>(14)? != 0,
        key_epoch,
        custody_age_ms,
        custody_clock_id,
        custody_tick_ms,
        custody_elapsed_available: row.get::<_, i64>(22)? != 0,
        status,
        inserted_order,
    })
}

const ITEM_COLUMNS: &str = "item_id,data_class,topic,scope,priority,publisher,causal_counter,causal_context,event_sequence,logical_key,ttl_ms,observed_at_ms,sealed,content_len,tombstone,key_epoch,version_status,inserted_order,envelope_id,custody_age_ms,custody_clock_id,custody_tick_ms,custody_elapsed_available";

// Lifecycle maintenance needs stable grouping, retention, and elapsed-custody
// metadata, but never the source-sealed envelope or causal context. Keeping a
// separate projection prevents quota and garbage-collection scans from copying
// those potentially large BLOBs across the SQLite boundary for every item.
const LIFECYCLE_ITEM_COLUMNS: &str = "item_id,data_class,topic,scope,logical_key,ttl_ms,observed_at_ms,tombstone,version_status,custody_age_ms,custody_clock_id,custody_tick_ms,custody_elapsed_available";

#[derive(Clone, Debug)]
struct LifecycleItem {
    id: ItemId,
    class: DataClass,
    topic: Topic,
    scope: Scope,
    logical_key: Vec<u8>,
    ttl_ms: Option<u64>,
    observed_at_ms: Option<u64>,
    tombstone: bool,
    status: VersionStatus,
    custody_age_ms: u64,
    custody_clock_id: Option<[u8; 16]>,
    custody_tick_ms: Option<u64>,
    custody_elapsed_available: bool,
}

impl LifecycleItem {
    fn group_key(&self) -> (i64, String, String, Vec<u8>) {
        (
            class_to_i64(self.class),
            self.topic.as_str().to_owned(),
            self.scope.as_str().to_owned(),
            self.logical_key.clone(),
        )
    }

    fn is_expired_at(&self, sample: Option<CustodySample>) -> bool {
        custody_disposition_from_fields(
            self.ttl_ms,
            self.tombstone,
            self.custody_age_ms,
            self.custody_clock_id,
            self.custody_tick_ms,
            self.custody_elapsed_available,
            sample,
        )
        .is_expired()
    }
}

fn decode_lifecycle_item_row(row: &Row<'_>) -> rusqlite::Result<LifecycleItem> {
    fn conversion(error: StoreError) -> rusqlite::Error {
        rusqlite::Error::FromSqlConversionFailure(0, rusqlite::types::Type::Blob, Box::new(error))
    }

    let ttl_ms = row
        .get::<_, Option<i64>>(5)?
        .map(|value| from_sql_u64(value, "lifecycle ttl"))
        .transpose()
        .map_err(conversion)?;
    let observed_at_ms = row
        .get::<_, Option<i64>>(6)?
        .map(|value| from_sql_u64(value, "lifecycle observation time"))
        .transpose()
        .map_err(conversion)?;
    let custody_clock_id = row
        .get::<_, Option<Vec<u8>>>(10)?
        .map(|value| clock_from_vec(value, "lifecycle custody clock id"))
        .transpose()
        .map_err(conversion)?;
    let custody_tick_ms = row
        .get::<_, Option<i64>>(11)?
        .map(|value| from_sql_u64(value, "lifecycle custody tick"))
        .transpose()
        .map_err(conversion)?;
    Ok(LifecycleItem {
        id: item_from_vec(row.get(0)?, "lifecycle item id").map_err(conversion)?,
        class: class_from_i64(row.get(1)?).map_err(conversion)?,
        topic: Topic::new(row.get::<_, String>(2)?)
            .map_err(|error| conversion(StoreError::Corrupt(error.to_string())))?,
        scope: Scope::new(row.get::<_, String>(3)?)
            .map_err(|error| conversion(StoreError::Corrupt(error.to_string())))?,
        logical_key: row.get(4)?,
        ttl_ms,
        observed_at_ms,
        tombstone: row.get::<_, i64>(7)? != 0,
        status: status_from_i64(row.get(8)?).map_err(conversion)?,
        custody_age_ms: from_sql_u64(row.get(9)?, "lifecycle custody age").map_err(conversion)?,
        custody_clock_id,
        custody_tick_ms,
        custody_elapsed_available: row.get::<_, i64>(12)? != 0,
    })
}

// `length(sealed)` is evaluated by SQLite and crosses the Rust boundary as an
// integer. The source-sealed BLOB itself is deliberately absent from this
// projection, as are semantic item IDs, publishers, causal contexts, logical
// keys, and application length/payload metadata.
const INVENTORY_ITEM_COLUMNS: &str = "0 AS object_kind,envelope_id,length(sealed) AS sealed_len,priority,scope,key_epoch,ttl_ms,tombstone,custody_age_ms,custody_clock_id,custody_tick_ms,custody_elapsed_available";
const INVENTORY_CONTROL_COLUMNS: &str = "1 AS object_kind,envelope_id,length(sealed) AS sealed_len,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL";

fn select_inventory_metadata_bounded(
    connection: &Connection,
    topics: &BTreeSet<Topic>,
    scopes: &BTreeSet<Scope>,
    max_objects: usize,
) -> Result<Vec<InventoryMetadata>, StoreError> {
    crate::wire::validate_interest_work(topics.len(), scopes.len())
        .map_err(|error| StoreError::Invalid(error.to_string()))?;

    use rusqlite::types::Value;
    let query_limit = max_objects
        .checked_add(1)
        .ok_or_else(|| StoreError::Invalid(INVENTORY_OBJECT_LIMIT_ERROR.into()))?;
    let query_limit = i64::try_from(query_limit)
        .map_err(|_| StoreError::Invalid(INVENTORY_OBJECT_LIMIT_ERROR.into()))?;
    let mut values =
        Vec::<Value>::with_capacity(topics.len().saturating_add(scopes.len()).saturating_add(1));
    let mut sql = if topics.is_empty() || scopes.is_empty() {
        format!("SELECT {INVENTORY_CONTROL_COLUMNS} FROM controls WHERE applied=1")
    } else {
        let topic_parameters = std::iter::repeat_n("?", topics.len())
            .collect::<Vec<_>>()
            .join(",");
        let scope_parameters = std::iter::repeat_n("?", scopes.len())
            .collect::<Vec<_>>()
            .join(",");
        values.extend(
            topics
                .iter()
                .map(|topic| Value::from(topic.as_str().to_owned())),
        );
        values.extend(
            scopes
                .iter()
                .map(|scope| Value::from(scope.as_str().to_owned())),
        );
        format!(
            "SELECT {INVENTORY_ITEM_COLUMNS} FROM items INDEXED BY items_projection \
             WHERE topic IN ({topic_parameters}) AND scope IN ({scope_parameters}) \
             UNION ALL SELECT {INVENTORY_CONTROL_COLUMNS} FROM controls WHERE applied=1"
        )
    };
    sql.push_str(" LIMIT ?");
    values.push(Value::Integer(query_limit));

    let mut statement = connection.prepare(&sql)?;
    let rows = statement.query_map(
        rusqlite::params_from_iter(values),
        decode_inventory_metadata_row,
    )?;
    let mut metadata = Vec::new();
    for row in rows {
        let row = row?;
        if metadata.len() == max_objects {
            return Err(StoreError::Invalid(INVENTORY_OBJECT_LIMIT_ERROR.into()));
        }
        metadata.push(row);
    }
    Ok(metadata)
}

fn decode_inventory_metadata_row(row: &Row<'_>) -> rusqlite::Result<InventoryMetadata> {
    fn conversion(error: StoreError) -> rusqlite::Error {
        rusqlite::Error::FromSqlConversionFailure(0, rusqlite::types::Type::Blob, Box::new(error))
    }

    let object_kind: i64 = row.get(0)?;
    let envelope_id = item_from_vec(row.get(1)?, "inventory envelope id").map_err(conversion)?;
    let total_len = from_sql_u64(row.get(2)?, "inventory sealed length").map_err(conversion)?;
    match object_kind {
        0 => {
            let priority = priority_from_i64(row.get(3)?).map_err(conversion)?;
            let scope = Scope::new(row.get::<_, String>(4)?)
                .map_err(|error| conversion(StoreError::Corrupt(error.to_string())))?;
            let key_epoch = from_sql_u64(row.get(5)?, "inventory key epoch").map_err(conversion)?;
            let ttl_ms = row
                .get::<_, Option<i64>>(6)?
                .map(|value| from_sql_u64(value, "inventory ttl"))
                .transpose()
                .map_err(conversion)?;
            let custody_age_ms =
                from_sql_u64(row.get(8)?, "inventory custody age").map_err(conversion)?;
            let custody_clock_id = row
                .get::<_, Option<Vec<u8>>>(9)?
                .map(|value| {
                    value.try_into().map_err(|_| {
                        StoreError::Corrupt("inventory custody clock id is not 16 bytes".into())
                    })
                })
                .transpose()
                .map_err(conversion)?;
            let custody_tick_ms = row
                .get::<_, Option<i64>>(10)?
                .map(|value| from_sql_u64(value, "inventory custody tick"))
                .transpose()
                .map_err(conversion)?;
            Ok(InventoryMetadata::Data {
                envelope_id,
                total_len,
                priority,
                scope,
                key_epoch,
                ttl_ms,
                tombstone: row.get::<_, i64>(7)? != 0,
                custody_age_ms,
                custody_clock_id,
                custody_tick_ms,
                custody_elapsed_available: row.get::<_, i64>(11)? != 0,
            })
        }
        1 => Ok(InventoryMetadata::Control {
            envelope_id,
            total_len,
        }),
        _ => Err(conversion(StoreError::Corrupt(
            "unknown inventory object kind".into(),
        ))),
    }
}

fn load_item_tx(
    transaction: &Transaction<'_>,
    id: &ItemId,
) -> Result<Option<StoredItem>, StoreError> {
    let sql = format!("SELECT {ITEM_COLUMNS} FROM items WHERE item_id=?1");
    let mut statement = transaction.prepare(&sql)?;
    Ok(statement
        .query_row(params![id.as_slice()], decode_item_row)
        .optional()?)
}

fn custody_disposition_from_fields(
    ttl_ms: Option<u64>,
    tombstone: bool,
    custody_age_ms: u64,
    custody_clock_id: Option<[u8; 16]>,
    custody_tick_ms: Option<u64>,
    custody_elapsed_available: bool,
    sample: Option<CustodySample>,
) -> CustodyDisposition {
    let checkpoint = custody_checkpoint(custody_clock_id, custody_tick_ms);
    let continuity = if custody_elapsed_available {
        CustodyContinuity::Continuous
    } else {
        CustodyContinuity::Lost
    };
    let mut age = CustodyAge::from_parts(custody_age_ms, checkpoint, continuity)
        .unwrap_or_else(|_| CustodyAge::unknown(custody_age_ms));
    evaluate_custody(ttl_ms, tombstone, &mut age, sample)
}

fn custody_checkpoint(
    custody_clock_id: Option<[u8; 16]>,
    custody_tick_ms: Option<u64>,
) -> Option<CustodySample> {
    custody_clock_id
        .zip(custody_tick_ms)
        .map(|(clock_id, tick_ms)| CustodySample { clock_id, tick_ms })
}

fn advance_custody_fields(
    ttl_ms: Option<u64>,
    custody_age_ms: &mut u64,
    custody_clock_id: &mut Option<[u8; 16]>,
    custody_tick_ms: &mut Option<u64>,
    custody_elapsed_available: &mut bool,
    sample: Option<CustodySample>,
) {
    let checkpoint = custody_checkpoint(*custody_clock_id, *custody_tick_ms);
    let continuity = if *custody_elapsed_available {
        CustodyContinuity::Continuous
    } else {
        CustodyContinuity::Lost
    };
    let Ok(mut age) = CustodyAge::from_parts(*custody_age_ms, checkpoint, continuity) else {
        *custody_elapsed_available = false;
        return;
    };
    if ttl_ms.is_none() && sample.is_none() {
        return;
    }
    let _ = age.checkpoint(sample);
    *custody_age_ms = age.cumulative_age_ms();
    let checkpoint = age.checkpoint_sample();
    *custody_clock_id = checkpoint.map(|value| value.clock_id);
    *custody_tick_ms = checkpoint.map(|value| value.tick_ms);
    *custody_elapsed_available = age.is_continuous();
}

fn advance_custody_tx(
    transaction: &Transaction<'_>,
    id: ItemId,
    sample: Option<CustodySample>,
) -> Result<Option<StoredItem>, StoreError> {
    let Some(mut item) = load_item_tx(transaction, &id)? else {
        return Ok(None);
    };
    advance_custody_fields(
        item.ttl_ms,
        &mut item.custody_age_ms,
        &mut item.custody_clock_id,
        &mut item.custody_tick_ms,
        &mut item.custody_elapsed_available,
        sample,
    );
    transaction.execute(
        "UPDATE items SET custody_age_ms=?1,custody_clock_id=?2,custody_tick_ms=?3,\n\
           custody_elapsed_available=?4 WHERE item_id=?5",
        params![
            sql_u64(item.custody_age_ms, "custody age")?,
            item.custody_clock_id.map(|value| value.to_vec()),
            item.custody_tick_ms
                .map(|value| sql_u64(value, "custody tick"))
                .transpose()?,
            if item.custody_elapsed_available {
                1i64
            } else {
                0i64
            },
            id.as_slice()
        ],
    )?;
    Ok(Some(item))
}

fn advance_lifecycle_custody_tx(
    transaction: &Transaction<'_>,
    item: &mut LifecycleItem,
    sample: Option<CustodySample>,
) -> Result<(), StoreError> {
    advance_custody_fields(
        item.ttl_ms,
        &mut item.custody_age_ms,
        &mut item.custody_clock_id,
        &mut item.custody_tick_ms,
        &mut item.custody_elapsed_available,
        sample,
    );
    transaction.execute(
        "UPDATE items SET custody_age_ms=?1,custody_clock_id=?2,custody_tick_ms=?3,\n\
           custody_elapsed_available=?4 WHERE item_id=?5",
        params![
            sql_u64(item.custody_age_ms, "custody age")?,
            item.custody_clock_id.map(|value| value.to_vec()),
            item.custody_tick_ms
                .map(|value| sql_u64(value, "custody tick"))
                .transpose()?,
            if item.custody_elapsed_available {
                1i64
            } else {
                0i64
            },
            item.id.as_slice()
        ],
    )?;
    Ok(())
}

fn merge_duplicate_custody_tx(
    transaction: &Transaction<'_>,
    existing: &StoredItem,
    incoming: &StoredItem,
) -> Result<(), StoreError> {
    if existing.envelope_id != incoming.envelope_id || existing.sealed != incoming.sealed {
        return Err(StoreError::Invalid(
            "semantic item was replayed with a different source-sealed envelope".into(),
        ));
    }
    // Once elapsed custody becomes unknown it cannot be made known again by a
    // replay; doing so would erase unaccounted local custody time.  When both
    // states are continuous, account local residence at the incoming sample
    // before taking the nondecreasing authenticated maximum.
    let incoming_sample = incoming
        .custody_elapsed_available
        .then(|| custody_checkpoint(incoming.custody_clock_id, incoming.custody_tick_ms))
        .flatten();
    let (age, continuity_unknown, clock_id, tick, anchor_available) =
        merge_authenticated_custody_fields(
            Some((
                existing.custody_age_ms,
                !existing.custody_elapsed_available,
                existing.custody_clock_id,
                existing.custody_tick_ms,
                existing.custody_elapsed_available,
            )),
            incoming.custody_age_ms,
            incoming_sample,
        );
    transaction.execute(
        "UPDATE items SET custody_age_ms=?1,custody_clock_id=?2,custody_tick_ms=?3,\n\
           custody_elapsed_available=?4 WHERE item_id=?5",
        params![
            sql_u64(age, "custody age")?,
            clock_id.map(|value| value.to_vec()),
            tick.map(|value| sql_u64(value, "custody tick"))
                .transpose()?,
            if !continuity_unknown && anchor_available {
                1i64
            } else {
                0i64
            },
            existing.id.as_slice()
        ],
    )?;
    Ok(())
}

const CONTROL_COLUMNS: &str =
    "envelope_id,authority,signer,sequence,previous_control,kind,sealed,applied,inserted_order";

fn control_kind_from_i64(value: i64) -> Result<ControlKind, StoreError> {
    match value {
        1 => Ok(ControlKind::Revocation),
        2 => Ok(ControlKind::ScopeEpoch),
        _ => Err(StoreError::Corrupt("unknown control kind".into())),
    }
}

fn optional_envelope_from_vec(
    value: Option<Vec<u8>>,
    field: &'static str,
) -> Result<Option<EnvelopeId>, StoreError> {
    value.map(|bytes| item_from_vec(bytes, field)).transpose()
}

fn decode_control_row(row: &Row<'_>) -> rusqlite::Result<StoredControl> {
    fn conversion(error: StoreError) -> rusqlite::Error {
        rusqlite::Error::FromSqlConversionFailure(0, rusqlite::types::Type::Blob, Box::new(error))
    }
    Ok(StoredControl {
        envelope_id: item_from_vec(row.get(0)?, "control envelope id").map_err(conversion)?,
        authority: node_from_vec(row.get(1)?, "control authority").map_err(conversion)?,
        signer: node_from_vec(row.get(2)?, "control signer").map_err(conversion)?,
        sequence: from_sql_u64(row.get(3)?, "control sequence").map_err(conversion)?,
        previous_control: optional_envelope_from_vec(row.get(4)?, "previous control")
            .map_err(conversion)?,
        kind: control_kind_from_i64(row.get(5)?).map_err(conversion)?,
        sealed: row.get(6)?,
        applied: row.get::<_, i64>(7)? != 0,
        inserted_order: from_sql_u64(row.get(8)?, "control inserted order").map_err(conversion)?,
    })
}

fn load_control_tx(
    transaction: &Transaction<'_>,
    envelope_id: &EnvelopeId,
) -> Result<Option<StoredControl>, StoreError> {
    let sql = format!("SELECT {CONTROL_COLUMNS} FROM controls WHERE envelope_id=?1");
    Ok(transaction
        .query_row(&sql, params![envelope_id.as_slice()], decode_control_row)
        .optional()?)
}

fn validate_control(control: &VerifiedStoredControl) -> Result<(), StoreError> {
    let digest: EnvelopeId = Sha256::digest(&control.sealed).into();
    if digest != control.envelope_id || control.sequence == 0 {
        return Err(StoreError::Invalid(
            "control identifier or sequence is invalid".into(),
        ));
    }
    if (control.sequence == 1) != control.previous_control.is_none() {
        return Err(StoreError::ControlFork);
    }
    match (&control.kind, &control.revocation, &control.scope_epoch) {
        (ControlKind::Revocation, Some(effect), None)
            if effect.authority == control.authority
                && effect.signer == control.signer
                && effect.control_sequence == control.sequence
                && effect.previous_control == control.previous_control
                && effect.sealed_notice == control.sealed => {}
        (ControlKind::ScopeEpoch, None, Some(effect))
            if effect.authority == control.authority
                && effect.signer == control.signer
                && effect.control_sequence == control.sequence
                && effect.previous_control == control.previous_control
                && effect.sealed_notice == control.sealed => {}
        _ => {
            return Err(StoreError::Invalid(
                "authenticated control metadata is internally inconsistent".into(),
            ));
        }
    }
    Ok(())
}

fn validate_control_effect_order_tx(
    transaction: &Transaction<'_>,
    control: &StoredControl,
) -> Result<(), StoreError> {
    let (column, key, value): (&str, rusqlite::types::Value, u64) = match control.kind {
        ControlKind::Revocation => {
            let (subject, generation): (Vec<u8>, i64) = transaction.query_row(
                "SELECT subject,generation FROM controls WHERE envelope_id=?1",
                params![control.envelope_id.as_slice()],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )?;
            (
                "subject",
                node_from_vec(subject, "control effect subject")?
                    .to_vec()
                    .into(),
                from_sql_u64(generation, "control effect generation")?,
            )
        }
        ControlKind::ScopeEpoch => {
            let (scope, epoch): (String, i64) = transaction.query_row(
                "SELECT scope,epoch FROM controls WHERE envelope_id=?1",
                params![control.envelope_id.as_slice()],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )?;
            (
                "scope",
                Scope::new(scope)
                    .map_err(|error| StoreError::Corrupt(error.to_string()))?
                    .as_str()
                    .to_owned()
                    .into(),
                from_sql_u64(epoch, "control effect epoch")?,
            )
        }
    };
    let sql = format!(
        "SELECT authority,sequence,CASE kind WHEN 1 THEN generation ELSE epoch END \
         FROM controls WHERE applied=1 AND {column}=?1 ORDER BY sequence"
    );
    let mut statement = transaction.prepare(&sql)?;
    let rows = statement.query_map(params![key], |row| {
        Ok((
            row.get::<_, Vec<u8>>(0)?,
            row.get::<_, i64>(1)?,
            row.get::<_, i64>(2)?,
        ))
    })?;
    for row in rows {
        let (authority, sequence, prior_value) = row?;
        let authority = node_from_vec(authority, "control effect authority")?;
        let sequence = from_sql_u64(sequence, "control effect sequence")?;
        let prior_value = from_sql_u64(prior_value, "control effect value")?;
        if authority != control.authority {
            return Err(StoreError::ControlFork);
        }
        if (sequence < control.sequence && prior_value >= value)
            || (sequence > control.sequence && prior_value <= value)
            || (sequence == control.sequence && prior_value != value)
        {
            return Err(StoreError::ControlRollback);
        }
    }
    Ok(())
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ControlInsert {
    Inserted,
    Duplicate,
    Rejected(RejectedControl),
}

fn control_signer_revoked_tx(
    transaction: &Transaction<'_>,
    signer: NodeId,
) -> Result<bool, StoreError> {
    Ok(transaction.query_row(
        "SELECT EXISTS(SELECT 1 FROM revocations WHERE subject=?1)",
        params![signer.as_slice()],
        |row| row.get::<_, i64>(0),
    )? != 0)
}

fn purge_pending_control_suffix_tx(
    transaction: &Transaction<'_>,
    authority: NodeId,
    first_sequence: u64,
) -> Result<Vec<RejectedControl>, StoreError> {
    let rejected = {
        let mut statement = transaction.prepare(
            "SELECT envelope_id,signer FROM controls\n\
             WHERE authority=?1 AND applied=0 AND sequence>=?2\n\
             ORDER BY sequence,envelope_id",
        )?;
        statement
            .query_map(
                params![
                    authority.as_slice(),
                    sql_u64(first_sequence, "rejected control suffix sequence")?
                ],
                |row| Ok((row.get::<_, Vec<u8>>(0)?, row.get::<_, Vec<u8>>(1)?)),
            )?
            .map(|row| {
                let (envelope_id, signer) = row?;
                Ok(RejectedControl {
                    envelope_id: item_from_vec(envelope_id, "rejected control envelope")?,
                    signer: node_from_vec(signer, "rejected control signer")?,
                })
            })
            .collect::<Result<Vec<_>, StoreError>>()?
    };
    transaction.execute(
        "DELETE FROM controls WHERE authority=?1 AND applied=0 AND sequence>=?2",
        params![
            authority.as_slice(),
            sql_u64(first_sequence, "rejected control suffix sequence")?
        ],
    )?;
    Ok(rejected)
}

fn purge_pending_bridge_control_suffix_tx(
    transaction: &Transaction<'_>,
    authority: NodeId,
    first_sequence: u64,
) -> Result<Vec<RejectedControl>, StoreError> {
    let rejected = {
        let mut statement = transaction.prepare(
            "SELECT envelope_id,control_signer FROM bridge_authorization_controls\n\
             WHERE authority_id=?1 AND applied=0 AND sequence>=?2\n\
             ORDER BY sequence,envelope_id",
        )?;
        statement
            .query_map(
                params![
                    authority.as_slice(),
                    sql_u64(first_sequence, "rejected bridge suffix sequence")?
                ],
                |row| Ok((row.get::<_, Vec<u8>>(0)?, row.get::<_, Vec<u8>>(1)?)),
            )?
            .map(|row| {
                let (envelope_id, signer) = row?;
                Ok(RejectedControl {
                    envelope_id: item_from_vec(envelope_id, "rejected bridge control")?,
                    signer: node_from_vec(signer, "rejected bridge signer")?,
                })
            })
            .collect::<Result<Vec<_>, StoreError>>()?
    };
    let sequence = sql_u64(first_sequence, "rejected bridge suffix sequence")?;
    for table in [
        "bridge_authorization_topics",
        "bridge_authorization_peer_receipts",
        "bridge_authorization_peer_attempts",
        "bridge_authorization_outbox",
    ] {
        transaction.execute(
            &format!(
                "DELETE FROM {table} WHERE envelope_id IN (\n\
                   SELECT envelope_id FROM bridge_authorization_controls\n\
                   WHERE authority_id=?1 AND applied=0 AND sequence>=?2)"
            ),
            params![authority.as_slice(), sequence],
        )?;
    }
    transaction.execute(
        "DELETE FROM bridge_authorization_controls\n\
         WHERE authority_id=?1 AND applied=0 AND sequence>=?2",
        params![authority.as_slice(), sequence],
    )?;
    Ok(rejected)
}

fn purge_revoked_principal_pending_suffixes_tx(
    transaction: &Transaction<'_>,
    principal: NodeId,
) -> Result<Vec<RejectedControl>, StoreError> {
    let ordinary_starts = {
        let mut statement = transaction.prepare(
            "SELECT authority,min(sequence) FROM controls\n\
             WHERE applied=0 AND (signer=?1 OR authority=?1)\n\
             GROUP BY authority ORDER BY authority",
        )?;
        statement
            .query_map(params![principal.as_slice()], |row| {
                Ok((row.get::<_, Vec<u8>>(0)?, row.get::<_, i64>(1)?))
            })?
            .collect::<Result<Vec<_>, _>>()?
    };
    let mut rejected = Vec::new();
    for (authority, first_sequence) in ordinary_starts {
        rejected.extend(purge_pending_control_suffix_tx(
            transaction,
            node_from_vec(authority, "pending control authority")?,
            from_sql_u64(first_sequence, "pending control sequence")?,
        )?);
    }

    let bridge_starts = {
        let mut statement = transaction.prepare(
            "SELECT authority_id,min(sequence) FROM bridge_authorization_controls\n\
             WHERE applied=0 AND (control_signer=?1 OR authority_id=?1)\n\
             GROUP BY authority_id ORDER BY authority_id",
        )?;
        statement
            .query_map(params![principal.as_slice()], |row| {
                Ok((row.get::<_, Vec<u8>>(0)?, row.get::<_, i64>(1)?))
            })?
            .collect::<Result<Vec<_>, _>>()?
    };
    for (authority, first_sequence) in bridge_starts {
        rejected.extend(purge_pending_bridge_control_suffix_tx(
            transaction,
            node_from_vec(authority, "pending bridge control authority")?,
            from_sql_u64(first_sequence, "pending bridge control sequence")?,
        )?);
    }
    Ok(rejected)
}

fn remove_revoked_principal_bridge_routes_tx(
    transaction: &Transaction<'_>,
    principal: NodeId,
) -> Result<(), StoreError> {
    transaction.execute(
        "DELETE FROM bridge_route_outbox WHERE wrapper_envelope_id IN (\n\
           SELECT w.wrapper_envelope_id FROM bridge_route_wrappers w\n\
           WHERE w.source_publisher=?1\n\
           UNION\n\
           SELECT d.wrapper_envelope_id FROM bridge_wrapper_authorizations d\n\
           JOIN bridge_authorization_controls c\n\
             ON c.envelope_id=d.authorization_envelope_id\n\
           WHERE c.authority_id=?1 OR c.control_signer=?1 OR c.bridge_node_id=?1\n\
         )",
        params![principal.as_slice()],
    )?;
    transaction.execute(
        "DELETE FROM bridge_active_routes WHERE wrapper_envelope_id IN (\n\
           SELECT w.wrapper_envelope_id FROM bridge_route_wrappers w\n\
           WHERE w.source_publisher=?1\n\
           UNION\n\
           SELECT d.wrapper_envelope_id FROM bridge_wrapper_authorizations d\n\
           JOIN bridge_authorization_controls c\n\
             ON c.envelope_id=d.authorization_envelope_id\n\
           WHERE c.authority_id=?1 OR c.control_signer=?1 OR c.bridge_node_id=?1\n\
         )",
        params![principal.as_slice()],
    )?;
    Ok(())
}

fn insert_control_tx(
    transaction: &Transaction<'_>,
    control: &VerifiedStoredControl,
) -> Result<ControlInsert, StoreError> {
    validate_control(control)?;
    if let Some(existing) = load_control_tx(transaction, &control.envelope_id)? {
        if existing.authority != control.authority
            || existing.signer != control.signer
            || existing.sequence != control.sequence
            || existing.previous_control != control.previous_control
            || existing.kind != control.kind
            || existing.sealed != control.sealed
        {
            return Err(StoreError::ControlFork);
        }
        return Ok(ControlInsert::Duplicate);
    }
    if control_signer_revoked_tx(transaction, control.authority)?
        || control_signer_revoked_tx(transaction, control.signer)?
    {
        return Ok(ControlInsert::Rejected(RejectedControl {
            envelope_id: control.envelope_id,
            signer: control.signer,
        }));
    }
    let occupied: Option<Vec<u8>> = transaction
        .query_row(
            "SELECT envelope_id FROM controls WHERE authority=?1 AND sequence=?2",
            params![
                control.authority.as_slice(),
                sql_u64(control.sequence, "control sequence")?
            ],
            |row| row.get(0),
        )
        .optional()?;
    if occupied.is_some() {
        return Err(StoreError::ControlFork);
    }
    let (subject, generation, scope, epoch, observed_at_ms) = match control.kind {
        ControlKind::Revocation => {
            let effect = control.revocation.as_ref().expect("validated revocation");
            (
                Some(effect.subject.to_vec()),
                Some(sql_u64(effect.generation, "revocation generation")?),
                None,
                None,
                effect
                    .observed_at_ms
                    .map(|value| sql_u64(value, "revocation observation"))
                    .transpose()?,
            )
        }
        ControlKind::ScopeEpoch => {
            let effect = control.scope_epoch.as_ref().expect("validated scope epoch");
            (
                None,
                None,
                Some(effect.scope.as_str().to_owned()),
                Some(sql_u64(effect.epoch, "scope epoch")?),
                None,
            )
        }
    };
    let order = next_order(transaction)?;
    transaction.execute(
        "INSERT INTO controls(envelope_id,authority,signer,sequence,previous_control,kind,sealed,\n\
           subject,generation,scope,epoch,observed_at_ms,applied,inserted_order)\n\
         VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,0,?13)",
        params![
            control.envelope_id.as_slice(),
            control.authority.as_slice(),
            control.signer.as_slice(),
            sql_u64(control.sequence, "control sequence")?,
            control.previous_control.map(|value| value.to_vec()),
            control.kind as u8 as i64,
            control.sealed,
            subject,
            generation,
            scope,
            epoch,
            observed_at_ms,
            sql_u64(order, "control order")?
        ],
    )?;
    transaction.execute(
        "INSERT INTO control_outbox(envelope_id,enqueued_order) VALUES(?1,?2)",
        params![
            control.envelope_id.as_slice(),
            sql_u64(order, "control outbox order")?
        ],
    )?;
    Ok(ControlInsert::Inserted)
}

fn apply_control_effect_tx(
    transaction: &Transaction<'_>,
    control: &StoredControl,
) -> Result<Option<NodeId>, StoreError> {
    let mut revoked_signer = None;
    match control.kind {
        ControlKind::Revocation => {
            let (subject, generation, observed): (Vec<u8>, i64, Option<i64>) = transaction
                .query_row(
                    "SELECT subject,generation,observed_at_ms FROM controls WHERE envelope_id=?1",
                    params![control.envelope_id.as_slice()],
                    |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
                )?;
            let subject = node_from_vec(subject, "revocation subject")?;
            let generation = from_sql_u64(generation, "revocation generation")?;
            let existing: Option<(Vec<u8>, i64, Vec<u8>)> = transaction
                .query_row(
                    "SELECT authority,generation,sealed_notice FROM revocations WHERE subject=?1",
                    params![subject.as_slice()],
                    |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
                )
                .optional()?;
            if let Some((authority, old, sealed)) = existing {
                if node_from_vec(authority, "revocation authority")? != control.authority {
                    return Err(StoreError::ControlFork);
                }
                let old = from_sql_u64(old, "revocation generation")?;
                if old >= generation {
                    return if old == generation && sealed == control.sealed {
                        Ok(Some(subject))
                    } else {
                        Err(StoreError::ControlRollback)
                    };
                }
            }
            transaction.execute(
                "INSERT INTO revocations(subject,authority,generation,sealed_notice,observed_at_ms)\n\
                 VALUES(?1,?2,?3,?4,?5) ON CONFLICT(subject) DO UPDATE SET\n\
                 authority=excluded.authority,generation=excluded.generation,\n\
                 sealed_notice=excluded.sealed_notice,observed_at_ms=excluded.observed_at_ms",
                params![
                    subject.as_slice(),
                    control.authority.as_slice(),
                    sql_u64(generation, "revocation generation")?,
                    control.sealed,
                    observed
                ],
            )?;
            transaction.execute(
                "INSERT INTO peers(node_id,peer_status,sync_status,last_change_ms,detail)\n\
                 VALUES(?1,4,4,?2,'revoked by authenticated mesh control')\n\
                 ON CONFLICT(node_id) DO UPDATE SET peer_status=4,sync_status=4,\n\
                 last_change_ms=excluded.last_change_ms,detail=excluded.detail",
                params![subject.as_slice(), observed],
            )?;
            remove_revoked_principal_bridge_routes_tx(transaction, subject)?;
            revoked_signer = Some(subject);
        }
        ControlKind::ScopeEpoch => {
            let (scope, epoch): (String, i64) = transaction.query_row(
                "SELECT scope,epoch FROM controls WHERE envelope_id=?1",
                params![control.envelope_id.as_slice()],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )?;
            let epoch = from_sql_u64(epoch, "scope epoch")?;
            let existing: Option<(i64, Vec<u8>)> = transaction
                .query_row(
                    "SELECT epoch,sealed_notice FROM scope_epochs WHERE scope=?1",
                    params![scope],
                    |row| Ok((row.get(0)?, row.get(1)?)),
                )
                .optional()?;
            if let Some((old, sealed)) = existing {
                let old = from_sql_u64(old, "scope epoch")?;
                if old >= epoch {
                    return if old == epoch && sealed == control.sealed {
                        Ok(None)
                    } else {
                        Err(StoreError::ControlRollback)
                    };
                }
            }
            transaction.execute(
                "INSERT INTO scope_epochs(scope,epoch,sealed_notice) VALUES(?1,?2,?3)\n\
                 ON CONFLICT(scope) DO UPDATE SET epoch=excluded.epoch,sealed_notice=excluded.sealed_notice",
                params![scope, sql_u64(epoch, "scope epoch")?, control.sealed],
            )?;
        }
    }
    Ok(revoked_signer)
}

#[derive(Default)]
struct ControlActivation {
    activated: Vec<StoredControl>,
    rejected: Vec<RejectedControl>,
}

fn activate_control_chain_tx(
    transaction: &Transaction<'_>,
    authority: NodeId,
) -> Result<ControlActivation, StoreError> {
    let head: Option<(i64, Vec<u8>)> = transaction
        .query_row(
            "SELECT sequence,envelope_id FROM control_heads WHERE authority=?1",
            params![authority.as_slice()],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .optional()?;
    let (mut sequence, mut previous) = match head {
        Some((sequence, envelope)) => (
            from_sql_u64(sequence, "control head sequence")?,
            Some(item_from_vec(envelope, "control head")?),
        ),
        None => (0, None),
    };
    let mut result = ControlActivation::default();
    loop {
        let sql =
            format!("SELECT {CONTROL_COLUMNS} FROM controls WHERE authority=?1 AND sequence=?2");
        let next: Option<StoredControl> = transaction
            .query_row(
                &sql,
                params![
                    authority.as_slice(),
                    sql_u64(sequence.saturating_add(1), "next control sequence")?
                ],
                decode_control_row,
            )
            .optional()?;
        let Some(mut next) = next else { break };
        if next.previous_control != previous {
            return Err(StoreError::ControlFork);
        }
        if control_signer_revoked_tx(transaction, authority)?
            || control_signer_revoked_tx(transaction, next.signer)?
        {
            if next.applied {
                return Err(StoreError::Corrupt(
                    "an applied control belongs to an earlier-revoked principal".into(),
                ));
            }
            result.rejected.extend(purge_pending_control_suffix_tx(
                transaction,
                authority,
                next.sequence,
            )?);
            break;
        }
        // Pending suffixes are durable transport inputs, not authority state.
        // Only the already-applied prefix may constrain this effect, and the
        // check is repeated here at the exact crash-atomic activation point.
        validate_control_effect_order_tx(transaction, &next)?;
        let revoked_signer = apply_control_effect_tx(transaction, &next)?;
        transaction.execute(
            "UPDATE controls SET applied=1 WHERE envelope_id=?1",
            params![next.envelope_id.as_slice()],
        )?;
        if let Some(revoked_signer) = revoked_signer {
            result
                .rejected
                .extend(purge_revoked_principal_pending_suffixes_tx(
                    transaction,
                    revoked_signer,
                )?);
        }
        transaction.execute(
            "INSERT INTO control_heads(authority,sequence,envelope_id) VALUES(?1,?2,?3)\n\
             ON CONFLICT(authority) DO UPDATE SET sequence=excluded.sequence,envelope_id=excluded.envelope_id",
            params![
                authority.as_slice(),
                sql_u64(next.sequence, "control head sequence")?,
                next.envelope_id.as_slice()
            ],
        )?;
        next.applied = true;
        sequence = next.sequence;
        previous = Some(next.envelope_id);
        result.activated.push(next);
    }
    Ok(result)
}

fn control_outcome(
    envelope_id: EnvelopeId,
    inserted: ControlInsert,
    mut activation: ControlActivation,
) -> ControlOutcome {
    if let ControlInsert::Rejected(rejected) = inserted
        && !activation.rejected.contains(&rejected)
    {
        activation.rejected.push(rejected);
    }
    if !activation.activated.is_empty() {
        return ControlOutcome::Applied {
            envelope_id,
            activated: activation.activated,
            rejected: activation.rejected,
        };
    }
    if let ControlInsert::Rejected(rejected) = inserted {
        return ControlOutcome::Rejected {
            envelope_id: rejected.envelope_id,
            signer: rejected.signer,
            rejected: activation.rejected,
        };
    }
    if let Some(rejected) = activation
        .rejected
        .iter()
        .find(|rejected| rejected.envelope_id == envelope_id)
        .copied()
    {
        return ControlOutcome::Rejected {
            envelope_id: rejected.envelope_id,
            signer: rejected.signer,
            rejected: activation.rejected,
        };
    }
    match inserted {
        ControlInsert::Inserted => ControlOutcome::Pending { envelope_id },
        ControlInsert::Duplicate => ControlOutcome::Duplicate { envelope_id },
        ControlInsert::Rejected(_) => unreachable!("rejected insert handled above"),
    }
}

fn load_group_tx(
    transaction: &Transaction<'_>,
    item: &StoredItem,
) -> Result<Vec<StoredItem>, StoreError> {
    if !matches!(item.class, DataClass::State | DataClass::Record) {
        return Ok(vec![item.clone()]);
    }
    let sql = format!(
        "SELECT {ITEM_COLUMNS} FROM items\n\
         WHERE data_class=?1 AND topic=?2 AND scope=?3 AND logical_key=?4"
    );
    let mut statement = transaction.prepare(&sql)?;
    let rows = statement.query_map(
        params![
            class_to_i64(item.class),
            item.topic.as_str(),
            item.scope.as_str(),
            item.logical_key
        ],
        decode_item_row,
    )?;
    rows.collect::<Result<Vec<_>, _>>()
        .map_err(StoreError::from)
}

fn same_batch_item_semantics(left: &StoredItem, right: &StoredItem) -> bool {
    left.id == right.id
        && left.class == right.class
        && left.topic == right.topic
        && left.scope == right.scope
        && left.priority == right.priority
        && left.stamp == right.stamp
        && left.event_sequence == right.event_sequence
        && left.logical_key == right.logical_key
        && left.ttl_ms == right.ttl_ms
        && left.content_len == right.content_len
        && left.tombstone == right.tombstone
        && left.key_epoch == right.key_epoch
}

fn record_accepted_frontier_dot_tx(
    transaction: &Transaction<'_>,
    topic: &Topic,
    scope: &Scope,
    dot: Dot,
) -> Result<(), StoreError> {
    // An authenticated publisher may assert arbitrary predecessor entries. Only
    // the envelope's own accepted dot is direct local evidence and may advance
    // the context attached to a later local publication in this exact domain.
    // Schema-11 observations remain in the reserved legacy-global sentinel and
    // count in every domain until a separately specified safe checkpoint exists.
    let publisher_known: bool = transaction.query_row(
        "SELECT EXISTS(\n\
           SELECT 1 FROM causal_frontier WHERE publisher=?1 AND\n\
             ((topic=?2 AND scope=?3) OR (topic=?4 AND scope=?5))\n\
         )",
        params![
            dot.publisher.as_slice(),
            topic.as_str(),
            scope.as_str(),
            LEGACY_CAUSAL_TOPIC,
            LEGACY_CAUSAL_SCOPE
        ],
        |row| row.get(0),
    )?;
    if !publisher_known {
        let publisher_count: i64 = transaction.query_row(
            "SELECT count(*) FROM (\n\
               SELECT publisher FROM causal_frontier WHERE topic=?1 AND scope=?2\n\
               UNION\n\
               SELECT publisher FROM causal_frontier WHERE topic=?3 AND scope=?4\n\
             )",
            params![
                topic.as_str(),
                scope.as_str(),
                LEGACY_CAUSAL_TOPIC,
                LEGACY_CAUSAL_SCOPE
            ],
            |row| row.get(0),
        )?;
        if publisher_count >= MAX_CAUSAL_CONTEXT_ENTRIES as i64 {
            return Err(StoreError::Invalid(
                "directly observed causal publisher limit reached for domain".into(),
            ));
        }
    }
    transaction.execute(
        "INSERT INTO causal_frontier(topic,scope,publisher,counter) VALUES(?1,?2,?3,?4)\n\
         ON CONFLICT(topic,scope,publisher) DO UPDATE\n\
           SET counter=max(counter,excluded.counter)",
        params![
            topic.as_str(),
            scope.as_str(),
            dot.publisher.as_slice(),
            sql_u64(dot.counter, "frontier counter")?
        ],
    )?;
    Ok(())
}

fn update_reduction_tx(
    transaction: &Transaction<'_>,
    item: &StoredItem,
) -> Result<Reduction, StoreError> {
    let reduction = reduce_group(load_group_tx(transaction, item)?);
    for (id, status) in &reduction.statuses {
        transaction.execute(
            "UPDATE items SET version_status=?1 WHERE item_id=?2",
            params![*status as u8 as i64, id.as_slice()],
        )?;
    }
    if item.class == DataClass::Record {
        transaction.execute(
            "DELETE FROM conflict_siblings WHERE topic=?1 AND scope=?2 AND logical_key=?3",
            params![item.topic.as_str(), item.scope.as_str(), item.logical_key],
        )?;
        if let Some(conflict) = &reduction.conflict {
            for sibling in &conflict.siblings {
                transaction.execute(
                    "INSERT INTO conflict_siblings(topic,scope,logical_key,item_id)\n\
                     VALUES(?1,?2,?3,?4)",
                    params![
                        item.topic.as_str(),
                        item.scope.as_str(),
                        item.logical_key,
                        sibling.as_slice()
                    ],
                )?;
            }
        }
    }
    Ok(reduction)
}

fn insert_item_tx(
    transaction: &Transaction<'_>,
    mut item: StoredItem,
    config: &StoreConfig,
    defer_quota: bool,
) -> Result<ApplyOutcome, StoreError> {
    validate_item(&item)?;
    if let Some(existing) = load_item_tx(transaction, &item.id)? {
        merge_duplicate_custody_tx(transaction, &existing, &item)?;
        return Ok(ApplyOutcome::Duplicate { id: item.id });
    }

    let existing_dot: Option<Vec<u8>> = transaction
        .query_row(
            "SELECT item_id FROM accepted_dots WHERE publisher=?1 AND counter=?2",
            params![
                item.stamp.dot.publisher.as_slice(),
                sql_u64(item.stamp.dot.counter, "causal counter")?
            ],
            |row| row.get(0),
        )
        .optional()?;
    let accepted_dot = existing_dot
        .map(|existing| item_from_vec(existing, "item id"))
        .transpose()?;
    if let Some(accepted) = accepted_dot {
        if accepted != item.id {
            return Err(StoreError::Equivocation {
                publisher: item.stamp.dot.publisher,
                counter: item.stamp.dot.counter,
            });
        }
        if !matches_retained_bridge_origin_tx(transaction, &item)? {
            // The item itself was explicitly garbage-collected, but the
            // permanent acceptance ledger prevents unauthenticated replay
            // from resurrecting it. Retained provider-authenticated bridge
            // source bytes are the sole materialization exception.
            return Ok(ApplyOutcome::Duplicate { id: item.id });
        }
    }
    if let Some(sequence) = item.event_sequence {
        let existing_event: Option<Vec<u8>> = transaction
            .query_row(
                "SELECT item_id FROM accepted_events\n\
                 WHERE publisher=?1 AND topic=?2 AND scope=?3 AND sequence=?4",
                params![
                    item.stamp.dot.publisher.as_slice(),
                    item.topic.as_str(),
                    item.scope.as_str(),
                    sql_u64(sequence, "event sequence")?
                ],
                |row| row.get(0),
            )
            .optional()?;
        let event_conflicts = existing_event
            .map(|existing| item_from_vec(existing, "item id"))
            .transpose()?
            .is_some_and(|existing| existing != item.id);
        if event_conflicts {
            return Err(StoreError::EventEquivocation {
                publisher: item.stamp.dot.publisher,
                sequence,
            });
        }
    }

    item.inserted_order = next_order(transaction)?;
    item.status = VersionStatus::Current;
    let accounted = item.accounted_bytes();
    transaction.execute(
        "INSERT INTO items(\n\
           item_id,data_class,topic,scope,priority,publisher,causal_counter,causal_context,\n\
           event_sequence,logical_key,ttl_ms,observed_at_ms,sealed,content_len,tombstone,\n\
           key_epoch,version_status,inserted_order,accounted_bytes,envelope_id,\n\
           custody_age_ms,custody_clock_id,custody_tick_ms,custody_elapsed_available\n\
         ) VALUES(\n\
           ?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14,?15,?16,?17,?18,?19,\n\
           ?20,?21,?22,?23,?24\n\
         )",
        params![
            item.id.as_slice(),
            class_to_i64(item.class),
            item.topic.as_str(),
            item.scope.as_str(),
            item.priority as u8 as i64,
            item.stamp.dot.publisher.as_slice(),
            sql_u64(item.stamp.dot.counter, "causal counter")?,
            encode_context(&item.stamp.context),
            item.event_sequence
                .map(|value| sql_u64(value, "event sequence"))
                .transpose()?,
            item.logical_key,
            item.ttl_ms.map(|value| sql_u64(value, "ttl")).transpose()?,
            item.observed_at_ms
                .map(|value| sql_u64(value, "observation time"))
                .transpose()?,
            item.sealed,
            sql_u64(item.content_len, "content length")?,
            i64::from(item.tombstone),
            sql_u64(item.key_epoch, "key epoch")?,
            item.status as u8 as i64,
            sql_u64(item.inserted_order, "inserted order")?,
            sql_u64(accounted, "accounted bytes")?,
            item.envelope_id.as_slice(),
            sql_u64(item.custody_age_ms, "custody age")?,
            item.custody_clock_id.map(|value| value.to_vec()),
            item.custody_tick_ms
                .map(|value| sql_u64(value, "custody tick"))
                .transpose()?,
            if item.custody_elapsed_available {
                1i64
            } else {
                0i64
            },
        ],
    )?;
    transaction.execute(
        "INSERT INTO accepted_dots(publisher,counter,item_id) VALUES(?1,?2,?3)\n\
         ON CONFLICT(publisher,counter) DO NOTHING",
        params![
            item.stamp.dot.publisher.as_slice(),
            sql_u64(item.stamp.dot.counter, "causal counter")?,
            item.id.as_slice()
        ],
    )?;
    if let Some(sequence) = item.event_sequence {
        transaction.execute(
            "INSERT INTO accepted_events(publisher,topic,scope,sequence,item_id)\n\
             VALUES(?1,?2,?3,?4,?5)\n\
             ON CONFLICT(publisher,topic,scope,sequence) DO NOTHING",
            params![
                item.stamp.dot.publisher.as_slice(),
                item.topic.as_str(),
                item.scope.as_str(),
                sql_u64(sequence, "event sequence")?,
                item.id.as_slice()
            ],
        )?;
    }
    if item.tombstone {
        let retain_until = match item.observed_at_ms {
            Some(observed) => Some(sql_u64(
                observed.saturating_add(config.tombstone_retention_ms),
                "tombstone retention",
            )?),
            None => None,
        };
        transaction.execute(
            "INSERT INTO tombstones(item_id,retain_until_ms) VALUES(?1,?2)",
            params![item.id.as_slice(), retain_until],
        )?;
    }
    let reduction = update_reduction_tx(transaction, &item)?;
    transaction.execute(
        "INSERT INTO outbox(item_id,enqueued_order) VALUES(?1,?2)",
        params![
            item.id.as_slice(),
            sql_u64(item.inserted_order, "outbox order")?
        ],
    )?;
    record_accepted_frontier_dot_tx(transaction, &item.topic, &item.scope, item.stamp.dot)?;
    let evicted = if defer_quota {
        Vec::new()
    } else {
        enforce_quotas_tx(
            transaction,
            config,
            Some(item.id),
            item.observed_at_ms,
            item.custody_clock_id
                .zip(item.custody_tick_ms)
                .map(|(clock_id, tick_ms)| CustodySample { clock_id, tick_ms }),
        )?
    };
    let status = reduction
        .statuses
        .iter()
        .find_map(|(id, status)| (id == &item.id).then_some(*status))
        .unwrap_or(VersionStatus::Current);
    Ok(ApplyOutcome::Inserted {
        id: item.id,
        status,
        conflict: reduction.conflict,
        evicted,
    })
}

fn committed_usage_tx(
    transaction: &Transaction<'_>,
    scope: Option<&Scope>,
) -> Result<QuotaUsage, StoreError> {
    let (items, item_bytes): (i64, i64) = match scope {
        Some(scope) => transaction.query_row(
            "SELECT\n\
               (SELECT count(*) FROM items WHERE scope=?1) +\n\
               (SELECT count(*) FROM batch_proofs WHERE scope=?1) +\n\
               (SELECT count(*) FROM batch_item_representations r JOIN items i\n\
                  ON i.item_id=r.item_id WHERE i.scope=?1) +\n\
               (SELECT count(*) FROM bridge_source_objects WHERE origin_scope=?1) +\n\
               (SELECT count(*) FROM bridge_pending_sources WHERE origin_scope=?1) +\n\
               (SELECT count(*) FROM bridge_route_wrappers WHERE current_scope=?1) +\n\
               (SELECT count(*) FROM bridge_pending_wrappers WHERE current_scope=?1) +\n\
               (SELECT count(*) FROM bridge_authorization_controls\n\
                  WHERE source_scope=?1 OR target_scope=?1) +\n\
               (SELECT count(*) FROM bridge_target_projection p\n\
                  JOIN bridge_active_routes a ON a.wrapper_envelope_id=p.wrapper_envelope_id\n\
                  WHERE p.target_scope=?1 AND NOT EXISTS(\n\
                    SELECT 1 FROM items i WHERE i.item_id=p.source_item_id\n\
                      AND i.scope=p.target_scope AND i.key_epoch=p.target_route_epoch)),\n\
               (SELECT coalesce(sum(accounted_bytes),0) FROM items WHERE scope=?1) +\n\
               (SELECT coalesce(sum(accounted_bytes),0) FROM batch_proofs WHERE scope=?1) +\n\
               (SELECT coalesce(sum(r.accounted_bytes),0)\n\
                  FROM batch_item_representations r JOIN items i ON i.item_id=r.item_id\n\
                  WHERE i.scope=?1) +\n\
               (SELECT coalesce(sum(accounted_bytes),0) FROM bridge_source_objects\n\
                  WHERE origin_scope=?1) +\n\
               (SELECT coalesce(sum(accounted_bytes),0) FROM bridge_pending_sources\n\
                  WHERE origin_scope=?1) +\n\
               (SELECT coalesce(sum(accounted_bytes),0) FROM bridge_route_wrappers\n\
                  WHERE current_scope=?1) +\n\
               (SELECT coalesce(sum(accounted_bytes),0) FROM bridge_pending_wrappers\n\
                  WHERE current_scope=?1) +\n\
               (SELECT coalesce(sum(accounted_bytes),0) FROM bridge_authorization_controls\n\
                  WHERE source_scope=?1 OR target_scope=?1) +\n\
               (SELECT count(*) * 128 FROM bridge_target_projection p\n\
                  JOIN bridge_active_routes a ON a.wrapper_envelope_id=p.wrapper_envelope_id\n\
                  WHERE p.target_scope=?1 AND NOT EXISTS(\n\
                    SELECT 1 FROM items i WHERE i.item_id=p.source_item_id\n\
                      AND i.scope=p.target_scope AND i.key_epoch=p.target_route_epoch))",
            params![scope.as_str()],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )?,
        None => transaction.query_row(
            "SELECT\n\
               (SELECT count(*) FROM items) + (SELECT count(*) FROM controls) +\n\
               (SELECT count(*) FROM batch_proofs) +\n\
               (SELECT count(*) FROM batch_item_representations) +\n\
               (SELECT count(*) FROM bridge_authorization_controls) +\n\
               (SELECT count(*) FROM bridge_source_objects) +\n\
               (SELECT count(*) FROM bridge_route_wrappers) +\n\
               (SELECT count(*) FROM bridge_pending_sources) +\n\
               (SELECT count(*) FROM bridge_pending_wrappers) +\n\
               (SELECT count(*) FROM bridge_unresolved_sources) +\n\
               (SELECT count(*) FROM bridge_pending_blob_carriers) +\n\
               (SELECT count(*) FROM bridge_blob_carrier_commits),\n\
               (SELECT coalesce(sum(accounted_bytes),0) FROM items) +\n\
               (SELECT coalesce(sum(accounted_bytes),0) FROM batch_proofs) +\n\
               (SELECT coalesce(sum(accounted_bytes),0) FROM batch_item_representations) +\n\
               (SELECT coalesce(sum(length(sealed)),0) FROM controls) +\n\
               (SELECT coalesce(sum(accounted_bytes),0) FROM bridge_authorization_controls) +\n\
               (SELECT coalesce(sum(accounted_bytes),0) FROM bridge_source_objects) +\n\
               (SELECT coalesce(sum(accounted_bytes),0) FROM bridge_route_wrappers) +\n\
               (SELECT coalesce(sum(accounted_bytes),0) FROM bridge_pending_sources) +\n\
               (SELECT coalesce(sum(accounted_bytes),0) FROM bridge_pending_wrappers) +\n\
               (SELECT coalesce(sum(accounted_bytes),0) FROM bridge_unresolved_sources) +\n\
               (SELECT coalesce(sum(accounted_bytes),0) FROM bridge_pending_blob_carriers) +\n\
               (SELECT coalesce(sum(accounted_bytes),0) FROM bridge_blob_carrier_commits)",
            [],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )?,
    };
    let bridge_metadata = bridge_metadata_usage_tx(transaction, scope)?;
    let batch_metadata = batch_metadata_usage_tx(transaction, scope)?;
    Ok(QuotaUsage {
        items: from_sql_u64(items, "item usage")?
            .checked_add(bridge_metadata.items)
            .and_then(|value| value.checked_add(batch_metadata.items))
            .ok_or_else(|| StoreError::Corrupt("quota item usage overflow".into()))?,
        bytes: from_sql_u64(item_bytes, "item byte usage")?
            .checked_add(bridge_metadata.bytes)
            .and_then(|value| value.checked_add(batch_metadata.bytes))
            .ok_or_else(|| StoreError::Corrupt("quota byte usage overflow".into()))?,
    })
}

/// Fixed accounting for batch delivery metadata. Exact proof, item, and
/// secondary-representation bytes are charged separately above.
fn batch_metadata_usage_tx(
    transaction: &Transaction<'_>,
    scope: Option<&Scope>,
) -> Result<QuotaUsage, StoreError> {
    let rows: i64 = match scope {
        None => transaction.query_row(
            "SELECT\n\
               (SELECT count(*) FROM batch_proof_outbox) +\n\
               (SELECT count(*) FROM batch_proof_peer_receipts) +\n\
               (SELECT count(*) FROM batch_proof_peer_attempts) +\n\
               (SELECT count(*) FROM batch_compact_outbox) +\n\
               (SELECT count(*) FROM batch_compact_peer_receipts) +\n\
               (SELECT count(*) FROM batch_compact_peer_attempts)",
            [],
            |row| row.get(0),
        )?,
        Some(scope) => transaction.query_row(
            "SELECT\n\
               (SELECT count(*) FROM batch_proof_outbox o JOIN batch_proofs p\n\
                  ON p.proof_envelope_id=o.proof_envelope_id WHERE p.scope=?1) +\n\
               (SELECT count(*) FROM batch_proof_peer_receipts r JOIN batch_proofs p\n\
                  ON p.proof_envelope_id=r.proof_envelope_id WHERE p.scope=?1) +\n\
               (SELECT count(*) FROM batch_proof_peer_attempts a JOIN batch_proofs p\n\
                  ON p.proof_envelope_id=a.proof_envelope_id WHERE p.scope=?1) +\n\
               (SELECT count(*) FROM batch_compact_outbox o JOIN items i\n\
                  ON i.item_id=o.item_id WHERE i.scope=?1) +\n\
               (SELECT count(*) FROM batch_compact_peer_receipts r JOIN items i\n\
                  ON i.item_id=r.item_id WHERE i.scope=?1) +\n\
               (SELECT count(*) FROM batch_compact_peer_attempts a JOIN items i\n\
                  ON i.item_id=a.item_id WHERE i.scope=?1)",
            params![scope.as_str()],
            |row| row.get(0),
        )?,
    };
    let rows = from_sql_u64(rows, "batch metadata usage")?;
    Ok(QuotaUsage {
        items: rows,
        bytes: rows
            .checked_mul(96)
            .ok_or_else(|| StoreError::Corrupt("batch metadata usage overflow".into()))?,
    })
}

/// Charges bounded metadata independently from the exact objects counted by
/// `committed_usage_tx`. Shared source bytes are therefore charged once at the
/// origin while each target mapping, dependency, outbox, attempt, delivery,
/// receipt, and possession consumes a small fixed record charge.
fn bridge_metadata_usage_tx(
    transaction: &Transaction<'_>,
    scope: Option<&Scope>,
) -> Result<QuotaUsage, StoreError> {
    let (rows, bytes): (i64, i64) = match scope {
        None => transaction.query_row(
            "SELECT\n\
               (SELECT count(*) FROM bridge_authorization_topics) +\n\
               (SELECT count(*) FROM bridge_authorization_heads) +\n\
               (SELECT count(*) FROM bridge_authorization_highwater) +\n\
               (SELECT count(*) FROM bridge_authorization_outbox) +\n\
               (SELECT count(*) FROM bridge_authorization_peer_receipts) +\n\
               (SELECT count(*) FROM bridge_authorization_peer_attempts) +\n\
               (SELECT count(*) FROM bridge_pending_wrapper_authorizations) +\n\
               (SELECT count(*) FROM bridge_wrapper_authorizations) +\n\
               (SELECT count(*) FROM bridge_active_routes) +\n\
               (SELECT count(*) FROM bridge_route_outbox) +\n\
               (SELECT count(*) FROM bridge_route_peer_receipts) +\n\
               (SELECT count(*) FROM bridge_route_peer_attempts) +\n\
               (SELECT count(*) FROM bridge_target_projection) +\n\
               (SELECT count(*) FROM bridge_source_peer_receipts) +\n\
               (SELECT count(*) FROM bridge_source_peer_attempts) +\n\
               (SELECT count(*) FROM bridge_source_path_peer_receipts) +\n\
               (SELECT count(*) FROM bridge_blob_carrier_peer_receipts) +\n\
               (SELECT count(*) FROM bridge_blob_carrier_peer_possessions) +\n\
               (SELECT count(*) FROM bridge_projection_deliveries) +\n\
               (SELECT count(*) FROM semantic_app_deliveries),\n\
               ((SELECT count(*) FROM bridge_authorization_topics) +\n\
                (SELECT count(*) FROM bridge_authorization_heads) +\n\
                (SELECT count(*) FROM bridge_authorization_highwater) +\n\
                (SELECT count(*) FROM bridge_authorization_outbox) +\n\
                (SELECT count(*) FROM bridge_authorization_peer_receipts) +\n\
                (SELECT count(*) FROM bridge_authorization_peer_attempts) +\n\
                (SELECT count(*) FROM bridge_pending_wrapper_authorizations) +\n\
                (SELECT count(*) FROM bridge_wrapper_authorizations) +\n\
                (SELECT count(*) FROM bridge_active_routes) +\n\
                (SELECT count(*) FROM bridge_route_outbox) +\n\
                (SELECT count(*) FROM bridge_route_peer_receipts) +\n\
                (SELECT count(*) FROM bridge_route_peer_attempts) +\n\
                (SELECT count(*) FROM bridge_target_projection) +\n\
                (SELECT count(*) FROM bridge_source_peer_receipts) +\n\
                (SELECT count(*) FROM bridge_source_peer_attempts) +\n\
                (SELECT count(*) FROM bridge_source_path_peer_receipts) +\n\
                (SELECT count(*) FROM bridge_blob_carrier_peer_receipts) +\n\
                (SELECT count(*) FROM bridge_blob_carrier_peer_possessions) +\n\
                (SELECT count(*) FROM bridge_projection_deliveries) +\n\
                (SELECT count(*) FROM semantic_app_deliveries)) * 96 +\n\
               (SELECT coalesce(sum(length(topic)),0) FROM bridge_authorization_topics)",
            [],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )?,
        Some(scope) => transaction.query_row(
            "SELECT\n\
               (SELECT count(*) FROM bridge_authorization_topics t\n\
                  JOIN bridge_authorization_controls c ON c.envelope_id=t.envelope_id\n\
                  WHERE c.source_scope=?1 OR c.target_scope=?1) +\n\
               (SELECT count(*) FROM bridge_authorization_heads h\n\
                  JOIN bridge_authorization_controls c ON c.envelope_id=h.envelope_id\n\
                  WHERE c.source_scope=?1 OR c.target_scope=?1) +\n\
               (SELECT count(*) FROM bridge_authorization_highwater h\n\
                  JOIN bridge_authorization_controls c ON c.envelope_id=h.envelope_id\n\
                  WHERE c.source_scope=?1 OR c.target_scope=?1) +\n\
               (SELECT count(*) FROM bridge_authorization_outbox o\n\
                  JOIN bridge_authorization_controls c ON c.envelope_id=o.envelope_id\n\
                  WHERE c.source_scope=?1 OR c.target_scope=?1) +\n\
               (SELECT count(*) FROM bridge_authorization_peer_receipts r\n\
                  JOIN bridge_authorization_controls c ON c.envelope_id=r.envelope_id\n\
                  WHERE c.source_scope=?1 OR c.target_scope=?1) +\n\
               (SELECT count(*) FROM bridge_authorization_peer_attempts a\n\
                  JOIN bridge_authorization_controls c ON c.envelope_id=a.envelope_id\n\
                  WHERE c.source_scope=?1 OR c.target_scope=?1) +\n\
               (SELECT count(*) FROM bridge_wrapper_authorizations e\n\
                  JOIN bridge_route_wrappers w ON w.wrapper_envelope_id=e.wrapper_envelope_id\n\
                  WHERE w.current_scope=?1) +\n\
               (SELECT count(*) FROM bridge_pending_wrapper_authorizations e\n\
                  JOIN bridge_pending_wrappers w ON w.wrapper_envelope_id=e.wrapper_envelope_id\n\
                  WHERE w.current_scope=?1) +\n\
               (SELECT count(*) FROM bridge_active_routes a JOIN bridge_route_wrappers w\n\
                  ON w.wrapper_envelope_id=a.wrapper_envelope_id WHERE w.current_scope=?1) +\n\
               (SELECT count(*) FROM bridge_route_outbox o JOIN bridge_route_wrappers w\n\
                  ON w.wrapper_envelope_id=o.wrapper_envelope_id WHERE w.current_scope=?1) +\n\
               (SELECT count(*) FROM bridge_route_peer_receipts r JOIN bridge_route_wrappers w\n\
                  ON w.wrapper_envelope_id=r.wrapper_envelope_id WHERE w.current_scope=?1) +\n\
               (SELECT count(*) FROM bridge_route_peer_attempts r JOIN bridge_route_wrappers w\n\
                  ON w.wrapper_envelope_id=r.wrapper_envelope_id WHERE w.current_scope=?1) +\n\
               (SELECT count(*) FROM bridge_target_projection p WHERE p.target_scope=?1) +\n\
               (SELECT count(*) FROM bridge_source_path_peer_receipts r\n\
                  JOIN bridge_route_wrappers w ON w.wrapper_envelope_id=r.wrapper_envelope_id\n\
                  WHERE w.current_scope=?1) +\n\
               (SELECT count(*) FROM bridge_blob_carrier_peer_receipts r\n\
                  JOIN bridge_route_wrappers w ON w.wrapper_envelope_id=r.wrapper_envelope_id\n\
                  WHERE w.current_scope=?1) +\n\
               (SELECT count(*) FROM bridge_projection_deliveries d\n\
                  JOIN bridge_route_wrappers w ON w.wrapper_envelope_id=d.wrapper_envelope_id\n\
                  WHERE w.current_scope=?1) +\n\
               (SELECT count(*) FROM semantic_app_deliveries d\n\
                  WHERE d.target_scope=?1) +\n\
               (SELECT count(*) FROM bridge_source_peer_receipts r JOIN bridge_source_objects s\n\
                  ON s.origin_envelope_id=r.origin_envelope_id WHERE s.origin_scope=?1) +\n\
               (SELECT count(*) FROM bridge_source_peer_attempts r JOIN bridge_source_objects s\n\
                  ON s.origin_envelope_id=r.origin_envelope_id WHERE s.origin_scope=?1) +\n\
               (SELECT count(*) FROM bridge_blob_carrier_peer_possessions r\n\
                  JOIN bridge_source_objects s ON s.origin_envelope_id=r.source_envelope_id\n\
                  WHERE s.origin_scope=?1),\n\
               ((SELECT count(*) FROM bridge_authorization_topics t\n\
                   JOIN bridge_authorization_controls c ON c.envelope_id=t.envelope_id\n\
                   WHERE c.source_scope=?1 OR c.target_scope=?1) +\n\
                (SELECT count(*) FROM bridge_authorization_heads h\n\
                   JOIN bridge_authorization_controls c ON c.envelope_id=h.envelope_id\n\
                   WHERE c.source_scope=?1 OR c.target_scope=?1) +\n\
                (SELECT count(*) FROM bridge_authorization_highwater h\n\
                   JOIN bridge_authorization_controls c ON c.envelope_id=h.envelope_id\n\
                   WHERE c.source_scope=?1 OR c.target_scope=?1) +\n\
                (SELECT count(*) FROM bridge_authorization_outbox o\n\
                   JOIN bridge_authorization_controls c ON c.envelope_id=o.envelope_id\n\
                   WHERE c.source_scope=?1 OR c.target_scope=?1) +\n\
                (SELECT count(*) FROM bridge_authorization_peer_receipts r\n\
                   JOIN bridge_authorization_controls c ON c.envelope_id=r.envelope_id\n\
                   WHERE c.source_scope=?1 OR c.target_scope=?1) +\n\
                (SELECT count(*) FROM bridge_authorization_peer_attempts a\n\
                   JOIN bridge_authorization_controls c ON c.envelope_id=a.envelope_id\n\
                   WHERE c.source_scope=?1 OR c.target_scope=?1) +\n\
                (SELECT count(*) FROM bridge_wrapper_authorizations e\n\
                   JOIN bridge_route_wrappers w ON w.wrapper_envelope_id=e.wrapper_envelope_id\n\
                   WHERE w.current_scope=?1) +\n\
                (SELECT count(*) FROM bridge_pending_wrapper_authorizations e\n\
                   JOIN bridge_pending_wrappers w ON w.wrapper_envelope_id=e.wrapper_envelope_id\n\
                   WHERE w.current_scope=?1) +\n\
                (SELECT count(*) FROM bridge_active_routes a JOIN bridge_route_wrappers w\n\
                   ON w.wrapper_envelope_id=a.wrapper_envelope_id WHERE w.current_scope=?1) +\n\
                (SELECT count(*) FROM bridge_route_outbox o JOIN bridge_route_wrappers w\n\
                   ON w.wrapper_envelope_id=o.wrapper_envelope_id WHERE w.current_scope=?1) +\n\
                (SELECT count(*) FROM bridge_route_peer_receipts r JOIN bridge_route_wrappers w\n\
                   ON w.wrapper_envelope_id=r.wrapper_envelope_id WHERE w.current_scope=?1) +\n\
                (SELECT count(*) FROM bridge_route_peer_attempts r JOIN bridge_route_wrappers w\n\
                   ON w.wrapper_envelope_id=r.wrapper_envelope_id WHERE w.current_scope=?1) +\n\
                (SELECT count(*) FROM bridge_target_projection p WHERE p.target_scope=?1) +\n\
                (SELECT count(*) FROM bridge_source_path_peer_receipts r\n\
                   JOIN bridge_route_wrappers w ON w.wrapper_envelope_id=r.wrapper_envelope_id\n\
                   WHERE w.current_scope=?1) +\n\
                (SELECT count(*) FROM bridge_blob_carrier_peer_receipts r\n\
                   JOIN bridge_route_wrappers w ON w.wrapper_envelope_id=r.wrapper_envelope_id\n\
                   WHERE w.current_scope=?1) +\n\
                (SELECT count(*) FROM bridge_projection_deliveries d\n\
                   JOIN bridge_route_wrappers w ON w.wrapper_envelope_id=d.wrapper_envelope_id\n\
                   WHERE w.current_scope=?1) +\n\
                (SELECT count(*) FROM semantic_app_deliveries d\n\
                   WHERE d.target_scope=?1) +\n\
                (SELECT count(*) FROM bridge_source_peer_receipts r JOIN bridge_source_objects s\n\
                   ON s.origin_envelope_id=r.origin_envelope_id WHERE s.origin_scope=?1) +\n\
                (SELECT count(*) FROM bridge_source_peer_attempts r JOIN bridge_source_objects s\n\
                   ON s.origin_envelope_id=r.origin_envelope_id WHERE s.origin_scope=?1) +\n\
                (SELECT count(*) FROM bridge_blob_carrier_peer_possessions r\n\
                   JOIN bridge_source_objects s ON s.origin_envelope_id=r.source_envelope_id\n\
                   WHERE s.origin_scope=?1)) * 96 +\n\
               (SELECT coalesce(sum(length(t.topic)),0)\n\
                  FROM bridge_authorization_topics t JOIN bridge_authorization_controls c\n\
                    ON c.envelope_id=t.envelope_id\n\
                  WHERE c.source_scope=?1 OR c.target_scope=?1)",
            params![scope.as_str()],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )?,
    };
    Ok(QuotaUsage {
        items: from_sql_u64(rows, "bridge metadata row usage")?,
        bytes: from_sql_u64(bytes, "bridge metadata byte usage")?,
    })
}

#[derive(Clone, Copy, Debug, Default)]
struct BridgeMappingGcCounts {
    mappings: u64,
    wrappers: u64,
    sources: u64,
    metadata_rows: u64,
}

fn evict_bridge_mapping_tx(
    transaction: &Transaction<'_>,
    wrapper_envelope_id: EnvelopeId,
) -> Result<BridgeMappingGcCounts, StoreError> {
    let source: Option<Vec<u8>> = transaction
        .query_row(
            "SELECT origin_envelope_id FROM bridge_route_wrappers WHERE wrapper_envelope_id=?1",
            params![wrapper_envelope_id.as_slice()],
            |row| row.get(0),
        )
        .optional()?;
    let Some(source) = source else {
        return Ok(BridgeMappingGcCounts::default());
    };
    let source = node_from_vec(source, "bridge GC source")?;
    let metadata_before: i64 = transaction.query_row(
        "SELECT\n\
           (SELECT count(*) FROM bridge_wrapper_authorizations WHERE wrapper_envelope_id=?1) +\n\
           (SELECT count(*) FROM bridge_active_routes WHERE wrapper_envelope_id=?1) +\n\
           (SELECT count(*) FROM bridge_route_outbox WHERE wrapper_envelope_id=?1) +\n\
           (SELECT count(*) FROM bridge_route_peer_receipts WHERE wrapper_envelope_id=?1) +\n\
           (SELECT count(*) FROM bridge_route_peer_attempts WHERE wrapper_envelope_id=?1) +\n\
           (SELECT count(*) FROM bridge_target_projection WHERE wrapper_envelope_id=?1) +\n\
           (SELECT count(*) FROM bridge_source_path_peer_receipts WHERE wrapper_envelope_id=?1) +\n\
           (SELECT count(*) FROM bridge_blob_carrier_peer_receipts WHERE wrapper_envelope_id=?1) +\n\
           (SELECT count(*) FROM bridge_projection_deliveries WHERE wrapper_envelope_id=?1)",
        params![wrapper_envelope_id.as_slice()],
        |row| row.get(0),
    )?;
    transaction.execute(
        "DELETE FROM bridge_projection_deliveries WHERE wrapper_envelope_id=?1",
        params![wrapper_envelope_id.as_slice()],
    )?;
    transaction.execute(
        "DELETE FROM bridge_target_projection WHERE wrapper_envelope_id=?1",
        params![wrapper_envelope_id.as_slice()],
    )?;
    transaction.execute(
        "DELETE FROM bridge_source_path_peer_receipts WHERE wrapper_envelope_id=?1",
        params![wrapper_envelope_id.as_slice()],
    )?;
    transaction.execute(
        "DELETE FROM bridge_blob_carrier_peer_receipts WHERE wrapper_envelope_id=?1",
        params![wrapper_envelope_id.as_slice()],
    )?;
    transaction.execute(
        "DELETE FROM bridge_route_peer_receipts WHERE wrapper_envelope_id=?1",
        params![wrapper_envelope_id.as_slice()],
    )?;
    transaction.execute(
        "DELETE FROM bridge_route_peer_attempts WHERE wrapper_envelope_id=?1",
        params![wrapper_envelope_id.as_slice()],
    )?;
    transaction.execute(
        "DELETE FROM bridge_route_outbox WHERE wrapper_envelope_id=?1",
        params![wrapper_envelope_id.as_slice()],
    )?;
    transaction.execute(
        "DELETE FROM bridge_active_routes WHERE wrapper_envelope_id=?1",
        params![wrapper_envelope_id.as_slice()],
    )?;
    transaction.execute(
        "DELETE FROM bridge_wrapper_authorizations WHERE wrapper_envelope_id=?1",
        params![wrapper_envelope_id.as_slice()],
    )?;
    let wrappers = transaction.execute(
        "DELETE FROM bridge_route_wrappers WHERE wrapper_envelope_id=?1",
        params![wrapper_envelope_id.as_slice()],
    )? as u64;
    let mapping_references: i64 = transaction.query_row(
        "SELECT EXISTS(SELECT 1 FROM bridge_route_wrappers WHERE origin_envelope_id=?1)\n\
         OR EXISTS(SELECT 1 FROM bridge_pending_wrappers WHERE origin_envelope_id=?1)",
        params![source.as_slice()],
        |row| row.get(0),
    )?;
    let mut sources = 0u64;
    let mut source_metadata = 0u64;
    if mapping_references == 0 {
        for (table, column) in [
            ("bridge_source_peer_receipts", "origin_envelope_id"),
            ("bridge_source_peer_attempts", "origin_envelope_id"),
            ("bridge_blob_carrier_peer_possessions", "source_envelope_id"),
            ("bridge_pending_blob_carriers", "source_envelope_id"),
            ("bridge_blob_carrier_commits", "source_envelope_id"),
        ] {
            source_metadata = source_metadata.saturating_add(transaction.execute(
                &format!("DELETE FROM {table} WHERE {column}=?1"),
                params![source.as_slice()],
            )? as u64);
        }
        sources = transaction.execute(
            "DELETE FROM bridge_source_objects WHERE origin_envelope_id=?1",
            params![source.as_slice()],
        )? as u64;
    }
    Ok(BridgeMappingGcCounts {
        mappings: wrappers,
        wrappers,
        sources,
        metadata_rows: from_sql_u64(metadata_before, "bridge GC metadata")?
            .saturating_add(source_metadata),
    })
}

fn cleanup_unreferenced_bridge_authorizations_tx(
    transaction: &Transaction<'_>,
    limit: usize,
) -> Result<(u64, u64), StoreError> {
    if limit == 0 {
        return Ok((0, 0));
    }
    let candidates = {
        let mut statement = transaction.prepare(
            "SELECT c.envelope_id FROM bridge_authorization_controls c\n\
             WHERE NOT EXISTS(SELECT 1 FROM bridge_authorization_heads h\n\
                                WHERE h.envelope_id=c.envelope_id)\n\
               AND NOT EXISTS(SELECT 1 FROM bridge_authorization_highwater h\n\
                                WHERE h.envelope_id=c.envelope_id)\n\
               AND NOT EXISTS(SELECT 1 FROM bridge_wrapper_authorizations e\n\
                                WHERE e.authorization_envelope_id=c.envelope_id)\n\
               AND NOT EXISTS(SELECT 1 FROM bridge_pending_wrapper_authorizations e\n\
                                WHERE e.authorization_envelope_id=c.envelope_id)\n\
               AND NOT EXISTS(SELECT 1 FROM bridge_authorization_controls n\n\
                                WHERE n.previous_control_id=c.envelope_id)\n\
             ORDER BY c.inserted_order LIMIT ?1",
        )?;
        statement
            .query_map([i64::try_from(limit).unwrap_or(i64::MAX)], |row| {
                row.get::<_, Vec<u8>>(0)
            })?
            .collect::<Result<Vec<_>, _>>()?
    };
    let mut removed = 0u64;
    let mut metadata = 0u64;
    for id in candidates {
        let id = node_from_vec(id, "bridge GC authorization")?;
        for table in [
            "bridge_authorization_topics",
            "bridge_authorization_outbox",
            "bridge_authorization_peer_receipts",
            "bridge_authorization_peer_attempts",
        ] {
            metadata = metadata.saturating_add(transaction.execute(
                &format!("DELETE FROM {table} WHERE envelope_id=?1"),
                params![id.as_slice()],
            )? as u64);
        }
        removed = removed.saturating_add(transaction.execute(
            "DELETE FROM bridge_authorization_controls WHERE envelope_id=?1",
            params![id.as_slice()],
        )? as u64);
    }
    Ok((removed, metadata))
}

fn usage_tx(
    transaction: &Transaction<'_>,
    scope: Option<&Scope>,
) -> Result<QuotaUsage, StoreError> {
    let mut usage = committed_usage_tx(transaction, scope)?;
    if scope.is_none() {
        let (staging_items, staging_bytes): (i64, i64) = transaction.query_row(
            "SELECT\n\
               (SELECT count(*) FROM pending_batch_items) +\n\
               (SELECT count(*) FROM rejected_batch_proofs),\n\
               (SELECT coalesce(sum(length(bytes)),0) FROM sealed_chunks) +\n\
               (SELECT coalesce(sum(accounted_bytes),0) FROM pending_batch_items) +\n\
               (SELECT coalesce(sum(accounted_bytes),0) FROM rejected_batch_proofs)",
            [],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )?;
        usage.items = usage
            .items
            .checked_add(from_sql_u64(staging_items, "staging item usage")?)
            .ok_or_else(|| StoreError::Corrupt("quota item usage overflow".into()))?;
        usage.bytes = usage
            .bytes
            .checked_add(from_sql_u64(staging_bytes, "staging byte usage")?)
            .ok_or_else(|| StoreError::Corrupt("quota byte usage overflow".into()))?;
    }
    Ok(usage)
}

#[derive(Clone)]
struct EvictionCandidate {
    id: ItemId,
    scope: String,
    is_tombstone: bool,
    tombstone_retain_until: Option<u64>,
    bridge_source_referenced: bool,
}

fn eviction_candidates_tx(
    transaction: &Transaction<'_>,
) -> Result<Vec<EvictionCandidate>, StoreError> {
    let mut statement = transaction.prepare(
        "SELECT i.item_id,i.scope,i.tombstone,t.retain_until_ms,\n\
                EXISTS(SELECT 1 FROM bridge_source_objects b WHERE b.reused_item_id=i.item_id)\n\
         FROM items i LEFT JOIN tombstones t ON t.item_id=i.item_id\n\
         ORDER BY i.priority ASC, i.version_status DESC, i.inserted_order ASC",
    )?;
    let rows = statement.query_map([], |row| {
        let id = item_from_vec(row.get(0)?, "eviction item").map_err(|error| {
            rusqlite::Error::FromSqlConversionFailure(
                0,
                rusqlite::types::Type::Blob,
                Box::new(error),
            )
        })?;
        let retain = row
            .get::<_, Option<i64>>(3)?
            .map(|value| from_sql_u64(value, "tombstone retention"))
            .transpose()
            .map_err(|error| {
                rusqlite::Error::FromSqlConversionFailure(
                    3,
                    rusqlite::types::Type::Integer,
                    Box::new(error),
                )
            })?;
        Ok(EvictionCandidate {
            id,
            scope: row.get(1)?,
            is_tombstone: row.get::<_, i64>(2)? != 0,
            tombstone_retain_until: retain,
            bridge_source_referenced: row.get::<_, i64>(4)? != 0,
        })
    })?;
    Ok(rows.collect::<Result<Vec<_>, _>>()?)
}

fn candidate_evictable(
    candidate: &EvictionCandidate,
    protected: &BTreeSet<ItemId>,
    now_ms: Option<u64>,
) -> bool {
    if protected.contains(&candidate.id) {
        return false;
    }
    if candidate.bridge_source_referenced {
        return false;
    }
    if !candidate.is_tombstone {
        return true;
    }
    match candidate.tombstone_retain_until {
        None => false,
        Some(retain) => now_ms.is_some_and(|now| now >= retain),
    }
}

fn delete_item_tx(transaction: &Transaction<'_>, id: ItemId) -> Result<bool, StoreError> {
    let previous = load_item_tx(transaction, &id)?;
    let changed =
        transaction.execute("DELETE FROM items WHERE item_id=?1", params![id.as_slice()])? != 0;
    if let (true, Some(previous)) = (changed, previous)
        && matches!(previous.class, DataClass::State | DataClass::Record)
    {
        update_reduction_tx(transaction, &previous)?;
    }
    Ok(changed)
}

fn enforce_quotas_tx(
    transaction: &Transaction<'_>,
    config: &StoreConfig,
    protected: Option<ItemId>,
    now_ms: Option<u64>,
    custody_sample: Option<CustodySample>,
) -> Result<Vec<ItemId>, StoreError> {
    let protected = protected.into_iter().collect();
    enforce_quotas_protected_tx(transaction, config, &protected, now_ms, custody_sample)
}

fn enforce_quotas_protected_tx(
    transaction: &Transaction<'_>,
    config: &StoreConfig,
    protected: &BTreeSet<ItemId>,
    now_ms: Option<u64>,
    custody_sample: Option<CustodySample>,
) -> Result<Vec<ItemId>, StoreError> {
    let mut removed = Vec::new();
    if custody_sample.is_some() {
        let sql = format!(
            "SELECT {LIFECYCLE_ITEM_COLUMNS} FROM items\n\
             WHERE tombstone=0 AND ttl_ms IS NOT NULL"
        );
        let mut statement = transaction.prepare(&sql)?;
        let expired = statement
            .query_map([], decode_lifecycle_item_row)?
            .filter_map(|row| match row {
                Ok(item)
                    if !protected.contains(&item.id)
                        && !item.tombstone
                        && item.is_expired_at(custody_sample) =>
                {
                    Some(Ok(item.id))
                }
                Ok(_) => None,
                Err(error) => Some(Err(error)),
            })
            .collect::<Result<Vec<_>, _>>()?;
        drop(statement);
        for id in expired {
            if delete_item_tx(transaction, id)? {
                removed.push(id);
            }
        }
    }
    let candidates = eviction_candidates_tx(transaction)?;
    // Unauthenticated transfer bytes have a separately bounded partition and
    // are deliberately invisible to committed-item eviction. A hostile peer
    // can exhaust only staging; it cannot make this loop remove a record.
    let max_committed_bytes = committed_byte_limit(config);
    evict_unreferenced_batch_proofs_for_quota_tx(
        transaction,
        None,
        config.max_items,
        max_committed_bytes,
    )?;
    evict_bridge_mappings_for_quota_tx(transaction, None, config.max_items, max_committed_bytes)?;
    let mut usage = committed_usage_tx(transaction, None)?;
    for candidate in &candidates {
        if usage.items <= config.max_items && usage.bytes <= max_committed_bytes {
            break;
        }
        if !candidate_evictable(candidate, protected, now_ms) {
            continue;
        }
        if delete_item_tx(transaction, candidate.id)? {
            removed.push(candidate.id);
            evict_unreferenced_batch_proofs_for_quota_tx(
                transaction,
                None,
                config.max_items,
                max_committed_bytes,
            )?;
            usage = committed_usage_tx(transaction, None)?;
        }
    }
    if usage.items > config.max_items || usage.bytes > max_committed_bytes {
        return Err(StoreError::QuotaExceeded);
    }

    let mut quota_statement =
        transaction.prepare("SELECT scope,max_items,max_bytes FROM quotas")?;
    let quotas = quota_statement
        .query_map([], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, i64>(1)?,
                row.get::<_, i64>(2)?,
            ))
        })?
        .collect::<Result<Vec<_>, _>>()?;
    drop(quota_statement);
    for (scope, max_items, max_bytes) in quotas {
        let scope_value =
            Scope::new(scope.clone()).map_err(|error| StoreError::Corrupt(error.to_string()))?;
        let max_items = from_sql_u64(max_items, "scope max items")?;
        let max_bytes = from_sql_u64(max_bytes, "scope max bytes")?;
        evict_unreferenced_batch_proofs_for_quota_tx(
            transaction,
            Some(&scope_value),
            max_items,
            max_bytes,
        )?;
        evict_bridge_mappings_for_quota_tx(transaction, Some(&scope_value), max_items, max_bytes)?;
        let mut scope_usage = committed_usage_tx(transaction, Some(&scope_value))?;
        for candidate in candidates
            .iter()
            .filter(|candidate| candidate.scope == scope)
        {
            if scope_usage.items <= max_items && scope_usage.bytes <= max_bytes {
                break;
            }
            if removed.contains(&candidate.id) || !candidate_evictable(candidate, protected, now_ms)
            {
                continue;
            }
            if delete_item_tx(transaction, candidate.id)? {
                removed.push(candidate.id);
                evict_unreferenced_batch_proofs_for_quota_tx(
                    transaction,
                    Some(&scope_value),
                    max_items,
                    max_bytes,
                )?;
                scope_usage = committed_usage_tx(transaction, Some(&scope_value))?;
            }
        }
        if scope_usage.items > max_items || scope_usage.bytes > max_bytes {
            return Err(StoreError::QuotaExceeded);
        }
    }
    Ok(removed)
}

/// Proofs can be shared by many compact representations and can arrive before
/// any item. Quota pressure may remove only a proof with no accepted or pending
/// dependent; foreign-key cascades then remove its delivery metadata.
fn evict_unreferenced_batch_proofs_for_quota_tx(
    transaction: &Transaction<'_>,
    scope: Option<&Scope>,
    max_items: u64,
    max_bytes: u64,
) -> Result<(), StoreError> {
    loop {
        let usage = committed_usage_tx(transaction, scope)?;
        if usage.items <= max_items && usage.bytes <= max_bytes {
            return Ok(());
        }
        let candidate: Option<Vec<u8>> = match scope {
            Some(scope) => transaction
                .query_row(
                    "SELECT p.proof_envelope_id FROM batch_proofs p\n\
                     WHERE p.scope=?1\n\
                       AND NOT EXISTS(SELECT 1 FROM batch_item_representations r\n\
                         WHERE r.proof_envelope_id=p.proof_envelope_id)\n\
                       AND NOT EXISTS(SELECT 1 FROM pending_batch_items q\n\
                         WHERE q.proof_envelope_id=p.proof_envelope_id)\n\
                     ORDER BY p.inserted_order LIMIT 1",
                    params![scope.as_str()],
                    |row| row.get(0),
                )
                .optional()?,
            None => transaction
                .query_row(
                    "SELECT p.proof_envelope_id FROM batch_proofs p\n\
                     WHERE NOT EXISTS(SELECT 1 FROM batch_item_representations r\n\
                         WHERE r.proof_envelope_id=p.proof_envelope_id)\n\
                       AND NOT EXISTS(SELECT 1 FROM pending_batch_items q\n\
                         WHERE q.proof_envelope_id=p.proof_envelope_id)\n\
                     ORDER BY p.inserted_order LIMIT 1",
                    [],
                    |row| row.get(0),
                )
                .optional()?,
        };
        let Some(candidate) = candidate else {
            return Ok(());
        };
        transaction.execute(
            "DELETE FROM batch_proofs WHERE proof_envelope_id=?1",
            params![candidate],
        )?;
    }
}

fn evict_bridge_mappings_for_quota_tx(
    transaction: &Transaction<'_>,
    scope: Option<&Scope>,
    max_items: u64,
    max_bytes: u64,
) -> Result<(), StoreError> {
    let mut removed = 0u64;
    loop {
        let usage = committed_usage_tx(transaction, scope)?;
        if usage.items <= max_items && usage.bytes <= max_bytes {
            return Ok(());
        }
        let candidate = match scope {
            Some(scope) => transaction
                .query_row(
                    "SELECT w.wrapper_envelope_id FROM bridge_route_wrappers w\n\
                     JOIN bridge_source_objects s ON s.origin_envelope_id=w.origin_envelope_id\n\
                     WHERE w.current_scope=?1 AND s.tombstone=0\n\
                     ORDER BY EXISTS(SELECT 1 FROM bridge_active_routes a\n\
                       WHERE a.wrapper_envelope_id=w.wrapper_envelope_id) ASC,\n\
                       w.source_priority ASC,w.inserted_order ASC LIMIT 1",
                    params![scope.as_str()],
                    |row| row.get::<_, Vec<u8>>(0),
                )
                .optional()?,
            None => transaction
                .query_row(
                    "SELECT w.wrapper_envelope_id FROM bridge_route_wrappers w\n\
                     JOIN bridge_source_objects s ON s.origin_envelope_id=w.origin_envelope_id\n\
                     WHERE s.tombstone=0\n\
                     ORDER BY EXISTS(SELECT 1 FROM bridge_active_routes a\n\
                       WHERE a.wrapper_envelope_id=w.wrapper_envelope_id) ASC,\n\
                       w.source_priority ASC,w.inserted_order ASC LIMIT 1",
                    [],
                    |row| row.get::<_, Vec<u8>>(0),
                )
                .optional()?,
        };
        let Some(candidate) = candidate else {
            return Ok(());
        };
        evict_bridge_mapping_tx(
            transaction,
            node_from_vec(candidate, "bridge quota eviction wrapper")?,
        )?;
        removed = removed.checked_add(1).ok_or(StoreError::QuotaExceeded)?;
        if removed > MAX_BRIDGE_STORE_BATCH as u64 {
            return Err(StoreError::QuotaExceeded);
        }
    }
}

fn verify_completed_object_tx(
    transaction: &Transaction<'_>,
    object: ItemId,
    total_len: u64,
) -> Result<(), StoreError> {
    let mut statement = transaction.prepare(
        "SELECT start_offset,end_offset,bytes FROM sealed_chunks\n\
         WHERE object_id=?1 ORDER BY start_offset",
    )?;
    let rows = statement.query_map(params![object.as_slice()], |row| {
        Ok((
            row.get::<_, i64>(0)?,
            row.get::<_, i64>(1)?,
            row.get::<_, Vec<u8>>(2)?,
        ))
    })?;
    let mut cursor = 0u64;
    let mut digest = Sha256::new();
    for row in rows {
        let (start, end, bytes) = row?;
        let start = from_sql_u64(start, "completed chunk start")?;
        let end = from_sql_u64(end, "completed chunk end")?;
        if start != cursor || end.saturating_sub(start) != bytes.len() as u64 {
            return Err(StoreError::Corrupt(
                "completed object chunks are not contiguous".into(),
            ));
        }
        digest.update(&bytes);
        cursor = end;
    }
    drop(statement);
    if cursor != total_len {
        return Err(StoreError::Corrupt(
            "completed object length does not match durable chunks".into(),
        ));
    }
    let calculated: ItemId = digest.finalize().into();
    let typed_identity: Option<Vec<u8>> = transaction
        .query_row(
            "SELECT object_id FROM transfer_identities WHERE storage_key=?1",
            params![object.as_slice()],
            |row| row.get(0),
        )
        .optional()?;
    if let Some(encoded) = typed_identity {
        let encoded: [u8; ObjectId::WIRE_LEN] = encoded
            .try_into()
            .map_err(|_| StoreError::Corrupt("typed transfer identity length".into()))?;
        let typed = ObjectId::from_wire_bytes(encoded)
            .ok_or_else(|| StoreError::Corrupt("typed transfer identity kind".into()))?;
        if transfer_storage_key(typed) != object {
            return Err(StoreError::Corrupt(
                "typed transfer identity storage key mismatch".into(),
            ));
        }
        // Typed identities are verified at the terminal runtime boundary so a
        // mismatch can atomically discard the whole staging object and reset
        // reducer progress. Source envelopes use their full SHA-256 identity;
        // Blob objects additionally bind the canonical carrier header, proof,
        // and ciphertext digest.
        let _ = calculated;
        return Ok(());
    }
    if calculated != object {
        return Err(StoreError::Invalid(
            "completed object does not match its content address".into(),
        ));
    }
    Ok(())
}

fn load_frontier(
    connection: &Connection,
    topic: &Topic,
    scope: &Scope,
) -> Result<VersionVector, StoreError> {
    let mut frontier = VersionVector::default();
    let mut statement = connection.prepare(
        "SELECT publisher,max(counter) FROM (\n\
           SELECT publisher,counter FROM causal_frontier WHERE topic=?1 AND scope=?2\n\
           UNION ALL\n\
           SELECT publisher,counter FROM causal_frontier WHERE topic=?3 AND scope=?4\n\
         ) GROUP BY publisher ORDER BY publisher",
    )?;
    let rows = statement.query_map(
        params![
            topic.as_str(),
            scope.as_str(),
            LEGACY_CAUSAL_TOPIC,
            LEGACY_CAUSAL_SCOPE
        ],
        |row| Ok((row.get::<_, Vec<u8>>(0)?, row.get::<_, i64>(1)?)),
    )?;
    for row in rows {
        let (publisher, counter) = row?;
        frontier.observe(Dot {
            publisher: node_from_vec(publisher, "frontier publisher")?,
            counter: from_sql_u64(counter, "frontier counter")?,
        });
        if frontier.len() > MAX_CAUSAL_CONTEXT_ENTRIES {
            return Err(StoreError::Corrupt(
                "directly observed causal frontier exceeds the protocol bound".into(),
            ));
        }
    }
    Ok(frontier)
}

impl RecordStore for SqliteStore {
    fn config(&self) -> &StoreConfig {
        &self.config
    }

    fn reserve_publish(
        &mut self,
        publisher: NodeId,
        class: DataClass,
        topic: &Topic,
        scope: &Scope,
    ) -> Result<PublishReservation, StoreError> {
        if self.is_zeroized()? {
            return Err(StoreError::Zeroized);
        }
        let context = load_frontier(&self.connection, topic, scope)?;
        if context.len() >= MAX_CAUSAL_CONTEXT_ENTRIES && context.counter(&publisher) == 0 {
            return Err(StoreError::Invalid(
                "directly observed causal publisher limit reached for domain".into(),
            ));
        }
        let persisted_previous: i64 = self
            .connection
            .query_row(
                "SELECT counter FROM publisher_counters WHERE publisher=?1",
                params![publisher.as_slice()],
                |row| row.get(0),
            )
            .optional()?
            .unwrap_or(0);
        let observed_previous: i64 = self.connection.query_row(
            "SELECT coalesce(max(counter),0) FROM accepted_dots WHERE publisher=?1",
            params![publisher.as_slice()],
            |row| row.get(0),
        )?;
        let previous_counter = from_sql_u64(
            persisted_previous.max(observed_previous),
            "publisher counter",
        )?;
        let counter = previous_counter
            .checked_add(1)
            .ok_or_else(|| StoreError::Invalid("publisher counter exhausted".into()))?;
        let (event_previous, event_sequence) = if class == DataClass::Event {
            let persisted: i64 = self
                .connection
                .query_row(
                    "SELECT counter FROM event_counters\n\
                     WHERE publisher=?1 AND topic=?2 AND scope=?3",
                    params![publisher.as_slice(), topic.as_str(), scope.as_str()],
                    |row| row.get(0),
                )
                .optional()?
                .unwrap_or(0);
            let observed: i64 = self.connection.query_row(
                "SELECT coalesce(max(sequence),0) FROM accepted_events\n\
                 WHERE publisher=?1 AND topic=?2 AND scope=?3",
                params![publisher.as_slice(), topic.as_str(), scope.as_str()],
                |row| row.get(0),
            )?;
            let previous = from_sql_u64(persisted.max(observed), "event counter")?;
            (
                Some(previous),
                Some(
                    previous
                        .checked_add(1)
                        .ok_or_else(|| StoreError::Invalid("event sequence exhausted".into()))?,
                ),
            )
        } else {
            (None, None)
        };
        Ok(PublishReservation {
            previous_counter,
            counter,
            event_previous,
            event_sequence,
            context,
        })
    }

    fn reserve_batch_publish(
        &mut self,
        publisher: NodeId,
        class: DataClass,
        topic: &Topic,
        scope: &Scope,
        item_count: u16,
    ) -> Result<BatchPublishReservation, StoreError> {
        if !(crate::batch::MIN_BATCH_ITEMS..=crate::batch::MAX_BATCH_ITEMS).contains(&item_count) {
            return Err(StoreError::Invalid(
                "invalid source batch item count".into(),
            ));
        }
        let first = self.reserve_publish(publisher, class, topic, scope)?;
        let span = u64::from(item_count - 1);
        first
            .counter
            .checked_add(span)
            .ok_or_else(|| StoreError::Invalid("publisher counter range exhausted".into()))?;
        if let Some(sequence) = first.event_sequence {
            sequence
                .checked_add(span)
                .ok_or_else(|| StoreError::Invalid("event sequence range exhausted".into()))?;
        }
        Ok(BatchPublishReservation {
            previous_counter: first.previous_counter,
            first_counter: first.counter,
            item_count,
            event_previous: first.event_previous,
            first_event_sequence: first.event_sequence,
            context: first.context,
        })
    }

    fn commit_publish(
        &mut self,
        reservation: &PublishReservation,
        item: StoredItem,
    ) -> Result<ApplyOutcome, StoreError> {
        if item.stamp.dot.counter != reservation.counter {
            return Err(StoreError::Invalid(
                "sealed item does not match reserved causal counter".into(),
            ));
        }
        if item.event_sequence != reservation.event_sequence {
            return Err(StoreError::Invalid(
                "sealed item does not match reserved event sequence".into(),
            ));
        }
        let config = self.config.clone();
        let transaction = self.connection.transaction()?;
        let persisted_current: i64 = transaction
            .query_row(
                "SELECT counter FROM publisher_counters WHERE publisher=?1",
                params![item.stamp.dot.publisher.as_slice()],
                |row| row.get(0),
            )
            .optional()?
            .unwrap_or(0);
        let observed_current: i64 = transaction.query_row(
            "SELECT coalesce(max(counter),0) FROM accepted_dots WHERE publisher=?1",
            params![item.stamp.dot.publisher.as_slice()],
            |row| row.get(0),
        )?;
        if from_sql_u64(persisted_current.max(observed_current), "publisher counter")?
            != reservation.previous_counter
        {
            return Err(StoreError::CounterChanged);
        }
        if item.class == DataClass::Event {
            let persisted: i64 = transaction
                .query_row(
                    "SELECT counter FROM event_counters\n\
                     WHERE publisher=?1 AND topic=?2 AND scope=?3",
                    params![
                        item.stamp.dot.publisher.as_slice(),
                        item.topic.as_str(),
                        item.scope.as_str()
                    ],
                    |row| row.get(0),
                )
                .optional()?
                .unwrap_or(0);
            let observed: i64 = transaction.query_row(
                "SELECT coalesce(max(sequence),0) FROM accepted_events\n\
                 WHERE publisher=?1 AND topic=?2 AND scope=?3",
                params![
                    item.stamp.dot.publisher.as_slice(),
                    item.topic.as_str(),
                    item.scope.as_str()
                ],
                |row| row.get(0),
            )?;
            if Some(from_sql_u64(persisted.max(observed), "event counter")?)
                != reservation.event_previous
            {
                return Err(StoreError::CounterChanged);
            }
        }
        let outcome = insert_item_tx(&transaction, item.clone(), &config, false)?;
        transaction.execute(
            "INSERT INTO publisher_counters(publisher,counter) VALUES(?1,?2)\n\
             ON CONFLICT(publisher) DO UPDATE SET counter=excluded.counter",
            params![
                item.stamp.dot.publisher.as_slice(),
                sql_u64(reservation.counter, "publisher counter")?
            ],
        )?;
        if let Some(sequence) = reservation.event_sequence {
            transaction.execute(
                "INSERT INTO event_counters(publisher,topic,scope,counter) VALUES(?1,?2,?3,?4)\n\
                 ON CONFLICT(publisher,topic,scope) DO UPDATE SET counter=excluded.counter",
                params![
                    item.stamp.dot.publisher.as_slice(),
                    item.topic.as_str(),
                    item.scope.as_str(),
                    sql_u64(sequence, "event counter")?
                ],
            )?;
        }
        transaction.commit()?;
        Ok(outcome)
    }

    fn commit_local_batch(
        &mut self,
        reservation: &BatchPublishReservation,
        commit: LocalBatchCommit,
    ) -> Result<BatchCommitOutcome, StoreError> {
        let event_range_starts_at_next =
            match (reservation.event_previous, reservation.first_event_sequence) {
                (None, None) => true,
                (Some(previous), Some(first)) => previous.checked_add(1) == Some(first),
                _ => false,
            };
        if commit.items.len() != usize::from(reservation.item_count)
            || !(crate::batch::MIN_BATCH_ITEMS..=crate::batch::MAX_BATCH_ITEMS)
                .contains(&reservation.item_count)
            || reservation.previous_counter.checked_add(1) != Some(reservation.first_counter)
            || !event_range_starts_at_next
            || commit.proof_bytes.is_empty()
            || exact_object_id(&commit.proof_bytes) != commit.proof_envelope_id
        {
            return Err(StoreError::Invalid(
                "local batch proof or item count is invalid".into(),
            ));
        }
        let mut ids = BTreeSet::new();
        let mut canonical = Vec::with_capacity(commit.items.len());
        let mut expected_context = reservation.context.clone();
        for (index, item) in commit.items.iter().enumerate() {
            if item.compact.sealed.is_empty()
                || exact_object_id(&item.compact.sealed) != item.compact.envelope_id
                || !ids.insert(item.compact.id)
            {
                return Err(StoreError::Invalid(
                    "local compact batch representation is invalid".into(),
                ));
            }
            let expected_counter = reservation
                .first_counter
                .checked_add(index as u64)
                .ok_or_else(|| StoreError::Invalid("batch counter range exhausted".into()))?;
            let expected_event = reservation
                .first_event_sequence
                .map(|first| {
                    first
                        .checked_add(index as u64)
                        .ok_or_else(|| StoreError::Invalid("batch event range exhausted".into()))
                })
                .transpose()?;
            if item.compact.stamp.dot.counter != expected_counter
                || item.compact.event_sequence != expected_event
                || item.compact.stamp.context != expected_context
            {
                return Err(StoreError::Invalid(
                    "local compact item does not match reserved range or causal context".into(),
                ));
            }
            expected_context.observe(item.compact.stamp.dot);
            match commit.storage_policy {
                BatchStoragePolicy::RetainedDual => {
                    let singleton = item.singleton.as_ref().ok_or(StoreError::Invalid(
                        "retained-dual batch lacks singleton representation".into(),
                    ))?;
                    if singleton.sealed.is_empty()
                        || exact_object_id(&singleton.sealed) != singleton.envelope_id
                        || !same_batch_item_semantics(&item.compact, singleton)
                    {
                        return Err(StoreError::Invalid(
                            "batch singleton and compact semantics differ".into(),
                        ));
                    }
                    canonical.push(singleton.clone());
                }
                BatchStoragePolicy::BatchOnly => {
                    if item.singleton.is_some() {
                        return Err(StoreError::Invalid(
                            "batch-only commit contains singleton representation".into(),
                        ));
                    }
                    canonical.push(item.compact.clone());
                }
            }
        }
        let publisher = canonical
            .first()
            .ok_or(StoreError::Invalid("empty local batch".into()))?
            .stamp
            .dot
            .publisher;
        if canonical.iter().any(|item| {
            item.stamp.dot.publisher != publisher
                || item.class != canonical[0].class
                || item.topic != canonical[0].topic
                || item.scope != canonical[0].scope
                || item.key_epoch != canonical[0].key_epoch
        }) {
            return Err(StoreError::Invalid(
                "local batch crosses its shared publisher or route boundary".into(),
            ));
        }
        let last_counter = reservation
            .first_counter
            .checked_add(u64::from(reservation.item_count - 1))
            .ok_or_else(|| StoreError::Invalid("batch counter range exhausted".into()))?;
        let config = self.config.clone();
        let transaction = self.connection.transaction()?;
        let persisted_current: i64 = transaction
            .query_row(
                "SELECT counter FROM publisher_counters WHERE publisher=?1",
                params![publisher.as_slice()],
                |row| row.get(0),
            )
            .optional()?
            .unwrap_or(0);
        let observed_current: i64 = transaction.query_row(
            "SELECT coalesce(max(counter),0) FROM accepted_dots WHERE publisher=?1",
            params![publisher.as_slice()],
            |row| row.get(0),
        )?;
        if from_sql_u64(persisted_current.max(observed_current), "publisher counter")?
            != reservation.previous_counter
        {
            return Err(StoreError::CounterChanged);
        }
        let first_class = canonical[0].class;
        let first_topic = canonical[0].topic.clone();
        let first_scope = canonical[0].scope.clone();
        if first_class == DataClass::Event {
            let persisted: i64 = transaction
                .query_row(
                    "SELECT counter FROM event_counters\n\
                     WHERE publisher=?1 AND topic=?2 AND scope=?3",
                    params![
                        publisher.as_slice(),
                        first_topic.as_str(),
                        first_scope.as_str()
                    ],
                    |row| row.get(0),
                )
                .optional()?
                .unwrap_or(0);
            let observed: i64 = transaction.query_row(
                "SELECT coalesce(max(sequence),0) FROM accepted_events\n\
                 WHERE publisher=?1 AND topic=?2 AND scope=?3",
                params![
                    publisher.as_slice(),
                    first_topic.as_str(),
                    first_scope.as_str()
                ],
                |row| row.get(0),
            )?;
            if Some(from_sql_u64(persisted.max(observed), "event counter")?)
                != reservation.event_previous
            {
                return Err(StoreError::CounterChanged);
            }
        } else if reservation.first_event_sequence.is_some() || reservation.event_previous.is_some()
        {
            return Err(StoreError::Invalid(
                "non-event batch reserves event sequence".into(),
            ));
        }
        let proof_order = next_order(&transaction)?;
        let proof_accounted = (commit.proof_bytes.len() as u64)
            .checked_add(128)
            .ok_or(StoreError::QuotaExceeded)?;
        transaction.execute(
            "INSERT INTO batch_proofs(\n\
               proof_envelope_id,batch_id,scope,exact_bytes,inserted_order,accounted_bytes)\n\
             VALUES(?1,?2,?3,?4,?5,?6)",
            params![
                commit.proof_envelope_id.as_slice(),
                commit.batch_id.as_slice(),
                first_scope.as_str(),
                &commit.proof_bytes,
                sql_u64(proof_order, "batch proof order")?,
                sql_u64(proof_accounted, "batch proof bytes")?
            ],
        )?;
        let mut outcomes = Vec::with_capacity(canonical.len());
        for (source, mut chosen) in commit.items.iter().zip(canonical.iter().cloned()) {
            let outcome = insert_item_tx(&transaction, chosen.clone(), &config, true)?;
            chosen = load_item_tx(&transaction, &chosen.id)?.ok_or(StoreError::Corrupt(
                "committed batch item disappeared".into(),
            ))?;
            let compact_canonical = commit.storage_policy == BatchStoragePolicy::BatchOnly;
            if commit.storage_policy == BatchStoragePolicy::RetainedDual {
                let representation_order = next_order(&transaction)?;
                transaction.execute(
                    "INSERT INTO batch_item_representations(\n\
                       item_id,representation,envelope_id,proof_envelope_id,exact_bytes,\n\
                       canonical,inserted_order,accounted_bytes)\n\
                     VALUES(?1,0,?2,NULL,NULL,1,?3,96)",
                    params![
                        chosen.id.as_slice(),
                        chosen.envelope_id.as_slice(),
                        sql_u64(representation_order, "singleton representation order")?
                    ],
                )?;
            }
            let compact_order = next_order(&transaction)?;
            let compact_accounted = 96u64
                .checked_add(if compact_canonical {
                    0
                } else {
                    source.compact.sealed.len() as u64
                })
                .ok_or(StoreError::QuotaExceeded)?;
            transaction.execute(
                "INSERT INTO batch_item_representations(\n\
                   item_id,representation,envelope_id,proof_envelope_id,exact_bytes,\n\
                   canonical,inserted_order,accounted_bytes)\n\
                 VALUES(?1,1,?2,?3,?4,?5,?6,?7)",
                params![
                    chosen.id.as_slice(),
                    source.compact.envelope_id.as_slice(),
                    commit.proof_envelope_id.as_slice(),
                    (!compact_canonical).then_some(source.compact.sealed.as_slice()),
                    i64::from(compact_canonical),
                    sql_u64(compact_order, "compact representation order")?,
                    sql_u64(compact_accounted, "compact representation bytes")?
                ],
            )?;
            let outbox_order = next_order(&transaction)?;
            transaction.execute(
                "INSERT INTO batch_compact_outbox(item_id,enqueued_order) VALUES(?1,?2)",
                params![
                    chosen.id.as_slice(),
                    sql_u64(outbox_order, "compact outbox order")?
                ],
            )?;
            if compact_canonical {
                transaction.execute(
                    "DELETE FROM outbox WHERE item_id=?1",
                    params![chosen.id.as_slice()],
                )?;
            }
            outcomes.push(outcome);
        }
        let proof_outbox_order = next_order(&transaction)?;
        transaction.execute(
            "INSERT INTO batch_proof_outbox(proof_envelope_id,enqueued_order) VALUES(?1,?2)",
            params![
                commit.proof_envelope_id.as_slice(),
                sql_u64(proof_outbox_order, "batch proof outbox order")?
            ],
        )?;
        transaction.execute(
            "INSERT INTO publisher_counters(publisher,counter) VALUES(?1,?2)\n\
             ON CONFLICT(publisher) DO UPDATE SET counter=excluded.counter",
            params![
                publisher.as_slice(),
                sql_u64(last_counter, "batch publisher counter")?
            ],
        )?;
        if let Some(first_sequence) = reservation.first_event_sequence {
            let last_sequence = first_sequence
                .checked_add(u64::from(reservation.item_count - 1))
                .ok_or_else(|| StoreError::Invalid("batch event range exhausted".into()))?;
            transaction.execute(
                "INSERT INTO event_counters(publisher,topic,scope,counter) VALUES(?1,?2,?3,?4)\n\
                 ON CONFLICT(publisher,topic,scope) DO UPDATE SET counter=excluded.counter",
                params![
                    publisher.as_slice(),
                    first_topic.as_str(),
                    first_scope.as_str(),
                    sql_u64(last_sequence, "batch event counter")?
                ],
            )?;
        }
        let quota_sample = canonical.first().and_then(|item| {
            item.custody_clock_id
                .zip(item.custody_tick_ms)
                .map(|(clock_id, tick_ms)| CustodySample { clock_id, tick_ms })
        });
        let quota_now = canonical
            .iter()
            .filter_map(|item| item.observed_at_ms)
            .max();
        let evicted =
            enforce_quotas_protected_tx(&transaction, &config, &ids, quota_now, quota_sample)?;
        transaction.commit()?;
        self.verified_batch_proofs.insert(commit.proof_envelope_id);
        Ok(BatchCommitOutcome { outcomes, evicted })
    }

    fn ingest(&mut self, item: StoredItem) -> Result<ApplyOutcome, StoreError> {
        let compact_canonical: bool = self.connection.query_row(
            "SELECT EXISTS(\n\
               SELECT 1 FROM items i JOIN batch_item_representations r ON r.item_id=i.item_id\n\
               WHERE i.item_id=?1 AND i.envelope_id<>?2\n\
                 AND r.representation=1 AND r.canonical=1)",
            params![item.id.as_slice(), item.envelope_id.as_slice()],
            |row| row.get(0),
        )?;
        if compact_canonical {
            return Ok(self.register_singleton_representation(item)?.outcome);
        }
        let config = self.config.clone();
        let transaction = self.connection.transaction()?;
        let outcome = insert_item_tx(&transaction, item, &config, false)?;
        transaction.commit()?;
        Ok(outcome)
    }

    fn select_inventory_metadata(
        &mut self,
        topics: &BTreeSet<Topic>,
        scopes: &BTreeSet<Scope>,
    ) -> Result<Vec<InventoryMetadata>, StoreError> {
        select_inventory_metadata_bounded(
            &self.connection,
            topics,
            scopes,
            MAX_COMPOSITE_INVENTORY_OBJECTS,
        )
    }

    fn query(&mut self, query: &StoreQuery) -> Result<Vec<StoredItem>, StoreError> {
        use rusqlite::types::Value;
        let mut sql = format!("SELECT {ITEM_COLUMNS} FROM items WHERE 1=1");
        let mut values = Vec::<Value>::new();
        if let Some(topic) = &query.topic {
            sql.push_str(" AND topic=?");
            values.push(topic.as_str().to_owned().into());
        }
        if let Some(scope) = &query.scope {
            if query.include_descendant_scopes {
                sql.push_str(" AND (scope=? OR scope LIKE ?)");
                values.push(scope.as_str().to_owned().into());
                values.push(format!("{}/%", scope.as_str()).into());
            } else {
                sql.push_str(" AND scope=?");
                values.push(scope.as_str().to_owned().into());
            }
        }
        if let Some(class) = query.class {
            sql.push_str(" AND data_class=?");
            values.push(class_to_i64(class).into());
        }
        if let Some(key) = &query.logical_key {
            sql.push_str(" AND logical_key=?");
            values.push(key.clone().into());
        }
        if !query.include_recoverable_versions {
            sql.push_str(" AND version_status=0");
        }
        if !query.include_tombstones {
            sql.push_str(" AND tombstone=0");
        }
        sql.push_str(" ORDER BY priority DESC,inserted_order ASC");
        let mut statement = self.connection.prepare(&sql)?;
        let rows = statement.query_map(rusqlite::params_from_iter(values), decode_item_row)?;
        let mut items = Vec::new();
        for row in rows {
            let item = row?;
            if item.is_expired_at(query.custody_sample) {
                continue;
            }
            items.push(item);
            if query.limit.is_some_and(|limit| items.len() >= limit) {
                break;
            }
        }
        Ok(items)
    }

    fn get(&mut self, id: &ItemId) -> Result<Option<StoredItem>, StoreError> {
        let sql = format!("SELECT {ITEM_COLUMNS} FROM items WHERE item_id=?1");
        Ok(self
            .connection
            .query_row(&sql, params![id.as_slice()], decode_item_row)
            .optional()?)
    }

    fn stored_batch_material(
        &mut self,
        id: &ItemId,
    ) -> Result<Option<StoredBatchMaterial>, StoreError> {
        SqliteStore::stored_batch_material(self, id)
    }

    fn get_by_envelope(
        &mut self,
        envelope_id: &EnvelopeId,
    ) -> Result<Option<StoredItem>, StoreError> {
        let sql = format!("SELECT {ITEM_COLUMNS} FROM items WHERE envelope_id=?1");
        Ok(self
            .connection
            .query_row(&sql, params![envelope_id.as_slice()], decode_item_row)
            .optional()?)
    }

    fn read_item_envelope_range(
        &mut self,
        envelope_id: &EnvelopeId,
        range: ChunkRange,
        max_bytes: usize,
    ) -> Result<Vec<u8>, StoreError> {
        if range.is_empty() || max_bytes == 0 {
            return Ok(Vec::new());
        }
        let length = range.len().min(max_bytes as u64);
        let bytes: Option<Vec<u8>> = self
            .connection
            .query_row(
                "SELECT substr(sealed,?2,?3) FROM items WHERE envelope_id=?1",
                params![
                    envelope_id.as_slice(),
                    sql_u64(range.start.saturating_add(1), "envelope read offset")?,
                    sql_u64(length, "envelope read length")?
                ],
                |row| row.get(0),
            )
            .optional()?;
        bytes.ok_or(StoreError::NotFound("item envelope"))
    }

    fn reserve_control(
        &mut self,
        principal: ControlPrincipal,
    ) -> Result<ControlReservation, StoreError> {
        if self.is_zeroized()? {
            return Err(StoreError::Zeroized);
        }
        if self.is_revoked(&principal.signer)? {
            return Err(StoreError::ControlSignerRevoked(principal.signer));
        }
        if self.is_revoked(&principal.authority)? {
            return Err(StoreError::ControlAuthorityRevoked(principal.authority));
        }
        let head: Option<(i64, Vec<u8>)> = self
            .connection
            .query_row(
                "SELECT sequence,envelope_id FROM control_heads WHERE authority=?1",
                params![principal.authority.as_slice()],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .optional()?;
        let (previous_sequence, previous_control) = match head {
            Some((sequence, envelope)) => (
                from_sql_u64(sequence, "control head sequence")?,
                Some(item_from_vec(envelope, "control head")?),
            ),
            None => (0, None),
        };
        Ok(ControlReservation {
            authority: principal.authority,
            signer: principal.signer,
            previous_sequence,
            sequence: previous_sequence
                .checked_add(1)
                .ok_or_else(|| StoreError::Invalid("control sequence exhausted".into()))?,
            previous_control,
        })
    }

    fn commit_local_control(
        &mut self,
        reservation: &ControlReservation,
        control: &VerifiedStoredControl,
    ) -> Result<ControlOutcome, StoreError> {
        if control.authority != reservation.authority
            || control.signer != reservation.signer
            || control.sequence != reservation.sequence
            || control.previous_control != reservation.previous_control
        {
            return Err(StoreError::Invalid(
                "sealed control does not match reservation".into(),
            ));
        }
        let transaction = self.connection.transaction()?;
        let head: Option<(i64, Vec<u8>)> = transaction
            .query_row(
                "SELECT sequence,envelope_id FROM control_heads WHERE authority=?1",
                params![reservation.authority.as_slice()],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .optional()?;
        let (sequence, envelope) = match head {
            Some((sequence, envelope)) => (
                from_sql_u64(sequence, "control head sequence")?,
                Some(item_from_vec(envelope, "control head")?),
            ),
            None => (0, None),
        };
        if sequence != reservation.previous_sequence || envelope != reservation.previous_control {
            return Err(StoreError::CounterChanged);
        }
        if control_signer_revoked_tx(&transaction, reservation.signer)? {
            return Err(StoreError::ControlSignerRevoked(reservation.signer));
        }
        if control_signer_revoked_tx(&transaction, reservation.authority)? {
            return Err(StoreError::ControlAuthorityRevoked(reservation.authority));
        }
        let inserted = insert_control_tx(&transaction, control)?;
        let activation = activate_control_chain_tx(&transaction, control.authority)?;
        let refresh_bridge_liveness = !activation.activated.is_empty();
        let outcome = control_outcome(control.envelope_id, inserted, activation);
        transaction.commit()?;
        if refresh_bridge_liveness {
            self.clear_bridge_process_liveness();
        }
        Ok(outcome)
    }

    fn ingest_control(
        &mut self,
        control: &VerifiedStoredControl,
    ) -> Result<ControlOutcome, StoreError> {
        if self.is_zeroized()? {
            return Err(StoreError::Zeroized);
        }
        let transaction = self.connection.transaction()?;
        let inserted = insert_control_tx(&transaction, control)?;
        let activation = activate_control_chain_tx(&transaction, control.authority)?;
        let refresh_bridge_liveness = !activation.activated.is_empty();
        let outcome = control_outcome(control.envelope_id, inserted, activation);
        transaction.commit()?;
        if refresh_bridge_liveness {
            self.clear_bridge_process_liveness();
        }
        Ok(outcome)
    }

    fn applied_controls(&mut self) -> Result<Vec<StoredControl>, StoreError> {
        let sql = format!(
            "SELECT {CONTROL_COLUMNS} FROM controls WHERE applied=1 ORDER BY authority,sequence"
        );
        let mut statement = self.connection.prepare(&sql)?;
        let rows = statement.query_map([], decode_control_row)?;
        Ok(rows.collect::<Result<Vec<_>, _>>()?)
    }

    fn next_control_outbound(
        &mut self,
        peer: NodeId,
        limit: usize,
        byte_budget: u64,
        now_ms: Option<u64>,
    ) -> Result<Vec<StoredControl>, StoreError> {
        if limit == 0 || byte_budget == 0 || self.is_zeroized()? || self.is_revoked(&peer)? {
            return Ok(Vec::new());
        }
        let transaction = self.connection.transaction()?;
        let columns = CONTROL_COLUMNS
            .split(',')
            .map(|column| format!("c.{column}"))
            .collect::<Vec<_>>()
            .join(",");
        let sql = format!(
            "SELECT {columns} FROM control_outbox o JOIN controls c ON c.envelope_id=o.envelope_id\n\
             LEFT JOIN control_peer_receipts r ON r.peer=?1 AND r.envelope_id=c.envelope_id\n\
             WHERE r.envelope_id IS NULL ORDER BY o.attempts,o.enqueued_order"
        );
        let mut statement = transaction.prepare(&sql)?;
        let rows = statement.query_map(params![peer.as_slice()], decode_control_row)?;
        let mut selected = Vec::new();
        let mut used = 0u64;
        for row in rows {
            let control = row?;
            let size = control.sealed.len() as u64;
            if used.saturating_add(size) > byte_budget {
                continue;
            }
            used = used.saturating_add(size);
            selected.push(control);
            if selected.len() >= limit {
                break;
            }
        }
        drop(statement);
        for control in &selected {
            transaction.execute(
                "UPDATE control_outbox SET attempts=attempts+1,last_attempt_ms=?1 WHERE envelope_id=?2",
                params![
                    now_ms
                        .map(|value| sql_u64(value, "control emission time"))
                        .transpose()?,
                    control.envelope_id.as_slice()
                ],
            )?;
        }
        transaction.commit()?;
        Ok(selected)
    }

    fn acknowledge_control_peer(
        &mut self,
        peer: NodeId,
        envelope_ids: &[EnvelopeId],
        now_ms: Option<u64>,
    ) -> Result<(), StoreError> {
        let transaction = self.connection.transaction()?;
        for envelope_id in envelope_ids {
            transaction.execute(
                "INSERT INTO control_peer_receipts(peer,envelope_id,acknowledged_at_ms)\n\
                 VALUES(?1,?2,?3) ON CONFLICT(peer,envelope_id) DO UPDATE SET\n\
                 acknowledged_at_ms=excluded.acknowledged_at_ms",
                params![
                    peer.as_slice(),
                    envelope_id.as_slice(),
                    now_ms
                        .map(|value| sql_u64(value, "control acknowledgement time"))
                        .transpose()?
                ],
            )?;
        }
        transaction.commit()?;
        Ok(())
    }

    fn read_control_envelope_range(
        &mut self,
        envelope_id: &EnvelopeId,
        range: ChunkRange,
        max_bytes: usize,
    ) -> Result<Vec<u8>, StoreError> {
        if range.is_empty() || max_bytes == 0 {
            return Ok(Vec::new());
        }
        let length = range.len().min(max_bytes as u64);
        let bytes: Option<Vec<u8>> = self
            .connection
            .query_row(
                "SELECT substr(sealed,?2,?3) FROM controls WHERE envelope_id=?1",
                params![
                    envelope_id.as_slice(),
                    sql_u64(range.start.saturating_add(1), "control read offset")?,
                    sql_u64(length, "control read length")?
                ],
                |row| row.get(0),
            )
            .optional()?;
        bytes.ok_or(StoreError::NotFound("control envelope"))
    }

    fn conflicts(&mut self, query: &StoreQuery) -> Result<Vec<ConflictAnnotation>, StoreError> {
        let mut statement = self.connection.prepare(
            "SELECT topic,scope,logical_key,item_id FROM conflict_siblings\n\
             ORDER BY topic,scope,logical_key,item_id",
        )?;
        let rows = statement.query_map([], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, Vec<u8>>(2)?,
                row.get::<_, Vec<u8>>(3)?,
            ))
        })?;
        let mut groups: BTreeMap<(String, String, Vec<u8>), Vec<ItemId>> = BTreeMap::new();
        for row in rows {
            let (topic, scope, key, id) = row?;
            if query
                .topic
                .as_ref()
                .is_some_and(|wanted| wanted.as_str() != topic)
            {
                continue;
            }
            let parsed_scope = Scope::new(scope.clone())
                .map_err(|error| StoreError::Corrupt(error.to_string()))?;
            if let Some(wanted) = &query.scope {
                let matches = if query.include_descendant_scopes {
                    wanted.contains(&parsed_scope)
                } else {
                    wanted == &parsed_scope
                };
                if !matches {
                    continue;
                }
            }
            if query
                .logical_key
                .as_ref()
                .is_some_and(|wanted| wanted != &key)
            {
                continue;
            }
            groups
                .entry((topic, scope, key))
                .or_default()
                .push(item_from_vec(id, "conflict item")?);
        }
        Ok(groups
            .into_iter()
            .filter_map(|((_topic, _scope, logical_key), mut siblings)| {
                siblings.sort();
                (siblings.len() > 1).then_some(ConflictAnnotation {
                    logical_key,
                    siblings,
                    merge_policy: None,
                })
            })
            .collect())
    }

    fn create_subscription(
        &mut self,
        spec: &SubscriptionSpec,
    ) -> Result<SubscriptionId, StoreError> {
        self.connection.execute(
            "INSERT INTO subscriptions(topic,scope,descendants,data_class) VALUES(?1,?2,?3,?4)",
            params![
                spec.topic.as_str(),
                spec.scope.as_str(),
                if spec.include_descendant_scopes {
                    1i64
                } else {
                    0i64
                },
                spec.class.map(class_to_i64)
            ],
        )?;
        let id = self.connection.last_insert_rowid();
        Ok(SubscriptionId(from_sql_u64(id, "subscription id")?))
    }

    fn peek_subscription_page(
        &mut self,
        id: SubscriptionId,
        after: Option<SubscriptionCursor>,
        custody_sample: Option<CustodySample>,
    ) -> Result<SubscriptionCandidatePage, StoreError> {
        let subscription: Option<(String, String, i64, Option<i64>)> = self
            .connection
            .query_row(
                "SELECT topic,scope,descendants,data_class FROM subscriptions\n\
                 WHERE subscription_id=?1",
                params![sql_u64(id.0, "subscription id")?],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
            )
            .optional()?;
        let Some((topic, scope, descendants, class)) = subscription else {
            return Err(StoreError::NotFound("subscription"));
        };
        let columns = ITEM_COLUMNS
            .split(',')
            .map(|column| format!("i.{column}"))
            .collect::<Vec<_>>()
            .join(",");
        let sql = format!(
            "SELECT {columns} FROM items i WHERE i.topic=?1\n\
             AND (i.scope=?2 OR (?3 != 0 AND i.scope LIKE ?4))\n\
             AND (?5 IS NULL OR i.data_class=?5)\n\
             AND NOT EXISTS(SELECT 1 FROM semantic_app_deliveries d\n\
               WHERE d.subscription_id=?6 AND d.item_id=i.item_id\n\
                 AND d.acked_at_ms IS NOT NULL)\n\
             AND (?7 IS NULL OR i.priority<?7 OR\n\
               (i.priority=?7 AND i.inserted_order>?8))\n\
             ORDER BY i.priority DESC,i.inserted_order ASC LIMIT ?9"
        );
        let cursor_priority = after.map(|cursor| cursor.priority as u8 as i64);
        let cursor_order = after
            .map(|cursor| sql_u64(cursor.inserted_order, "subscription cursor"))
            .transpose()?;
        let rows = {
            let mut statement = self.connection.prepare(&sql)?;
            statement
                .query_map(
                    params![
                        topic,
                        scope,
                        descendants,
                        format!("{scope}/%"),
                        class,
                        sql_u64(id.0, "subscription id")?,
                        cursor_priority,
                        cursor_order,
                        i64::try_from(MAX_BRIDGE_STORE_BATCH)
                            .map_err(|_| StoreError::QuotaExceeded)?
                    ],
                    decode_item_row,
                )?
                .collect::<Result<Vec<_>, _>>()?
        };
        let row_count = rows.len();
        let next_cursor = rows.last().map(|item| SubscriptionCursor {
            priority: item.priority,
            inserted_order: item.inserted_order,
        });
        let entries = rows
            .into_iter()
            .filter(|item| !item.is_expired_at(custody_sample))
            .collect();
        Ok(SubscriptionCandidatePage {
            entries,
            next_cursor: (row_count == MAX_BRIDGE_STORE_BATCH)
                .then_some(next_cursor)
                .flatten(),
        })
    }

    fn record_subscription_deliveries(
        &mut self,
        id: SubscriptionId,
        items: &[StoredItem],
        now_ms: Option<u64>,
        custody_sample: Option<CustodySample>,
    ) -> Result<Vec<AppDelivery>, StoreError> {
        if items.len() > MAX_BRIDGE_PROJECTION_RESULTS {
            return Err(StoreError::Invalid(
                "subscription delivery batch exceeds bound".into(),
            ));
        }
        let transaction = self.connection.transaction()?;
        let subscription: Option<(String, String, i64, Option<i64>)> = transaction
            .query_row(
                "SELECT topic,scope,descendants,data_class FROM subscriptions\n\
                 WHERE subscription_id=?1",
                params![sql_u64(id.0, "subscription id")?],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
            )
            .optional()?;
        let Some((topic, scope, descendants, class)) = subscription else {
            return Err(StoreError::NotFound("subscription"));
        };
        let scope = Scope::new(scope).map_err(|error| StoreError::Corrupt(error.to_string()))?;
        let class = class.map(class_from_i64).transpose()?;
        let delivery_time = now_ms
            .map(|value| sql_u64(value, "delivery time"))
            .transpose()?;
        let mut candidates = BTreeMap::new();
        for candidate in items {
            let current = load_item_tx(&transaction, &candidate.id)?
                .ok_or(StoreError::NotFound("subscription item"))?;
            let scope_matches = if descendants != 0 {
                scope.contains(&current.scope)
            } else {
                scope == current.scope
            };
            if current != *candidate
                || current.topic.as_str() != topic
                || !scope_matches
                || class.is_some_and(|wanted| wanted != current.class)
                || current.is_expired_at(custody_sample)
            {
                return Err(StoreError::NotFound("current subscription item"));
            }
            candidates.entry(current.id).or_insert(current);
        }
        let mut deliveries = Vec::with_capacity(candidates.len());
        for (item_id, item) in candidates {
            transaction.execute(
                "INSERT INTO semantic_app_deliveries(\n\
                   subscription_id,item_id,target_scope,representation,wrapper_envelope_id)\n\
                 VALUES(?1,?2,?3,0,NULL)\n\
                 ON CONFLICT(subscription_id,item_id) DO UPDATE SET\n\
                   target_scope=excluded.target_scope,representation=0,wrapper_envelope_id=NULL\n\
                 WHERE semantic_app_deliveries.acked_at_ms IS NULL",
                params![
                    sql_u64(id.0, "subscription id")?,
                    item_id.as_slice(),
                    item.scope.as_str()
                ],
            )?;
            let changed = transaction.execute(
                "UPDATE semantic_app_deliveries SET attempts=attempts+1,last_delivery_ms=?1\n\
                 WHERE subscription_id=?2 AND item_id=?3 AND acked_at_ms IS NULL",
                params![
                    delivery_time,
                    sql_u64(id.0, "subscription id")?,
                    item_id.as_slice()
                ],
            )?;
            if changed == 0 {
                continue;
            }
            let attempts: i64 = transaction.query_row(
                "SELECT attempts FROM semantic_app_deliveries\n\
                 WHERE subscription_id=?1 AND item_id=?2",
                params![sql_u64(id.0, "subscription id")?, item_id.as_slice()],
                |row| row.get(0),
            )?;
            deliveries.push(AppDelivery {
                subscription: id,
                item,
                delivery_attempt: from_sql_u64(attempts, "delivery attempts")?,
            });
        }
        transaction.commit()?;
        Ok(deliveries)
    }

    fn poll_subscription(
        &mut self,
        id: SubscriptionId,
        limit: usize,
        now_ms: Option<u64>,
        custody_sample: Option<CustodySample>,
    ) -> Result<Vec<AppDelivery>, StoreError> {
        if limit == 0 {
            return Ok(Vec::new());
        }
        let mut candidates = Vec::new();
        let mut cursor = None;
        while candidates.len() < limit {
            let page = self.peek_subscription_page(id, cursor, custody_sample)?;
            candidates.extend(page.entries.into_iter().take(limit - candidates.len()));
            let Some(next) = page.next_cursor else { break };
            if Some(next) == cursor {
                return Err(StoreError::Corrupt(
                    "subscription scan cursor did not advance".into(),
                ));
            }
            cursor = Some(next);
        }
        self.record_subscription_deliveries(id, &candidates, now_ms, custody_sample)
    }

    fn acknowledge_delivery(
        &mut self,
        id: SubscriptionId,
        item: &ItemId,
        now_ms: Option<u64>,
    ) -> Result<(), StoreError> {
        let changed = self.connection.execute(
            "UPDATE semantic_app_deliveries SET acked_at_ms=?1\n\
             WHERE subscription_id=?2 AND item_id=?3",
            params![
                sql_u64(now_ms.unwrap_or(0), "ack time")?,
                sql_u64(id.0, "subscription id")?,
                item.as_slice()
            ],
        )?;
        if changed == 0 {
            return Err(StoreError::NotFound("application delivery"));
        }
        Ok(())
    }

    fn next_outbound(
        &mut self,
        peer: NodeId,
        minimum: Priority,
        limit: usize,
        byte_budget: u64,
        now_ms: Option<u64>,
        custody_sample: Option<CustodySample>,
    ) -> Result<Vec<StoredItem>, StoreError> {
        if limit == 0 || byte_budget == 0 || self.is_zeroized()? || self.is_revoked(&peer)? {
            return Ok(Vec::new());
        }
        let transaction = self.connection.transaction()?;
        let columns = ITEM_COLUMNS
            .split(',')
            .map(|column| format!("i.{column}"))
            .collect::<Vec<_>>()
            .join(",");
        let sql = format!(
            "SELECT {columns} FROM outbox o JOIN items i ON i.item_id=o.item_id\n\
             LEFT JOIN peer_receipts pr ON pr.peer=?1 AND pr.item_id=i.item_id\n\
             LEFT JOIN revocations rv ON rv.subject=i.publisher\n\
             LEFT JOIN scope_epochs se ON se.scope=i.scope\n\
             WHERE pr.item_id IS NULL AND rv.subject IS NULL AND i.priority>=?2\n\
               AND (se.epoch IS NULL OR i.key_epoch>=se.epoch)\n\
             ORDER BY i.priority DESC,o.attempts ASC,o.enqueued_order ASC"
        );
        let mut statement = transaction.prepare(&sql)?;
        let rows = statement.query_map(
            params![peer.as_slice(), minimum as u8 as i64],
            decode_item_row,
        )?;
        let mut candidate_ids = Vec::new();
        for row in rows {
            let item = row?;
            candidate_ids.push(item.id);
        }
        drop(statement);
        let mut selected = Vec::new();
        let mut used = 0u64;
        for id in candidate_ids {
            let Some(item) = advance_custody_tx(&transaction, id, custody_sample)? else {
                continue;
            };
            if !item.is_forwardable_at(custody_sample) {
                continue;
            }
            let size = item.sealed.len() as u64;
            if used.saturating_add(size) > byte_budget {
                continue;
            }
            used += size;
            selected.push(item);
            if selected.len() >= limit {
                break;
            }
        }
        for item in &selected {
            transaction.execute(
                "UPDATE outbox SET attempts=attempts+1,last_attempt_ms=?1 WHERE item_id=?2",
                params![
                    now_ms
                        .map(|value| sql_u64(value, "emission time"))
                        .transpose()?,
                    item.id.as_slice()
                ],
            )?;
        }
        transaction.commit()?;
        Ok(selected)
    }

    fn acknowledge_peer(
        &mut self,
        peer: NodeId,
        ids: &[ItemId],
        now_ms: Option<u64>,
    ) -> Result<(), StoreError> {
        let transaction = self.connection.transaction()?;
        for id in ids {
            transaction.execute(
                "INSERT INTO peer_receipts(peer,item_id,acknowledged_at_ms) VALUES(?1,?2,?3)\n\
                 ON CONFLICT(peer,item_id) DO UPDATE SET acknowledged_at_ms=excluded.acknowledged_at_ms",
                params![
                    peer.as_slice(),
                    id.as_slice(),
                    now_ms
                        .map(|value| sql_u64(value, "peer ack time"))
                        .transpose()?
                ],
            )?;
        }
        transaction.commit()?;
        Ok(())
    }

    fn set_scope_quota(&mut self, quota: ScopeQuota) -> Result<(), StoreError> {
        if quota.max_items == 0 || quota.max_bytes == 0 {
            return Err(StoreError::Invalid("scope quota must be nonzero".into()));
        }
        let transaction = self.connection.transaction()?;
        transaction.execute(
            "INSERT INTO quotas(scope,max_items,max_bytes) VALUES(?1,?2,?3)\n\
             ON CONFLICT(scope) DO UPDATE SET max_items=excluded.max_items,max_bytes=excluded.max_bytes",
            params![
                quota.scope.as_str(),
                sql_u64(quota.max_items, "scope max items")?,
                sql_u64(quota.max_bytes, "scope max bytes")?
            ],
        )?;
        enforce_quotas_tx(&transaction, &self.config, None, None, None)?;
        transaction.commit()?;
        Ok(())
    }

    fn quota_usage(&mut self, scope: Option<&Scope>) -> Result<QuotaUsage, StoreError> {
        let transaction = self.connection.unchecked_transaction()?;
        let usage = usage_tx(&transaction, scope)?;
        transaction.commit()?;
        Ok(usage)
    }

    fn collect_garbage(
        &mut self,
        now_ms: Option<u64>,
        custody_sample: Option<CustodySample>,
    ) -> Result<Vec<ItemId>, StoreError> {
        let _ = self.collect_bridge_garbage(custody_sample, MAX_BRIDGE_STORE_BATCH)?;
        let config = self.config.clone();
        let transaction = self.connection.transaction()?;
        if let Some(now) = now_ms {
            transaction.execute(
                "UPDATE tombstones SET retain_until_ms=?1 WHERE retain_until_ms IS NULL",
                params![sql_u64(
                    now.saturating_add(config.tombstone_retention_ms),
                    "tombstone retention"
                )?],
            )?;
        }
        let sql = format!(
            "SELECT {columns},t.retain_until_ms FROM items i\n\
             LEFT JOIN tombstones t ON t.item_id=i.item_id",
            columns = LIFECYCLE_ITEM_COLUMNS
                .split(',')
                .map(|column| format!("i.{column}"))
                .collect::<Vec<_>>()
                .join(",")
        );
        let mut statement = transaction.prepare(&sql)?;
        let rows = statement.query_map([], |row| {
            let item = decode_lifecycle_item_row(row)?;
            let retain: Option<i64> = row.get(13)?;
            Ok((item, retain))
        })?;
        let raw_entries = rows.collect::<Result<Vec<_>, _>>()?;
        drop(statement);
        let mut entries = Vec::new();
        let mut concurrent_groups = BTreeSet::new();
        for (mut item, retain) in raw_entries {
            advance_lifecycle_custody_tx(&transaction, &mut item, custody_sample)?;
            let group_key = item.group_key();
            if item.status == VersionStatus::Concurrent {
                concurrent_groups.insert(group_key);
            }
            entries.push((
                item,
                retain
                    .map(|value| from_sql_u64(value, "tombstone retention"))
                    .transpose()?,
            ));
        }
        let mut expired = Vec::new();
        let mut tombstone_groups = BTreeSet::new();
        for (item, retain) in entries {
            let group_key = item.group_key();
            let superseded_old = now_ms.is_some_and(|now| {
                item.status != VersionStatus::Current
                    && item.observed_at_ms.is_some_and(|observed| {
                        now >= observed.saturating_add(config.superseded_retention_ms)
                    })
            });
            if (!item.tombstone && item.is_expired_at(custody_sample)) || superseded_old {
                expired.push(item.id);
            }
            if item.tombstone
                && item.status == VersionStatus::Current
                && now_ms.zip(retain).is_some_and(|(now, value)| now >= value)
                && !concurrent_groups.contains(&group_key)
            {
                tombstone_groups.insert(group_key);
            }
        }
        for (class, topic, scope, key) in tombstone_groups {
            let mut ids = transaction.prepare(
                "SELECT item_id FROM items\n\
                 WHERE data_class=?1 AND topic=?2 AND scope=?3 AND logical_key=?4",
            )?;
            let group = ids
                .query_map(params![class, topic, scope, key], |row| {
                    row.get::<_, Vec<u8>>(0)
                })?
                .collect::<Result<Vec<_>, _>>()?;
            drop(ids);
            for id in group {
                expired.push(item_from_vec(id, "garbage item")?);
            }
        }
        expired.sort();
        expired.dedup();
        for id in &expired {
            delete_item_tx(&transaction, *id)?;
        }
        transaction.commit()?;
        Ok(expired)
    }

    fn begin_transfer(
        &mut self,
        object_id: ObjectId,
        total_len: u64,
        priority: Priority,
        now_ms: Option<u64>,
    ) -> Result<(), StoreError> {
        self.begin_typed_transfer(object_id, total_len, priority, now_ms, None)
    }

    fn begin_transfer_for_semantic_version(
        &mut self,
        object_id: ObjectId,
        total_len: u64,
        priority: Priority,
        now_ms: Option<u64>,
        semantic_version: u16,
    ) -> Result<(), StoreError> {
        self.begin_typed_transfer(
            object_id,
            total_len,
            priority,
            now_ms,
            Some(semantic_version),
        )
    }

    fn transfer_progress(&mut self, limit: usize) -> Result<Vec<TransferProgress>, StoreError> {
        if limit == 0 {
            return Ok(Vec::new());
        }
        let rows = {
            let mut statement = self.connection.prepare(
                "SELECT i.storage_key,i.object_id,i.origin_semantic_version,w.total_len\n\
                 FROM transfer_identities i JOIN wants w ON w.object_id=i.storage_key\n\
                 ORDER BY i.object_id LIMIT ?1",
            )?;
            statement
                .query_map([i64::try_from(limit).unwrap_or(i64::MAX)], |row| {
                    Ok((
                        row.get::<_, Vec<u8>>(0)?,
                        row.get::<_, Vec<u8>>(1)?,
                        row.get::<_, Option<i64>>(2)?,
                        row.get::<_, i64>(3)?,
                    ))
                })?
                .collect::<Result<Vec<_>, _>>()?
        };
        let mut progress = Vec::with_capacity(rows.len());
        for (storage_key, encoded_id, semantic_version, total_len) in rows {
            let encoded: [u8; ObjectId::WIRE_LEN] = encoded_id
                .try_into()
                .map_err(|_| StoreError::Corrupt("typed transfer identity length".into()))?;
            let object_id = ObjectId::from_wire_bytes(encoded)
                .ok_or_else(|| StoreError::Corrupt("typed transfer identity kind".into()))?;
            if transfer_storage_key(object_id).as_slice() != storage_key.as_slice() {
                return Err(StoreError::Corrupt(
                    "typed transfer identity storage key mismatch".into(),
                ));
            }
            let received = {
                let mut statement = self.connection.prepare(
                    "SELECT start_offset,end_offset FROM sealed_chunks\n\
                     WHERE object_id=?1 ORDER BY start_offset",
                )?;
                statement
                    .query_map(params![storage_key], |row| {
                        Ok((row.get::<_, i64>(0)?, row.get::<_, i64>(1)?))
                    })?
                    .map(|row| {
                        let (start, end) = row?;
                        ChunkRange::new(
                            from_sql_u64(start, "transfer range start")?,
                            from_sql_u64(end, "transfer range end")?,
                        )
                    })
                    .collect::<Result<Vec<_>, StoreError>>()?
            };
            progress.push(TransferProgress {
                object_id,
                origin_semantic_version: semantic_version
                    .map(|value| {
                        u16::try_from(value).map_err(|_| {
                            StoreError::Corrupt("transfer semantic version is invalid".into())
                        })
                    })
                    .transpose()?,
                total_len: from_sql_u64(total_len, "transfer total length")?,
                received,
            });
        }
        Ok(progress)
    }

    fn transfer_progress_for_semantic_version(
        &mut self,
        semantic_version: u16,
        limit: usize,
    ) -> Result<Vec<TransferProgress>, StoreError> {
        self.load_transfer_progress(Some(semantic_version), limit)
    }

    fn finish_transfer(&mut self, object_id: ObjectId) -> Result<(), StoreError> {
        let storage_key = transfer_storage_key(object_id);
        let transaction = self.connection.transaction()?;
        let stored: Option<Vec<u8>> = transaction
            .query_row(
                "SELECT object_id FROM transfer_identities WHERE storage_key=?1",
                params![storage_key.as_slice()],
                |row| row.get(0),
            )
            .optional()?;
        if let Some(stored) = stored
            && stored.as_slice() != object_id.to_wire_bytes()
        {
            return Err(StoreError::Corrupt(
                "typed transfer identity storage key mismatch".into(),
            ));
        }
        transaction.execute(
            "DELETE FROM wants WHERE object_id=?1",
            params![storage_key.as_slice()],
        )?;
        transaction.commit()?;
        Ok(())
    }

    fn begin_want(
        &mut self,
        object: ItemId,
        total_len: u64,
        priority: Priority,
        now_ms: Option<u64>,
    ) -> Result<(), StoreError> {
        if total_len == 0 {
            return Err(StoreError::Invalid(
                "wanted object must be non-empty".into(),
            ));
        }
        let per_object_limit = staged_object_byte_limit(&self.config);
        if total_len > per_object_limit {
            return Err(StoreError::Invalid(format!(
                "wanted object exceeds staging limit of {per_object_limit} bytes"
            )));
        }
        let object_limit = staging_object_limit(&self.config);
        let total = sql_u64(total_len, "wanted object length")?;
        let transaction = self.connection.transaction()?;
        let existing: Option<i64> = transaction
            .query_row(
                "SELECT total_len FROM wants WHERE object_id=?1",
                params![object.as_slice()],
                |row| row.get(0),
            )
            .optional()?;
        match existing {
            Some(existing) if from_sql_u64(existing, "wanted object length")? != total_len => {
                return Err(StoreError::Invalid(
                    "object identifier reused with a different length".into(),
                ));
            }
            Some(_) => {
                transaction.execute(
                    "UPDATE wants SET priority=max(priority,?1),updated_at_ms=?2 WHERE object_id=?3",
                    params![
                        priority as u8 as i64,
                        now_ms
                            .map(|value| sql_u64(value, "want update time"))
                            .transpose()?,
                        object.as_slice()
                    ],
                )?;
            }
            None => {
                let object_count: i64 = transaction.query_row(
                    "SELECT (SELECT count(*) FROM wants) +\n\
                            (SELECT count(*) FROM pending_batch_items) +\n\
                            (SELECT count(*) FROM rejected_batch_proofs)",
                    [],
                    |row| row.get(0),
                )?;
                if from_sql_u64(object_count, "staging object count")? >= object_limit {
                    return Err(StoreError::QuotaExceeded);
                }
                transaction.execute(
                    "INSERT INTO wants(object_id,total_len,priority,updated_at_ms) VALUES(?1,?2,?3,?4)",
                    params![
                        object.as_slice(),
                        total,
                        priority as u8 as i64,
                        now_ms
                            .map(|value| sql_u64(value, "want update time"))
                            .transpose()?
                    ],
                )?;
                transaction.execute(
                    "INSERT INTO want_ranges(object_id,start_offset,end_offset) VALUES(?1,0,?2)",
                    params![object.as_slice(), total],
                )?;
            }
        }
        transaction.commit()?;
        Ok(())
    }

    fn missing_ranges(
        &mut self,
        object: &ItemId,
        limit: usize,
    ) -> Result<Vec<ChunkRange>, StoreError> {
        if limit == 0 {
            return Ok(Vec::new());
        }
        let exists: bool = self.connection.query_row(
            "SELECT EXISTS(SELECT 1 FROM wants WHERE object_id=?1)",
            params![object.as_slice()],
            |row| row.get(0),
        )?;
        if !exists {
            return Err(StoreError::NotFound("wanted object"));
        }
        let mut statement = self.connection.prepare(
            "SELECT start_offset,end_offset FROM want_ranges\n\
             WHERE object_id=?1 ORDER BY start_offset LIMIT ?2",
        )?;
        let rows = statement.query_map(
            params![object.as_slice(), i64::try_from(limit).unwrap_or(i64::MAX)],
            |row| Ok((row.get::<_, i64>(0)?, row.get::<_, i64>(1)?)),
        )?;
        let mut ranges = Vec::new();
        for row in rows {
            let (start, end) = row?;
            ranges.push(ChunkRange::new(
                from_sql_u64(start, "range start")?,
                from_sql_u64(end, "range end")?,
            )?);
        }
        Ok(ranges)
    }

    fn put_sealed_chunk(
        &mut self,
        object: ItemId,
        total_len: u64,
        offset: u64,
        bytes: &[u8],
        now_ms: Option<u64>,
    ) -> Result<bool, StoreError> {
        if bytes.is_empty() {
            return Err(StoreError::Invalid("sealed chunk must be non-empty".into()));
        }
        let end = offset
            .checked_add(bytes.len() as u64)
            .ok_or_else(|| StoreError::Invalid("chunk range overflow".into()))?;
        if end > total_len {
            return Err(StoreError::Invalid("chunk exceeds object length".into()));
        }
        let config = self.config.clone();
        let transaction = self.connection.transaction()?;
        let stored_total: Option<i64> = transaction
            .query_row(
                "SELECT total_len FROM wants WHERE object_id=?1",
                params![object.as_slice()],
                |row| row.get(0),
            )
            .optional()?;
        let Some(stored_total) = stored_total else {
            return Err(StoreError::NotFound("wanted object"));
        };
        if from_sql_u64(stored_total, "wanted object length")? != total_len {
            return Err(StoreError::Invalid("chunk total length changed".into()));
        }
        let start_sql = sql_u64(offset, "chunk offset")?;
        let end_sql = sql_u64(end, "chunk end")?;
        let mut overlap_statement = transaction.prepare(
            "SELECT start_offset,end_offset,bytes FROM sealed_chunks\n\
             WHERE object_id=?1 AND start_offset<?3 AND end_offset>?2",
        )?;
        let overlaps = overlap_statement
            .query_map(params![object.as_slice(), start_sql, end_sql], |row| {
                Ok((
                    row.get::<_, i64>(0)?,
                    row.get::<_, i64>(1)?,
                    row.get::<_, Vec<u8>>(2)?,
                ))
            })?
            .collect::<Result<Vec<_>, _>>()?;
        drop(overlap_statement);
        if !overlaps.is_empty() {
            if overlaps.len() == 1
                && overlaps[0].0 == start_sql
                && overlaps[0].1 == end_sql
                && overlaps[0].2 == bytes
            {
                let remaining: i64 = transaction.query_row(
                    "SELECT count(*) FROM want_ranges WHERE object_id=?1",
                    params![object.as_slice()],
                    |row| row.get(0),
                )?;
                return Ok(remaining == 0);
            }
            return Err(StoreError::Invalid(
                "overlapping chunk is not an exact duplicate".into(),
            ));
        }
        let object_extent_count: i64 = transaction.query_row(
            "SELECT count(*) FROM sealed_chunks WHERE object_id=?1",
            params![object.as_slice()],
            |row| row.get(0),
        )?;
        if from_sql_u64(object_extent_count, "object staging extent count")?
            >= MAX_STAGED_RANGES_PER_OBJECT
        {
            return Err(StoreError::QuotaExceeded);
        }
        let global_extent_count: i64 =
            transaction.query_row("SELECT count(*) FROM sealed_chunks", [], |row| row.get(0))?;
        if from_sql_u64(global_extent_count, "global staging extent count")?
            >= MAX_STAGED_RANGES_GLOBAL
        {
            return Err(StoreError::QuotaExceeded);
        }
        let staged_bytes: i64 = transaction.query_row(
            "SELECT (SELECT coalesce(sum(length(bytes)),0) FROM sealed_chunks) +\n\
                    (SELECT coalesce(sum(accounted_bytes),0) FROM pending_batch_items) +\n\
                    (SELECT coalesce(sum(accounted_bytes),0) FROM rejected_batch_proofs)",
            [],
            |row| row.get(0),
        )?;
        let staged_bytes = from_sql_u64(staged_bytes, "staging byte usage")?;
        let incoming_bytes = u64::try_from(bytes.len())
            .map_err(|_| StoreError::Invalid("sealed chunk length overflow".into()))?;
        if incoming_bytes > staging_byte_limit(&config).saturating_sub(staged_bytes) {
            return Err(StoreError::QuotaExceeded);
        }
        transaction.execute(
            "INSERT INTO sealed_chunks(object_id,start_offset,end_offset,bytes) VALUES(?1,?2,?3,?4)",
            params![object.as_slice(), start_sql, end_sql, bytes],
        )?;
        let mut missing_statement = transaction.prepare(
            "SELECT start_offset,end_offset FROM want_ranges\n\
             WHERE object_id=?1 AND start_offset<?3 AND end_offset>?2",
        )?;
        let affected = missing_statement
            .query_map(params![object.as_slice(), start_sql, end_sql], |row| {
                Ok((row.get::<_, i64>(0)?, row.get::<_, i64>(1)?))
            })?
            .collect::<Result<Vec<_>, _>>()?;
        drop(missing_statement);
        for (missing_start, missing_end) in affected {
            transaction.execute(
                "DELETE FROM want_ranges WHERE object_id=?1 AND start_offset=?2",
                params![object.as_slice(), missing_start],
            )?;
            if missing_start < start_sql {
                transaction.execute(
                    "INSERT INTO want_ranges(object_id,start_offset,end_offset) VALUES(?1,?2,?3)",
                    params![object.as_slice(), missing_start, start_sql],
                )?;
            }
            if end_sql < missing_end {
                transaction.execute(
                    "INSERT INTO want_ranges(object_id,start_offset,end_offset) VALUES(?1,?2,?3)",
                    params![object.as_slice(), end_sql, missing_end],
                )?;
            }
        }
        transaction.execute(
            "UPDATE wants SET updated_at_ms=?1 WHERE object_id=?2",
            params![
                now_ms
                    .map(|value| sql_u64(value, "chunk update time"))
                    .transpose()?,
                object.as_slice()
            ],
        )?;
        let remaining_before_quota: i64 = transaction.query_row(
            "SELECT count(*) FROM want_ranges WHERE object_id=?1",
            params![object.as_slice()],
            |row| row.get(0),
        )?;
        if remaining_before_quota == 0 {
            verify_completed_object_tx(&transaction, object, total_len)?;
        }
        let remaining: i64 = transaction.query_row(
            "SELECT count(*) FROM want_ranges WHERE object_id=?1",
            params![object.as_slice()],
            |row| row.get(0),
        )?;
        transaction.commit()?;
        Ok(remaining == 0)
    }

    fn read_sealed_range(
        &mut self,
        object: &ItemId,
        range: ChunkRange,
        max_bytes: usize,
    ) -> Result<Vec<u8>, StoreError> {
        if max_bytes == 0 {
            return Ok(Vec::new());
        }
        let requested_end = range.end.min(range.start.saturating_add(max_bytes as u64));
        let mut statement = self.connection.prepare(
            "SELECT start_offset,end_offset,bytes FROM sealed_chunks\n\
             WHERE object_id=?1 AND start_offset<?3 AND end_offset>?2\n\
             ORDER BY start_offset",
        )?;
        let rows = statement.query_map(
            params![
                object.as_slice(),
                sql_u64(range.start, "read start")?,
                sql_u64(requested_end, "read end")?
            ],
            |row| {
                Ok((
                    row.get::<_, i64>(0)?,
                    row.get::<_, i64>(1)?,
                    row.get::<_, Vec<u8>>(2)?,
                ))
            },
        )?;
        let mut cursor = range.start;
        let mut output = Vec::new();
        for row in rows {
            let (start, end, bytes) = row?;
            let start = from_sql_u64(start, "stored chunk start")?;
            let end = from_sql_u64(end, "stored chunk end")?;
            if start > cursor {
                break;
            }
            if end <= cursor {
                continue;
            }
            let copy_start = (cursor - start) as usize;
            let copy_end = (requested_end.min(end) - start) as usize;
            output.extend_from_slice(&bytes[copy_start..copy_end]);
            cursor = start + copy_end as u64;
            if cursor >= requested_end {
                break;
            }
        }
        Ok(output)
    }

    fn apply_revocation(&mut self, revocation: &Revocation) -> Result<bool, StoreError> {
        let transaction = self.connection.transaction()?;
        let existing: Option<(i64, Vec<u8>, Vec<u8>)> = transaction
            .query_row(
                "SELECT generation,authority,sealed_notice FROM revocations WHERE subject=?1",
                params![revocation.subject.as_slice()],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .optional()?;
        if let Some((generation, authority, notice)) = existing {
            let generation = from_sql_u64(generation, "revocation generation")?;
            if generation > revocation.generation {
                purge_revoked_principal_pending_suffixes_tx(&transaction, revocation.subject)?;
                remove_revoked_principal_bridge_routes_tx(&transaction, revocation.subject)?;
                transaction.commit()?;
                self.clear_bridge_process_liveness();
                self.clear_verified_batch_proofs();
                return Ok(false);
            }
            if generation == revocation.generation {
                if node_from_vec(authority, "revocation authority")? != revocation.authority
                    || notice != revocation.sealed_notice
                {
                    return Err(StoreError::Invalid(
                        "conflicting revocations use the same generation".into(),
                    ));
                }
                purge_revoked_principal_pending_suffixes_tx(&transaction, revocation.subject)?;
                remove_revoked_principal_bridge_routes_tx(&transaction, revocation.subject)?;
                transaction.commit()?;
                self.clear_bridge_process_liveness();
                self.clear_verified_batch_proofs();
                return Ok(false);
            }
        }
        transaction.execute(
            "INSERT INTO revocations(subject,authority,generation,sealed_notice,observed_at_ms)\n\
             VALUES(?1,?2,?3,?4,?5)\n\
             ON CONFLICT(subject) DO UPDATE SET authority=excluded.authority,\n\
               generation=excluded.generation,sealed_notice=excluded.sealed_notice,\n\
               observed_at_ms=excluded.observed_at_ms",
            params![
                revocation.subject.as_slice(),
                revocation.authority.as_slice(),
                sql_u64(revocation.generation, "revocation generation")?,
                revocation.sealed_notice,
                revocation
                    .observed_at_ms
                    .map(|value| sql_u64(value, "revocation time"))
                    .transpose()?
            ],
        )?;
        transaction.execute(
            "INSERT INTO peers(node_id,peer_status,sync_status,last_change_ms,detail)\n\
             VALUES(?1,4,4,?2,'revoked by authenticated mesh control')\n\
             ON CONFLICT(node_id) DO UPDATE SET peer_status=4,sync_status=4,\n\
               last_change_ms=excluded.last_change_ms,detail=excluded.detail",
            params![
                revocation.subject.as_slice(),
                revocation
                    .observed_at_ms
                    .map(|value| sql_u64(value, "revocation time"))
                    .transpose()?
            ],
        )?;
        purge_revoked_principal_pending_suffixes_tx(&transaction, revocation.subject)?;
        remove_revoked_principal_bridge_routes_tx(&transaction, revocation.subject)?;
        transaction.commit()?;
        self.clear_bridge_process_liveness();
        self.clear_verified_batch_proofs();
        Ok(true)
    }

    fn is_revoked(&mut self, node: &NodeId) -> Result<bool, StoreError> {
        Ok(self.connection.query_row(
            "SELECT EXISTS(SELECT 1 FROM revocations WHERE subject=?1)",
            params![node.as_slice()],
            |row| row.get(0),
        )?)
    }

    fn set_scope_epoch(&mut self, epoch: &ScopeEpoch) -> Result<bool, StoreError> {
        let transaction = self.connection.transaction()?;
        let existing: Option<(i64, Vec<u8>)> = transaction
            .query_row(
                "SELECT epoch,sealed_notice FROM scope_epochs WHERE scope=?1",
                params![epoch.scope.as_str()],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .optional()?;
        if let Some((current, notice)) = existing {
            let current = from_sql_u64(current, "scope epoch")?;
            if current > epoch.epoch {
                return Ok(false);
            }
            if current == epoch.epoch {
                if notice != epoch.sealed_notice {
                    return Err(StoreError::Invalid(
                        "conflicting key notices use the same scope epoch".into(),
                    ));
                }
                return Ok(false);
            }
        }
        transaction.execute(
            "INSERT INTO scope_epochs(scope,epoch,sealed_notice) VALUES(?1,?2,?3)\n\
             ON CONFLICT(scope) DO UPDATE SET epoch=excluded.epoch,sealed_notice=excluded.sealed_notice",
            params![
                epoch.scope.as_str(),
                sql_u64(epoch.epoch, "scope epoch")?,
                epoch.sealed_notice
            ],
        )?;
        let epoch_value = sql_u64(epoch.epoch, "scope epoch")?;
        transaction.execute(
            "DELETE FROM bridge_route_outbox WHERE wrapper_envelope_id IN (\n\
               SELECT wrapper_envelope_id FROM bridge_route_wrappers\n\
               WHERE (origin_scope=?1 AND origin_route_epoch<>?2)\n\
                  OR (current_scope=?1 AND current_route_epoch<>?2)\n\
               UNION\n\
               SELECT d.wrapper_envelope_id FROM bridge_wrapper_authorizations d\n\
               JOIN bridge_authorization_controls c\n\
                 ON c.envelope_id=d.authorization_envelope_id\n\
               WHERE (c.source_scope=?1 AND c.source_route_epoch<>?2)\n\
                  OR (c.target_scope=?1 AND c.target_route_epoch<>?2)\n\
             )",
            params![epoch.scope.as_str(), epoch_value],
        )?;
        transaction.execute(
            "DELETE FROM bridge_active_routes WHERE wrapper_envelope_id IN (\n\
               SELECT wrapper_envelope_id FROM bridge_route_wrappers\n\
               WHERE (origin_scope=?1 AND origin_route_epoch<>?2)\n\
                  OR (current_scope=?1 AND current_route_epoch<>?2)\n\
               UNION\n\
               SELECT d.wrapper_envelope_id FROM bridge_wrapper_authorizations d\n\
               JOIN bridge_authorization_controls c\n\
                 ON c.envelope_id=d.authorization_envelope_id\n\
               WHERE (c.source_scope=?1 AND c.source_route_epoch<>?2)\n\
                  OR (c.target_scope=?1 AND c.target_route_epoch<>?2)\n\
             )",
            params![epoch.scope.as_str(), epoch_value],
        )?;
        transaction.commit()?;
        self.clear_bridge_process_liveness();
        self.clear_verified_batch_proofs();
        Ok(true)
    }

    fn scope_epoch(&mut self, scope: &Scope) -> Result<u64, StoreError> {
        let value: Option<i64> = self
            .connection
            .query_row(
                "SELECT epoch FROM scope_epochs WHERE scope=?1",
                params![scope.as_str()],
                |row| row.get(0),
            )
            .optional()?;
        value
            .map(|value| from_sql_u64(value, "scope epoch"))
            .transpose()
            .map(|value| value.unwrap_or(0))
    }

    fn update_peer(&mut self, snapshot: &PeerSnapshot) -> Result<(), StoreError> {
        self.connection.execute(
            "INSERT INTO peers(node_id,peer_status,sync_status,last_change_ms,detail)\n\
             VALUES(?1,?2,?3,?4,?5)\n\
             ON CONFLICT(node_id) DO UPDATE SET peer_status=excluded.peer_status,\n\
               sync_status=excluded.sync_status,last_change_ms=excluded.last_change_ms,\n\
               detail=excluded.detail\n\
             WHERE peers.peer_status IS NOT excluded.peer_status\n\
                OR peers.sync_status IS NOT excluded.sync_status\n\
                OR peers.detail IS NOT excluded.detail",
            params![
                snapshot.node.as_slice(),
                peer_status_to_i64(snapshot.peer),
                sync_status_to_i64(snapshot.sync),
                snapshot
                    .last_change_ms
                    .map(|value| sql_u64(value, "peer change time"))
                    .transpose()?,
                snapshot.detail
            ],
        )?;
        Ok(())
    }

    fn peer(&mut self, node: &NodeId) -> Result<Option<PeerSnapshot>, StoreError> {
        let row: Option<(i64, i64, Option<i64>, Option<String>)> = self
            .connection
            .query_row(
                "SELECT peer_status,sync_status,last_change_ms,detail FROM peers WHERE node_id=?1",
                params![node.as_slice()],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
            )
            .optional()?;
        row.map(|(peer, sync, changed, detail)| {
            Ok(PeerSnapshot {
                node: *node,
                peer: peer_status_from_i64(peer)?,
                sync: sync_status_from_i64(sync)?,
                last_change_ms: changed
                    .map(|value| from_sql_u64(value, "peer change time"))
                    .transpose()?,
                detail,
            })
        })
        .transpose()
    }

    fn peers(&mut self) -> Result<Vec<PeerSnapshot>, StoreError> {
        let mut statement = self.connection.prepare(
            "SELECT node_id,peer_status,sync_status,last_change_ms,detail FROM peers ORDER BY node_id",
        )?;
        let rows = statement.query_map([], |row| {
            Ok((
                row.get::<_, Vec<u8>>(0)?,
                row.get::<_, i64>(1)?,
                row.get::<_, i64>(2)?,
                row.get::<_, Option<i64>>(3)?,
                row.get::<_, Option<String>>(4)?,
            ))
        })?;
        let mut peers = Vec::new();
        for row in rows {
            let (node, peer, sync, changed, detail) = row?;
            peers.push(PeerSnapshot {
                node: node_from_vec(node, "peer node")?,
                peer: peer_status_from_i64(peer)?,
                sync: sync_status_from_i64(sync)?,
                last_change_ms: changed
                    .map(|value| from_sql_u64(value, "peer change time"))
                    .transpose()?,
                detail,
            });
        }
        Ok(peers)
    }

    fn replace_bridge_filters(&mut self, filters: &[BridgeFilter]) -> Result<(), StoreError> {
        if filters.iter().any(|filter| filter.topics.is_empty()) {
            return Err(StoreError::Invalid(
                "bridge filters require at least one explicit topic".into(),
            ));
        }
        let transaction = self.connection.transaction()?;
        transaction.execute("DELETE FROM bridge_filters", [])?;
        for filter in filters {
            for topic in &filter.topics {
                transaction.execute(
                    "INSERT INTO bridge_filters(from_scope,to_scope,topic,minimum_priority)\n\
                     VALUES(?1,?2,?3,?4)",
                    params![
                        filter.from_scope.as_str(),
                        filter.to_scope.as_str(),
                        topic.as_str(),
                        filter.minimum_priority as u8 as i64
                    ],
                )?;
            }
        }
        transaction.commit()?;
        Ok(())
    }

    fn bridge_allows(
        &mut self,
        from: &Scope,
        to: &Scope,
        topic: &Topic,
        priority: Priority,
    ) -> Result<bool, StoreError> {
        let mut statement = self
            .connection
            .prepare("SELECT from_scope,to_scope,topic,minimum_priority FROM bridge_filters")?;
        let rows = statement.query_map([], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, i64>(3)?,
            ))
        })?;
        for row in rows {
            let (filter_from, filter_to, filter_topic, minimum) = row?;
            let filter_from =
                Scope::new(filter_from).map_err(|error| StoreError::Corrupt(error.to_string()))?;
            let filter_to =
                Scope::new(filter_to).map_err(|error| StoreError::Corrupt(error.to_string()))?;
            if filter_from == *from
                && filter_to == *to
                && filter_topic == topic.as_str()
                && priority >= priority_from_i64(minimum)?
            {
                return Ok(true);
            }
        }
        Ok(false)
    }

    fn event_gaps(&mut self, query: &StoreQuery) -> Result<Vec<EventGap>, StoreError> {
        let mut event_query = query.clone();
        event_query.class = Some(DataClass::Event);
        event_query.include_recoverable_versions = true;
        event_query.include_tombstones = true;
        event_query.limit = None;
        let items = self.query(&event_query)?;
        let mut streams: BTreeMap<(NodeId, Topic, Scope), BTreeSet<u64>> = BTreeMap::new();
        for item in items {
            if let Some(sequence) = item.event_sequence {
                streams
                    .entry((item.publisher(), item.topic, item.scope))
                    .or_default()
                    .insert(sequence);
            }
        }
        let mut gaps = Vec::new();
        for ((publisher, topic, scope), sequences) in streams {
            let mut expected = 1u64;
            for sequence in sequences {
                if sequence > expected {
                    gaps.push(EventGap {
                        publisher,
                        topic: topic.clone(),
                        scope: scope.clone(),
                        start_sequence: expected,
                        end_sequence: sequence,
                    });
                }
                expected = expected.max(sequence.saturating_add(1));
            }
        }
        Ok(gaps)
    }

    fn mark_zeroized(&mut self) -> Result<(), StoreError> {
        self.connection.execute(
            "INSERT INTO store_meta(key,value) VALUES('zeroized',1)\n\
             ON CONFLICT(key) DO UPDATE SET value=1",
            [],
        )?;
        // Key bytes are owned and erased by the crypto provider. These notices
        // are not secret, but removing them prevents accidental reuse of a local
        // epoch cache after zeroization.
        self.connection.execute("DELETE FROM scope_epochs", [])?;
        self.clear_bridge_process_liveness();
        self.clear_verified_batch_proofs();
        Ok(())
    }

    fn is_zeroized(&mut self) -> Result<bool, StoreError> {
        let value: Option<i64> = self
            .connection
            .query_row(
                "SELECT CAST(value AS INTEGER) FROM store_meta WHERE key='zeroized'",
                [],
                |row| row.get(0),
            )
            .optional()?;
        Ok(value.unwrap_or(0) != 0)
    }
}

fn peer_status_to_i64(status: PeerStatus) -> i64 {
    match status {
        PeerStatus::Offline => 0,
        PeerStatus::Authenticating => 1,
        PeerStatus::Ready => 2,
        PeerStatus::Rejected => 3,
        PeerStatus::Revoked => 4,
    }
}

fn peer_status_from_i64(value: i64) -> Result<PeerStatus, StoreError> {
    match value {
        0 => Ok(PeerStatus::Offline),
        1 => Ok(PeerStatus::Authenticating),
        2 => Ok(PeerStatus::Ready),
        3 => Ok(PeerStatus::Rejected),
        4 => Ok(PeerStatus::Revoked),
        _ => Err(StoreError::Corrupt("unknown peer status".into())),
    }
}

fn sync_status_to_i64(status: SyncStatus) -> i64 {
    match status {
        SyncStatus::Idle => 0,
        SyncStatus::Reconciling => 1,
        SyncStatus::Transferring => 2,
        SyncStatus::Converged => 3,
        SyncStatus::Suspended => 4,
    }
}

fn sync_status_from_i64(value: i64) -> Result<SyncStatus, StoreError> {
    match value {
        0 => Ok(SyncStatus::Idle),
        1 => Ok(SyncStatus::Reconciling),
        2 => Ok(SyncStatus::Transferring),
        3 => Ok(SyncStatus::Converged),
        4 => Ok(SyncStatus::Suspended),
        _ => Err(StoreError::Corrupt("unknown sync status".into())),
    }
}

/// Ephemeral test store with the exact same transaction and reducer semantics as
/// the durable implementation. It uses a private in-memory SQLite connection so
/// tests exercise the production schema without touching the filesystem.
pub struct InMemoryStore {
    inner: SqliteStore,
    #[cfg(test)]
    inventory_selection_calls: usize,
}

impl InMemoryStore {
    pub fn new(config: StoreConfig) -> Result<Self, StoreError> {
        Ok(Self {
            inner: SqliteStore::open_in_memory(config)?,
            #[cfg(test)]
            inventory_selection_calls: 0,
        })
    }

    #[cfg(test)]
    pub(crate) fn inventory_selection_call_count(&self) -> usize {
        self.inventory_selection_calls
    }
}

impl Default for InMemoryStore {
    fn default() -> Self {
        Self::new(StoreConfig::default()).expect("default in-memory store opens")
    }
}

impl RecordStore for InMemoryStore {
    fn config(&self) -> &StoreConfig {
        self.inner.config()
    }
    fn reserve_publish(
        &mut self,
        publisher: NodeId,
        class: DataClass,
        topic: &Topic,
        scope: &Scope,
    ) -> Result<PublishReservation, StoreError> {
        self.inner.reserve_publish(publisher, class, topic, scope)
    }
    fn reserve_batch_publish(
        &mut self,
        publisher: NodeId,
        class: DataClass,
        topic: &Topic,
        scope: &Scope,
        item_count: u16,
    ) -> Result<BatchPublishReservation, StoreError> {
        self.inner
            .reserve_batch_publish(publisher, class, topic, scope, item_count)
    }
    fn commit_publish(
        &mut self,
        reservation: &PublishReservation,
        item: StoredItem,
    ) -> Result<ApplyOutcome, StoreError> {
        self.inner.commit_publish(reservation, item)
    }
    fn commit_local_batch(
        &mut self,
        reservation: &BatchPublishReservation,
        commit: LocalBatchCommit,
    ) -> Result<BatchCommitOutcome, StoreError> {
        self.inner.commit_local_batch(reservation, commit)
    }
    fn ingest(&mut self, item: StoredItem) -> Result<ApplyOutcome, StoreError> {
        self.inner.ingest(item)
    }
    fn select_inventory_metadata(
        &mut self,
        topics: &BTreeSet<Topic>,
        scopes: &BTreeSet<Scope>,
    ) -> Result<Vec<InventoryMetadata>, StoreError> {
        #[cfg(test)]
        {
            self.inventory_selection_calls = self.inventory_selection_calls.saturating_add(1);
        }
        self.inner.select_inventory_metadata(topics, scopes)
    }
    fn query(&mut self, query: &StoreQuery) -> Result<Vec<StoredItem>, StoreError> {
        self.inner.query(query)
    }
    fn get(&mut self, id: &ItemId) -> Result<Option<StoredItem>, StoreError> {
        self.inner.get(id)
    }
    fn stored_batch_material(
        &mut self,
        id: &ItemId,
    ) -> Result<Option<StoredBatchMaterial>, StoreError> {
        RecordStore::stored_batch_material(&mut self.inner, id)
    }
    fn conflicts(&mut self, query: &StoreQuery) -> Result<Vec<ConflictAnnotation>, StoreError> {
        self.inner.conflicts(query)
    }
    fn create_subscription(
        &mut self,
        spec: &SubscriptionSpec,
    ) -> Result<SubscriptionId, StoreError> {
        self.inner.create_subscription(spec)
    }
    fn peek_subscription_page(
        &mut self,
        id: SubscriptionId,
        after: Option<SubscriptionCursor>,
        custody_sample: Option<CustodySample>,
    ) -> Result<SubscriptionCandidatePage, StoreError> {
        self.inner.peek_subscription_page(id, after, custody_sample)
    }
    fn record_subscription_deliveries(
        &mut self,
        id: SubscriptionId,
        items: &[StoredItem],
        now_ms: Option<u64>,
        custody_sample: Option<CustodySample>,
    ) -> Result<Vec<AppDelivery>, StoreError> {
        self.inner
            .record_subscription_deliveries(id, items, now_ms, custody_sample)
    }
    fn poll_subscription(
        &mut self,
        id: SubscriptionId,
        limit: usize,
        now_ms: Option<u64>,
        custody_sample: Option<CustodySample>,
    ) -> Result<Vec<AppDelivery>, StoreError> {
        self.inner
            .poll_subscription(id, limit, now_ms, custody_sample)
    }
    fn acknowledge_delivery(
        &mut self,
        id: SubscriptionId,
        item: &ItemId,
        now_ms: Option<u64>,
    ) -> Result<(), StoreError> {
        self.inner.acknowledge_delivery(id, item, now_ms)
    }
    fn next_outbound(
        &mut self,
        peer: NodeId,
        minimum: Priority,
        limit: usize,
        byte_budget: u64,
        now_ms: Option<u64>,
        custody_sample: Option<CustodySample>,
    ) -> Result<Vec<StoredItem>, StoreError> {
        self.inner
            .next_outbound(peer, minimum, limit, byte_budget, now_ms, custody_sample)
    }
    fn acknowledge_peer(
        &mut self,
        peer: NodeId,
        ids: &[ItemId],
        now_ms: Option<u64>,
    ) -> Result<(), StoreError> {
        self.inner.acknowledge_peer(peer, ids, now_ms)
    }
    fn set_scope_quota(&mut self, quota: ScopeQuota) -> Result<(), StoreError> {
        self.inner.set_scope_quota(quota)
    }
    fn quota_usage(&mut self, scope: Option<&Scope>) -> Result<QuotaUsage, StoreError> {
        self.inner.quota_usage(scope)
    }
    fn collect_garbage(
        &mut self,
        now_ms: Option<u64>,
        custody_sample: Option<CustodySample>,
    ) -> Result<Vec<ItemId>, StoreError> {
        self.inner.collect_garbage(now_ms, custody_sample)
    }
    fn get_by_envelope(
        &mut self,
        envelope_id: &EnvelopeId,
    ) -> Result<Option<StoredItem>, StoreError> {
        self.inner.get_by_envelope(envelope_id)
    }
    fn read_item_envelope_range(
        &mut self,
        envelope_id: &EnvelopeId,
        range: ChunkRange,
        max_bytes: usize,
    ) -> Result<Vec<u8>, StoreError> {
        self.inner
            .read_item_envelope_range(envelope_id, range, max_bytes)
    }
    fn reserve_control(
        &mut self,
        principal: ControlPrincipal,
    ) -> Result<ControlReservation, StoreError> {
        self.inner.reserve_control(principal)
    }
    fn commit_local_control(
        &mut self,
        reservation: &ControlReservation,
        control: &VerifiedStoredControl,
    ) -> Result<ControlOutcome, StoreError> {
        self.inner.commit_local_control(reservation, control)
    }
    fn ingest_control(
        &mut self,
        control: &VerifiedStoredControl,
    ) -> Result<ControlOutcome, StoreError> {
        self.inner.ingest_control(control)
    }
    fn applied_controls(&mut self) -> Result<Vec<StoredControl>, StoreError> {
        self.inner.applied_controls()
    }
    fn next_control_outbound(
        &mut self,
        peer: NodeId,
        limit: usize,
        byte_budget: u64,
        now_ms: Option<u64>,
    ) -> Result<Vec<StoredControl>, StoreError> {
        self.inner
            .next_control_outbound(peer, limit, byte_budget, now_ms)
    }
    fn acknowledge_control_peer(
        &mut self,
        peer: NodeId,
        envelope_ids: &[EnvelopeId],
        now_ms: Option<u64>,
    ) -> Result<(), StoreError> {
        self.inner
            .acknowledge_control_peer(peer, envelope_ids, now_ms)
    }
    fn read_control_envelope_range(
        &mut self,
        envelope_id: &EnvelopeId,
        range: ChunkRange,
        max_bytes: usize,
    ) -> Result<Vec<u8>, StoreError> {
        self.inner
            .read_control_envelope_range(envelope_id, range, max_bytes)
    }
    fn begin_transfer(
        &mut self,
        object_id: ObjectId,
        total_len: u64,
        priority: Priority,
        now_ms: Option<u64>,
    ) -> Result<(), StoreError> {
        self.inner
            .begin_transfer(object_id, total_len, priority, now_ms)
    }
    fn begin_transfer_for_semantic_version(
        &mut self,
        object_id: ObjectId,
        total_len: u64,
        priority: Priority,
        now_ms: Option<u64>,
        semantic_version: u16,
    ) -> Result<(), StoreError> {
        self.inner.begin_transfer_for_semantic_version(
            object_id,
            total_len,
            priority,
            now_ms,
            semantic_version,
        )
    }
    fn transfer_progress(&mut self, limit: usize) -> Result<Vec<TransferProgress>, StoreError> {
        self.inner.transfer_progress(limit)
    }
    fn transfer_progress_for_semantic_version(
        &mut self,
        semantic_version: u16,
        limit: usize,
    ) -> Result<Vec<TransferProgress>, StoreError> {
        self.inner
            .transfer_progress_for_semantic_version(semantic_version, limit)
    }
    fn finish_transfer(&mut self, object_id: ObjectId) -> Result<(), StoreError> {
        self.inner.finish_transfer(object_id)
    }
    fn begin_want(
        &mut self,
        object: ItemId,
        total_len: u64,
        priority: Priority,
        now_ms: Option<u64>,
    ) -> Result<(), StoreError> {
        self.inner.begin_want(object, total_len, priority, now_ms)
    }
    fn missing_ranges(
        &mut self,
        object: &ItemId,
        limit: usize,
    ) -> Result<Vec<ChunkRange>, StoreError> {
        self.inner.missing_ranges(object, limit)
    }
    fn put_sealed_chunk(
        &mut self,
        object: ItemId,
        total_len: u64,
        offset: u64,
        bytes: &[u8],
        now_ms: Option<u64>,
    ) -> Result<bool, StoreError> {
        self.inner
            .put_sealed_chunk(object, total_len, offset, bytes, now_ms)
    }
    fn read_sealed_range(
        &mut self,
        object: &ItemId,
        range: ChunkRange,
        max_bytes: usize,
    ) -> Result<Vec<u8>, StoreError> {
        self.inner.read_sealed_range(object, range, max_bytes)
    }
    fn apply_revocation(&mut self, revocation: &Revocation) -> Result<bool, StoreError> {
        self.inner.apply_revocation(revocation)
    }
    fn is_revoked(&mut self, node: &NodeId) -> Result<bool, StoreError> {
        self.inner.is_revoked(node)
    }
    fn set_scope_epoch(&mut self, epoch: &ScopeEpoch) -> Result<bool, StoreError> {
        self.inner.set_scope_epoch(epoch)
    }
    fn scope_epoch(&mut self, scope: &Scope) -> Result<u64, StoreError> {
        self.inner.scope_epoch(scope)
    }
    fn update_peer(&mut self, snapshot: &PeerSnapshot) -> Result<(), StoreError> {
        self.inner.update_peer(snapshot)
    }
    fn peer(&mut self, node: &NodeId) -> Result<Option<PeerSnapshot>, StoreError> {
        self.inner.peer(node)
    }
    fn peers(&mut self) -> Result<Vec<PeerSnapshot>, StoreError> {
        self.inner.peers()
    }
    fn replace_bridge_filters(&mut self, filters: &[BridgeFilter]) -> Result<(), StoreError> {
        self.inner.replace_bridge_filters(filters)
    }
    fn bridge_allows(
        &mut self,
        from: &Scope,
        to: &Scope,
        topic: &Topic,
        priority: Priority,
    ) -> Result<bool, StoreError> {
        self.inner.bridge_allows(from, to, topic, priority)
    }
    fn event_gaps(&mut self, query: &StoreQuery) -> Result<Vec<EventGap>, StoreError> {
        self.inner.event_gaps(query)
    }
    fn mark_zeroized(&mut self) -> Result<(), StoreError> {
        self.inner.mark_zeroized()
    }
    fn is_zeroized(&mut self) -> Result<bool, StoreError> {
        self.inner.is_zeroized()
    }
}

#[cfg(test)]
mod sqlite_integration_tests {
    use super::*;
    use crate::model::{CausalStamp, DataClass, Dot, Priority, Scope, Topic, VersionVector};
    use sha2::{Digest, Sha256};
    use std::fs;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn test_item(
        id_byte: u8,
        counter: u64,
        ttl_ms: Option<u64>,
        custody_age_ms: u64,
        sample: Option<CustodySample>,
    ) -> StoredItem {
        let sealed = vec![id_byte, counter as u8, 0xa5];
        StoredItem {
            id: [id_byte; 32],
            envelope_id: Sha256::digest(&sealed).into(),
            class: DataClass::State,
            topic: Topic::new("test.state").unwrap(),
            scope: Scope::new("mission/test").unwrap(),
            priority: Priority::Routine,
            stamp: CausalStamp {
                dot: Dot {
                    publisher: [7; 32],
                    counter,
                },
                context: VersionVector::default(),
            },
            event_sequence: None,
            logical_key: vec![id_byte],
            ttl_ms,
            observed_at_ms: None,
            sealed,
            content_len: 1,
            tombstone: false,
            key_epoch: 0,
            custody_age_ms,
            custody_clock_id: sample.map(|value| value.clock_id),
            custody_tick_ms: sample.map(|value| value.tick_ms),
            custody_elapsed_available: sample.is_some(),
            status: VersionStatus::Current,
            inserted_order: 0,
        }
    }

    fn indexed_publisher(index: usize) -> NodeId {
        let mut publisher = [0_u8; 32];
        publisher[..8].copy_from_slice(&(index as u64 + 1).to_be_bytes());
        publisher
    }

    fn local_batch_fixture(
        store: &mut SqliteStore,
        storage_policy: BatchStoragePolicy,
        priorities: [Priority; 2],
    ) -> (BatchPublishReservation, LocalBatchCommit) {
        let publisher = [7; 32];
        let topic = Topic::new("test.state").unwrap();
        let scope = Scope::new("mission/test").unwrap();
        let reservation = store
            .reserve_batch_publish(publisher, DataClass::State, &topic, &scope, 2)
            .unwrap();
        let mut context = reservation.context.clone();
        let items = (0..2)
            .map(|index| {
                let counter = reservation.first_counter + index as u64;
                let mut compact = test_item(0x60 + index as u8, counter, None, 0, None);
                compact.priority = priorities[index];
                compact.stamp.context = context.clone();
                compact.sealed = format!("compact-{counter}").into_bytes();
                compact.envelope_id = exact_object_id(&compact.sealed);
                context.observe(compact.stamp.dot);
                let singleton = if storage_policy == BatchStoragePolicy::RetainedDual {
                    let mut singleton = compact.clone();
                    singleton.sealed = format!("singleton-{counter}").into_bytes();
                    singleton.envelope_id = exact_object_id(&singleton.sealed);
                    Some(singleton)
                } else {
                    None
                };
                LocalBatchItemCommit { compact, singleton }
            })
            .collect();
        let proof_bytes = b"local-provider-authenticated-batch-proof".to_vec();
        let commit = LocalBatchCommit {
            proof_envelope_id: exact_object_id(&proof_bytes),
            batch_id: [0x51; 32],
            proof_bytes,
            items,
            storage_policy,
        };
        (reservation, commit)
    }

    #[allow(clippy::too_many_arguments)]
    fn insert_pending_batch_fixture(
        store: &mut SqliteStore,
        proof_envelope_id: EnvelopeId,
        envelope_id: EnvelopeId,
        item_id: ItemId,
        exact_bytes: &[u8],
        ttl_ms: Option<u64>,
        custody_age_ms: u64,
        sample: Option<CustodySample>,
    ) {
        let transaction = store.connection.transaction().unwrap();
        let order = next_order(&transaction).unwrap();
        transaction
            .execute(
                "INSERT INTO pending_batch_items(\n\
                   envelope_id,item_id,proof_envelope_id,scope,priority,publisher,key_epoch,\n\
                   ttl_ms,cumulative_custody_age_ms,forwarding_custody_age_ms,\n\
                   age_continuity_unknown,custody_clock_id,custody_tick_ms,\n\
                   custody_elapsed_available,exact_bytes,inserted_order,accounted_bytes)\n\
                 VALUES(?1,?2,?3,'mission/test',0,?4,0,?5,?6,?6,?7,?8,?9,?10,?11,?12,?13)",
                params![
                    envelope_id.as_slice(),
                    item_id.as_slice(),
                    proof_envelope_id.as_slice(),
                    [7u8; 32].as_slice(),
                    ttl_ms
                        .map(|value| sql_u64(value, "test pending ttl"))
                        .transpose()
                        .unwrap(),
                    sql_u64(custody_age_ms, "test pending age").unwrap(),
                    i64::from(sample.is_none()),
                    sample.map(|value| value.clock_id.to_vec()),
                    sample.map(|value| sql_u64(value.tick_ms, "test pending tick").unwrap()),
                    i64::from(sample.is_some()),
                    exact_bytes,
                    sql_u64(order, "test pending order").unwrap(),
                    sql_u64(exact_bytes.len() as u64 + 160, "test pending bytes").unwrap()
                ],
            )
            .unwrap();
        transaction.commit().unwrap();
    }

    fn revocation_control(
        authority: NodeId,
        sequence: u64,
        previous_control: Option<EnvelopeId>,
        generation: u64,
    ) -> VerifiedStoredControl {
        signed_revocation_control(
            authority,
            authority,
            [44; 32],
            sequence,
            previous_control,
            generation,
        )
    }

    fn signed_revocation_control(
        authority: NodeId,
        signer: NodeId,
        subject: NodeId,
        sequence: u64,
        previous_control: Option<EnvelopeId>,
        generation: u64,
    ) -> VerifiedStoredControl {
        let sealed = [
            signer.as_slice(),
            subject.as_slice(),
            sequence.to_be_bytes().as_slice(),
            generation.to_be_bytes().as_slice(),
        ]
        .concat();
        let envelope_id = Sha256::digest(&sealed).into();
        VerifiedStoredControl {
            envelope_id,
            authority,
            signer,
            sequence,
            previous_control,
            kind: ControlKind::Revocation,
            revocation: Some(Revocation {
                subject,
                authority,
                signer,
                generation,
                control_sequence: sequence,
                previous_control,
                sealed_notice: sealed.clone(),
                observed_at_ms: None,
            }),
            scope_epoch: None,
            sealed,
        }
    }

    fn bridge_signature(seed: u8) -> Vec<u8> {
        let mut signature = vec![seed; crate::bridge::HYBRID_SIGNATURE_BYTES];
        signature[..2].copy_from_slice(&64u16.to_be_bytes());
        signature[66..70].copy_from_slice(&3_309u32.to_be_bytes());
        signature
    }

    fn verified_bridge_authorization() -> VerifiedBridgeAuthorization {
        let mission_id = [0x41; 32];
        let bridge_node_id = [0x43; 32];
        let source_scope = Scope::new("mission/source").unwrap();
        let target_scope = Scope::new("mission/target").unwrap();
        let authorization = BridgeAuthorization {
            mission_id,
            authority_id: [0x42; 32],
            control_sequence: 1,
            previous_control_id: None,
            authorization_key: crate::bridge::bridge_authorization_key(
                &mission_id,
                &bridge_node_id,
                &source_scope,
                &target_scope,
            )
            .unwrap(),
            generation: 1,
            bridge_node_id,
            source_scope,
            target_scope,
            enabled: Some(crate::bridge::EnabledAuthorization {
                source_route_epoch: 3,
                target_route_epoch: 5,
                source_route_commitment: [0x44; 32],
                target_route_commitment: [0x45; 32],
                allowed_priority_mask: 0b1110,
                max_total_hops: 4,
                topics: vec![
                    Topic::new("orders").unwrap(),
                    Topic::new("position").unwrap(),
                ],
                bridge_credential: vec![0x46; 128],
                authority_credential_signature: bridge_signature(0x47),
            }),
            authority_control_signature: bridge_signature(0x48),
        };
        let exact_bytes = b"provider-authenticated-ASTRBA01-object".to_vec();
        let envelope_id = exact_object_id(&exact_bytes);
        VerifiedBridgeAuthorization::from_provider(
            envelope_id,
            authorization,
            [0x49; 32],
            exact_bytes,
        )
        .unwrap()
    }

    fn bridge_authorization_successor(
        previous: &VerifiedBridgeAuthorization,
        generation: u64,
        enabled: bool,
    ) -> VerifiedBridgeAuthorization {
        bridge_authorization_successor_signed(
            previous,
            previous.control_signer,
            generation,
            enabled,
        )
    }

    fn bridge_authorization_successor_signed(
        previous: &VerifiedBridgeAuthorization,
        control_signer: NodeId,
        generation: u64,
        enabled: bool,
    ) -> VerifiedBridgeAuthorization {
        let mut authorization = previous.authorization.clone();
        authorization.control_sequence += 1;
        authorization.previous_control_id = Some(previous.envelope_id);
        authorization.generation = generation;
        if !enabled {
            authorization.enabled = None;
        }
        let exact_bytes = [
            b"provider-authenticated-ASTRBA01-successor".as_slice(),
            authorization.control_sequence.to_be_bytes().as_slice(),
            generation.to_be_bytes().as_slice(),
            &[u8::from(enabled)],
            control_signer.as_slice(),
        ]
        .concat();
        let envelope_id = exact_object_id(&exact_bytes);
        VerifiedBridgeAuthorization::from_provider(
            envelope_id,
            authorization,
            control_signer,
            exact_bytes,
        )
        .unwrap()
    }

    fn bridge_authorization_at_sequence_signed(
        template: &VerifiedBridgeAuthorization,
        control_signer: NodeId,
        sequence: u64,
        previous_control_id: EnvelopeId,
        generation: u64,
    ) -> VerifiedBridgeAuthorization {
        let mut authorization = template.authorization.clone();
        authorization.control_sequence = sequence;
        authorization.previous_control_id = Some(previous_control_id);
        authorization.generation = generation;
        let exact_bytes = [
            b"provider-authenticated-ASTRBA01-positioned".as_slice(),
            sequence.to_be_bytes().as_slice(),
            previous_control_id.as_slice(),
            generation.to_be_bytes().as_slice(),
            control_signer.as_slice(),
        ]
        .concat();
        VerifiedBridgeAuthorization::from_provider(
            exact_object_id(&exact_bytes),
            authorization,
            control_signer,
            exact_bytes,
        )
        .unwrap()
    }

    #[allow(clippy::too_many_arguments)]
    fn verified_bridge_edge_control(
        sequence: u64,
        previous: Option<EnvelopeId>,
        source: &str,
        source_epoch: u64,
        target: &str,
        target_epoch: u64,
        bridge_node_id: NodeId,
    ) -> VerifiedBridgeAuthorization {
        let mission_id = [0x41; 32];
        let source_scope = Scope::new(source).unwrap();
        let target_scope = Scope::new(target).unwrap();
        let authorization = BridgeAuthorization {
            mission_id,
            authority_id: [0x42; 32],
            control_sequence: sequence,
            previous_control_id: previous,
            authorization_key: crate::bridge::bridge_authorization_key(
                &mission_id,
                &bridge_node_id,
                &source_scope,
                &target_scope,
            )
            .unwrap(),
            generation: 1,
            bridge_node_id,
            source_scope,
            target_scope,
            enabled: Some(crate::bridge::EnabledAuthorization {
                source_route_epoch: source_epoch,
                target_route_epoch: target_epoch,
                source_route_commitment: [0x44; 32],
                target_route_commitment: [0x45; 32],
                allowed_priority_mask: 0b1110,
                max_total_hops: 8,
                topics: vec![
                    Topic::new("orders").unwrap(),
                    Topic::new("position").unwrap(),
                ],
                bridge_credential: vec![0x46; 128],
                authority_credential_signature: bridge_signature(0x47),
            }),
            authority_control_signature: bridge_signature(0x48),
        };
        let exact_bytes = [
            b"provider-authenticated-edge-control".as_slice(),
            sequence.to_be_bytes().as_slice(),
            source.as_bytes(),
            &[0],
            target.as_bytes(),
            bridge_node_id.as_slice(),
        ]
        .concat();
        let envelope_id = exact_object_id(&exact_bytes);
        VerifiedBridgeAuthorization::from_provider(
            envelope_id,
            authorization,
            [0x49; 32],
            exact_bytes,
        )
        .unwrap()
    }

    fn configure_bridge_epoch(store: &mut SqliteStore, scope: &str, epoch: u64) {
        store
            .set_scope_epoch(&ScopeEpoch {
                authority: [0x42; 32],
                signer: [0x42; 32],
                scope: Scope::new(scope).unwrap(),
                epoch,
                control_sequence: epoch,
                previous_control: None,
                sealed_notice: [scope.as_bytes(), &epoch.to_be_bytes()].concat(),
            })
            .unwrap();
    }

    fn verified_bridge_route(
        authorizations: &[&VerifiedBridgeAuthorization],
        signature_seed: u8,
        source_bytes: &[u8],
    ) -> VerifiedBridgeRoute {
        let origin_envelope_id = exact_object_id(source_bytes);
        let mut hops = Vec::with_capacity(authorizations.len());
        let mut previous_digest = [0; 32];
        for (index, authorization) in authorizations.iter().enumerate() {
            let enabled = authorization.authorization.enabled.as_ref().unwrap();
            let hop = crate::bridge::BridgeHop {
                authorization_envelope_id: authorization.envelope_id,
                bridge_node_id: authorization.authorization.bridge_node_id,
                from_scope: authorization.authorization.source_scope.clone(),
                from_route_epoch: enabled.source_route_epoch,
                to_scope: authorization.authorization.target_scope.clone(),
                to_route_epoch: enabled.target_route_epoch,
                cumulative_custody_age_ms: 100 + index as u64,
                age_continuity_unknown: false,
                previous_hop_digest: previous_digest,
                bridge_hybrid_signature: bridge_signature(signature_seed.wrapping_add(index as u8)),
            };
            previous_digest = hop.digest(u8::try_from(index + 1).unwrap()).unwrap();
            hops.push(hop);
        }
        let first = authorizations.first().unwrap();
        let last = authorizations.last().unwrap();
        let mut route = BridgeRoute {
            mission_id: [0x41; 32],
            origin_envelope_id,
            source_item_id: Sha256::digest(
                [b"bridge-source-item".as_slice(), source_bytes].concat(),
            )
            .into(),
            origin_scope: first.authorization.source_scope.clone(),
            origin_route_epoch: first
                .authorization
                .enabled
                .as_ref()
                .unwrap()
                .source_route_epoch,
            current_scope: last.authorization.target_scope.clone(),
            current_route_epoch: last
                .authorization
                .enabled
                .as_ref()
                .unwrap()
                .target_route_epoch,
            source_route_descriptor: b"exact-provider-verified-format-2-route".to_vec(),
            hops,
            bridge_route_id: [0; 32],
        };
        route.bridge_route_id = route.compute_route_id().unwrap();
        let exact_wrapper_bytes = [
            b"provider-authenticated-ASTRBW01-object".as_slice(),
            route.bridge_route_id.as_slice(),
        ]
        .concat();
        let wrapper_envelope_id = exact_object_id(&exact_wrapper_bytes);
        let mut counter_bytes = [0u8; 8];
        counter_bytes[1..].copy_from_slice(&origin_envelope_id[..7]);
        let source = VerifiedBridgeSource::from_provider(
            origin_envelope_id,
            VerifiedBridgeSourceMetadata {
                source_item_id: route.source_item_id,
                class: DataClass::State,
                topic: Topic::new("orders").unwrap(),
                priority: Priority::Immediate,
                stamp: CausalStamp {
                    dot: Dot {
                        publisher: [0x62; 32],
                        counter: u64::from_be_bytes(counter_bytes).saturating_add(1),
                    },
                    context: VersionVector::default(),
                },
                event_sequence: None,
                logical_key: b"bridge-test-key".to_vec(),
                ttl_ms: None,
                blob_route: None,
                content_len: source_bytes.len() as u64,
                tombstone: false,
                origin_scope: route.origin_scope.clone(),
                origin_route_epoch: route.origin_route_epoch,
            },
            source_bytes.to_vec(),
            route.hops.last().unwrap().cumulative_custody_age_ms,
        )
        .unwrap();
        VerifiedBridgeRoute::from_provider(
            wrapper_envelope_id,
            route,
            exact_wrapper_bytes,
            100,
            source,
        )
        .unwrap()
    }

    fn pending_wrapper_from_route(route: &VerifiedBridgeRoute) -> VerifiedPendingBridgeWrapper {
        VerifiedPendingBridgeWrapper::from_provider(
            route.wrapper_envelope_id,
            route.route.clone(),
            route.exact_wrapper_bytes.clone(),
            route.authenticated_forwarding_age_ms,
        )
        .unwrap()
    }

    fn bridge_sample(tick_ms: u64) -> CustodySample {
        CustodySample {
            clock_id: [0xa5; 16],
            tick_ms,
        }
    }

    fn downgrade_schema_v13_to_v12_for_test(connection: &Connection) {
        downgrade_schema_v14_to_v13_for_test(connection);
        connection
            .execute_batch(
                "ALTER TABLE transfer_identities RENAME TO transfer_identities_v13;\n\
                 CREATE TABLE transfer_identities (\n\
                   storage_key BLOB PRIMARY KEY REFERENCES wants(object_id) ON DELETE CASCADE\n\
                     CHECK(length(storage_key)=32),\n\
                   object_id BLOB NOT NULL UNIQUE CHECK(length(object_id)=33),\n\
                   origin_semantic_version INTEGER\n\
                     CHECK(origin_semantic_version IS NULL OR origin_semantic_version IN (1,2))\n\
                 ) STRICT;\n\
                 INSERT INTO transfer_identities(storage_key,object_id,origin_semantic_version)\n\
                   SELECT storage_key,object_id,origin_semantic_version\n\
                   FROM transfer_identities_v13;\n\
                 DROP TABLE transfer_identities_v13;\n\
                 PRAGMA user_version=12;",
            )
            .unwrap();
    }

    fn downgrade_schema_v14_to_v13_for_test(connection: &Connection) {
        downgrade_schema_v15_to_v14_for_test(connection);
        connection
            .execute_batch(
                "ALTER TABLE transfer_identities RENAME TO transfer_identities_v14;\n\
                 CREATE TABLE transfer_identities (\n\
                   storage_key BLOB PRIMARY KEY REFERENCES wants(object_id) ON DELETE CASCADE\n\
                     CHECK(length(storage_key)=32),\n\
                   object_id BLOB NOT NULL UNIQUE CHECK(length(object_id)=33),\n\
                   origin_semantic_version INTEGER\n\
                     CHECK(origin_semantic_version IS NULL OR origin_semantic_version IN (1,2,3))\n\
                 ) STRICT;\n\
                 INSERT INTO transfer_identities(storage_key,object_id,origin_semantic_version)\n\
                   SELECT storage_key,object_id,origin_semantic_version\n\
                   FROM transfer_identities_v14;\n\
                 DROP TABLE transfer_identities_v14;\n\
                 PRAGMA user_version=13;",
            )
            .unwrap();
    }

    fn downgrade_schema_v15_to_v14_for_test(connection: &Connection) {
        downgrade_schema_v16_to_v15_for_test(connection);
        connection
            .execute_batch(
                "ALTER TABLE transfer_identities RENAME TO transfer_identities_v15;\n\
                 CREATE TABLE transfer_identities (\n\
                   storage_key BLOB PRIMARY KEY REFERENCES wants(object_id) ON DELETE CASCADE\n\
                     CHECK(length(storage_key)=32),\n\
                   object_id BLOB NOT NULL UNIQUE CHECK(length(object_id)=33),\n\
                   origin_semantic_version INTEGER\n\
                     CHECK(origin_semantic_version IS NULL OR origin_semantic_version IN (1,2,3,4))\n\
                 ) STRICT;\n\
                 INSERT INTO transfer_identities(storage_key,object_id,origin_semantic_version)\n\
                   SELECT storage_key,object_id,origin_semantic_version\n\
                   FROM transfer_identities_v15;\n\
                 DROP TABLE transfer_identities_v15;\n\
                 PRAGMA user_version=14;",
            )
            .unwrap();
    }

    fn downgrade_schema_v16_to_v15_for_test(connection: &Connection) {
        connection
            .execute_batch(
                "ALTER TABLE transfer_identities RENAME TO transfer_identities_v16;\n\
                 CREATE TABLE transfer_identities (\n\
                   storage_key BLOB PRIMARY KEY REFERENCES wants(object_id) ON DELETE CASCADE\n\
                     CHECK(length(storage_key)=32),\n\
                   object_id BLOB NOT NULL UNIQUE CHECK(length(object_id)=33),\n\
                   origin_semantic_version INTEGER\n\
                     CHECK(origin_semantic_version IS NULL OR origin_semantic_version IN (1,2,3,4,5))\n\
                 ) STRICT;\n\
                 INSERT INTO transfer_identities(storage_key,object_id,origin_semantic_version)\n\
                   SELECT storage_key,object_id,origin_semantic_version\n\
                   FROM transfer_identities_v16;\n\
                 DROP TABLE transfer_identities_v16;\n\
                 PRAGMA user_version=15;",
            )
            .unwrap();
    }

    fn downgrade_schema_v12_to_v11_for_test(connection: &Connection) {
        downgrade_schema_v13_to_v12_for_test(connection);
        connection
            .execute_batch(
                "ALTER TABLE causal_frontier RENAME TO causal_frontier_v12;\n\
                 CREATE TABLE causal_frontier (\n\
                   publisher BLOB PRIMARY KEY CHECK(length(publisher)=32),\n\
                   counter INTEGER NOT NULL CHECK(counter>0)\n\
                 ) STRICT;\n\
                 INSERT INTO causal_frontier(publisher,counter)\n\
                   SELECT publisher,max(counter) FROM causal_frontier_v12 GROUP BY publisher;\n\
                 DROP TABLE causal_frontier_v12;\n\
                 PRAGMA user_version=11;",
            )
            .unwrap();
    }

    fn downgrade_empty_or_populated_schema_v11_to_v10(connection: &Connection) {
        downgrade_schema_v12_to_v11_for_test(connection);
        connection
            .execute_batch(
                "DROP INDEX controls_signer;\n\
                 DROP INDEX bridge_controls_signer;\n\
                 DROP TRIGGER controls_require_signer_insert;\n\
                 DROP TRIGGER controls_require_signer_update;\n\
                 DROP TRIGGER bridge_controls_require_signer_insert;\n\
                 DROP TRIGGER bridge_controls_require_signer_update;\n\
                 ALTER TABLE controls DROP COLUMN signer;\n\
                 ALTER TABLE bridge_authorization_controls DROP COLUMN control_signer;\n\
                 PRAGMA user_version=10;",
            )
            .unwrap();
    }

    fn schema_has_column(connection: &Connection, table: &str, column: &str) -> bool {
        let sql = format!("PRAGMA table_info({table})");
        let mut statement = connection.prepare(&sql).unwrap();
        statement
            .query_map([], |row| row.get::<_, String>(1))
            .unwrap()
            .collect::<Result<Vec<_>, _>>()
            .unwrap()
            .iter()
            .any(|name| name == column)
    }

    fn ordinary_item_from_bridge_source(
        route: &VerifiedBridgeRoute,
        scope: Scope,
        key_epoch: u64,
        sample: CustodySample,
    ) -> StoredItem {
        let metadata = &route.source.metadata;
        StoredItem {
            id: metadata.source_item_id,
            envelope_id: route.route.origin_envelope_id,
            class: metadata.class,
            topic: metadata.topic.clone(),
            scope,
            priority: metadata.priority,
            stamp: metadata.stamp.clone(),
            event_sequence: metadata.event_sequence,
            logical_key: metadata.logical_key.clone(),
            ttl_ms: metadata.ttl_ms,
            observed_at_ms: None,
            sealed: route.source.exact_bytes.clone(),
            content_len: metadata.content_len,
            tombstone: metadata.tombstone,
            key_epoch,
            custody_age_ms: route.source.authenticated_forwarding_age_ms,
            custody_clock_id: Some(sample.clock_id),
            custody_tick_ms: Some(sample.tick_ms),
            custody_elapsed_available: true,
            status: VersionStatus::Current,
            inserted_order: 0,
        }
    }

    #[test]
    fn bundled_sqlite_runtime_is_pinned() {
        let store = SqliteStore::open_in_memory(StoreConfig::default()).unwrap();
        assert_eq!(store.sqlite_version().unwrap(), "3.53.2");
    }

    #[test]
    fn peer_last_change_advances_only_for_a_real_state_transition() {
        let mut store = SqliteStore::open_in_memory(StoreConfig::default()).unwrap();
        let node = [0x51; 32];
        let initial = PeerSnapshot {
            node,
            peer: PeerStatus::Authenticating,
            sync: SyncStatus::Reconciling,
            last_change_ms: Some(10),
            detail: None,
        };
        store.update_peer(&initial).unwrap();

        let repeated = PeerSnapshot {
            last_change_ms: Some(20),
            ..initial.clone()
        };
        store.update_peer(&repeated).unwrap();
        assert_eq!(
            store
                .connection
                .query_row("SELECT changes()", [], |row| row.get::<_, i64>(0))
                .unwrap(),
            0,
            "an identical peer snapshot must not write its SQLite row"
        );
        assert_eq!(store.peer(&node).unwrap(), Some(initial));

        let transitioned = PeerSnapshot {
            node,
            peer: PeerStatus::Ready,
            sync: SyncStatus::Transferring,
            last_change_ms: Some(30),
            detail: Some("authenticated transfer active".into()),
        };
        store.update_peer(&transitioned).unwrap();
        assert_eq!(
            store
                .connection
                .query_row("SELECT changes()", [], |row| row.get::<_, i64>(0))
                .unwrap(),
            1,
            "a peer transition must update its SQLite row"
        );
        assert_eq!(store.peer(&node).unwrap(), Some(transitioned));
    }

    #[test]
    fn empty_schema_v10_migrates_to_signer_aware_v11() {
        let path = std::env::temp_dir().join(format!(
            "aster-empty-v10-to-v11-{}-{}.sqlite3",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        drop(SqliteStore::open(&path, StoreConfig::default()).unwrap());
        {
            let connection = Connection::open(&path).unwrap();
            downgrade_empty_or_populated_schema_v11_to_v10(&connection);
            assert_eq!(
                connection
                    .query_row("PRAGMA user_version", [], |row| row.get::<_, i64>(0))
                    .unwrap(),
                10
            );
            assert!(!schema_has_column(&connection, "controls", "signer"));
            assert!(!schema_has_column(
                &connection,
                "bridge_authorization_controls",
                "control_signer"
            ));
        }

        {
            let reopened = SqliteStore::open(&path, StoreConfig::default()).unwrap();
            assert_eq!(
                reopened
                    .connection
                    .query_row("PRAGMA user_version", [], |row| row.get::<_, i64>(0))
                    .unwrap(),
                SCHEMA_VERSION
            );
            assert!(schema_has_column(
                &reopened.connection,
                "controls",
                "signer"
            ));
            assert!(schema_has_column(
                &reopened.connection,
                "bridge_authorization_controls",
                "control_signer"
            ));
        }
        let _ = fs::remove_file(&path);
        let _ = fs::remove_file(path.with_extension("sqlite3-wal"));
        let _ = fs::remove_file(path.with_extension("sqlite3-shm"));
    }

    #[test]
    fn populated_schema_v10_requires_explicit_signer_migration() {
        let path = std::env::temp_dir().join(format!(
            "aster-populated-v10-to-v11-{}-{}.sqlite3",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        {
            let mut store = SqliteStore::open(&path, StoreConfig::default()).unwrap();
            store
                .ingest_control(&revocation_control([0x71; 32], 1, None, 1))
                .unwrap();
            store
                .ingest_bridge_authorization(&verified_bridge_authorization())
                .unwrap();
        }
        {
            let connection = Connection::open(&path).unwrap();
            downgrade_empty_or_populated_schema_v11_to_v10(&connection);
        }

        assert!(matches!(
            SqliteStore::open(&path, StoreConfig::default()),
            Err(StoreError::LegacyControlMigrationRequired)
        ));
        {
            let connection = Connection::open(&path).unwrap();
            assert_eq!(
                connection
                    .query_row("PRAGMA user_version", [], |row| row.get::<_, i64>(0))
                    .unwrap(),
                10
            );
            assert!(!schema_has_column(&connection, "controls", "signer"));
            assert!(!schema_has_column(
                &connection,
                "bridge_authorization_controls",
                "control_signer"
            ));
        }
        let _ = fs::remove_file(&path);
        let _ = fs::remove_file(path.with_extension("sqlite3-wal"));
        let _ = fs::remove_file(path.with_extension("sqlite3-shm"));
    }

    #[test]
    fn schema_v11_global_frontier_migrates_to_v12_sentinel_and_survives_reopen() {
        let path = std::env::temp_dir().join(format!(
            "aster-causal-v11-to-v12-{}-{}.sqlite3",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        drop(SqliteStore::open(&path, StoreConfig::default()).unwrap());
        let legacy_a = [0xa1; 32];
        let legacy_b = [0xb2; 32];
        {
            let connection = Connection::open(&path).unwrap();
            downgrade_schema_v12_to_v11_for_test(&connection);
            connection
                .execute(
                    "INSERT INTO causal_frontier(publisher,counter) VALUES(?1,7),(?2,9)",
                    params![legacy_a.as_slice(), legacy_b.as_slice()],
                )
                .unwrap();
        }

        let topic = Topic::new("test.state").unwrap();
        let scope = Scope::new("mission/test").unwrap();
        {
            let mut store = SqliteStore::open(&path, StoreConfig::default()).unwrap();
            assert_eq!(
                store
                    .connection
                    .query_row("PRAGMA user_version", [], |row| row.get::<_, i64>(0))
                    .unwrap(),
                SCHEMA_VERSION
            );
            let sentinel_rows: i64 = store
                .connection
                .query_row(
                    "SELECT count(*) FROM causal_frontier WHERE topic=?1 AND scope=?2",
                    params![LEGACY_CAUSAL_TOPIC, LEGACY_CAUSAL_SCOPE],
                    |row| row.get(0),
                )
                .unwrap();
            assert_eq!(sentinel_rows, 2);
            let context = load_frontier(&store.connection, &topic, &scope).unwrap();
            assert_eq!(context.counter(&legacy_a), 7);
            assert_eq!(context.counter(&legacy_b), 9);

            let transaction = store.connection.transaction().unwrap();
            record_accepted_frontier_dot_tx(
                &transaction,
                &topic,
                &scope,
                Dot {
                    publisher: legacy_a,
                    counter: 11,
                },
            )
            .unwrap();
            transaction.commit().unwrap();
            let sentinel_a: i64 = store
                .connection
                .query_row(
                    "SELECT counter FROM causal_frontier\n\
                     WHERE topic=?1 AND scope=?2 AND publisher=?3",
                    params![
                        LEGACY_CAUSAL_TOPIC,
                        LEGACY_CAUSAL_SCOPE,
                        legacy_a.as_slice()
                    ],
                    |row| row.get(0),
                )
                .unwrap();
            assert_eq!(sentinel_a, 7, "exact updates must not mutate the sentinel");

            let mut item = test_item(0x6c, 1, None, 0, None);
            let domain_only = [0xc3; 32];
            item.stamp.dot.publisher = domain_only;
            assert!(matches!(
                store.ingest(item).unwrap(),
                ApplyOutcome::Inserted { .. }
            ));
        }

        {
            let store = SqliteStore::open(&path, StoreConfig::default()).unwrap();
            let exact = load_frontier(&store.connection, &topic, &scope).unwrap();
            assert_eq!(exact.counter(&legacy_a), 11);
            assert_eq!(exact.counter(&legacy_b), 9);
            assert_eq!(exact.counter(&[0xc3; 32]), 1);

            let unrelated_scope = Scope::new("mission/unrelated").unwrap();
            let unrelated = load_frontier(&store.connection, &topic, &unrelated_scope).unwrap();
            assert_eq!(unrelated.counter(&legacy_a), 7);
            assert_eq!(unrelated.counter(&legacy_b), 9);
            assert_eq!(unrelated.counter(&[0xc3; 32]), 0);
        }
        let _ = fs::remove_file(&path);
        let _ = fs::remove_file(path.with_extension("sqlite3-wal"));
        let _ = fs::remove_file(path.with_extension("sqlite3-shm"));
    }

    #[test]
    fn populated_schema_v12_transfer_provenance_migrates_to_current() {
        let path = std::env::temp_dir().join(format!(
            "aster-transfer-v12-to-current-{}-{}.sqlite3",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let proof = ObjectId::new(ObjectKind::SourceBatchProof, [0xd3; 32]);
        let storage_key = transfer_storage_key(proof);
        {
            let mut store = SqliteStore::open(&path, StoreConfig::default()).unwrap();
            store
                .begin_transfer_for_semantic_version(proof, 8, Priority::Immediate, None, 2)
                .unwrap();
            store
                .put_sealed_chunk(storage_key, 8, 0, &[1, 2, 3], None)
                .unwrap();
        }
        {
            let connection = Connection::open(&path).unwrap();
            downgrade_schema_v13_to_v12_for_test(&connection);
            assert_eq!(
                connection
                    .query_row("PRAGMA user_version", [], |row| row.get::<_, i64>(0))
                    .unwrap(),
                12
            );
        }
        {
            let mut store = SqliteStore::open(&path, StoreConfig::default()).unwrap();
            assert_eq!(
                store
                    .connection
                    .query_row("PRAGMA user_version", [], |row| row.get::<_, i64>(0))
                    .unwrap(),
                SCHEMA_VERSION
            );
            assert_eq!(
                store.transfer_progress_for_semantic_version(4, 8).unwrap()[0]
                    .origin_semantic_version,
                Some(2)
            );
            store
                .begin_transfer_for_semantic_version(proof, 8, Priority::Flash, None, 4)
                .unwrap();
            assert_eq!(
                store.missing_ranges(&storage_key, 8).unwrap(),
                vec![ChunkRange::new(3, 8).unwrap()]
            );
        }
        let _ = fs::remove_file(&path);
        let _ = fs::remove_file(path.with_extension("sqlite3-wal"));
        let _ = fs::remove_file(path.with_extension("sqlite3-shm"));
    }

    #[test]
    fn schema_v13_migrates_and_v4_provenance_survives_restart() {
        let path = std::env::temp_dir().join(format!(
            "aster-transfer-v13-to-v14-{}-{}.sqlite3",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let existing = ObjectId::new(ObjectKind::SourceBatchProof, [0xd4; 32]);
        let v4 = ObjectId::new(ObjectKind::BridgeAuthorization, [0xd5; 32]);
        {
            let mut store = SqliteStore::open(&path, StoreConfig::default()).unwrap();
            store
                .begin_transfer_for_semantic_version(existing, 8, Priority::Immediate, None, 3)
                .unwrap();
        }
        {
            let connection = Connection::open(&path).unwrap();
            downgrade_schema_v14_to_v13_for_test(&connection);
            assert_eq!(
                connection
                    .query_row("PRAGMA user_version", [], |row| row.get::<_, i64>(0))
                    .unwrap(),
                13
            );
        }
        {
            let mut store = SqliteStore::open(&path, StoreConfig::default()).unwrap();
            assert_eq!(
                store
                    .connection
                    .query_row("PRAGMA user_version", [], |row| row.get::<_, i64>(0))
                    .unwrap(),
                SCHEMA_VERSION
            );
            store
                .begin_transfer_for_semantic_version(existing, 8, Priority::Flash, None, 4)
                .unwrap();
            store
                .begin_transfer_for_semantic_version(v4, 9, Priority::Routine, None, 4)
                .unwrap();
            store
                .put_sealed_chunk(transfer_storage_key(v4), 9, 0, &[1, 2, 3], None)
                .unwrap();
        }
        {
            let mut store = SqliteStore::open(&path, StoreConfig::default()).unwrap();
            let progress = store.transfer_progress_for_semantic_version(4, 8).unwrap();
            assert!(progress.iter().any(|entry| {
                entry.object_id == existing && entry.origin_semantic_version == Some(3)
            }));
            assert!(progress.iter().any(|entry| {
                entry.object_id == v4
                    && entry.origin_semantic_version == Some(4)
                    && entry.received == [ChunkRange::new(0, 3).unwrap()]
            }));
        }
        let _ = fs::remove_file(&path);
        let _ = fs::remove_file(path.with_extension("sqlite3-wal"));
        let _ = fs::remove_file(path.with_extension("sqlite3-shm"));
    }

    #[test]
    fn schema_v14_migrates_and_v5_provenance_survives_restart() {
        let path = std::env::temp_dir().join(format!(
            "aster-transfer-v14-to-v15-{}-{}.sqlite3",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let existing_v4 = ObjectId::new(ObjectKind::SourceBatchProof, [0xd6; 32]);
        let new_v5 = ObjectId::new(ObjectKind::BridgeAuthorization, [0xd7; 32]);
        {
            let mut store = SqliteStore::open(&path, StoreConfig::default()).unwrap();
            store
                .begin_transfer_for_semantic_version(existing_v4, 8, Priority::Immediate, None, 4)
                .unwrap();
            store
                .put_sealed_chunk(transfer_storage_key(existing_v4), 8, 0, &[1, 2], None)
                .unwrap();
        }
        {
            let connection = Connection::open(&path).unwrap();
            downgrade_schema_v15_to_v14_for_test(&connection);
            assert_eq!(
                connection
                    .query_row("PRAGMA user_version", [], |row| row.get::<_, i64>(0))
                    .unwrap(),
                14
            );
        }
        {
            let mut store = SqliteStore::open(&path, StoreConfig::default()).unwrap();
            assert_eq!(
                store
                    .connection
                    .query_row("PRAGMA user_version", [], |row| row.get::<_, i64>(0))
                    .unwrap(),
                SCHEMA_VERSION
            );
            let migrated = store.transfer_progress_for_semantic_version(5, 8).unwrap();
            assert!(migrated.iter().any(|entry| {
                entry.object_id == existing_v4
                    && entry.origin_semantic_version == Some(4)
                    && entry.received == [ChunkRange::new(0, 2).unwrap()]
            }));
            store
                .begin_transfer_for_semantic_version(new_v5, 9, Priority::Routine, None, 5)
                .unwrap();
            store
                .put_sealed_chunk(transfer_storage_key(new_v5), 9, 0, &[3, 4, 5], None)
                .unwrap();
        }
        {
            let mut store = SqliteStore::open(&path, StoreConfig::default()).unwrap();
            let progress = store.transfer_progress_for_semantic_version(5, 8).unwrap();
            assert!(progress.iter().any(|entry| {
                entry.object_id == existing_v4
                    && entry.origin_semantic_version == Some(4)
                    && entry.received == [ChunkRange::new(0, 2).unwrap()]
            }));
            assert!(progress.iter().any(|entry| {
                entry.object_id == new_v5
                    && entry.origin_semantic_version == Some(5)
                    && entry.received == [ChunkRange::new(0, 3).unwrap()]
            }));
        }
        let _ = fs::remove_file(&path);
        let _ = fs::remove_file(path.with_extension("sqlite3-wal"));
        let _ = fs::remove_file(path.with_extension("sqlite3-shm"));
    }

    #[test]
    fn schema_v15_migrates_and_v6_provenance_survives_restart() {
        let path = std::env::temp_dir().join(format!(
            "aster-transfer-v15-to-v16-{}-{}.sqlite3",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let existing_v5 = ObjectId::new(ObjectKind::SourceBatchProof, [0xd8; 32]);
        let new_v6 = ObjectId::new(ObjectKind::BridgeRouteWrapper, [0xd9; 32]);
        let rejected_v8 = ObjectId::new(ObjectKind::SourceEnvelope, [0xda; 32]);
        {
            let mut store = SqliteStore::open(&path, StoreConfig::default()).unwrap();
            store
                .begin_transfer_for_semantic_version(existing_v5, 8, Priority::Immediate, None, 5)
                .unwrap();
            store
                .put_sealed_chunk(transfer_storage_key(existing_v5), 8, 0, &[1, 2], None)
                .unwrap();
        }
        {
            let connection = Connection::open(&path).unwrap();
            downgrade_schema_v16_to_v15_for_test(&connection);
            assert_eq!(
                connection
                    .query_row("PRAGMA user_version", [], |row| row.get::<_, i64>(0))
                    .unwrap(),
                15
            );
        }
        {
            let mut store = SqliteStore::open(&path, StoreConfig::default()).unwrap();
            assert_eq!(
                store
                    .connection
                    .query_row("PRAGMA user_version", [], |row| row.get::<_, i64>(0))
                    .unwrap(),
                SCHEMA_VERSION
            );
            let migrated = store.transfer_progress_for_semantic_version(6, 8).unwrap();
            assert!(migrated.iter().any(|entry| {
                entry.object_id == existing_v5
                    && entry.origin_semantic_version == Some(5)
                    && entry.received == [ChunkRange::new(0, 2).unwrap()]
            }));
            store
                .begin_transfer_for_semantic_version(new_v6, 9, Priority::Routine, None, 6)
                .unwrap();
            store
                .put_sealed_chunk(transfer_storage_key(new_v6), 9, 0, &[3, 4, 5], None)
                .unwrap();
            assert!(matches!(
                store.begin_transfer_for_semantic_version(
                    rejected_v8,
                    7,
                    Priority::Routine,
                    None,
                    8
                ),
                Err(StoreError::Invalid(_))
            ));
        }
        {
            let mut store = SqliteStore::open(&path, StoreConfig::default()).unwrap();
            let progress = store.transfer_progress_for_semantic_version(6, 8).unwrap();
            assert!(progress.iter().any(|entry| {
                entry.object_id == existing_v5
                    && entry.origin_semantic_version == Some(5)
                    && entry.received == [ChunkRange::new(0, 2).unwrap()]
            }));
            assert!(progress.iter().any(|entry| {
                entry.object_id == new_v6
                    && entry.origin_semantic_version == Some(6)
                    && entry.received == [ChunkRange::new(0, 3).unwrap()]
            }));
        }
        let _ = fs::remove_file(&path);
        let _ = fs::remove_file(path.with_extension("sqlite3-wal"));
        let _ = fs::remove_file(path.with_extension("sqlite3-shm"));
    }

    #[test]
    fn invalid_schema_v15_provenance_rolls_back_v16_migration() {
        let path = std::env::temp_dir().join(format!(
            "aster-transfer-v15-to-v16-rollback-{}-{}.sqlite3",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let existing_v5 = ObjectId::new(ObjectKind::SourceBatchProof, [0xdb; 32]);
        let storage_key = transfer_storage_key(existing_v5);
        {
            let mut store = SqliteStore::open(&path, StoreConfig::default()).unwrap();
            store
                .begin_transfer_for_semantic_version(existing_v5, 8, Priority::Immediate, None, 5)
                .unwrap();
        }
        {
            let connection = Connection::open(&path).unwrap();
            downgrade_schema_v16_to_v15_for_test(&connection);
            connection
                .execute_batch("PRAGMA ignore_check_constraints=ON;")
                .unwrap();
            connection
                .execute(
                    "UPDATE transfer_identities SET origin_semantic_version=8\n\
                     WHERE storage_key=?1",
                    params![storage_key.as_slice()],
                )
                .unwrap();
            connection
                .execute_batch("PRAGMA ignore_check_constraints=OFF;")
                .unwrap();
        }

        assert!(matches!(
            SqliteStore::open(&path, StoreConfig::default()),
            Err(StoreError::Sqlite(_))
        ));

        {
            let connection = Connection::open(&path).unwrap();
            assert_eq!(
                connection
                    .query_row("PRAGMA user_version", [], |row| row.get::<_, i64>(0))
                    .unwrap(),
                15
            );
            assert_eq!(
                connection
                    .query_row(
                        "SELECT origin_semantic_version FROM transfer_identities\n\
                         WHERE storage_key=?1",
                        params![storage_key.as_slice()],
                        |row| row.get::<_, i64>(0),
                    )
                    .unwrap(),
                8
            );
            assert_eq!(
                connection
                    .query_row(
                        "SELECT count(*) FROM sqlite_master\n\
                         WHERE type='table' AND name='transfer_identities_v15'",
                        [],
                        |row| row.get::<_, i64>(0),
                    )
                    .unwrap(),
                0
            );
        }
        let _ = fs::remove_file(&path);
        let _ = fs::remove_file(path.with_extension("sqlite3-wal"));
        let _ = fs::remove_file(path.with_extension("sqlite3-shm"));
    }

    #[test]
    fn over_bound_schema_v11_frontier_fails_closed_without_schema_mutation() {
        let path = std::env::temp_dir().join(format!(
            "aster-causal-over-bound-v11-{}-{}.sqlite3",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        drop(SqliteStore::open(&path, StoreConfig::default()).unwrap());
        {
            let mut connection = Connection::open(&path).unwrap();
            downgrade_schema_v12_to_v11_for_test(&connection);
            let transaction = connection.transaction().unwrap();
            for index in 0..=MAX_CAUSAL_CONTEXT_ENTRIES {
                transaction
                    .execute(
                        "INSERT INTO causal_frontier(publisher,counter) VALUES(?1,1)",
                        params![indexed_publisher(index).as_slice()],
                    )
                    .unwrap();
            }
            transaction.commit().unwrap();
        }

        assert!(matches!(
            SqliteStore::open(&path, StoreConfig::default()),
            Err(StoreError::Corrupt(_))
        ));
        {
            let connection = Connection::open(&path).unwrap();
            assert_eq!(
                connection
                    .query_row("PRAGMA user_version", [], |row| row.get::<_, i64>(0))
                    .unwrap(),
                11
            );
            assert!(!schema_has_column(&connection, "causal_frontier", "topic"));
            assert_eq!(
                connection
                    .query_row("SELECT count(*) FROM causal_frontier", [], |row| {
                        row.get::<_, i64>(0)
                    })
                    .unwrap(),
                (MAX_CAUSAL_CONTEXT_ENTRIES + 1) as i64
            );
        }
        let _ = fs::remove_file(&path);
        let _ = fs::remove_file(path.with_extension("sqlite3-wal"));
        let _ = fs::remove_file(path.with_extension("sqlite3-shm"));
    }

    #[test]
    fn inventory_projection_returns_metadata_without_materializing_sealed_or_causal_bytes() {
        assert!(
            INVENTORY_ITEM_COLUMNS
                .split(',')
                .all(|column| column.trim() != "sealed"),
            "the inventory projection must never return the sealed BLOB"
        );
        assert!(INVENTORY_ITEM_COLUMNS.contains("length(sealed) AS sealed_len"));
        assert!(!INVENTORY_ITEM_COLUMNS.contains("causal_context"));
        assert!(!INVENTORY_ITEM_COLUMNS.contains("logical_key"));

        let mut store = SqliteStore::open_in_memory(StoreConfig::default()).unwrap();
        let sample = CustodySample {
            clock_id: [0x35; 16],
            tick_ms: 100,
        };
        let mut item = test_item(0x35, 1, Some(500), 20, Some(sample));
        item.sealed = vec![0xa5; 1024 * 1024];
        item.envelope_id = exact_object_id(&item.sealed);
        let expected_envelope_id = item.envelope_id;
        store.ingest(item).unwrap();

        // A malformed causal payload makes the ordinary full-row decoder fail.
        // The inventory projection remains valid because it never selects or
        // decodes that field (nor any application payload field).
        store
            .connection
            .execute("UPDATE items SET causal_context=x'ff'", [])
            .unwrap();
        assert!(matches!(
            store.query(&StoreQuery {
                include_recoverable_versions: true,
                include_tombstones: true,
                ..StoreQuery::default()
            }),
            Err(StoreError::Sqlite(_))
        ));

        let topics = BTreeSet::from([Topic::new("test.state").unwrap()]);
        let scopes = BTreeSet::from([Scope::new("mission/test").unwrap()]);
        let metadata = store.select_inventory_metadata(&topics, &scopes).unwrap();
        assert_eq!(metadata.len(), 1);
        assert_eq!(metadata[0].envelope_id(), expected_envelope_id);
        assert_eq!(metadata[0].total_len(), 1024 * 1024);
        assert!(metadata[0].is_forwardable_at(Some(CustodySample {
            clock_id: sample.clock_id,
            tick_ms: 200,
        })));
        assert!(!metadata[0].is_forwardable_at(Some(CustodySample {
            clock_id: sample.clock_id,
            tick_ms: 700,
        })));
    }

    #[test]
    fn garbage_collection_lifecycle_scan_does_not_decode_sealed_or_causal_blobs() {
        assert!(
            LIFECYCLE_ITEM_COLUMNS
                .split(',')
                .all(|column| !matches!(column.trim(), "sealed" | "causal_context")),
            "lifecycle scans must not return source-sealed or causal BLOBs"
        );

        let mut store = SqliteStore::open_in_memory(StoreConfig::default()).unwrap();
        let mut item = test_item(0x36, 1, None, 0, None);
        item.sealed = vec![0xa6; 1024 * 1024];
        item.envelope_id = exact_object_id(&item.sealed);
        let item_id = item.id;
        store.ingest(item).unwrap();
        store
            .connection
            .execute(
                "UPDATE items SET causal_context=x'ff' WHERE item_id=?1",
                params![item_id.as_slice()],
            )
            .unwrap();

        assert!(matches!(
            store.query(&StoreQuery {
                include_recoverable_versions: true,
                include_tombstones: true,
                ..StoreQuery::default()
            }),
            Err(StoreError::Sqlite(_))
        ));
        assert!(store.collect_garbage(None, None).unwrap().is_empty());
        assert_eq!(
            store
                .connection
                .query_row(
                    "SELECT length(sealed) FROM items WHERE item_id=?1",
                    params![item_id.as_slice()],
                    |row| row.get::<_, i64>(0),
                )
                .unwrap(),
            1024 * 1024
        );
    }

    #[test]
    fn quota_expiry_lifecycle_scan_does_not_decode_protected_record_blobs() {
        let sample = CustodySample {
            clock_id: [0x37; 16],
            tick_ms: 0,
        };
        let mut item = test_item(0x37, 1, Some(10), 0, Some(sample));
        item.sealed = vec![0xa7; 1024 * 1024];
        item.envelope_id = exact_object_id(&item.sealed);
        let item_id = item.id;
        let mut store = SqliteStore::open_in_memory(StoreConfig::default()).unwrap();
        store.ingest(item).unwrap();
        store
            .connection
            .execute(
                "UPDATE items SET causal_context=x'ff' WHERE item_id=?1",
                params![item_id.as_slice()],
            )
            .unwrap();

        let config = store.config.clone();
        let transaction = store.connection.transaction().unwrap();
        let protected = BTreeSet::from([item_id]);
        assert!(
            enforce_quotas_protected_tx(
                &transaction,
                &config,
                &protected,
                Some(20),
                Some(CustodySample {
                    clock_id: sample.clock_id,
                    tick_ms: 20,
                }),
            )
            .unwrap()
            .is_empty()
        );
        transaction.commit().unwrap();
        assert_eq!(
            store
                .connection
                .query_row(
                    "SELECT count(*) FROM items WHERE item_id=?1",
                    params![item_id.as_slice()],
                    |row| row.get::<_, i64>(0),
                )
                .unwrap(),
            1
        );
    }

    #[test]
    fn lifecycle_gc_preserves_concurrent_tombstone_and_superseded_reducer_semantics() {
        let config = StoreConfig {
            tombstone_retention_ms: 10,
            superseded_retention_ms: 10,
            ..StoreConfig::default()
        };
        let mut store = SqliteStore::open_in_memory(config).unwrap();

        let mut live = test_item(0x10, 1, None, 0, None);
        live.stamp.dot.publisher = [0x10; 32];
        live.logical_key = b"concurrent-tombstone".to_vec();
        live.observed_at_ms = Some(0);
        let mut tombstone = test_item(0x20, 1, None, 0, None);
        tombstone.stamp.dot.publisher = [0x20; 32];
        tombstone.logical_key = live.logical_key.clone();
        tombstone.observed_at_ms = Some(0);
        tombstone.tombstone = true;
        store.ingest(live.clone()).unwrap();
        store.ingest(tombstone.clone()).unwrap();
        assert_eq!(
            store.get(&live.id).unwrap().unwrap().status,
            VersionStatus::Concurrent
        );
        assert_eq!(
            store.get(&tombstone.id).unwrap().unwrap().status,
            VersionStatus::Current
        );

        let mut base = test_item(0x30, 1, None, 0, None);
        base.stamp.dot.publisher = [0x30; 32];
        base.logical_key = b"causal-successor".to_vec();
        base.observed_at_ms = Some(0);
        let mut successor = test_item(0x31, 2, None, 0, None);
        successor.stamp.dot.publisher = base.stamp.dot.publisher;
        successor.stamp.context.observe(base.stamp.dot);
        successor.logical_key = base.logical_key.clone();
        successor.observed_at_ms = Some(0);
        store.ingest(base.clone()).unwrap();
        store.ingest(successor.clone()).unwrap();
        assert_eq!(
            store.get(&base.id).unwrap().unwrap().status,
            VersionStatus::Superseded
        );
        assert_eq!(
            store.get(&successor.id).unwrap().unwrap().status,
            VersionStatus::Current
        );

        assert_eq!(
            store.collect_garbage(Some(10), None).unwrap(),
            vec![live.id, base.id]
        );
        assert!(store.get(&live.id).unwrap().is_none());
        assert!(store.get(&base.id).unwrap().is_none());
        assert_eq!(
            store.get(&tombstone.id).unwrap().unwrap().status,
            VersionStatus::Current
        );
        assert_eq!(
            store.get(&successor.id).unwrap().unwrap().status,
            VersionStatus::Current
        );

        assert_eq!(
            store.collect_garbage(Some(10), None).unwrap(),
            vec![tombstone.id]
        );
        assert!(store.get(&tombstone.id).unwrap().is_none());
        assert_eq!(
            store.get(&successor.id).unwrap().unwrap().status,
            VersionStatus::Current
        );
    }

    #[test]
    fn inventory_projection_rejects_cap_plus_one_without_materializing_the_remainder() {
        let mut store = SqliteStore::open_in_memory(StoreConfig::default()).unwrap();
        for counter in 1..=3 {
            let item = test_item(0x40 + counter as u8, counter, None, 0, None);
            assert!(matches!(
                store.ingest(item).unwrap(),
                ApplyOutcome::Inserted { .. }
            ));
        }
        let topics = BTreeSet::from([Topic::new("test.state").unwrap()]);
        let scopes = BTreeSet::from([Scope::new("mission/test").unwrap()]);

        assert_eq!(
            select_inventory_metadata_bounded(&store.connection, &topics, &scopes, 3)
                .unwrap()
                .len(),
            3
        );
        assert!(matches!(
            select_inventory_metadata_bounded(&store.connection, &topics, &scopes, 2),
            Err(StoreError::Invalid(message)) if message == INVENTORY_OBJECT_LIMIT_ERROR
        ));
    }

    #[test]
    fn store_and_durable_context_boundaries_reject_noncanonical_predecessors() {
        let mut store = SqliteStore::open_in_memory(StoreConfig::default()).unwrap();

        let mut zero = test_item(0x50, 1, None, 0, None);
        zero.stamp.context.observe(Dot {
            publisher: [0x80; 32],
            counter: 0,
        });
        assert!(matches!(store.ingest(zero), Err(StoreError::Invalid(_))));

        let mut oversized = test_item(0x51, 2, None, 0, None);
        for index in 0..=MAX_CAUSAL_CONTEXT_ENTRIES {
            let mut predecessor = [0u8; 32];
            predecessor[..8].copy_from_slice(&(index as u64 + 1).to_be_bytes());
            oversized.stamp.context.observe(Dot {
                publisher: predecessor,
                counter: 1,
            });
        }
        assert_eq!(
            oversized.stamp.context.len(),
            MAX_CAUSAL_CONTEXT_ENTRIES + 1
        );
        assert!(matches!(
            store.ingest(oversized),
            Err(StoreError::Invalid(_))
        ));
        let item_count: i64 = store
            .connection
            .query_row("SELECT count(*) FROM items", [], |row| row.get(0))
            .unwrap();
        assert_eq!(item_count, 0, "rejected ingress must not mutate the store");

        let mut encoded_zero = Vec::with_capacity(44);
        encoded_zero.extend_from_slice(&1u32.to_be_bytes());
        encoded_zero.extend_from_slice(&[0x82; 32]);
        encoded_zero.extend_from_slice(&0u64.to_be_bytes());
        assert!(matches!(
            decode_context(&encoded_zero),
            Err(StoreError::Corrupt(_))
        ));

        let encoded_oversized = ((MAX_CAUSAL_CONTEXT_ENTRIES + 1) as u32)
            .to_be_bytes()
            .to_vec();
        assert!(matches!(
            decode_context(&encoded_oversized),
            Err(StoreError::Corrupt(_))
        ));
    }

    #[test]
    fn verified_bridge_source_rejects_noncanonical_causal_contexts() {
        let exact_bytes = b"provider-authenticated-causal-boundary-source".to_vec();
        let origin_envelope_id = exact_object_id(&exact_bytes);
        let metadata = |context| VerifiedBridgeSourceMetadata {
            source_item_id: [0x91; 32],
            class: DataClass::State,
            topic: Topic::new("orders").unwrap(),
            priority: Priority::Immediate,
            stamp: CausalStamp {
                dot: Dot {
                    publisher: [0x92; 32],
                    counter: 1,
                },
                context,
            },
            event_sequence: None,
            logical_key: b"bridge-boundary".to_vec(),
            ttl_ms: None,
            blob_route: None,
            content_len: exact_bytes.len() as u64,
            tombstone: false,
            origin_scope: Scope::new("mission/source").unwrap(),
            origin_route_epoch: 1,
        };

        let mut zero = VersionVector::default();
        zero.observe(Dot {
            publisher: [0x93; 32],
            counter: 0,
        });
        assert!(
            VerifiedBridgeSource::from_provider(
                origin_envelope_id,
                metadata(zero),
                exact_bytes.clone(),
                0,
            )
            .is_err()
        );

        let mut oversized = VersionVector::default();
        for index in 0..=MAX_CAUSAL_CONTEXT_ENTRIES {
            let mut predecessor = [0u8; 32];
            predecessor[..8].copy_from_slice(&(index as u64 + 1).to_be_bytes());
            oversized.observe(Dot {
                publisher: predecessor,
                counter: 1,
            });
        }
        assert!(
            VerifiedBridgeSource::from_provider(
                origin_envelope_id,
                metadata(oversized),
                exact_bytes,
                0,
            )
            .is_err()
        );
    }

    #[test]
    fn authenticated_context_assertions_do_not_expand_local_publication_frontier() {
        let mut store = SqliteStore::open_in_memory(StoreConfig::default()).unwrap();
        let remote_publisher = [0x42; 32];
        let mut remote = test_item(0x52, 1, None, 0, None);
        remote.stamp.dot.publisher = remote_publisher;
        for index in 0..MAX_CAUSAL_CONTEXT_ENTRIES {
            let mut asserted_publisher = [0_u8; 32];
            asserted_publisher[..4].copy_from_slice(&(index as u32).to_be_bytes());
            remote.stamp.context.observe(Dot {
                publisher: asserted_publisher,
                counter: 1,
            });
        }
        assert_eq!(remote.stamp.context.len(), MAX_CAUSAL_CONTEXT_ENTRIES);
        assert!(matches!(
            store.ingest(remote).unwrap(),
            ApplyOutcome::Inserted { .. }
        ));

        let local_publisher = [0x99; 32];
        let topic = Topic::new("test.state").unwrap();
        let scope = Scope::new("mission/test").unwrap();
        let unrelated_topic = Topic::new("test.other").unwrap();
        let unrelated_scope = Scope::new("mission/other").unwrap();
        assert!(
            store
                .reserve_publish(local_publisher, DataClass::State, &unrelated_topic, &scope)
                .unwrap()
                .context
                .is_empty()
        );
        assert!(
            store
                .reserve_publish(local_publisher, DataClass::State, &topic, &unrelated_scope)
                .unwrap()
                .context
                .is_empty()
        );
        let reservation = store
            .reserve_publish(local_publisher, DataClass::State, &topic, &scope)
            .unwrap();
        assert_eq!(reservation.context.len(), 1);
        assert!(reservation.context.observes(Dot {
            publisher: remote_publisher,
            counter: 1,
        }));
        assert!(!reservation.context.observes(Dot {
            publisher: [0; 32],
            counter: 1,
        }));

        let mut local = test_item(0x53, reservation.counter, None, 0, None);
        local.stamp.dot.publisher = local_publisher;
        local.stamp.context = reservation.context.clone();
        assert!(matches!(
            store.commit_publish(&reservation, local).unwrap(),
            ApplyOutcome::Inserted { .. }
        ));
        let frontier_publishers: i64 = store
            .connection
            .query_row(
                "SELECT count(*) FROM causal_frontier WHERE topic=?1 AND scope=?2",
                params![topic.as_str(), scope.as_str()],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(frontier_publishers, 2);
    }

    #[test]
    fn domain_frontier_cap_is_distinct_atomic_and_isolated() {
        let mut store = SqliteStore::open_in_memory(StoreConfig::default()).unwrap();
        let topic = Topic::new("orders").unwrap();
        let saturated_scope = Scope::new("mission/source").unwrap();
        let unrelated_scope = Scope::new("mission/other").unwrap();
        {
            let transaction = store.connection.transaction().unwrap();
            for index in 0..(MAX_CAUSAL_CONTEXT_ENTRIES - 1) {
                transaction
                    .execute(
                        "INSERT INTO causal_frontier(topic,scope,publisher,counter)\n\
                         VALUES(?1,?2,?3,1)",
                        params![
                            topic.as_str(),
                            saturated_scope.as_str(),
                            indexed_publisher(index).as_slice()
                        ],
                    )
                    .unwrap();
            }
            // The same publisher in the compatibility sentinel counts once in
            // the exact-plus-legacy union, so one final exact publisher remains
            // admissible.
            transaction
                .execute(
                    "INSERT INTO causal_frontier(topic,scope,publisher,counter)\n\
                     VALUES(?1,?2,?3,2)",
                    params![
                        LEGACY_CAUSAL_TOPIC,
                        LEGACY_CAUSAL_SCOPE,
                        indexed_publisher(0).as_slice()
                    ],
                )
                .unwrap();
            record_accepted_frontier_dot_tx(
                &transaction,
                &topic,
                &saturated_scope,
                Dot {
                    publisher: indexed_publisher(MAX_CAUSAL_CONTEXT_ENTRIES - 1),
                    counter: 1,
                },
            )
            .unwrap();
            transaction.commit().unwrap();
        }

        let saturated = load_frontier(&store.connection, &topic, &saturated_scope).unwrap();
        assert_eq!(saturated.len(), MAX_CAUSAL_CONTEXT_ENTRIES);
        assert_eq!(saturated.counter(&indexed_publisher(0)), 2);
        assert!(
            store
                .reserve_publish([0xee; 32], DataClass::State, &topic, &saturated_scope)
                .is_err(),
            "a new local publisher must fail before sealing at the domain cap"
        );
        assert!(
            store
                .reserve_publish(
                    indexed_publisher(0),
                    DataClass::State,
                    &topic,
                    &saturated_scope
                )
                .is_ok(),
            "a publisher already represented in the union may advance at the cap"
        );

        let counts_before: (i64, i64, i64) = store
            .connection
            .query_row(
                "SELECT (SELECT count(*) FROM items),\n\
                        (SELECT count(*) FROM accepted_dots),\n\
                        (SELECT count(*) FROM outbox)",
                [],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .unwrap();
        let mut rejected = test_item(0x6d, 1, None, 0, None);
        rejected.topic = topic.clone();
        rejected.scope = saturated_scope.clone();
        rejected.stamp.dot.publisher = [0xee; 32];
        assert!(matches!(
            store.ingest(rejected),
            Err(StoreError::Invalid(_))
        ));
        let counts_after: (i64, i64, i64) = store
            .connection
            .query_row(
                "SELECT (SELECT count(*) FROM items),\n\
                        (SELECT count(*) FROM accepted_dots),\n\
                        (SELECT count(*) FROM outbox)",
                [],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .unwrap();
        assert_eq!(counts_after, counts_before, "cap rejection must roll back");

        let authorization = verified_bridge_authorization();
        let route = verified_bridge_route(
            &[&authorization],
            0x74,
            b"domain-cap-provider-authenticated-bridge-source",
        );
        let bridge_dots_before: i64 = store
            .connection
            .query_row("SELECT count(*) FROM accepted_dots", [], |row| row.get(0))
            .unwrap();
        let transaction = store.connection.transaction().unwrap();
        assert!(matches!(
            accept_bridge_source_semantics_tx(&transaction, &route.source),
            Err(StoreError::Invalid(_))
        ));
        drop(transaction);
        let bridge_dots_after: i64 = store
            .connection
            .query_row("SELECT count(*) FROM accepted_dots", [], |row| row.get(0))
            .unwrap();
        assert_eq!(bridge_dots_after, bridge_dots_before);

        let mut accepted_elsewhere = test_item(0x6e, 1, None, 0, None);
        accepted_elsewhere.topic = topic.clone();
        accepted_elsewhere.scope = unrelated_scope.clone();
        accepted_elsewhere.stamp.dot.publisher = [0xee; 32];
        assert!(matches!(
            store.ingest(accepted_elsewhere).unwrap(),
            ApplyOutcome::Inserted { .. }
        ));
        let unrelated = load_frontier(&store.connection, &topic, &unrelated_scope).unwrap();
        assert_eq!(unrelated.len(), 2, "sentinel plus one exact publisher");
        assert_eq!(unrelated.counter(&[0xee; 32]), 1);
        assert_eq!(
            load_frontier(&store.connection, &topic, &saturated_scope)
                .unwrap()
                .len(),
            MAX_CAUSAL_CONTEXT_ENTRIES
        );
    }

    #[test]
    fn staged_bridge_authorization_exact_bytes_survive_reopen_without_activation() {
        let path = std::env::temp_dir().join(format!(
            "aster-bridge-control-{}-{}.sqlite3",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let verified = verified_bridge_authorization();
        {
            let mut store = SqliteStore::open(&path, StoreConfig::default()).unwrap();
            assert_eq!(
                store.stage_bridge_authorization(&verified).unwrap(),
                BridgeControlStage::Inserted
            );
            assert_eq!(
                store.stage_bridge_authorization(&verified).unwrap(),
                BridgeControlStage::Duplicate
            );
            let stored = store
                .stored_bridge_authorization(&verified.envelope_id)
                .unwrap()
                .unwrap();
            assert_eq!(stored.exact_bytes, verified.exact_bytes);
            assert_eq!(stored.authorization, verified.authorization);
            assert!(!stored.applied);
        }
        {
            let reopened = SqliteStore::open(&path, StoreConfig::default()).unwrap();
            assert_eq!(
                reopened
                    .connection
                    .query_row("PRAGMA user_version", [], |row| row.get::<_, i64>(0))
                    .unwrap(),
                SCHEMA_VERSION
            );
            let stored = reopened
                .stored_bridge_authorization(&verified.envelope_id)
                .unwrap()
                .unwrap();
            assert_eq!(stored.exact_bytes, verified.exact_bytes);
            assert_eq!(stored.authorization, verified.authorization);
            assert!(!stored.applied);
        }
        let _ = fs::remove_file(&path);
        let _ = fs::remove_file(path.with_extension("sqlite3-wal"));
        let _ = fs::remove_file(path.with_extension("sqlite3-shm"));
    }

    #[test]
    fn bridge_control_chain_activates_contiguously_and_disable_high_water_survives_reopen() {
        let path = std::env::temp_dir().join(format!(
            "aster-bridge-chain-{}-{}.sqlite3",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let first = verified_bridge_authorization();
        let second = bridge_authorization_successor(&first, 2, true);
        let disabled = bridge_authorization_successor(&second, 3, false);
        let key = first.authorization.authorization_key;
        {
            let mut store = SqliteStore::open(&path, StoreConfig::default()).unwrap();
            assert!(matches!(
                store.ingest_bridge_authorization(&second).unwrap(),
                BridgeControlOutcome::Pending { .. }
            ));
            assert!(store.active_bridge_authorization(&key).unwrap().is_none());
            let activated = store.ingest_bridge_authorization(&first).unwrap();
            let BridgeControlOutcome::Applied { activated, .. } = activated else {
                panic!("gap closure must activate both contiguous controls");
            };
            assert_eq!(activated.len(), 2);
            assert_eq!(
                store
                    .active_bridge_authorization(&key)
                    .unwrap()
                    .unwrap()
                    .envelope_id,
                second.envelope_id
            );
            assert!(
                store
                    .bridge_authorization_is_live(&second.envelope_id)
                    .unwrap()
            );
            assert!(matches!(
                store.ingest_bridge_authorization(&disabled).unwrap(),
                BridgeControlOutcome::Applied { .. }
            ));
            let first_page = store.stored_bridge_authorizations_after(None, 2).unwrap();
            assert_eq!(first_page.len(), 2);
            let cursor = BridgeAuthorizationCursor {
                authority_id: first_page[1].authorization.authority_id,
                sequence: first_page[1].authorization.control_sequence,
            };
            let second_page = store
                .stored_bridge_authorizations_after(Some(cursor), 2)
                .unwrap();
            assert_eq!(second_page.len(), 1);
            assert_eq!(second_page[0].envelope_id, disabled.envelope_id);
            assert_eq!(
                store
                    .active_bridge_authorization(&key)
                    .unwrap()
                    .unwrap()
                    .envelope_id,
                disabled.envelope_id
            );
            assert!(
                !store
                    .bridge_authorization_is_live(&disabled.envelope_id)
                    .unwrap()
            );
        }
        {
            let mut reopened = SqliteStore::open(&path, StoreConfig::default()).unwrap();
            let high_water = reopened.active_bridge_authorization(&key).unwrap().unwrap();
            assert_eq!(high_water.envelope_id, disabled.envelope_id);
            assert!(high_water.authorization.enabled.is_none());
            assert!(
                !reopened
                    .bridge_authorization_is_live(&disabled.envelope_id)
                    .unwrap()
            );
            assert!(matches!(
                reopened.ingest_bridge_authorization(&disabled).unwrap(),
                BridgeControlOutcome::Duplicate { .. }
            ));
            assert!(
                !reopened
                    .bridge_authorization_is_live(&disabled.envelope_id)
                    .unwrap()
            );
        }
        let _ = fs::remove_file(&path);
        let _ = fs::remove_file(path.with_extension("sqlite3-wal"));
        let _ = fs::remove_file(path.with_extension("sqlite3-shm"));
    }

    #[test]
    fn bridge_control_fork_and_generation_rollback_fail_closed() {
        let mut store = SqliteStore::open_in_memory(StoreConfig::default()).unwrap();
        let first = verified_bridge_authorization();
        store.ingest_bridge_authorization(&first).unwrap();

        let mut fork_authorization = first.authorization.clone();
        fork_authorization.authority_control_signature = bridge_signature(0x99);
        let fork_exact = b"different-provider-authenticated-control".to_vec();
        let fork = VerifiedBridgeAuthorization::from_provider(
            exact_object_id(&fork_exact),
            fork_authorization,
            first.control_signer,
            fork_exact,
        )
        .unwrap();
        assert!(matches!(
            store.ingest_bridge_authorization(&fork),
            Err(StoreError::BridgeControlFork)
        ));

        let equal_generation = bridge_authorization_successor(&first, 1, true);
        assert!(matches!(
            store.ingest_bridge_authorization(&equal_generation),
            Err(StoreError::BridgeControlRollback)
        ));
        assert_eq!(
            store
                .active_bridge_authorization(&first.authorization.authorization_key)
                .unwrap()
                .unwrap()
                .envelope_id,
            first.envelope_id
        );
    }

    #[test]
    fn bridge_wrapper_source_mapping_and_outbox_promote_atomically_and_reopen_fail_closed() {
        let path = std::env::temp_dir().join(format!(
            "aster-bridge-route-{}-{}.sqlite3",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let authorization = verified_bridge_authorization();
        let source_bytes = b"exact-source-format-2-envelope";
        let route = verified_bridge_route(&[&authorization], 0x70, source_bytes);
        {
            let mut store = SqliteStore::open(&path, StoreConfig::default()).unwrap();
            configure_bridge_epoch(&mut store, "mission/source", 3);
            configure_bridge_epoch(&mut store, "mission/target", 5);
            assert!(matches!(
                store.ingest_bridge_authorization(&authorization).unwrap(),
                BridgeControlOutcome::Applied { .. }
            ));
            assert_eq!(
                store
                    .promote_verified_bridge_route_at(&route, Some(bridge_sample(10)))
                    .unwrap(),
                BridgeRouteOutcome::Active {
                    wrapper_envelope_id: route.wrapper_envelope_id,
                    replaced: None
                }
            );
            let active = store
                .active_bridge_route(
                    &route.route.origin_envelope_id,
                    &route.route.current_scope,
                    route.route.current_route_epoch,
                )
                .unwrap()
                .unwrap();
            assert_eq!(active.wrapper_envelope_id, route.wrapper_envelope_id);
            assert_eq!(active.origin_scope, route.route.origin_scope);
            assert_eq!(active.current_scope, route.route.current_scope);
            assert_eq!(active.exact_source_bytes, source_bytes);
            assert!(
                store
                    .bridge_route_is_live(&route.wrapper_envelope_id)
                    .unwrap()
            );
            assert_eq!(
                store
                    .connection
                    .query_row("SELECT count(*) FROM bridge_route_outbox", [], |row| {
                        row.get::<_, i64>(0)
                    })
                    .unwrap(),
                1
            );
        }
        {
            let mut reopened = SqliteStore::open(&path, StoreConfig::default()).unwrap();
            assert!(
                reopened
                    .active_bridge_route(
                        &route.route.origin_envelope_id,
                        &route.route.current_scope,
                        route.route.current_route_epoch,
                    )
                    .unwrap()
                    .is_none()
            );
            assert_eq!(
                reopened.stored_bridge_routes(1).unwrap()[0].wrapper_envelope_id,
                route.wrapper_envelope_id
            );
            assert_eq!(
                reopened.stored_bridge_sources(1).unwrap()[0].origin_envelope_id,
                route.route.origin_envelope_id
            );
            assert_eq!(reopened.stored_bridge_authorizations(1).unwrap().len(), 1);
            assert!(
                reopened
                    .next_bridge_authorization_outbound([0x99; 32], 1, 1_000_000, None)
                    .unwrap()
                    .is_empty()
            );
            assert!(
                !reopened
                    .bridge_route_is_live(&route.wrapper_envelope_id)
                    .unwrap()
            );
            assert!(matches!(
                reopened
                    .ingest_bridge_authorization(&authorization)
                    .unwrap(),
                BridgeControlOutcome::Duplicate { .. }
            ));
            assert!(matches!(
                reopened
                    .promote_verified_bridge_route_at(&route, Some(bridge_sample(10)))
                    .unwrap(),
                BridgeRouteOutcome::Duplicate { active: true, .. }
            ));
            assert!(
                reopened
                    .bridge_route_is_live(&route.wrapper_envelope_id)
                    .unwrap()
            );
        }
        let _ = fs::remove_file(&path);
        let _ = fs::remove_file(path.with_extension("sqlite3-wal"));
        let _ = fs::remove_file(path.with_extension("sqlite3-shm"));
    }

    #[test]
    fn active_bridge_path_selects_shortest_then_lexicographic_route_id() {
        let mut store = SqliteStore::open_in_memory(StoreConfig::default()).unwrap();
        for (scope, epoch) in [
            ("mission/source", 3),
            ("mission/middle", 4),
            ("mission/target", 5),
        ] {
            configure_bridge_epoch(&mut store, scope, epoch);
        }
        let first = verified_bridge_edge_control(
            1,
            None,
            "mission/source",
            3,
            "mission/middle",
            4,
            [0x71; 32],
        );
        let second = verified_bridge_edge_control(
            2,
            Some(first.envelope_id),
            "mission/middle",
            4,
            "mission/target",
            5,
            [0x72; 32],
        );
        let direct = verified_bridge_edge_control(
            3,
            Some(second.envelope_id),
            "mission/source",
            3,
            "mission/target",
            5,
            [0x73; 32],
        );
        for control in [&first, &second, &direct] {
            store.ingest_bridge_authorization(control).unwrap();
        }
        let source_bytes = b"shared-exact-source-format-2-envelope";
        let long = verified_bridge_route(&[&first, &second], 0x74, source_bytes);
        let direct_a = verified_bridge_route(&[&direct], 0x75, source_bytes);
        let direct_b = verified_bridge_route(&[&direct], 0x76, source_bytes);
        store
            .promote_verified_bridge_route_at(&long, Some(bridge_sample(10)))
            .unwrap();
        let (smaller, larger) = if direct_a.route.bridge_route_id < direct_b.route.bridge_route_id {
            (&direct_a, &direct_b)
        } else {
            (&direct_b, &direct_a)
        };
        assert!(matches!(
            store
                .promote_verified_bridge_route_at(smaller, Some(bridge_sample(10)))
                .unwrap(),
            BridgeRouteOutcome::Active {
                replaced: Some(value),
                ..
            } if value == long.wrapper_envelope_id
        ));
        assert!(matches!(
            store
                .promote_verified_bridge_route_at(larger, Some(bridge_sample(10)))
                .unwrap(),
            BridgeRouteOutcome::RetainedAlternate {
                active_wrapper_envelope_id,
                ..
            } if active_wrapper_envelope_id == smaller.wrapper_envelope_id
        ));
        let active = store
            .active_bridge_route(
                &smaller.route.origin_envelope_id,
                &smaller.route.current_scope,
                smaller.route.current_route_epoch,
            )
            .unwrap()
            .unwrap();
        assert_eq!(active.wrapper_envelope_id, smaller.wrapper_envelope_id);
        assert_eq!(active.hop_count, 1);
        assert_eq!(active.bridge_route_id, smaller.route.bridge_route_id);
        assert_eq!(
            store
                .connection
                .query_row("SELECT count(*) FROM bridge_route_outbox", [], |row| {
                    row.get::<_, i64>(0)
                })
                .unwrap(),
            1
        );
    }

    #[test]
    fn bridge_rekey_and_revocation_remove_active_mapping_but_preserve_recovery_bytes() {
        let mut store = SqliteStore::open_in_memory(StoreConfig::default()).unwrap();
        let authorization = verified_bridge_authorization();
        configure_bridge_epoch(&mut store, "mission/source", 3);
        configure_bridge_epoch(&mut store, "mission/target", 5);
        store.ingest_bridge_authorization(&authorization).unwrap();
        let route = verified_bridge_route(&[&authorization], 0x81, b"rekey-preserved-exact-source");
        store
            .promote_verified_bridge_route_at(&route, Some(bridge_sample(10)))
            .unwrap();
        assert!(
            store
                .set_scope_epoch(&ScopeEpoch {
                    authority: [0x42; 32],
                    signer: [0x42; 32],
                    scope: Scope::new("mission/target").unwrap(),
                    epoch: 6,
                    control_sequence: 6,
                    previous_control: None,
                    sealed_notice: b"target-epoch-6".to_vec(),
                })
                .unwrap()
        );
        assert!(
            store
                .active_bridge_route(
                    &route.route.origin_envelope_id,
                    &route.route.current_scope,
                    route.route.current_route_epoch,
                )
                .unwrap()
                .is_none()
        );
        assert!(
            store
                .stored_bridge_route(&route.wrapper_envelope_id)
                .unwrap()
                .is_some()
        );
        assert!(matches!(
            store.promote_verified_bridge_route_at(&route, Some(bridge_sample(10))),
            Err(StoreError::BridgeDependencyMissing)
        ));
        assert!(
            store
                .delete_bridge_wrapper(&route.wrapper_envelope_id)
                .unwrap()
        );
        assert!(
            store
                .delete_bridge_source(&route.route.origin_envelope_id)
                .unwrap()
        );
        assert!(matches!(
            store.delete_bridge_authorization(&authorization.envelope_id),
            Err(StoreError::BridgeObjectReferenced)
        ));

        configure_bridge_epoch(&mut store, "mission/target", 7);
        let successor = bridge_authorization_successor(&authorization, 2, true);
        let mut successor_body = successor.authorization;
        successor_body.enabled.as_mut().unwrap().target_route_epoch = 7;
        let exact = b"fresh-epoch-provider-authenticated-control".to_vec();
        let fresh_authorization = VerifiedBridgeAuthorization::from_provider(
            exact_object_id(&exact),
            successor_body,
            successor.control_signer,
            exact,
        )
        .unwrap();
        store
            .ingest_bridge_authorization(&fresh_authorization)
            .unwrap();
        let fresh_route = verified_bridge_route(
            &[&fresh_authorization],
            0x82,
            b"revocation-preserved-exact-source",
        );
        store
            .promote_verified_bridge_route_at(&fresh_route, Some(bridge_sample(10)))
            .unwrap();
        let source_revocation = signed_revocation_control(
            fresh_authorization.authorization.authority_id,
            fresh_authorization.control_signer,
            fresh_route.source.metadata.stamp.dot.publisher,
            1,
            None,
            1,
        );
        assert!(matches!(
            store.ingest_control(&source_revocation).unwrap(),
            ControlOutcome::Applied { .. }
        ));
        assert!(
            store
                .active_bridge_route(
                    &fresh_route.route.origin_envelope_id,
                    &fresh_route.route.current_scope,
                    fresh_route.route.current_route_epoch,
                )
                .unwrap()
                .is_none()
        );
        assert_eq!(
            store
                .connection
                .query_row(
                    "SELECT count(*) FROM bridge_route_outbox WHERE wrapper_envelope_id=?1",
                    params![fresh_route.wrapper_envelope_id.as_slice()],
                    |row| row.get::<_, i64>(0)
                )
                .unwrap(),
            0,
            "normal-chain revocation must immediately remove stale route work"
        );
        assert!(
            store
                .stored_bridge_route(&fresh_route.wrapper_envelope_id)
                .unwrap()
                .is_some()
        );
        assert!(matches!(
            store.promote_verified_bridge_route_at(&fresh_route, Some(bridge_sample(10))),
            Err(StoreError::BridgeRouteIneligible)
        ));
    }

    #[test]
    fn bridge_quota_rejection_rolls_back_source_wrapper_mapping_and_outbox() {
        let config = StoreConfig {
            max_items: 16,
            max_bytes: 15_000,
            ..StoreConfig::default()
        };
        let mut store = SqliteStore::open_in_memory(config).unwrap();
        let authorization = verified_bridge_authorization();
        configure_bridge_epoch(&mut store, "mission/source", 3);
        configure_bridge_epoch(&mut store, "mission/target", 5);
        store.ingest_bridge_authorization(&authorization).unwrap();
        let large_source = vec![0x91; 10_000];
        let route = verified_bridge_route(&[&authorization], 0x92, &large_source);
        assert!(matches!(
            store.promote_verified_bridge_route_at(&route, Some(bridge_sample(10))),
            Err(StoreError::QuotaExceeded)
        ));
        for table in [
            "bridge_source_objects",
            "bridge_route_wrappers",
            "bridge_active_routes",
            "bridge_route_outbox",
        ] {
            let sql = format!("SELECT count(*) FROM {table}");
            assert_eq!(
                store
                    .connection
                    .query_row(&sql, [], |row| row.get::<_, i64>(0))
                    .unwrap(),
                0
            );
        }
    }

    #[test]
    fn pending_bridge_dependencies_are_canonical_private_and_promote_without_double_charge() {
        let mut store = SqliteStore::open_in_memory(StoreConfig::default()).unwrap();
        let authorization = verified_bridge_authorization();
        let mut route =
            verified_bridge_route(&[&authorization], 0xa1, b"pending-dependency-exact-source");
        route.source.authenticated_forwarding_age_ms = 130;
        let pending = pending_wrapper_from_route(&route);
        assert!(
            store
                .stage_verified_pending_bridge_wrapper(&pending, Some(bridge_sample(10)))
                .unwrap()
        );
        let missing = store
            .missing_bridge_dependencies(&route.wrapper_envelope_id, 8)
            .unwrap();
        assert_eq!(missing.len(), 2);
        assert_eq!(missing[0].kind(), ObjectKind::BridgeAuthorization);
        assert_eq!(*missing[0].digest(), authorization.envelope_id);
        assert_eq!(missing[1].kind(), ObjectKind::SourceEnvelope);
        assert_eq!(*missing[1].digest(), route.route.origin_envelope_id);

        let unrelated =
            verified_bridge_route(&[&authorization], 0xa2, b"unreferenced-malicious-source");
        assert!(matches!(
            store.stage_verified_bridge_source(&unrelated.source),
            Err(StoreError::BridgeDependencyMissing)
        ));
        assert!(store.pending_bridge_sources(8).unwrap().is_empty());

        configure_bridge_epoch(&mut store, "mission/source", 3);
        configure_bridge_epoch(&mut store, "mission/target", 5);
        store.ingest_bridge_authorization(&authorization).unwrap();
        assert!(
            !store
                .stage_verified_pending_bridge_wrapper(&pending, Some(bridge_sample(10)))
                .unwrap()
        );
        let missing = store
            .missing_bridge_dependencies(&route.wrapper_envelope_id, 1)
            .unwrap();
        assert_eq!(missing.len(), 1);
        assert_eq!(missing[0].kind(), ObjectKind::SourceEnvelope);
        assert!(
            store
                .stage_verified_bridge_source_at(&route.source, Some(bridge_sample(10)))
                .unwrap()
        );
        assert_eq!(
            store
                .stored_pending_bridge_wrapper(&route.wrapper_envelope_id)
                .unwrap()
                .unwrap()
                .cumulative_custody_age_ms,
            130
        );
        assert!(
            store
                .missing_bridge_dependencies(&route.wrapper_envelope_id, 8)
                .unwrap()
                .is_empty()
        );
        assert_eq!(
            store
                .connection
                .query_row("SELECT count(*) FROM items", [], |row| row.get::<_, i64>(0))
                .unwrap(),
            0
        );
        let before: (i64, i64) = store
            .connection
            .query_row(
                "SELECT\n\
                   (SELECT count(*) FROM bridge_pending_wrappers) +\n\
                   (SELECT count(*) FROM bridge_pending_sources) +\n\
                   (SELECT count(*) FROM bridge_route_wrappers) +\n\
                   (SELECT count(*) FROM bridge_source_objects),\n\
                   (SELECT coalesce(sum(accounted_bytes),0) FROM bridge_pending_wrappers) +\n\
                   (SELECT coalesce(sum(accounted_bytes),0) FROM bridge_pending_sources) +\n\
                   (SELECT coalesce(sum(accounted_bytes),0) FROM bridge_route_wrappers) +\n\
                   (SELECT coalesce(sum(accounted_bytes),0) FROM bridge_source_objects)",
                [],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .unwrap();
        assert!(matches!(
            store
                .promote_verified_bridge_route_at(&route, Some(bridge_sample(10)))
                .unwrap(),
            BridgeRouteOutcome::Active { .. }
        ));
        let after: (i64, i64) = store
            .connection
            .query_row(
                "SELECT\n\
                   (SELECT count(*) FROM bridge_pending_wrappers) +\n\
                   (SELECT count(*) FROM bridge_pending_sources) +\n\
                   (SELECT count(*) FROM bridge_route_wrappers) +\n\
                   (SELECT count(*) FROM bridge_source_objects),\n\
                   (SELECT coalesce(sum(accounted_bytes),0) FROM bridge_pending_wrappers) +\n\
                   (SELECT coalesce(sum(accounted_bytes),0) FROM bridge_pending_sources) +\n\
                   (SELECT coalesce(sum(accounted_bytes),0) FROM bridge_route_wrappers) +\n\
                   (SELECT coalesce(sum(accounted_bytes),0) FROM bridge_source_objects)",
                [],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .unwrap();
        assert_eq!(before, after);
        assert!(store.pending_bridge_wrappers(8).unwrap().is_empty());
        assert!(store.pending_bridge_sources(8).unwrap().is_empty());
        assert_eq!(store.stored_bridge_routes(8).unwrap().len(), 1);
        assert_eq!(store.stored_bridge_sources(8).unwrap().len(), 1);
        assert_eq!(
            store
                .connection
                .query_row("SELECT count(*) FROM outbox", [], |row| row
                    .get::<_, i64>(0))
                .unwrap(),
            0
        );
    }

    #[test]
    fn deferred_typed_bridge_transfers_are_atomic_and_restart_idempotent() {
        let path = std::env::temp_dir().join(format!(
            "aster-bridge-deferred-{}-{}.sqlite3",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let authorization = verified_bridge_authorization();
        let route =
            verified_bridge_route(&[&authorization], 0xb1, b"atomic-deferred-source-carrier");
        let pending = pending_wrapper_from_route(&route);
        {
            let mut store = SqliteStore::open(&path, StoreConfig::default()).unwrap();
            let wrapper_id =
                ObjectId::new(ObjectKind::BridgeRouteWrapper, route.wrapper_envelope_id);
            store
                .begin_transfer(
                    wrapper_id,
                    route.exact_wrapper_bytes.len() as u64,
                    Priority::Immediate,
                    None,
                )
                .unwrap();
            assert!(
                store
                    .put_sealed_chunk(
                        transfer_storage_key(wrapper_id),
                        route.exact_wrapper_bytes.len() as u64,
                        0,
                        &route.exact_wrapper_bytes,
                        None,
                    )
                    .unwrap()
            );
            assert!(
                store
                    .defer_verified_pending_bridge_wrapper_transfer(
                        &pending,
                        Some(bridge_sample(25)),
                    )
                    .unwrap()
            );

            let source_id =
                ObjectId::new(ObjectKind::SourceEnvelope, route.route.origin_envelope_id);
            store
                .begin_transfer(
                    source_id,
                    route.source.exact_bytes.len() as u64,
                    Priority::Immediate,
                    None,
                )
                .unwrap();
            assert!(
                store
                    .put_sealed_chunk(
                        transfer_storage_key(source_id),
                        route.source.exact_bytes.len() as u64,
                        0,
                        &route.source.exact_bytes,
                        None,
                    )
                    .unwrap()
            );
            assert!(
                store
                    .defer_verified_bridge_source_transfer(&route.source, None)
                    .unwrap()
            );
            assert!(store.transfer_progress(8).unwrap().is_empty());
            assert_eq!(store.pending_bridge_wrappers(8).unwrap().len(), 1);
            assert_eq!(store.pending_bridge_sources(8).unwrap().len(), 1);
        }
        {
            let mut reopened = SqliteStore::open(&path, StoreConfig::default()).unwrap();
            assert_eq!(reopened.pending_bridge_wrappers(8).unwrap().len(), 1);
            assert_eq!(reopened.pending_bridge_sources(8).unwrap().len(), 1);
            assert!(matches!(
                reopened.defer_verified_bridge_source_transfer(&route.source, None),
                Err(StoreError::BridgeDependencyMissing)
            ));
            assert!(
                !reopened
                    .defer_verified_pending_bridge_wrapper_transfer(
                        &pending,
                        Some(bridge_sample(25)),
                    )
                    .unwrap()
            );
            assert!(
                !reopened
                    .defer_verified_bridge_source_transfer(&route.source, None)
                    .unwrap()
            );
            assert!(reopened.transfer_progress(8).unwrap().is_empty());
            assert_eq!(reopened.pending_bridge_wrappers(8).unwrap().len(), 1);
            assert_eq!(reopened.pending_bridge_sources(8).unwrap().len(), 1);
        }
        let _ = fs::remove_file(&path);
        let _ = fs::remove_file(path.with_extension("sqlite3-wal"));
        let _ = fs::remove_file(path.with_extension("sqlite3-shm"));
    }

    #[test]
    fn pending_bridge_blob_carriers_complete_or_discard_by_exact_provider_capability() {
        let path = std::env::temp_dir().join(format!(
            "aster-bridge-blob-carrier-{}-{}.sqlite3",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let mut store = SqliteStore::open(&path, StoreConfig::default()).unwrap();
        let authorization = verified_bridge_authorization();
        configure_bridge_epoch(&mut store, "mission/source", 3);
        configure_bridge_epoch(&mut store, "mission/target", 5);
        store.ingest_bridge_authorization(&authorization).unwrap();

        let base = verified_bridge_route(&[&authorization], 0xb4, b"exact-blob-source-manifest");
        let mut metadata = base.source.metadata.clone();
        metadata.class = DataClass::Blob;
        metadata.blob_route = Some(VerifiedBlobRouteMetadata {
            blob_id: [0xb5; 32],
            chunk_count: 2,
            merkle_root: [0xb6; 32],
        });
        let source = VerifiedBridgeSource::from_provider(
            base.route.origin_envelope_id,
            metadata,
            base.source.exact_bytes.clone(),
            base.source.authenticated_forwarding_age_ms,
        )
        .unwrap();
        let route = VerifiedBridgeRoute::from_provider(
            base.wrapper_envelope_id,
            base.route.clone(),
            base.exact_wrapper_bytes.clone(),
            base.authenticated_forwarding_age_ms,
            source,
        )
        .unwrap();

        let carrier_id = ObjectId::for_blob_chunk_digest([0xb7; 32]);
        let carrier_bytes = b"ASTRBT01-provider-checked-private-carrier".to_vec();
        store
            .begin_transfer(
                carrier_id,
                carrier_bytes.len() as u64,
                Priority::Immediate,
                None,
            )
            .unwrap();
        store
            .put_sealed_chunk(
                transfer_storage_key(carrier_id),
                carrier_bytes.len() as u64,
                0,
                &carrier_bytes,
                None,
            )
            .unwrap();
        let pending = VerifiedPendingBridgeBlobCarrier::from_provider(
            carrier_id,
            route.route.origin_envelope_id,
            carrier_bytes.clone(),
        )
        .unwrap();
        assert!(
            store
                .defer_verified_pending_bridge_blob_carrier_transfer(&pending)
                .unwrap()
        );
        assert!(store.transfer_progress(8).unwrap().is_empty());
        assert_eq!(
            store
                .pending_bridge_blob_carriers_after(None, 8)
                .unwrap()
                .len(),
            1
        );

        store
            .promote_verified_bridge_route_at(&route, Some(bridge_sample(10)))
            .unwrap();
        let committed = VerifiedBridgeBlobCarrierCommit::from_provider(
            carrier_id,
            route.route.origin_envelope_id,
            carrier_bytes.clone(),
        )
        .unwrap();
        assert!(
            store
                .complete_verified_bridge_blob_carrier_commit(&committed, Some(bridge_sample(10)),)
                .unwrap()
        );
        assert!(
            !store
                .complete_verified_bridge_blob_carrier_commit(&committed, Some(bridge_sample(10)),)
                .unwrap()
        );
        store
            .begin_transfer(
                carrier_id,
                carrier_bytes.len() as u64,
                Priority::Immediate,
                None,
            )
            .unwrap();
        store
            .put_sealed_chunk(
                transfer_storage_key(carrier_id),
                carrier_bytes.len() as u64,
                0,
                &carrier_bytes,
                None,
            )
            .unwrap();
        assert!(
            !store
                .defer_verified_pending_bridge_blob_carrier_transfer(&pending)
                .unwrap()
        );
        assert!(store.transfer_progress(8).unwrap().is_empty());

        let rejected_id = ObjectId::for_blob_chunk_digest([0xb8; 32]);
        let rejected_bytes = b"ASTRBT01-provider-rejected-route-proof".to_vec();
        store
            .begin_transfer(
                rejected_id,
                rejected_bytes.len() as u64,
                Priority::Routine,
                None,
            )
            .unwrap();
        store
            .put_sealed_chunk(
                transfer_storage_key(rejected_id),
                rejected_bytes.len() as u64,
                0,
                &rejected_bytes,
                None,
            )
            .unwrap();
        store
            .defer_verified_pending_bridge_blob_carrier_transfer(
                &VerifiedPendingBridgeBlobCarrier::from_provider(
                    rejected_id,
                    route.route.origin_envelope_id,
                    rejected_bytes.clone(),
                )
                .unwrap(),
            )
            .unwrap();
        let rejected = VerifiedRejectedBridgeBlobCarrier::from_provider(
            rejected_id,
            route.route.origin_envelope_id,
            rejected_bytes,
        )
        .unwrap();
        assert!(
            store
                .discard_rejected_pending_bridge_blob_carrier(&rejected)
                .unwrap()
        );
        assert!(
            !store
                .discard_rejected_pending_bridge_blob_carrier(&rejected)
                .unwrap()
        );
        drop(store);
        let mut reopened = SqliteStore::open(&path, StoreConfig::default()).unwrap();
        assert!(reopened.transfer_progress(8).unwrap().is_empty());
        assert!(
            !reopened
                .defer_verified_pending_bridge_blob_carrier_transfer(&pending)
                .unwrap()
        );
        drop(reopened);
        let _ = fs::remove_file(&path);
        let _ = fs::remove_file(path.with_extension("sqlite3-wal"));
        let _ = fs::remove_file(path.with_extension("sqlite3-shm"));
    }

    #[test]
    fn bridge_ttl_outboxes_ranges_receipts_and_forwarding_age_fail_closed() {
        let mut store = SqliteStore::open_in_memory(StoreConfig::default()).unwrap();
        let authorization = verified_bridge_authorization();
        configure_bridge_epoch(&mut store, "mission/source", 3);
        configure_bridge_epoch(&mut store, "mission/target", 5);
        store.ingest_bridge_authorization(&authorization).unwrap();
        let mut route = verified_bridge_route(&[&authorization], 0xc1, b"finite-ttl-bridge-source");
        route.source.metadata.ttl_ms = Some(150);
        assert!(matches!(
            store
                .promote_verified_bridge_route_at(&route, Some(bridge_sample(10)))
                .unwrap(),
            BridgeRouteOutcome::Active { .. }
        ));
        assert!(
            store
                .bridge_route_is_live_at(&route.wrapper_envelope_id, Some(bridge_sample(59)))
                .unwrap()
        );
        assert!(
            !store
                .bridge_route_is_live_at(&route.wrapper_envelope_id, Some(bridge_sample(60)))
                .unwrap()
        );
        assert!(
            !store
                .bridge_route_is_live_at(
                    &route.wrapper_envelope_id,
                    Some(CustodySample {
                        clock_id: [0xb6; 16],
                        tick_ms: 20,
                    }),
                )
                .unwrap()
        );
        assert!(
            !store
                .bridge_route_is_live_at(&route.wrapper_envelope_id, Some(bridge_sample(9)))
                .unwrap()
        );

        let peer = [0xd1; 32];
        let controls = store
            .next_bridge_authorization_outbound(peer, 4, 1_000_000, Some(1))
            .unwrap();
        assert_eq!(controls.len(), 1);
        assert_eq!(
            store
                .read_bridge_authorization_range(
                    &authorization.envelope_id,
                    ChunkRange::new(0, authorization.exact_bytes.len() as u64).unwrap(),
                    5,
                )
                .unwrap(),
            authorization.exact_bytes[..5]
        );
        store
            .acknowledge_bridge_authorization_peer(peer, &[authorization.envelope_id], Some(2))
            .unwrap();
        assert!(
            store
                .next_bridge_authorization_outbound(peer, 4, 1_000_000, Some(3))
                .unwrap()
                .is_empty()
        );

        let routes = store
            .next_bridge_route_outbound(peer, 4, 1_000_000, Some(4), Some(bridge_sample(20)))
            .unwrap();
        assert_eq!(routes.len(), 1);
        assert_eq!(
            store
                .read_bridge_wrapper_range(
                    &route.wrapper_envelope_id,
                    ChunkRange::new(0, route.exact_wrapper_bytes.len() as u64).unwrap(),
                    7,
                    Some(bridge_sample(20)),
                )
                .unwrap(),
            route.exact_wrapper_bytes[..7]
        );
        let source_first_peer = [0xd2; 32];
        assert_eq!(
            store
                .filter_unacknowledged_bridge_sources_for_path(
                    source_first_peer,
                    route.wrapper_envelope_id,
                    &[route.route.origin_envelope_id],
                    4,
                )
                .unwrap(),
            vec![route.route.origin_envelope_id]
        );
        store
            .acknowledge_bridge_source_path_peer(
                source_first_peer,
                route.wrapper_envelope_id,
                &[route.route.origin_envelope_id],
                Some(5),
                Some(bridge_sample(20)),
            )
            .unwrap();
        assert!(
            store
                .filter_unacknowledged_bridge_sources_for_path(
                    source_first_peer,
                    route.wrapper_envelope_id,
                    &[route.route.origin_envelope_id],
                    4,
                )
                .unwrap()
                .is_empty()
        );
        assert_eq!(
            store
                .connection
                .query_row(
                    "SELECT count(*) FROM bridge_route_peer_receipts WHERE peer=?1",
                    params![source_first_peer.as_slice()],
                    |row| row.get::<_, i64>(0),
                )
                .unwrap(),
            0
        );
        store
            .acknowledge_bridge_route_peer(
                source_first_peer,
                &[route.wrapper_envelope_id],
                Some(5),
                Some(bridge_sample(20)),
            )
            .unwrap();
        assert!(
            store
                .next_bridge_source_outbound(
                    source_first_peer,
                    4,
                    1_000_000,
                    Some(bridge_sample(20)),
                )
                .unwrap()
                .is_empty()
        );
        store
            .acknowledge_bridge_route_peer(
                peer,
                &[route.wrapper_envelope_id],
                Some(5),
                Some(bridge_sample(20)),
            )
            .unwrap();
        let sources = store
            .next_bridge_source_outbound(peer, 4, 1_000_000, Some(bridge_sample(20)))
            .unwrap();
        assert_eq!(sources.len(), 1);
        assert_eq!(
            store
                .read_bridge_source_range(
                    &route.route.origin_envelope_id,
                    ChunkRange::new(0, route.source.exact_bytes.len() as u64).unwrap(),
                    6,
                    Some(bridge_sample(20)),
                )
                .unwrap(),
            route.source.exact_bytes[..6]
        );
        store
            .acknowledge_bridge_source_peer(
                peer,
                &[route.route.origin_envelope_id],
                Some(5),
                Some(bridge_sample(20)),
            )
            .unwrap();
        assert!(
            store
                .next_bridge_route_outbound(peer, 4, 1_000_000, Some(6), Some(bridge_sample(20)))
                .unwrap()
                .is_empty()
        );
        assert!(
            store
                .next_bridge_source_outbound(peer, 4, 1_000_000, Some(bridge_sample(20)))
                .unwrap()
                .is_empty()
        );
        store
            .connection
            .execute(
                "DELETE FROM bridge_active_routes WHERE wrapper_envelope_id=?1",
                params![route.wrapper_envelope_id.as_slice()],
            )
            .unwrap();
        store
            .connection
            .execute(
                "DELETE FROM bridge_route_outbox WHERE wrapper_envelope_id=?1",
                params![route.wrapper_envelope_id.as_slice()],
            )
            .unwrap();
        assert!(matches!(
            store.delete_bridge_wrapper(&route.wrapper_envelope_id),
            Err(StoreError::BridgeObjectReferenced)
        ));
        store
            .connection
            .execute(
                "DELETE FROM bridge_route_peer_receipts WHERE wrapper_envelope_id=?1",
                params![route.wrapper_envelope_id.as_slice()],
            )
            .unwrap();
        assert!(
            store
                .delete_bridge_wrapper(&route.wrapper_envelope_id)
                .unwrap()
        );
        assert!(matches!(
            store.delete_bridge_source(&route.route.origin_envelope_id),
            Err(StoreError::BridgeObjectReferenced)
        ));

        let mut expired =
            verified_bridge_route(&[&authorization], 0xc2, b"equal-forwarding-age-source");
        expired.source.metadata.ttl_ms = Some(100);
        assert!(matches!(
            store.promote_verified_bridge_route_at(&expired, Some(bridge_sample(1))),
            Err(StoreError::BridgeRouteIneligible)
        ));
    }

    #[test]
    fn bridge_semantic_ledger_rejects_equivocation_and_reduces_target_projection() {
        let mut store = SqliteStore::open_in_memory(StoreConfig::default()).unwrap();
        let authorization = verified_bridge_authorization();
        configure_bridge_epoch(&mut store, "mission/source", 3);
        configure_bridge_epoch(&mut store, "mission/target", 5);
        store.ingest_bridge_authorization(&authorization).unwrap();
        let first = verified_bridge_route(&[&authorization], 0xe1, b"first-semantic-source");
        store
            .promote_verified_bridge_route_at(&first, Some(bridge_sample(10)))
            .unwrap();

        let mut equivocation =
            verified_bridge_route(&[&authorization], 0xe2, b"equivocating-semantic-source");
        equivocation.source.metadata.stamp.dot = first.source.metadata.stamp.dot;
        assert!(matches!(
            store.promote_verified_bridge_route_at(&equivocation, Some(bridge_sample(10))),
            Err(StoreError::Equivocation { .. })
        ));
        assert!(
            store
                .stored_bridge_route(&equivocation.wrapper_envelope_id)
                .unwrap()
                .is_none()
        );

        let mut successor =
            verified_bridge_route(&[&authorization], 0xe3, b"causally-newer-semantic-source");
        successor.source.metadata.stamp.dot = Dot {
            publisher: [0x63; 32],
            counter: 1,
        };
        successor
            .source
            .metadata
            .stamp
            .context
            .observe(first.source.metadata.stamp.dot);
        store
            .promote_verified_bridge_route_at(&successor, Some(bridge_sample(10)))
            .unwrap();
        let route_page = store.stored_bridge_routes_after(None, 1).unwrap();
        assert_eq!(route_page.len(), 1);
        assert_eq!(
            store
                .stored_bridge_routes_after(Some(route_page[0].inserted_order), 1)
                .unwrap()
                .len(),
            1
        );
        let source_page = store.stored_bridge_sources_after(None, 1).unwrap();
        assert_eq!(source_page.len(), 1);
        assert_eq!(
            store
                .stored_bridge_sources_after(Some(source_page[0].inserted_order), 1)
                .unwrap()
                .len(),
            1
        );
        let first_status: i64 = store
            .connection
            .query_row(
                "SELECT version_status FROM bridge_target_projection\n\
                 WHERE wrapper_envelope_id=?1",
                params![first.wrapper_envelope_id.as_slice()],
                |row| row.get(0),
            )
            .unwrap();
        let successor_status: i64 = store
            .connection
            .query_row(
                "SELECT version_status FROM bridge_target_projection\n\
                 WHERE wrapper_envelope_id=?1",
                params![successor.wrapper_envelope_id.as_slice()],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(first_status, VersionStatus::Superseded as u8 as i64);
        assert_eq!(successor_status, VersionStatus::Current as u8 as i64);
    }

    #[test]
    fn recoverable_bridge_projection_falls_back_after_current_expiry_and_revocation() {
        let mut store = SqliteStore::open_in_memory(StoreConfig::default()).unwrap();
        let authorization = verified_bridge_authorization();
        configure_bridge_epoch(&mut store, "mission/source", 3);
        configure_bridge_epoch(&mut store, "mission/target", 5);
        store.ingest_bridge_authorization(&authorization).unwrap();
        let first = verified_bridge_route(&[&authorization], 0xea, b"fallback-first-source");
        store
            .promote_verified_bridge_route_at(&first, Some(bridge_sample(10)))
            .unwrap();
        let mut expiring =
            verified_bridge_route(&[&authorization], 0xeb, b"fallback-expiring-successor");
        expiring.source.metadata.stamp.dot = Dot {
            publisher: [0x63; 32],
            counter: 1,
        };
        expiring
            .source
            .metadata
            .stamp
            .context
            .observe(first.source.metadata.stamp.dot);
        expiring.source.metadata.ttl_ms = Some(150);
        store
            .promote_verified_bridge_route_at(&expiring, Some(bridge_sample(10)))
            .unwrap();
        let query = BridgeProjectionQuery {
            target_scope: Some(first.route.current_scope.clone()),
            target_route_epoch: Some(first.route.current_route_epoch),
            topic: Some(first.source.metadata.topic.clone()),
            class: Some(DataClass::State),
            mutable_classes_only: false,
            acknowledged_subscription: None,
            logical_key: Some(first.source.metadata.logical_key.clone()),
            version_status: None,
            include_tombstones: false,
            custody_sample: Some(bridge_sample(60)),
            limit: Some(8),
        };
        let fallback = store.query_active_bridge_projection(&query).unwrap();
        assert_eq!(fallback.len(), 1);
        assert_eq!(
            fallback[0].source.metadata.source_item_id,
            first.source.metadata.source_item_id
        );
        let subscription = store
            .create_subscription(&SubscriptionSpec {
                topic: first.source.metadata.topic.clone(),
                scope: first.route.current_scope.clone(),
                include_descendant_scopes: false,
                class: Some(DataClass::State),
            })
            .unwrap();
        let candidates = store
            .peek_bridge_projection_subscription_page(subscription, None, Some(bridge_sample(60)))
            .unwrap()
            .entries;
        assert_eq!(candidates.len(), 1);
        assert_eq!(
            candidates[0].source.metadata.source_item_id,
            first.source.metadata.source_item_id
        );

        let mut revoked =
            verified_bridge_route(&[&authorization], 0xec, b"fallback-revoked-successor");
        revoked.source.metadata.stamp.dot = Dot {
            publisher: [0x64; 32],
            counter: 1,
        };
        revoked
            .source
            .metadata
            .stamp
            .context
            .observe(first.source.metadata.stamp.dot);
        store
            .promote_verified_bridge_route_at(&revoked, Some(bridge_sample(10)))
            .unwrap();
        store
            .apply_revocation(&Revocation {
                subject: revoked.source.metadata.stamp.dot.publisher,
                authority: [0x70; 32],
                signer: [0x70; 32],
                generation: 1,
                control_sequence: 1,
                previous_control: None,
                sealed_notice: b"provider-authenticated-revocation".to_vec(),
                observed_at_ms: None,
            })
            .unwrap();
        store.ingest_bridge_authorization(&authorization).unwrap();
        store
            .revalidate_committed_bridge_route_at(&first, Some(bridge_sample(60)))
            .unwrap();
        let fallback = store.query_active_bridge_projection(&query).unwrap();
        assert_eq!(fallback.len(), 1);
        assert_eq!(
            fallback[0].source.metadata.source_item_id,
            first.source.metadata.source_item_id
        );
    }

    #[test]
    fn active_bridge_projection_deduplicates_only_the_matching_target_view() {
        let authorization = verified_bridge_authorization();
        let sample = bridge_sample(10);
        let route =
            verified_bridge_route(&[&authorization], 0xe8, b"direct-origin-and-bridged-target");
        let mut store = SqliteStore::open_in_memory(StoreConfig::default()).unwrap();
        configure_bridge_epoch(&mut store, "mission/source", 3);
        configure_bridge_epoch(&mut store, "mission/target", 5);
        store.ingest_bridge_authorization(&authorization).unwrap();
        store
            .ingest(ordinary_item_from_bridge_source(
                &route,
                route.route.origin_scope.clone(),
                route.route.origin_route_epoch,
                sample,
            ))
            .unwrap();
        store
            .stage_verified_pending_bridge_wrapper(
                &pending_wrapper_from_route(&route),
                Some(sample),
            )
            .unwrap();
        store
            .stage_verified_bridge_source_at(&route.source, Some(sample))
            .unwrap();
        store
            .promote_verified_bridge_route_at(&route, Some(sample))
            .unwrap();
        let projected = store
            .query_active_bridge_projection(&BridgeProjectionQuery {
                target_scope: Some(route.route.current_scope.clone()),
                target_route_epoch: Some(route.route.current_route_epoch),
                topic: Some(route.source.metadata.topic.clone()),
                class: Some(route.source.metadata.class),
                mutable_classes_only: false,
                acknowledged_subscription: None,
                logical_key: Some(route.source.metadata.logical_key.clone()),
                version_status: Some(VersionStatus::Current),
                include_tombstones: false,
                custody_sample: Some(sample),
                limit: Some(8),
            })
            .unwrap();
        assert_eq!(projected.len(), 1);
        assert_eq!(projected[0].source.exact_bytes, route.source.exact_bytes);

        let other_route = verified_bridge_route(&[&authorization], 0xe9, b"ordinary-target-dedup");
        store
            .ingest(ordinary_item_from_bridge_source(
                &other_route,
                other_route.route.current_scope.clone(),
                other_route.route.current_route_epoch,
                sample,
            ))
            .unwrap();
        store
            .promote_verified_bridge_route_at(&other_route, Some(sample))
            .unwrap();
        let deduplicated = store
            .query_active_bridge_projection(&BridgeProjectionQuery {
                target_scope: Some(other_route.route.current_scope.clone()),
                target_route_epoch: Some(other_route.route.current_route_epoch),
                logical_key: Some(other_route.source.metadata.logical_key.clone()),
                custody_sample: Some(sample),
                limit: Some(8),
                ..BridgeProjectionQuery::default()
            })
            .unwrap();
        assert!(
            deduplicated
                .iter()
                .all(|entry| entry.source.metadata.source_item_id
                    != other_route.source.metadata.source_item_id)
        );
    }

    #[test]
    fn legacy_bridge_filter_requires_explicit_topic_and_exact_scopes() {
        let mut store = SqliteStore::open_in_memory(StoreConfig::default()).unwrap();
        assert!(matches!(
            store.replace_bridge_filters(&[BridgeFilter {
                from_scope: Scope::new("mission/source").unwrap(),
                to_scope: Scope::new("mission/target").unwrap(),
                topics: BTreeSet::new(),
                minimum_priority: Priority::Routine,
            }]),
            Err(StoreError::Invalid(_))
        ));
        let topic = Topic::new("orders").unwrap();
        store
            .replace_bridge_filters(&[BridgeFilter {
                from_scope: Scope::new("mission/source").unwrap(),
                to_scope: Scope::new("mission/target").unwrap(),
                topics: BTreeSet::from([topic.clone()]),
                minimum_priority: Priority::Routine,
            }])
            .unwrap();
        assert!(
            store
                .bridge_allows(
                    &Scope::new("mission/source").unwrap(),
                    &Scope::new("mission/target").unwrap(),
                    &topic,
                    Priority::Immediate,
                )
                .unwrap()
        );
        assert!(
            !store
                .bridge_allows(
                    &Scope::new("mission/source").unwrap(),
                    &Scope::new("mission/target").unwrap(),
                    &Topic::new("other").unwrap(),
                    Priority::Immediate,
                )
                .unwrap()
        );
        assert!(
            !store
                .bridge_allows(
                    &Scope::new("mission/source/team-a").unwrap(),
                    &Scope::new("mission/target").unwrap(),
                    &topic,
                    Priority::Immediate,
                )
                .unwrap()
        );
        assert!(
            !store
                .bridge_allows(
                    &Scope::new("mission/source").unwrap(),
                    &Scope::new("mission/target/team-b").unwrap(),
                    &topic,
                    Priority::Immediate,
                )
                .unwrap()
        );
    }

    #[test]
    fn accepted_dot_survives_item_gc_and_store_reopen() {
        let path = std::env::temp_dir().join(format!(
            "aster-ledger-{}-{}.sqlite3",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let sample0 = CustodySample {
            clock_id: [1; 16],
            tick_ms: 0,
        };
        let item = test_item(1, 1, Some(10), 0, Some(sample0));
        {
            let mut store = SqliteStore::open(&path, StoreConfig::default()).unwrap();
            assert!(matches!(
                store.ingest(item.clone()).unwrap(),
                ApplyOutcome::Inserted { .. }
            ));
            assert_eq!(
                store
                    .collect_garbage(
                        None,
                        Some(CustodySample {
                            clock_id: [1; 16],
                            tick_ms: 11,
                        }),
                    )
                    .unwrap(),
                vec![item.id]
            );
        }
        {
            let mut store = SqliteStore::open(&path, StoreConfig::default()).unwrap();
            assert!(matches!(
                store.ingest(item.clone()).unwrap(),
                ApplyOutcome::Duplicate { .. }
            ));
            assert!(store.get(&item.id).unwrap().is_none());
            let mut equivocation = test_item(2, 1, None, 0, Some(sample0));
            equivocation.stamp.dot.publisher = item.publisher();
            assert!(matches!(
                store.ingest(equivocation),
                Err(StoreError::Equivocation { .. })
            ));
        }
        let _ = fs::remove_file(&path);
        let _ = fs::remove_file(path.with_extension("sqlite3-wal"));
        let _ = fs::remove_file(path.with_extension("sqlite3-shm"));
    }

    #[test]
    fn typed_transfer_ranges_survive_reopen_without_peer_identity() {
        let path = std::env::temp_dir().join(format!(
            "aster-transfer-{}-{}.sqlite3",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let object_id = ObjectId::for_blob_chunk_digest([0x5a; 32]);
        {
            let mut store = SqliteStore::open(&path, StoreConfig::default()).unwrap();
            store
                .begin_transfer(object_id, 12, Priority::Routine, Some(1))
                .unwrap();
            store
                .put_sealed_chunk(transfer_storage_key(object_id), 12, 0, b"abc", Some(2))
                .unwrap();
            store
                .put_sealed_chunk(transfer_storage_key(object_id), 12, 7, b"xy", Some(3))
                .unwrap();
        }
        {
            let mut reopened = SqliteStore::open(&path, StoreConfig::default()).unwrap();
            assert_eq!(
                reopened.transfer_progress(1).unwrap(),
                vec![TransferProgress {
                    object_id,
                    origin_semantic_version: None,
                    total_len: 12,
                    received: vec![
                        ChunkRange { start: 0, end: 3 },
                        ChunkRange { start: 7, end: 9 },
                    ],
                }]
            );
            assert_eq!(
                reopened
                    .missing_ranges(&transfer_storage_key(object_id), 8)
                    .unwrap(),
                vec![
                    ChunkRange { start: 3, end: 7 },
                    ChunkRange { start: 9, end: 12 },
                ]
            );
        }
        let _ = fs::remove_file(&path);
        let _ = fs::remove_file(path.with_extension("sqlite3-wal"));
        let _ = fs::remove_file(path.with_extension("sqlite3-shm"));
    }

    #[test]
    fn hostile_typed_partials_are_bounded_without_evicting_committed_items() {
        let committed = test_item(0x31, 1, None, 0, None);
        let config = StoreConfig {
            max_items: 100,
            max_bytes: committed.accounted_bytes().saturating_mul(2),
            ..StoreConfig::default()
        };
        let stage_limit = staging_byte_limit(&config);
        assert!(stage_limit > 2);
        let mut store = SqliteStore::open_in_memory(config.clone()).unwrap();
        assert!(matches!(
            store.ingest(committed.clone()).unwrap(),
            ApplyOutcome::Inserted { .. }
        ));

        let oversized = ObjectId::for_blob_chunk_digest([0x40; 32]);
        assert!(matches!(
            store.begin_transfer(
                oversized,
                staged_object_byte_limit(&config).saturating_add(1),
                Priority::Routine,
                None,
            ),
            Err(StoreError::Invalid(_))
        ));

        let blob = ObjectId::for_blob_chunk_digest([0x41; 32]);
        store
            .begin_transfer(blob, stage_limit, Priority::Routine, Some(1))
            .unwrap();
        store
            .put_sealed_chunk(
                transfer_storage_key(blob),
                stage_limit,
                0,
                &vec![0xa5; usize::try_from(stage_limit - 1).unwrap()],
                Some(2),
            )
            .unwrap();
        let source = ObjectId::for_envelope(crate::wire::EnvelopeId::from_bytes([0x42; 32]));
        store
            .begin_transfer(source, 2, Priority::Routine, Some(3))
            .unwrap();
        assert!(matches!(
            store.put_sealed_chunk(transfer_storage_key(source), 2, 0, &[0x11, 0x22], Some(4),),
            Err(StoreError::QuotaExceeded)
        ));
        assert!(store.get(&committed.id).unwrap().is_some());
        store.abort_transfer(source).unwrap();
        store.abort_transfer(blob).unwrap();

        store
            .begin_transfer(source, stage_limit, Priority::Routine, Some(5))
            .unwrap();
        store
            .put_sealed_chunk(
                transfer_storage_key(source),
                stage_limit,
                0,
                &vec![0x5a; usize::try_from(stage_limit - 1).unwrap()],
                Some(6),
            )
            .unwrap();
        let second_blob = ObjectId::for_blob_chunk_digest([0x43; 32]);
        store
            .begin_transfer(second_blob, 2, Priority::Routine, Some(7))
            .unwrap();
        assert!(matches!(
            store.put_sealed_chunk(
                transfer_storage_key(second_blob),
                2,
                0,
                &[0x33, 0x44],
                Some(8),
            ),
            Err(StoreError::QuotaExceeded)
        ));
        assert!(store.get(&committed.id).unwrap().is_some());
        assert_eq!(store.quota_usage(None).unwrap().items, 1);

        store.abort_transfer(second_blob).unwrap();
        store.abort_transfer(source).unwrap();
        assert!(store.transfer_progress(16).unwrap().is_empty());
        assert_eq!(
            store.quota_usage(None).unwrap().bytes,
            committed.accounted_bytes()
        );
    }

    #[test]
    fn custody_age_is_monotonic_and_restart_without_continuity_withholds() {
        let first = CustodySample {
            clock_id: [2; 16],
            tick_ms: 5,
        };
        let mut store = SqliteStore::open_in_memory(StoreConfig::default()).unwrap();
        let item = test_item(3, 1, Some(100), 20, Some(first));
        store.ingest(item.clone()).unwrap();
        let peer = [8; 32];
        let later = CustodySample {
            clock_id: first.clock_id,
            tick_ms: 35,
        };
        let emitted = store
            .next_outbound(peer, Priority::Routine, 1, u64::MAX, None, Some(later))
            .unwrap();
        assert_eq!(emitted[0].custody_age_ms, 50);
        let restarted = CustodySample {
            clock_id: [3; 16],
            tick_ms: 0,
        };
        assert!(
            store
                .next_outbound(peer, Priority::Routine, 1, u64::MAX, None, Some(restarted))
                .unwrap()
                .is_empty()
        );
        let retained = store.get(&item.id).unwrap().unwrap();
        assert_eq!(retained.custody_age_ms, 50);
        assert!(!retained.custody_elapsed_available);
        assert!(store.collect_garbage(None, None).unwrap().is_empty());

        let below_ttl = test_item(4, 1, Some(100), 99, None);
        assert!(!below_ttl.is_expired_at(None));
        assert!(!below_ttl.is_forwardable_at(None));

        let at_ttl = test_item(5, 1, Some(100), 100, None);
        assert!(at_ttl.is_expired_at(None));
        assert!(!at_ttl.is_forwardable_at(None));

        let mut durable_tombstone = test_item(6, 1, Some(0), u64::MAX, None);
        durable_tombstone.tombstone = true;
        assert!(!durable_tombstone.is_expired_at(None));
        assert!(durable_tombstone.is_forwardable_at(None));
    }

    #[test]
    fn lower_bound_legacy_fields_preserve_lost_anchor_across_restart() {
        let first_clock = [0x91; 16];
        let later_clock = [0x92; 16];
        let mut age = custody_age_from_legacy_fields(10, false, Some(first_clock), Some(100), true);
        assert_eq!(
            age.checkpoint(Some(CustodySample {
                clock_id: later_clock,
                tick_ms: 1_000,
            })),
            Err(crate::custody::CustodyError::ContinuityUnavailable)
        );

        let fields = custody_fields_from_age(age);
        assert_eq!(fields, (10, true, Some(later_clock), Some(1_000), true));
        let mut reopened =
            custody_age_from_legacy_fields(fields.0, fields.1, fields.2, fields.3, fields.4);
        assert_eq!(
            reopened.checkpoint(Some(CustodySample {
                clock_id: later_clock,
                tick_ms: 1_019,
            })),
            Err(crate::custody::CustodyError::ContinuityUnavailable)
        );

        let persisted = custody_fields_from_age(reopened);
        assert_eq!(persisted, (29, true, Some(later_clock), Some(1_019), true));
        let reconstructed = custody_age_from_legacy_fields(
            persisted.0,
            persisted.1,
            persisted.2,
            persisted.3,
            persisted.4,
        );
        assert_eq!(reconstructed.cumulative_age_ms(), 29);
        assert_eq!(reconstructed.continuity(), CustodyContinuity::Lost);
        assert_eq!(
            reconstructed.checkpoint_sample(),
            Some(CustodySample {
                clock_id: later_clock,
                tick_ms: 1_019,
            })
        );
    }

    #[test]
    fn lower_bound_duplicate_merge_and_missing_sample_stay_monotone() {
        let clock_b = [0xa1; 16];
        let clock_c = [0xa2; 16];
        let mut fields = (10, true, Some(clock_b), Some(1_000), true);

        fields = merge_authenticated_custody_fields(
            Some(fields),
            8,
            Some(CustodySample {
                clock_id: clock_b,
                tick_ms: 1_010,
            }),
        );
        assert_eq!(fields, (20, true, Some(clock_b), Some(1_010), true));
        fields = merge_authenticated_custody_fields(
            Some(fields),
            50,
            Some(CustodySample {
                clock_id: clock_b,
                tick_ms: 1_015,
            }),
        );
        assert_eq!(fields, (50, true, Some(clock_b), Some(1_015), true));
        fields = merge_authenticated_custody_fields(Some(fields), 7, None);
        assert_eq!(fields, (50, true, None, None, false));
        fields = merge_authenticated_custody_fields(
            Some(fields),
            7,
            Some(CustodySample {
                clock_id: clock_c,
                tick_ms: 5_000,
            }),
        );
        assert_eq!(fields, (50, true, Some(clock_c), Some(5_000), true));
        fields = merge_authenticated_custody_fields(
            Some(fields),
            7,
            Some(CustodySample {
                clock_id: clock_c,
                tick_ms: 5_006,
            }),
        );
        assert_eq!(fields, (56, true, Some(clock_c), Some(5_006), true));
    }

    #[test]
    fn stale_duplicate_cannot_move_the_persisted_custody_anchor_backward() {
        let clock = [0xa3; 16];
        let initial = CustodySample {
            clock_id: clock,
            tick_ms: 1_000,
        };
        let mut store = SqliteStore::open_in_memory(StoreConfig::default()).unwrap();
        let item = test_item(0xa4, 1, Some(100), 10, Some(initial));
        store.ingest(item.clone()).unwrap();

        let first_peer = [0xa5; 32];
        let high_water = CustodySample {
            clock_id: clock,
            tick_ms: 1_010,
        };
        let emitted = store
            .next_outbound(
                first_peer,
                Priority::Routine,
                1,
                u64::MAX,
                None,
                Some(high_water),
            )
            .unwrap();
        assert_eq!(emitted[0].custody_age_ms, 20);

        let mut stale_duplicate = item.clone();
        stale_duplicate.custody_age_ms = 15;
        stale_duplicate.custody_tick_ms = Some(1_005);
        assert!(matches!(
            store.ingest(stale_duplicate).unwrap(),
            ApplyOutcome::Duplicate { .. }
        ));

        let later = CustodySample {
            clock_id: clock,
            tick_ms: 1_020,
        };
        assert!(
            store
                .next_outbound(
                    [0xa6; 32],
                    Priority::Routine,
                    1,
                    u64::MAX,
                    None,
                    Some(later),
                )
                .unwrap()
                .is_empty(),
            "the stale sample remains fail-closed after continuity loss"
        );
        let retained = store.get(&item.id).unwrap().unwrap();
        assert_eq!(retained.custody_age_ms, 30);
        assert_eq!(retained.custody_clock_id, Some(clock));
        assert_eq!(retained.custody_tick_ms, Some(1_020));
        assert!(!retained.custody_elapsed_available);
    }

    #[test]
    fn lower_bound_ordinary_fields_reanchor_without_restoring_continuity() {
        let mut age_ms = 10;
        let mut clock_id = Some([0xb1; 16]);
        let mut tick_ms = Some(100);
        let mut elapsed_available = true;

        advance_custody_fields(
            Some(100),
            &mut age_ms,
            &mut clock_id,
            &mut tick_ms,
            &mut elapsed_available,
            Some(CustodySample {
                clock_id: [0xb2; 16],
                tick_ms: 1_000,
            }),
        );
        assert_eq!(
            (age_ms, clock_id, tick_ms, elapsed_available),
            (10, Some([0xb2; 16]), Some(1_000), false,)
        );
        advance_custody_fields(
            Some(100),
            &mut age_ms,
            &mut clock_id,
            &mut tick_ms,
            &mut elapsed_available,
            Some(CustodySample {
                clock_id: [0xb2; 16],
                tick_ms: 1_009,
            }),
        );
        assert_eq!(
            (age_ms, clock_id, tick_ms, elapsed_available),
            (19, Some([0xb2; 16]), Some(1_009), false,)
        );
    }

    #[test]
    fn typed_transfer_origin_provenance_is_immutable_but_allows_safe_resume() {
        let mut store = SqliteStore::open_in_memory(StoreConfig::default()).unwrap();
        let blob = ObjectId::new(ObjectKind::BlobChunk, [0xf0; 32]);
        store
            .begin_transfer_for_semantic_version(blob, 8, Priority::Routine, Some(1), 2)
            .unwrap();
        let blob_key = transfer_storage_key(blob);
        store
            .put_sealed_chunk(blob_key, 8, 0, &[1, 2, 3], Some(2))
            .unwrap();
        let before = store.missing_ranges(&blob_key, 8).unwrap();
        store
            .begin_transfer_for_semantic_version(blob, 8, Priority::Immediate, Some(3), 1)
            .unwrap();
        store
            .begin_transfer_for_semantic_version(blob, 8, Priority::Flash, Some(4), 3)
            .unwrap();
        store
            .begin_transfer_for_semantic_version(blob, 8, Priority::Flash, Some(5), 4)
            .unwrap();
        assert_eq!(store.missing_ranges(&blob_key, 8).unwrap(), before);
        assert_eq!(
            store.transfer_progress(8).unwrap()[0].origin_semantic_version,
            Some(2)
        );

        let source_v1 = ObjectId::new(ObjectKind::SourceEnvelope, [0xf1; 32]);
        store
            .begin_transfer_for_semantic_version(source_v1, 8, Priority::Routine, None, 1)
            .unwrap();
        store
            .begin_transfer_for_semantic_version(source_v1, 8, Priority::Routine, None, 2)
            .unwrap();
        store
            .begin_transfer_for_semantic_version(source_v1, 8, Priority::Routine, None, 4)
            .unwrap();
        let source_v2 = ObjectId::new(ObjectKind::SourceEnvelope, [0xf2; 32]);
        store
            .begin_transfer_for_semantic_version(source_v2, 8, Priority::Routine, None, 2)
            .unwrap();
        store
            .begin_transfer_for_semantic_version(source_v2, 8, Priority::Immediate, None, 3)
            .unwrap();
        store
            .begin_transfer_for_semantic_version(source_v2, 8, Priority::Immediate, None, 4)
            .unwrap();
        let source_v2_key = transfer_storage_key(source_v2);
        store
            .put_sealed_chunk(source_v2_key, 8, 0, &[9, 8], None)
            .unwrap();
        let before = store.missing_ranges(&source_v2_key, 8).unwrap();
        assert!(matches!(
            store.begin_transfer_for_semantic_version(
                source_v2,
                8,
                Priority::Immediate,
                Some(99),
                1
            ),
            Err(StoreError::Invalid(_))
        ));
        assert_eq!(store.missing_ranges(&source_v2_key, 8).unwrap(), before);

        let source_v3 = ObjectId::new(ObjectKind::SourceEnvelope, [0xf4; 32]);
        store
            .begin_transfer_for_semantic_version(source_v3, 8, Priority::Routine, None, 3)
            .unwrap();
        store
            .begin_transfer_for_semantic_version(source_v3, 8, Priority::Immediate, None, 2)
            .unwrap();
        store
            .begin_transfer_for_semantic_version(source_v3, 8, Priority::Immediate, None, 4)
            .unwrap();
        let proof_v3 = ObjectId::new(ObjectKind::SourceBatchProof, [0xf5; 32]);
        store
            .begin_transfer_for_semantic_version(proof_v3, 8, Priority::Routine, None, 3)
            .unwrap();
        store
            .begin_transfer_for_semantic_version(proof_v3, 8, Priority::Immediate, None, 2)
            .unwrap();
        store
            .begin_transfer_for_semantic_version(proof_v3, 8, Priority::Immediate, None, 4)
            .unwrap();

        let proof_v4 = ObjectId::new(ObjectKind::SourceBatchProof, [0xf6; 32]);
        store
            .begin_transfer_for_semantic_version(proof_v4, 8, Priority::Routine, None, 4)
            .unwrap();
        store
            .begin_transfer_for_semantic_version(proof_v4, 8, Priority::Immediate, None, 2)
            .unwrap();
        store
            .begin_transfer_for_semantic_version(proof_v4, 8, Priority::Immediate, None, 5)
            .unwrap();
        store
            .begin_transfer_for_semantic_version(proof_v4, 8, Priority::Immediate, None, 6)
            .unwrap();
        store
            .begin_transfer_for_semantic_version(proof_v4, 8, Priority::Immediate, None, 7)
            .unwrap();
        assert!(matches!(
            store.begin_transfer_for_semantic_version(proof_v4, 8, Priority::Immediate, None, 8),
            Err(StoreError::Invalid(_))
        ));

        let unknown = ObjectId::new(ObjectKind::SourceEnvelope, [0xf3; 32]);
        store
            .begin_transfer(unknown, 8, Priority::Routine, None)
            .unwrap();
        assert!(matches!(
            store.begin_transfer_for_semantic_version(unknown, 8, Priority::Routine, None, 1),
            Err(StoreError::Invalid(_))
        ));
        assert!(
            store
                .transfer_progress(16)
                .unwrap()
                .iter()
                .any(|progress| progress.object_id == unknown
                    && progress.origin_semantic_version.is_none())
        );
    }

    #[test]
    fn version_aware_transfer_hydration_filters_before_limit() {
        let mut store = SqliteStore::open_in_memory(StoreConfig::default()).unwrap();
        for byte in 1..=4 {
            store
                .begin_transfer_for_semantic_version(
                    ObjectId::new(ObjectKind::SourceEnvelope, [byte; 32]),
                    8,
                    Priority::Routine,
                    None,
                    2,
                )
                .unwrap();
        }
        let blob = ObjectId::new(ObjectKind::BlobChunk, [0xff; 32]);
        store
            .begin_transfer_for_semantic_version(blob, 8, Priority::Routine, None, 2)
            .unwrap();
        assert_eq!(
            store
                .transfer_progress_for_semantic_version(1, 1)
                .unwrap()
                .into_iter()
                .map(|progress| progress.object_id)
                .collect::<Vec<_>>(),
            vec![blob]
        );
        assert_eq!(
            store
                .transfer_progress_for_semantic_version(3, 16)
                .unwrap()
                .len(),
            5
        );
        assert_eq!(
            store
                .transfer_progress_for_semantic_version(4, 16)
                .unwrap()
                .len(),
            5
        );
        assert_eq!(
            store
                .transfer_progress_for_semantic_version(5, 16)
                .unwrap()
                .len(),
            5
        );
        assert_eq!(
            store
                .transfer_progress_for_semantic_version(6, 16)
                .unwrap()
                .len(),
            5
        );
        assert_eq!(
            store
                .transfer_progress_for_semantic_version(7, 16)
                .unwrap()
                .len(),
            5
        );
        assert!(store.transfer_progress_for_semantic_version(8, 16).is_err());
    }

    #[test]
    fn ttl_free_bridge_route_revalidates_across_clock_restart_but_finite_ttl_fails_closed() {
        let authorization = verified_bridge_authorization();
        let mut store = SqliteStore::open_in_memory(StoreConfig::default()).unwrap();
        configure_bridge_epoch(&mut store, "mission/source", 3);
        configure_bridge_epoch(&mut store, "mission/target", 5);
        store.ingest_bridge_authorization(&authorization).unwrap();
        let route = verified_bridge_route(&[&authorization], 0xd1, b"restart-no-ttl-source");
        store
            .promote_verified_bridge_route_at(&route, Some(bridge_sample(10)))
            .unwrap();
        store.clear_bridge_process_liveness();
        store.ingest_bridge_authorization(&authorization).unwrap();
        let restarted = CustodySample {
            clock_id: [0x55; 16],
            tick_ms: 1,
        };
        store
            .revalidate_committed_bridge_route_at(&route, Some(restarted))
            .unwrap();
        assert!(
            store
                .bridge_route_is_live_at(&route.wrapper_envelope_id, Some(restarted))
                .unwrap()
        );

        let mut finite =
            verified_bridge_route(&[&authorization], 0xd2, b"restart-finite-ttl-source");
        finite.source.metadata.ttl_ms = Some(1_000);
        store
            .promote_verified_bridge_route_at(&finite, Some(bridge_sample(10)))
            .unwrap();
        store.clear_bridge_process_liveness();
        store.ingest_bridge_authorization(&authorization).unwrap();
        assert!(matches!(
            store.revalidate_committed_bridge_route_at(&finite, Some(restarted)),
            Err(StoreError::BridgeRouteIneligible)
        ));
    }

    #[test]
    fn bridge_path_replacement_preserves_active_age_and_ignores_stale_active_rank() {
        let authorization = verified_bridge_authorization();
        let sample = bridge_sample(10);
        let a = verified_bridge_route(&[&authorization], 0xd6, b"age-monotonic-source");
        let b = verified_bridge_route(&[&authorization], 0xd7, b"age-monotonic-source");
        let (mut active, mut better) = if a.route.bridge_route_id > b.route.bridge_route_id {
            (a, b)
        } else {
            (b, a)
        };
        active.source.metadata.ttl_ms = Some(1_000);
        better.source.metadata.ttl_ms = Some(1_000);
        let mut store = SqliteStore::open_in_memory(StoreConfig::default()).unwrap();
        configure_bridge_epoch(&mut store, "mission/source", 3);
        configure_bridge_epoch(&mut store, "mission/target", 5);
        store.ingest_bridge_authorization(&authorization).unwrap();
        store
            .promote_verified_bridge_route_at(&active, Some(sample))
            .unwrap();
        store
            .connection
            .execute(
                "UPDATE bridge_route_wrappers SET cumulative_custody_age_ms=700\n\
                 WHERE wrapper_envelope_id=?1",
                params![active.wrapper_envelope_id.as_slice()],
            )
            .unwrap();
        assert!(matches!(
            store
                .promote_verified_bridge_route_at(&better, Some(sample))
                .unwrap(),
            BridgeRouteOutcome::Active {
                replaced: Some(id), ..
            } if id == active.wrapper_envelope_id
        ));
        assert!(
            store
                .stored_bridge_route(&better.wrapper_envelope_id)
                .unwrap()
                .unwrap()
                .cumulative_custody_age_ms
                >= 700
        );

        let c = verified_bridge_route(&[&authorization], 0xd8, b"stale-active-source");
        let d = verified_bridge_route(&[&authorization], 0xd9, b"stale-active-source");
        let (shorter_rank, worse_rank) = if c.route.bridge_route_id < d.route.bridge_route_id {
            (c, d)
        } else {
            (d, c)
        };
        store
            .promote_verified_bridge_route_at(&shorter_rank, Some(sample))
            .unwrap();
        store
            .verified_bridge_routes
            .remove(&shorter_rank.wrapper_envelope_id);
        assert!(matches!(
            store
                .promote_verified_bridge_route_at(&worse_rank, Some(sample))
                .unwrap(),
            BridgeRouteOutcome::Active {
                replaced: Some(id), ..
            } if id == shorter_rank.wrapper_envelope_id
        ));
    }

    #[test]
    fn bridge_gc_removes_expired_last_reference_but_preserves_control_highwater() {
        let authorization = verified_bridge_authorization();
        let mut route = verified_bridge_route(&[&authorization], 0xda, b"expired-gc-source");
        route.source.metadata.ttl_ms = Some(150);
        let mut store = SqliteStore::open_in_memory(StoreConfig::default()).unwrap();
        configure_bridge_epoch(&mut store, "mission/source", 3);
        configure_bridge_epoch(&mut store, "mission/target", 5);
        store.ingest_bridge_authorization(&authorization).unwrap();
        store
            .promote_verified_bridge_route_at(&route, Some(bridge_sample(10)))
            .unwrap();
        let report = store
            .collect_bridge_garbage(Some(bridge_sample(60)), 8)
            .unwrap();
        assert_eq!(report.mappings, 1);
        assert_eq!(report.wrappers, 1);
        assert_eq!(report.sources, 1);
        assert!(
            store
                .stored_bridge_route(&route.wrapper_envelope_id)
                .unwrap()
                .is_none()
        );
        assert!(
            store
                .stored_bridge_source(&route.route.origin_envelope_id)
                .unwrap()
                .is_none()
        );
        assert_eq!(
            store
                .connection
                .query_row(
                    "SELECT count(*) FROM bridge_authorization_highwater\n\
                     WHERE authorization_key=?1",
                    params![authorization.authorization.authorization_key.as_slice()],
                    |row| row.get::<_, i64>(0),
                )
                .unwrap(),
            1
        );
        assert!(
            store
                .stored_bridge_authorization(&authorization.envelope_id)
                .unwrap()
                .is_some()
        );
    }

    #[test]
    fn bridge_gc_deletes_shared_source_only_after_final_mapping() {
        let authorization = verified_bridge_authorization();
        let first = verified_bridge_route(&[&authorization], 0xdb, b"shared-gc-source");
        let second = verified_bridge_route(&[&authorization], 0xdc, b"shared-gc-source");
        let mut store = SqliteStore::open_in_memory(StoreConfig::default()).unwrap();
        configure_bridge_epoch(&mut store, "mission/source", 3);
        configure_bridge_epoch(&mut store, "mission/target", 5);
        store.ingest_bridge_authorization(&authorization).unwrap();
        store
            .promote_verified_bridge_route_at(&first, Some(bridge_sample(10)))
            .unwrap();
        store
            .promote_verified_bridge_route_at(&second, Some(bridge_sample(10)))
            .unwrap();
        {
            let transaction = store.connection.transaction().unwrap();
            let removed = evict_bridge_mapping_tx(&transaction, first.wrapper_envelope_id).unwrap();
            assert_eq!(removed.wrappers, 1);
            assert_eq!(removed.sources, 0);
            transaction.commit().unwrap();
        }
        assert!(
            store
                .stored_bridge_source(&first.route.origin_envelope_id)
                .unwrap()
                .is_some()
        );
        {
            let transaction = store.connection.transaction().unwrap();
            let removed =
                evict_bridge_mapping_tx(&transaction, second.wrapper_envelope_id).unwrap();
            assert_eq!(removed.wrappers, 1);
            assert_eq!(removed.sources, 1);
            transaction.commit().unwrap();
        }
        assert!(
            store
                .stored_bridge_source(&first.route.origin_envelope_id)
                .unwrap()
                .is_none()
        );
    }

    #[test]
    fn bridge_gc_activates_live_alternate_and_never_evicts_unaged_tombstone() {
        let authorization = verified_bridge_authorization();
        let a = verified_bridge_route(&[&authorization], 0xe4, b"gc-alternate-source");
        let b = verified_bridge_route(&[&authorization], 0xe5, b"gc-alternate-source");
        let (mut active, mut alternate) = if a.route.bridge_route_id < b.route.bridge_route_id {
            (a, b)
        } else {
            (b, a)
        };
        active.source.metadata.ttl_ms = Some(1_000);
        alternate.source.metadata.ttl_ms = Some(1_000);
        let mut store = SqliteStore::open_in_memory(StoreConfig::default()).unwrap();
        configure_bridge_epoch(&mut store, "mission/source", 3);
        configure_bridge_epoch(&mut store, "mission/target", 5);
        store.ingest_bridge_authorization(&authorization).unwrap();
        store
            .promote_verified_bridge_route_at(&active, Some(bridge_sample(10)))
            .unwrap();
        store
            .promote_verified_bridge_route_at(&alternate, Some(bridge_sample(10)))
            .unwrap();
        store
            .connection
            .execute(
                "UPDATE bridge_route_wrappers SET age_continuity_unknown=1,\n\
                   custody_clock_id=NULL,custody_tick_ms=NULL,custody_elapsed_available=0\n\
                 WHERE wrapper_envelope_id=?1",
                params![active.wrapper_envelope_id.as_slice()],
            )
            .unwrap();
        let report = store
            .collect_bridge_garbage(Some(bridge_sample(10)), 8)
            .unwrap();
        assert_eq!(report.wrappers, 1);
        assert_eq!(
            store
                .active_bridge_route_at(
                    &alternate.route.origin_envelope_id,
                    &alternate.route.current_scope,
                    alternate.route.current_route_epoch,
                    Some(bridge_sample(10)),
                )
                .unwrap()
                .unwrap()
                .wrapper_envelope_id,
            alternate.wrapper_envelope_id
        );

        let mut tombstone =
            verified_bridge_route(&[&authorization], 0xe6, b"retained-bridge-tombstone");
        tombstone.source.metadata.tombstone = true;
        tombstone.source.metadata.ttl_ms = Some(0);
        store
            .promote_verified_bridge_route_at(&tombstone, Some(bridge_sample(10)))
            .unwrap();
        {
            let transaction = store.connection.transaction().unwrap();
            evict_bridge_mappings_for_quota_tx(&transaction, None, 0, 0).unwrap();
            transaction.commit().unwrap();
        }
        let stored_tombstone = store
            .stored_bridge_route(&tombstone.wrapper_envelope_id)
            .unwrap()
            .unwrap();
        assert!(stored_tombstone.tombstone);
        assert_eq!(stored_tombstone.ttl_ms, Some(0));
        assert!(
            store
                .bridge_route_is_live_at(&tombstone.wrapper_envelope_id, None)
                .unwrap()
        );
        assert!(
            store
                .stored_bridge_source(&tombstone.route.origin_envelope_id)
                .unwrap()
                .is_some()
        );
    }

    #[test]
    fn bridge_quota_evicts_lower_priority_mapping_before_higher_priority() {
        let authorization = verified_bridge_authorization();
        let mut lower = verified_bridge_route(&[&authorization], 0xdd, b"quota-low-source");
        lower.source.metadata.priority = Priority::Priority;
        let mut higher = verified_bridge_route(&[&authorization], 0xde, b"quota-high-source");
        higher.source.metadata.priority = Priority::Flash;
        let mut store = SqliteStore::open_in_memory(StoreConfig::default()).unwrap();
        configure_bridge_epoch(&mut store, "mission/source", 3);
        configure_bridge_epoch(&mut store, "mission/target", 5);
        store.ingest_bridge_authorization(&authorization).unwrap();
        store
            .promote_verified_bridge_route_at(&lower, Some(bridge_sample(10)))
            .unwrap();
        store
            .promote_verified_bridge_route_at(&higher, Some(bridge_sample(10)))
            .unwrap();
        let transaction = store.connection.transaction().unwrap();
        let usage = committed_usage_tx(&transaction, None).unwrap();
        evict_bridge_mappings_for_quota_tx(
            &transaction,
            None,
            usage.items.saturating_sub(1),
            usage.bytes,
        )
        .unwrap();
        transaction.commit().unwrap();
        assert!(
            store
                .stored_bridge_route(&lower.wrapper_envelope_id)
                .unwrap()
                .is_none()
        );
        assert!(
            store
                .stored_bridge_route(&higher.wrapper_envelope_id)
                .unwrap()
                .is_some()
        );
    }

    #[test]
    fn semantic_delivery_ack_survives_bridge_path_replacement_and_direct_arrival() {
        let authorization = verified_bridge_authorization();
        let sample = bridge_sample(10);
        let source_bytes = b"shared-delivery-source";
        let first = verified_bridge_route(&[&authorization], 0xd3, source_bytes);
        let replacement = verified_bridge_route(&[&authorization], 0xd4, source_bytes);
        assert_ne!(first.wrapper_envelope_id, replacement.wrapper_envelope_id);
        let mut store = SqliteStore::open_in_memory(StoreConfig::default()).unwrap();
        configure_bridge_epoch(&mut store, "mission/source", 3);
        configure_bridge_epoch(&mut store, "mission/target", 5);
        store.ingest_bridge_authorization(&authorization).unwrap();
        store
            .promote_verified_bridge_route_at(&first, Some(sample))
            .unwrap();
        let subscription = store
            .create_subscription(&SubscriptionSpec {
                topic: first.source.metadata.topic.clone(),
                scope: first.route.current_scope.clone(),
                include_descendant_scopes: false,
                class: Some(first.source.metadata.class),
            })
            .unwrap();
        let page = store
            .peek_bridge_projection_subscription_page(subscription, None, Some(sample))
            .unwrap();
        assert_eq!(page.entries.len(), 1);
        let opened = ProviderOpenedBridgeProjection::from_provider(page.entries[0].clone());
        let delivery = store
            .record_bridge_projection_deliveries(subscription, &[opened], Some(20), Some(sample))
            .unwrap();
        assert_eq!(delivery[0].delivery_attempt, 1);
        store
            .acknowledge_bridge_projection_delivery(
                subscription,
                first.source.metadata.source_item_id,
                Some(21),
            )
            .unwrap();
        {
            let transaction = store.connection.transaction().unwrap();
            evict_bridge_mapping_tx(&transaction, first.wrapper_envelope_id).unwrap();
            transaction.commit().unwrap();
        }
        let wrapper: Option<Vec<u8>> = store
            .connection
            .query_row(
                "SELECT wrapper_envelope_id FROM semantic_app_deliveries\n\
                 WHERE subscription_id=?1 AND item_id=?2",
                params![
                    sql_u64(subscription.0, "subscription id").unwrap(),
                    first.source.metadata.source_item_id.as_slice()
                ],
                |row| row.get(0),
            )
            .unwrap();
        assert!(wrapper.is_none());
        store
            .promote_verified_bridge_route_at(&replacement, Some(sample))
            .unwrap();
        assert!(
            store
                .peek_bridge_projection_subscription_page(subscription, None, Some(sample))
                .unwrap()
                .entries
                .is_empty()
        );
        let acknowledged = store
            .peek_acknowledged_bridge_projection_subscription_page(subscription, None, Some(sample))
            .unwrap();
        assert_eq!(acknowledged.entries.len(), 1);
        assert_eq!(
            acknowledged.entries[0].source.metadata.source_item_id,
            first.source.metadata.source_item_id
        );

        let target_item = ordinary_item_from_bridge_source(
            &replacement,
            replacement.route.current_scope.clone(),
            replacement.route.current_route_epoch,
            sample,
        );
        assert!(matches!(
            store.ingest(target_item).unwrap(),
            ApplyOutcome::Inserted { .. }
        ));
        assert!(
            store
                .poll_subscription(subscription, 8, Some(30), Some(sample))
                .unwrap()
                .is_empty()
        );
    }

    #[test]
    fn acknowledged_bridge_projection_skips_immutable_classes_before_materialization() {
        let authorization = verified_bridge_authorization();
        let sample = bridge_sample(10);
        let base = verified_bridge_route(&[&authorization], 0xd7, b"immutable-bridge-event");
        let mut metadata = base.source.metadata.clone();
        metadata.class = DataClass::Event;
        metadata.event_sequence = Some(1);
        let source = VerifiedBridgeSource::from_provider(
            base.route.origin_envelope_id,
            metadata,
            base.source.exact_bytes.clone(),
            base.source.authenticated_forwarding_age_ms,
        )
        .unwrap();
        let route = VerifiedBridgeRoute::from_provider(
            base.wrapper_envelope_id,
            base.route.clone(),
            base.exact_wrapper_bytes.clone(),
            base.authenticated_forwarding_age_ms,
            source,
        )
        .unwrap();
        let mut store = SqliteStore::open_in_memory(StoreConfig::default()).unwrap();
        configure_bridge_epoch(&mut store, "mission/source", 3);
        configure_bridge_epoch(&mut store, "mission/target", 5);
        store.ingest_bridge_authorization(&authorization).unwrap();
        store
            .promote_verified_bridge_route_at(&route, Some(sample))
            .unwrap();
        let event_subscription = store
            .create_subscription(&SubscriptionSpec {
                topic: route.source.metadata.topic.clone(),
                scope: route.route.current_scope.clone(),
                include_descendant_scopes: false,
                class: Some(DataClass::Event),
            })
            .unwrap();
        let any_subscription = store
            .create_subscription(&SubscriptionSpec {
                topic: route.source.metadata.topic.clone(),
                scope: route.route.current_scope.clone(),
                include_descendant_scopes: false,
                class: None,
            })
            .unwrap();
        for subscription in [event_subscription, any_subscription] {
            let projection = store
                .peek_bridge_projection_subscription_page(subscription, None, Some(sample))
                .unwrap()
                .entries
                .remove(0);
            store
                .record_bridge_projection_deliveries(
                    subscription,
                    &[ProviderOpenedBridgeProjection::from_provider(projection)],
                    Some(20),
                    Some(sample),
                )
                .unwrap();
            store
                .acknowledge_bridge_projection_delivery(
                    subscription,
                    route.source.metadata.source_item_id,
                    Some(21),
                )
                .unwrap();
        }

        // A mutable-witness scan must filter the Event row in SQL. Corrupting
        // the otherwise valid wrapper makes any accidental materialization
        // observable as an error.
        store
            .connection
            .execute(
                "UPDATE bridge_route_wrappers SET exact_bytes=x'00'\n\
                 WHERE wrapper_envelope_id=?1",
                params![route.wrapper_envelope_id.as_slice()],
            )
            .unwrap();
        for subscription in [event_subscription, any_subscription] {
            assert!(
                store
                    .peek_acknowledged_bridge_projection_subscription_page(
                        subscription,
                        None,
                        Some(sample),
                    )
                    .unwrap()
                    .entries
                    .is_empty()
            );
        }
    }

    #[test]
    fn ordinary_arrival_between_bridge_poll_and_ack_uses_one_attempt_ledger() {
        let authorization = verified_bridge_authorization();
        let sample = bridge_sample(10);
        let route =
            verified_bridge_route(&[&authorization], 0xd5, b"bridge-then-direct-before-ack");
        let mut store = SqliteStore::open_in_memory(StoreConfig::default()).unwrap();
        configure_bridge_epoch(&mut store, "mission/source", 3);
        configure_bridge_epoch(&mut store, "mission/target", 5);
        store.ingest_bridge_authorization(&authorization).unwrap();
        store
            .promote_verified_bridge_route_at(&route, Some(sample))
            .unwrap();
        let subscription = store
            .create_subscription(&SubscriptionSpec {
                topic: route.source.metadata.topic.clone(),
                scope: route.route.current_scope.clone(),
                include_descendant_scopes: false,
                class: Some(route.source.metadata.class),
            })
            .unwrap();
        let bridge = store
            .peek_bridge_projection_subscription_page(subscription, None, Some(sample))
            .unwrap()
            .entries
            .remove(0);
        assert_eq!(
            store
                .record_bridge_projection_deliveries(
                    subscription,
                    &[ProviderOpenedBridgeProjection::from_provider(bridge)],
                    Some(20),
                    Some(sample),
                )
                .unwrap()[0]
                .delivery_attempt,
            1
        );
        let direct = ordinary_item_from_bridge_source(
            &route,
            route.route.current_scope.clone(),
            route.route.current_route_epoch,
            sample,
        );
        assert!(matches!(
            store.ingest(direct.clone()).unwrap(),
            ApplyOutcome::Inserted { .. }
        ));
        let ordinary = store
            .peek_subscription_page(subscription, None, Some(sample))
            .unwrap()
            .entries;
        assert_eq!(ordinary.len(), 1);
        assert_eq!(ordinary[0].id, direct.id);
        assert_eq!(
            store
                .record_subscription_deliveries(subscription, &ordinary, Some(21), Some(sample),)
                .unwrap()[0]
                .delivery_attempt,
            2
        );
        let (representation, attempts): (i64, i64) = store
            .connection
            .query_row(
                "SELECT representation,attempts FROM semantic_app_deliveries\n\
                 WHERE subscription_id=?1 AND item_id=?2",
                params![
                    sql_u64(subscription.0, "subscription id").unwrap(),
                    direct.id.as_slice()
                ],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .unwrap();
        assert_eq!((representation, attempts), (0, 2));
        store
            .acknowledge_bridge_projection_delivery(subscription, direct.id, Some(22))
            .unwrap();
        assert!(
            store
                .poll_subscription(subscription, 8, Some(23), Some(sample))
                .unwrap()
                .is_empty()
        );
    }

    #[test]
    fn controls_apply_only_as_contiguous_monotonic_chain_and_are_receipted() {
        let mut store = SqliteStore::open_in_memory(StoreConfig::default()).unwrap();
        let authority = [9; 32];
        let one = revocation_control(authority, 1, None, 1);
        let two = revocation_control(authority, 2, Some(one.envelope_id), 2);
        let three = revocation_control(authority, 3, Some(two.envelope_id), 3);
        assert!(matches!(
            store.ingest_control(&one).unwrap(),
            ControlOutcome::Applied { ref activated, .. } if activated.len() == 1
        ));
        assert!(matches!(
            store.ingest_control(&three).unwrap(),
            ControlOutcome::Pending { .. }
        ));
        assert!(matches!(
            store.ingest_control(&two).unwrap(),
            ControlOutcome::Applied { ref activated, .. } if activated.len() == 2
        ));
        assert!(store.is_revoked(&[44; 32]).unwrap());
        assert_eq!(store.applied_controls().unwrap().len(), 3);
        let peer = [10; 32];
        let outbound = store
            .next_control_outbound(peer, 8, u64::MAX, None)
            .unwrap();
        assert_eq!(outbound.len(), 3);
        store
            .acknowledge_control_peer(
                peer,
                &outbound
                    .iter()
                    .map(|value| value.envelope_id)
                    .collect::<Vec<_>>(),
                None,
            )
            .unwrap();
        assert!(
            store
                .next_control_outbound(peer, 8, u64::MAX, None)
                .unwrap()
                .is_empty()
        );

        let rollback = revocation_control(authority, 4, Some(three.envelope_id), 2);
        assert!(matches!(
            store.ingest_control(&rollback),
            Err(StoreError::ControlRollback)
        ));
    }

    #[test]
    fn revoked_signer_pending_suffix_is_rejected_and_recovery_signer_reuses_the_chain() {
        let mut store = SqliteStore::open_in_memory(StoreConfig::default()).unwrap();
        let authority = [0x20; 32];
        let old_signer = [0x21; 32];
        let recovery_signer = [0x22; 32];
        let revoke_old =
            signed_revocation_control(authority, recovery_signer, old_signer, 1, None, 1);
        let bad_two = signed_revocation_control(
            authority,
            old_signer,
            [0x23; 32],
            2,
            Some(revoke_old.envelope_id),
            1,
        );
        let bad_three = signed_revocation_control(
            authority,
            old_signer,
            [0x24; 32],
            3,
            Some(bad_two.envelope_id),
            1,
        );
        assert!(matches!(
            store.ingest_control(&bad_three).unwrap(),
            ControlOutcome::Pending { .. }
        ));
        assert!(matches!(
            store.ingest_control(&bad_two).unwrap(),
            ControlOutcome::Pending { .. }
        ));

        let ControlOutcome::Applied {
            activated,
            rejected,
            ..
        } = store.ingest_control(&revoke_old).unwrap()
        else {
            panic!("the valid revocation prefix must commit");
        };
        assert_eq!(
            activated
                .iter()
                .map(|control| control.envelope_id)
                .collect::<Vec<_>>(),
            vec![revoke_old.envelope_id]
        );
        assert_eq!(
            rejected
                .iter()
                .map(|control| control.envelope_id)
                .collect::<Vec<_>>(),
            vec![bad_two.envelope_id, bad_three.envelope_id]
        );
        assert_eq!(store.applied_controls().unwrap().len(), 1);

        let good_two = signed_revocation_control(
            authority,
            recovery_signer,
            [0x25; 32],
            2,
            Some(revoke_old.envelope_id),
            1,
        );
        let good_three = signed_revocation_control(
            authority,
            recovery_signer,
            [0x26; 32],
            3,
            Some(good_two.envelope_id),
            1,
        );
        assert!(matches!(
            store.ingest_control(&good_three).unwrap(),
            ControlOutcome::Pending { .. }
        ));
        let ControlOutcome::Applied { activated, .. } = store.ingest_control(&good_two).unwrap()
        else {
            panic!("recovery signer must continue the same mission chain");
        };
        assert_eq!(activated.len(), 2);
        assert!(
            activated
                .iter()
                .all(|control| control.signer == recovery_signer)
        );
        assert_eq!(store.applied_controls().unwrap().len(), 3);
    }

    #[test]
    fn far_future_revoked_signer_control_cannot_poison_recovery_after_restart() {
        let path = std::env::temp_dir().join(format!(
            "aster-far-future-control-signer-{}-{}.sqlite3",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let authority = [0x27; 32];
        let compromised_signer = [0x28; 32];
        let recovery_signer = [0x29; 32];
        let effect_subject = [0x2a; 32];
        let revoke_compromised =
            signed_revocation_control(authority, recovery_signer, compromised_signer, 1, None, 1);
        let valid_two = signed_revocation_control(
            authority,
            recovery_signer,
            effect_subject,
            2,
            Some(revoke_compromised.envelope_id),
            2,
        );
        let poisoned_future = signed_revocation_control(
            authority,
            compromised_signer,
            effect_subject,
            1_000_000,
            Some([0xee; 32]),
            1,
        );

        {
            let mut store = SqliteStore::open(&path, StoreConfig::default()).unwrap();
            assert!(matches!(
                store.ingest_control(&poisoned_future).unwrap(),
                ControlOutcome::Pending { .. }
            ));
            assert!(matches!(
                store.ingest_control(&valid_two).unwrap(),
                ControlOutcome::Pending { .. }
            ));
        }
        {
            let mut reopened = SqliteStore::open(&path, StoreConfig::default()).unwrap();
            let ControlOutcome::Applied {
                activated,
                rejected,
                ..
            } = reopened.ingest_control(&revoke_compromised).unwrap()
            else {
                panic!("revocation must purge the poisoned future and activate valid recovery");
            };
            assert_eq!(
                activated
                    .iter()
                    .map(|control| control.envelope_id)
                    .collect::<Vec<_>>(),
                vec![revoke_compromised.envelope_id, valid_two.envelope_id]
            );
            assert_eq!(
                rejected
                    .iter()
                    .map(|control| control.envelope_id)
                    .collect::<Vec<_>>(),
                vec![poisoned_future.envelope_id]
            );
        }
        {
            let mut reopened = SqliteStore::open(&path, StoreConfig::default()).unwrap();
            assert_eq!(
                reopened
                    .connection
                    .query_row(
                        "SELECT count(*) FROM controls WHERE envelope_id=?1",
                        params![poisoned_future.envelope_id.as_slice()],
                        |row| row.get::<_, i64>(0)
                    )
                    .unwrap(),
                0
            );
            assert_eq!(
                reopened
                    .applied_controls()
                    .unwrap()
                    .iter()
                    .map(|control| control.envelope_id)
                    .collect::<Vec<_>>(),
                vec![revoke_compromised.envelope_id, valid_two.envelope_id]
            );

            let rollback = signed_revocation_control(
                authority,
                recovery_signer,
                effect_subject,
                3,
                Some(valid_two.envelope_id),
                1,
            );
            assert!(matches!(
                reopened.ingest_control(&rollback),
                Err(StoreError::ControlRollback)
            ));
            assert_eq!(
                reopened
                    .connection
                    .query_row(
                        "SELECT count(*) FROM controls WHERE envelope_id=?1",
                        params![rollback.envelope_id.as_slice()],
                        |row| row.get::<_, i64>(0)
                    )
                    .unwrap(),
                0,
                "a rejected contiguous rollback must not occupy the chain"
            );
        }
        let _ = fs::remove_file(&path);
        let _ = fs::remove_file(path.with_extension("sqlite3-wal"));
        let _ = fs::remove_file(path.with_extension("sqlite3-shm"));
    }

    #[test]
    fn far_future_revoked_bridge_signer_is_purged_without_deleting_valid_prefix() {
        let path = std::env::temp_dir().join(format!(
            "aster-far-future-bridge-signer-{}-{}.sqlite3",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let first = verified_bridge_authorization();
        let recovery_signer = first.control_signer;
        let compromised_signer = [0x4a; 32];
        let valid_two = bridge_authorization_successor_signed(&first, recovery_signer, 2, true);
        let poisoned_future = bridge_authorization_at_sequence_signed(
            &first,
            compromised_signer,
            1_000_000,
            [0xed; 32],
            1,
        );
        let revoke_compromised =
            signed_revocation_control([0x4b; 32], recovery_signer, compromised_signer, 1, None, 1);

        {
            let mut store = SqliteStore::open(&path, StoreConfig::default()).unwrap();
            assert!(matches!(
                store.ingest_bridge_authorization(&poisoned_future).unwrap(),
                BridgeControlOutcome::Pending { .. }
            ));
            assert!(matches!(
                store.ingest_bridge_authorization(&valid_two).unwrap(),
                BridgeControlOutcome::Pending { .. }
            ));
        }
        {
            let mut reopened = SqliteStore::open(&path, StoreConfig::default()).unwrap();
            let ControlOutcome::Applied { rejected, .. } =
                reopened.ingest_control(&revoke_compromised).unwrap()
            else {
                panic!("ordinary revocation must activate and purge bridge signer poison");
            };
            assert_eq!(
                rejected
                    .iter()
                    .map(|control| control.envelope_id)
                    .collect::<Vec<_>>(),
                vec![poisoned_future.envelope_id]
            );
            assert!(
                reopened
                    .stored_bridge_authorization(&poisoned_future.envelope_id)
                    .unwrap()
                    .is_none()
            );
            assert!(
                reopened
                    .stored_bridge_authorization(&valid_two.envelope_id)
                    .unwrap()
                    .is_some(),
                "the valid earlier candidate from the recovery signer must survive"
            );
        }
        {
            let mut reopened = SqliteStore::open(&path, StoreConfig::default()).unwrap();
            assert!(
                reopened
                    .stored_bridge_authorization(&poisoned_future.envelope_id)
                    .unwrap()
                    .is_none()
            );
            assert!(matches!(
                reopened.ingest_bridge_authorization(&first).unwrap(),
                BridgeControlOutcome::Applied { ref activated, .. } if activated.len() == 1
            ));
            assert!(matches!(
                reopened.ingest_bridge_authorization(&valid_two).unwrap(),
                BridgeControlOutcome::Applied { ref activated, .. } if activated.len() == 1
            ));
            assert_eq!(
                reopened
                    .active_bridge_authorization(&valid_two.authorization.authorization_key)
                    .unwrap()
                    .unwrap()
                    .envelope_id,
                valid_two.envelope_id
            );

            let rollback =
                bridge_authorization_successor_signed(&valid_two, recovery_signer, 1, true);
            assert!(matches!(
                reopened.ingest_bridge_authorization(&rollback),
                Err(StoreError::BridgeControlRollback)
            ));
            assert_eq!(
                reopened
                    .active_bridge_authorization(&valid_two.authorization.authorization_key)
                    .unwrap()
                    .unwrap()
                    .envelope_id,
                valid_two.envelope_id
            );
        }
        let _ = fs::remove_file(&path);
        let _ = fs::remove_file(path.with_extension("sqlite3-wal"));
        let _ = fs::remove_file(path.with_extension("sqlite3-shm"));
    }

    #[test]
    fn stable_authority_self_revocation_is_a_durable_terminal_chain_link() {
        let path = std::env::temp_dir().join(format!(
            "aster-terminal-authority-revocation-{}-{}.sqlite3",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let bridge_first = verified_bridge_authorization();
        let authority = bridge_first.authorization.authority_id;
        let current_signer = bridge_first.control_signer;
        let recovery_signer = [0x4c; 32];
        let self_revocation =
            signed_revocation_control(authority, current_signer, authority, 1, None, 1);
        let pending_delegate = signed_revocation_control(
            authority,
            recovery_signer,
            [0x4d; 32],
            2,
            Some(self_revocation.envelope_id),
            1,
        );
        let pending_bridge =
            bridge_authorization_successor_signed(&bridge_first, recovery_signer, 2, true);

        {
            let mut store = SqliteStore::open(&path, StoreConfig::default()).unwrap();
            assert!(matches!(
                store.ingest_control(&pending_delegate).unwrap(),
                ControlOutcome::Pending { .. }
            ));
            assert!(matches!(
                store.ingest_bridge_authorization(&pending_bridge).unwrap(),
                BridgeControlOutcome::Pending { .. }
            ));
            let ControlOutcome::Applied {
                activated,
                rejected,
                ..
            } = store.ingest_control(&self_revocation).unwrap()
            else {
                panic!("authority self-revocation must apply as its final link");
            };
            assert_eq!(
                activated
                    .iter()
                    .map(|control| control.envelope_id)
                    .collect::<Vec<_>>(),
                vec![self_revocation.envelope_id]
            );
            assert_eq!(
                rejected
                    .iter()
                    .map(|control| control.envelope_id)
                    .collect::<Vec<_>>(),
                vec![pending_delegate.envelope_id, pending_bridge.envelope_id]
            );
        }
        {
            let mut reopened = SqliteStore::open(&path, StoreConfig::default()).unwrap();
            assert!(reopened.is_revoked(&authority).unwrap());
            assert_eq!(reopened.applied_controls().unwrap().len(), 1);
            assert!(matches!(
                reopened.reserve_control(ControlPrincipal {
                    authority,
                    signer: recovery_signer,
                }),
                Err(StoreError::ControlAuthorityRevoked(node)) if node == authority
            ));

            let ordinary_outcome = reopened.ingest_control(&pending_delegate).unwrap();
            assert!(matches!(ordinary_outcome, ControlOutcome::Rejected { .. }));
            assert_eq!(
                ordinary_outcome.rejected_input(),
                Some(RejectedControl {
                    envelope_id: pending_delegate.envelope_id,
                    signer: recovery_signer,
                })
            );
            let bridge_outcome = reopened
                .ingest_bridge_authorization(&pending_bridge)
                .unwrap();
            assert!(matches!(
                bridge_outcome,
                BridgeControlOutcome::Rejected { .. }
            ));
            assert_eq!(
                bridge_outcome.rejected_input(),
                Some(RejectedControl {
                    envelope_id: pending_bridge.envelope_id,
                    signer: recovery_signer,
                })
            );
        }
        let _ = fs::remove_file(&path);
        let _ = fs::remove_file(path.with_extension("sqlite3-wal"));
        let _ = fs::remove_file(path.with_extension("sqlite3-shm"));
    }

    #[test]
    fn rejected_insert_is_reported_when_an_unrelated_pending_link_activates() {
        let mut store = SqliteStore::open_in_memory(StoreConfig::default()).unwrap();
        let authority = [0x30; 32];
        let live_signer = [0x31; 32];
        let revoked_signer = [0x32; 32];
        store
            .apply_revocation(&Revocation {
                subject: revoked_signer,
                authority,
                signer: live_signer,
                generation: 1,
                control_sequence: 1,
                previous_control: None,
                sealed_notice: b"provider-authenticated-signer-revocation".to_vec(),
                observed_at_ms: None,
            })
            .unwrap();
        let valid = signed_revocation_control(authority, live_signer, [0x33; 32], 1, None, 1);
        {
            let transaction = store.connection.transaction().unwrap();
            assert_eq!(
                insert_control_tx(&transaction, &valid).unwrap(),
                ControlInsert::Inserted
            );
            transaction.commit().unwrap();
        }
        let rejected = signed_revocation_control(
            authority,
            revoked_signer,
            [0x34; 32],
            2,
            Some(valid.envelope_id),
            1,
        );
        let ControlOutcome::Applied {
            activated,
            rejected: rejected_controls,
            ..
        } = store.ingest_control(&rejected).unwrap()
        else {
            panic!("the staged valid link must activate");
        };
        assert_eq!(activated.len(), 1);
        assert_eq!(activated[0].envelope_id, valid.envelope_id);
        assert_eq!(
            rejected_controls,
            vec![RejectedControl {
                envelope_id: rejected.envelope_id,
                signer: revoked_signer,
            }]
        );
        let outcome = ControlOutcome::Applied {
            envelope_id: rejected.envelope_id,
            activated,
            rejected: rejected_controls,
        };
        assert_eq!(
            outcome.rejected_input(),
            Some(RejectedControl {
                envelope_id: rejected.envelope_id,
                signer: revoked_signer,
            }),
            "transport callers must not acknowledge the rejected input as committed"
        );
    }

    #[test]
    fn signer_substitution_and_reservation_signer_mismatch_fail_closed() {
        let mut store = SqliteStore::open_in_memory(StoreConfig::default()).unwrap();
        let authority = [0x40; 32];
        let reserved_signer = [0x41; 32];
        let substituted_signer = [0x42; 32];
        let reservation = store
            .reserve_control(ControlPrincipal {
                authority,
                signer: reserved_signer,
            })
            .unwrap();
        let mismatched = signed_revocation_control(
            authority,
            substituted_signer,
            [0x43; 32],
            reservation.sequence,
            reservation.previous_control,
            1,
        );
        assert!(matches!(
            store.commit_local_control(&reservation, &mismatched),
            Err(StoreError::Invalid(_))
        ));

        let accepted =
            signed_revocation_control(authority, reserved_signer, [0x44; 32], 1, None, 1);
        store.ingest_control(&accepted).unwrap();
        let mut substituted = accepted.clone();
        substituted.signer = substituted_signer;
        substituted.revocation.as_mut().unwrap().signer = substituted_signer;
        assert!(matches!(
            store.ingest_control(&substituted),
            Err(StoreError::ControlFork)
        ));
    }

    #[test]
    fn bridge_revoked_signer_suffix_is_rejected_and_no_longer_live() {
        let mut store = SqliteStore::open_in_memory(StoreConfig::default()).unwrap();
        let recovery_signer = [0x49; 32];
        let old_signer = [0x4a; 32];
        let first = verified_bridge_authorization();
        assert_eq!(first.control_signer, recovery_signer);
        let bad_two = bridge_authorization_successor_signed(&first, old_signer, 2, true);
        let bad_three = bridge_authorization_successor_signed(&bad_two, old_signer, 3, true);
        assert!(matches!(
            store.ingest_bridge_authorization(&bad_three).unwrap(),
            BridgeControlOutcome::Pending { .. }
        ));
        assert!(matches!(
            store.ingest_bridge_authorization(&bad_two).unwrap(),
            BridgeControlOutcome::Pending { .. }
        ));
        store
            .apply_revocation(&Revocation {
                subject: old_signer,
                authority: first.authorization.authority_id,
                signer: recovery_signer,
                generation: 1,
                control_sequence: 1,
                previous_control: None,
                sealed_notice: b"provider-authenticated-old-signer-revocation".to_vec(),
                observed_at_ms: None,
            })
            .unwrap();
        assert!(
            store
                .stored_bridge_authorization(&bad_two.envelope_id)
                .unwrap()
                .is_none()
        );
        assert!(
            store
                .stored_bridge_authorization(&bad_three.envelope_id)
                .unwrap()
                .is_none()
        );
        let BridgeControlOutcome::Applied { activated, .. } =
            store.ingest_bridge_authorization(&first).unwrap()
        else {
            panic!("the recovery signer must activate the first bridge link");
        };
        assert_eq!(activated.len(), 1);

        let BridgeControlOutcome::Rejected { rejected, .. } =
            store.ingest_bridge_authorization(&bad_two).unwrap()
        else {
            panic!("the reauthenticated revoked-signer suffix must be rejected");
        };
        assert_eq!(
            rejected
                .iter()
                .map(|control| control.envelope_id)
                .collect::<Vec<_>>(),
            vec![bad_two.envelope_id]
        );
        let good_two = bridge_authorization_successor_signed(&first, recovery_signer, 2, true);
        let good_three = bridge_authorization_successor_signed(&good_two, recovery_signer, 3, true);
        assert!(matches!(
            store.ingest_bridge_authorization(&good_three).unwrap(),
            BridgeControlOutcome::Pending { .. }
        ));
        let BridgeControlOutcome::Applied { activated, .. } =
            store.ingest_bridge_authorization(&good_two).unwrap()
        else {
            panic!("the recovery bridge signer must reuse the chain suffix");
        };
        assert_eq!(activated.len(), 2);

        let current = store
            .active_bridge_authorization(&good_two.authorization.authorization_key)
            .unwrap()
            .unwrap();
        store
            .apply_revocation(&Revocation {
                subject: current.control_signer,
                authority: current.authorization.authority_id,
                signer: [0x4b; 32],
                generation: 1,
                control_sequence: 2,
                previous_control: None,
                sealed_notice: b"provider-authenticated-current-signer-revocation".to_vec(),
                observed_at_ms: None,
            })
            .unwrap();
        assert!(matches!(
            store.ingest_bridge_authorization(&good_two).unwrap(),
            BridgeControlOutcome::Duplicate { .. }
        ));
        assert!(
            !store
                .bridge_authorization_is_live(&current.envelope_id)
                .unwrap()
        );
    }

    #[test]
    fn local_retained_dual_batch_commits_all_provenance_and_counters_atomically() {
        let mut store = SqliteStore::open_in_memory(StoreConfig::default()).unwrap();
        let (reservation, commit) = local_batch_fixture(
            &mut store,
            BatchStoragePolicy::RetainedDual,
            [Priority::Routine, Priority::Immediate],
        );
        let proof_id = commit.proof_envelope_id;
        let compact = commit.items[0].compact.clone();
        let singleton = commit.items[0].singleton.clone().unwrap();
        let outcome = store.commit_local_batch(&reservation, commit).unwrap();
        assert_eq!(outcome.outcomes.len(), 2);
        assert!(outcome.evicted.is_empty());
        assert_eq!(
            store.get(&compact.id).unwrap().unwrap().sealed,
            singleton.sealed
        );
        let material = store.stored_batch_material(&compact.id).unwrap().unwrap();
        assert_eq!(material.compact_envelope_id, compact.envelope_id);
        assert_eq!(material.compact_bytes, compact.sealed);
        assert_eq!(material.singleton_envelope_id, Some(singleton.envelope_id));
        assert_eq!(material.proof.proof_envelope_id, proof_id);
        assert_eq!(
            store
                .stored_batch_material_by_compact_envelope(&compact.envelope_id)
                .unwrap()
                .unwrap(),
            material
        );
        assert_eq!(
            store.stored_item(&compact.id).unwrap().unwrap().id,
            compact.id
        );
        assert_eq!(
            store
                .stored_item_representation(&compact.id, 1)
                .unwrap()
                .unwrap()
                .envelope_id,
            singleton.envelope_id
        );
        assert_eq!(
            store
                .stored_item_representation(&compact.id, 2)
                .unwrap()
                .unwrap()
                .envelope_id,
            compact.envelope_id
        );
        assert_eq!(
            store
                .stored_item_representation(&compact.id, 3)
                .unwrap()
                .unwrap()
                .envelope_id,
            compact.envelope_id
        );
        assert_eq!(
            store
                .stored_item_representation(&compact.id, 4)
                .unwrap()
                .unwrap()
                .envelope_id,
            compact.envelope_id
        );
        assert_eq!(
            store
                .stored_item_representation(&compact.id, 5)
                .unwrap()
                .unwrap()
                .envelope_id,
            compact.envelope_id
        );
        assert_eq!(
            store
                .stored_item_representation(&compact.id, 6)
                .unwrap()
                .unwrap()
                .envelope_id,
            compact.envelope_id
        );
        assert_eq!(
            store
                .stored_item_representation(&compact.id, 7)
                .unwrap()
                .unwrap()
                .envelope_id,
            compact.envelope_id
        );
        assert!(store.stored_item_representation(&compact.id, 8).is_err());
        let next = store
            .reserve_batch_publish(
                [7; 32],
                DataClass::State,
                &Topic::new("test.state").unwrap(),
                &Scope::new("mission/test").unwrap(),
                2,
            )
            .unwrap();
        assert_eq!(next.first_counter, reservation.first_counter + 2);
    }

    #[test]
    fn batch_quota_failure_rolls_back_proof_items_representations_and_counter() {
        let config = StoreConfig {
            max_items: 4,
            max_bytes: 1024 * 1024,
            ..StoreConfig::default()
        };
        let mut store = SqliteStore::open_in_memory(config).unwrap();
        let (reservation, commit) = local_batch_fixture(
            &mut store,
            BatchStoragePolicy::RetainedDual,
            [Priority::Routine, Priority::Routine],
        );
        assert!(matches!(
            store.commit_local_batch(&reservation, commit),
            Err(StoreError::QuotaExceeded)
        ));
        for table in ["items", "batch_proofs", "batch_item_representations"] {
            let count: i64 = store
                .connection
                .query_row(&format!("SELECT count(*) FROM {table}"), [], |row| {
                    row.get(0)
                })
                .unwrap();
            assert_eq!(count, 0, "{table} was not rolled back");
        }
        let retry = store
            .reserve_batch_publish(
                [7; 32],
                DataClass::State,
                &Topic::new("test.state").unwrap(),
                &Scope::new("mission/test").unwrap(),
                2,
            )
            .unwrap();
        assert_eq!(retry.first_counter, reservation.first_counter);
    }

    #[test]
    fn compact_delivery_waits_for_peer_proof_receipt_and_late_singleton_enables_v1() {
        let mut store = SqliteStore::open_in_memory(StoreConfig::default()).unwrap();
        let (reservation, commit) = local_batch_fixture(
            &mut store,
            BatchStoragePolicy::BatchOnly,
            [Priority::Routine, Priority::Flash],
        );
        let proof_id = commit.proof_envelope_id;
        let compact = commit.items[0].compact.clone();
        let mut singleton = compact.clone();
        singleton.sealed = b"late-authenticated-singleton".to_vec();
        singleton.envelope_id = exact_object_id(&singleton.sealed);
        store.commit_local_batch(&reservation, commit).unwrap();
        let peer = [0x91; 32];
        assert_eq!(
            store
                .filter_unacknowledged_batch_proofs(peer, &[[0xff; 32], proof_id], 8)
                .unwrap(),
            vec![proof_id]
        );
        assert!(
            store
                .peek_batch_compact_outbound(peer, Priority::Routine, 8, u64::MAX, None)
                .unwrap()
                .is_empty()
        );
        assert!(
            store
                .filter_unacknowledged_batch_compacts(peer, &[compact.id], 8)
                .unwrap()
                .is_empty()
        );
        let proofs = store
            .next_batch_proof_outbound(peer, Priority::Flash, 8, u64::MAX, Some(10), None)
            .unwrap();
        assert_eq!(proofs.len(), 1);
        assert_eq!(proofs[0].proof_envelope_id, proof_id);
        assert_eq!(proofs[0].effective_priority, Priority::Flash);
        store
            .acknowledge_batch_proof_peer(peer, &[proof_id], Some(11))
            .unwrap();
        assert!(
            store
                .filter_unacknowledged_batch_proofs(peer, &[proof_id], 8)
                .unwrap()
                .is_empty()
        );
        let compacts = store
            .next_batch_compact_outbound(peer, Priority::Routine, 8, u64::MAX, Some(12), None)
            .unwrap();
        assert_eq!(compacts.len(), 2);
        let compact_candidates = compacts
            .iter()
            .rev()
            .map(|item| item.item_id)
            .collect::<Vec<_>>();
        assert_eq!(
            store
                .filter_unacknowledged_batch_compacts(peer, &compact_candidates, 8)
                .unwrap(),
            compact_candidates
        );
        assert!(
            store
                .filter_batch_blob_ready(peer, &compact_candidates, 8)
                .unwrap()
                .is_empty()
        );
        assert!(
            store
                .stored_item_representation(&compact.id, 1)
                .unwrap()
                .is_none()
        );
        assert!(matches!(
            store.ingest(singleton.clone()).unwrap(),
            ApplyOutcome::Duplicate { .. }
        ));
        assert_eq!(
            store
                .stored_item_representation(&compact.id, 1)
                .unwrap()
                .unwrap()
                .envelope_id,
            singleton.envelope_id
        );
        assert_eq!(
            store
                .stored_item_representation(&compact.id, 2)
                .unwrap()
                .unwrap()
                .envelope_id,
            compact.envelope_id
        );
        store
            .acknowledge_batch_compact_peer(
                peer,
                &compacts.iter().map(|item| item.item_id).collect::<Vec<_>>(),
                Some(13),
            )
            .unwrap();
        assert_eq!(
            store
                .filter_batch_blob_ready(peer, &compact_candidates, 8)
                .unwrap(),
            compact_candidates
        );
        assert!(
            store
                .peek_batch_compact_outbound(peer, Priority::Routine, 8, u64::MAX, None)
                .unwrap()
                .is_empty()
        );
    }

    #[test]
    fn pending_first_invalid_exact_proof_is_durably_terminal() {
        let path = std::env::temp_dir().join(format!(
            "aster-rejected-batch-proof-{}-{}.sqlite3",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let invalid_proof = b"complete-but-provider-invalid-proof".to_vec();
        let proof_id = exact_object_id(&invalid_proof);
        let compact = b"route-authenticated-pending-compact".to_vec();
        let compact_id = exact_object_id(&compact);
        {
            let mut store = SqliteStore::open(&path, StoreConfig::default()).unwrap();
            insert_pending_batch_fixture(
                &mut store,
                proof_id,
                compact_id,
                [0x72; 32],
                &compact,
                None,
                4,
                Some(CustodySample {
                    clock_id: [3; 16],
                    tick_ms: 10,
                }),
            );
            assert!(store.reject_batch_proof(proof_id, &invalid_proof).unwrap());
            assert!(
                store
                    .stored_pending_batch_item(&compact_id)
                    .unwrap()
                    .is_none()
            );
            assert!(store.is_batch_proof_rejected(&proof_id).unwrap());
        }
        {
            let store = SqliteStore::open(&path, StoreConfig::default()).unwrap();
            assert!(store.is_batch_proof_rejected(&proof_id).unwrap());
            assert!(
                store
                    .stored_pending_batch_item(&compact_id)
                    .unwrap()
                    .is_none()
            );
        }
        let _ = fs::remove_file(&path);
        let _ = fs::remove_file(path.with_extension("sqlite3-wal"));
        let _ = fs::remove_file(path.with_extension("sqlite3-shm"));
    }

    #[test]
    fn finite_ttl_pending_batch_custody_survives_restart_and_fails_closed() {
        let path = std::env::temp_dir().join(format!(
            "aster-pending-batch-custody-{}-{}.sqlite3",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let proof_id = [0x81; 32];
        let compact = b"finite-ttl-pending-compact".to_vec();
        let compact_id = exact_object_id(&compact);
        {
            let mut store = SqliteStore::open(&path, StoreConfig::default()).unwrap();
            insert_pending_batch_fixture(
                &mut store,
                proof_id,
                compact_id,
                [0x82; 32],
                &compact,
                Some(100),
                80,
                Some(CustodySample {
                    clock_id: [5; 16],
                    tick_ms: 10,
                }),
            );
        }
        {
            let store = SqliteStore::open(&path, StoreConfig::default()).unwrap();
            let pending = store
                .stored_pending_batch_item(&compact_id)
                .unwrap()
                .unwrap();
            assert_eq!(
                pending.effective_custody_age_ms(Some(CustodySample {
                    clock_id: [5; 16],
                    tick_ms: 40,
                })),
                Some(110)
            );
            assert_eq!(
                pending.effective_custody_age_ms(Some(CustodySample {
                    clock_id: [6; 16],
                    tick_ms: 1,
                })),
                None
            );
        }
        let _ = fs::remove_file(&path);
        let _ = fs::remove_file(path.with_extension("sqlite3-wal"));
        let _ = fs::remove_file(path.with_extension("sqlite3-shm"));
    }
}
