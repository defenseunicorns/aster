//! Mission-bound Blob publication metadata and crash-safe ciphertext depot.
//!
//! Signed Blob publications live in redb, while potentially large encrypted
//! chunks live below the fixed sibling `blob-depot-v1` directory.  A depot
//! variant is keyed by `(BlobId, content group, content epoch)`, so distinct
//! publishers and priorities may reference the same immutable encrypted
//! content without aliasing their source-authenticated publication identities.
//! Depot limits bound durable import/chunk metadata rows and redb-marked chunk
//! file bytes. They do not claim a bound on unmarked, temporary, or hostile
//! untracked filesystem allocation.

pub(crate) mod depot;
#[allow(dead_code)] // Lifecycle authority becomes active in Tasks 2-4.
pub(crate) mod lifecycle;

pub use lifecycle::{
    BlobLifecycleLimits, BlobMaintenanceBudget, BlobMaintenanceCandidate, BlobMaintenanceClass,
    BlobMaintenanceProgress,
};

use std::collections::{BTreeMap, BTreeSet};
use std::error::Error;
use std::fmt;

use aster_mesh::{
    BlobId, BlobRouteCommitment, BlobStore as CoreBlobStore, ContentVerifiedBlobEnvelope,
    CurrentBlobLineage, MAX_BLOB_CHUNK_SIZE, MAX_BLOB_CHUNKS, MAX_BLOB_MANIFEST_BYTES,
    SELECTED_BLOB_CHUNK_SIZE as CORE_SELECTED_BLOB_CHUNK_SIZE, VerifiedBlobContentCompletion,
    VerifiedBlobTransferPlan,
};
use redb::{ReadableTable, ReadableTableMetadata, TableDefinition, TableHandle};

use super::*;

pub use depot::{AuthenticatedBlobReadDepot, BlobDepot, BlobDepotCompletion};

pub(crate) const BLOB_PUBLICATIONS: TableDefinition<&[u8], &[u8]> =
    TableDefinition::new("aster.semantic-blob-publications.v1");
pub(crate) const BLOB_BYTES: TableDefinition<&[u8], &[u8]> =
    TableDefinition::new("aster.semantic-blob-bytes.v1");
pub(crate) const BLOB_SEMANTIC_ITEMS: TableDefinition<&[u8], &[u8]> =
    TableDefinition::new("aster.semantic-blob-items.v1");
// Composite `(topic, scope, BlobId, semantic publication id)` keys retain
// every signed publication which references one immutable Blob.
pub(crate) const BLOB_CONTENT_INDEX: TableDefinition<&[u8], &[u8]> =
    TableDefinition::new("aster.semantic-blob-content.v1");
pub(crate) const BLOB_ACCEPTANCE_MARKERS: TableDefinition<&[u8], u64> =
    TableDefinition::new("aster.semantic-blob-markers.v1");
pub(crate) const BLOB_OPERATIONS: TableDefinition<&[u8], &[u8]> =
    TableDefinition::new("aster.blob-operations.v1");
pub(crate) const BLOB_IMPORTS: TableDefinition<&[u8], &[u8]> =
    TableDefinition::new("aster.blob-imports.v1");
pub(crate) const BLOB_CHUNKS: TableDefinition<&[u8], &[u8]> =
    TableDefinition::new("aster.blob-chunks.v1");
pub(crate) const BLOB_DEPOT_METADATA: TableDefinition<&str, u64> =
    TableDefinition::new("aster.blob-depot-metadata.v1");
// Network staging is intentionally disjoint from application-visible Blob
// publications. A complete, content-verified source remains pending until its
// exact encrypted content has passed the final promotion gate. Carrier rows
// retain only one contiguous prefix for one exact typed kind-2 object.
pub(crate) const BLOB_PENDING_SOURCES: TableDefinition<&[u8], &[u8]> =
    TableDefinition::new("aster.pending-blob-sources.v1");
pub(crate) const BLOB_CARRIER_PREFIXES: TableDefinition<&[u8], &[u8]> =
    TableDefinition::new("aster.pending-blob-carrier-prefixes.v1");
pub(crate) const BLOB_NETWORK_METADATA: TableDefinition<&str, u64> =
    TableDefinition::new("aster.blob-network-metadata.v1");
// Peer scheduling metadata is mission-bound and audited, but it is outside
// both ordinary semantic quotas and the network byte/row staging partition.
pub(crate) const BLOB_CARRIER_FETCH_CURSORS: TableDefinition<&[u8], &[u8]> =
    TableDefinition::new("aster.blob-carrier-fetch-cursors.v1");

pub(crate) const BLOB_ITEM_COUNT: &str = "semantic_blob_item_count";
pub(crate) const BLOB_TOTAL_BYTES: &str = "semantic_blob_total_bytes";
pub(crate) const LAST_BLOB_ACCEPTANCE_MARKER: &str = "last_semantic_blob_acceptance_marker";
pub(crate) const BLOB_OPERATION_COUNT: &str = "semantic_blob_operation_count";
pub(crate) const BLOB_OPERATION_TOTAL_BYTES: &str = "semantic_blob_operation_total_bytes";

pub(crate) const DEPOT_SCHEMA_VERSION: &str = "schema_version";
pub(crate) const DEPOT_VARIANT_COUNT: &str = "variant_count";
pub(crate) const DEPOT_COMMITTED_CHUNK_COUNT: &str = "committed_chunk_count";
pub(crate) const DEPOT_COMMITTED_FILE_BYTES: &str = "committed_file_bytes";
pub(crate) const DEPOT_RESERVED_FILE_BYTES: &str = "reserved_file_bytes";
pub(crate) const DEPOT_OWNER_TOKEN_0: &str = "owner_token_0";
pub(crate) const DEPOT_OWNER_TOKEN_1: &str = "owner_token_1";
pub(crate) const DEPOT_OWNER_TOKEN_2: &str = "owner_token_2";
pub(crate) const DEPOT_OWNER_TOKEN_3: &str = "owner_token_3";
pub(crate) const DEPOT_OWNER_BINDING_0: &str = "owner_binding_0";
pub(crate) const DEPOT_OWNER_BINDING_1: &str = "owner_binding_1";
pub(crate) const DEPOT_OWNER_BINDING_2: &str = "owner_binding_2";
pub(crate) const DEPOT_OWNER_BINDING_3: &str = "owner_binding_3";
pub(crate) const BLOB_DEPOT_SCHEMA_VERSION: u64 = 2;

const BLOB_NETWORK_SCHEMA_VERSION_FIELD: &str = "schema_version";
const BLOB_NETWORK_STAGING_ROWS: &str = "staging_rows";
const BLOB_NETWORK_STAGING_BYTES: &str = "staging_bytes";
const BLOB_NETWORK_SCHEMA_VERSION: u64 = 1;

const BLOB_METADATA_VERSION_V1: u8 = 1;
const BLOB_METADATA_VERSION: u8 = 2;
const BLOB_OPERATION_VERSION: u8 = 1;
const PENDING_BLOB_SOURCE_VERSION: u8 = 1;
const BLOB_CARRIER_PREFIX_VERSION: u8 = 1;
const BLOB_PUBLICATION_INTENT_DOMAIN: &[u8] = b"aster/blob-publication-intent/v1";
const BLOB_VARIANT_DOMAIN: &[u8] = b"aster/blob-depot-variant/v1";
const BLOB_SOURCE_PROJECTION_DOMAIN: &[u8] = b"aster/blob-source-projection/v1";

/// Selected interoperable Blob chunk size (64 KiB).
pub const SELECTED_BLOB_CHUNK_SIZE: u32 = CORE_SELECTED_BLOB_CHUNK_SIZE;
/// Maximum chunks representable by the selected one-MiB manifest bound.
pub const MAX_SELECTED_BLOB_CHUNKS: u64 = MAX_BLOB_CHUNKS;
/// Maximum byte length of one durable Blob operation key.
pub const MAX_BLOB_OPERATION_KEY_BYTES: usize = 256;
/// Maximum durable idempotent Blob operation mappings per store.
pub const MAX_BLOB_OPERATIONS: u64 = 4_096;
/// Maximum aggregate operation-key plus operation-record bytes.
pub const MAX_BLOB_OPERATION_BYTES: u64 = 512 * 1024;
/// Maximum signed publications retained for one `(topic, scope, BlobId)` read plan.
pub const MAX_BLOB_PUBLICATIONS_PER_CONTENT: usize = 1_024;
/// Maximum selected network Blob plaintext bytes (64 MiB).
pub const MAX_NETWORK_BLOB_BYTES: u64 = 64 * 1024 * 1024;
/// Maximum exact source-sealed manifest envelope admitted for networking (1 MiB).
pub const MAX_BLOB_NETWORK_SOURCE_BYTES: usize = 1024 * 1024;
/// Maximum selected 64-KiB chunks in one network Blob.
pub const MAX_NETWORK_BLOB_CHUNKS: u64 = 1_024;
/// Maximum aggregate pending-source and carrier-prefix rows.
pub const MAX_BLOB_NETWORK_STAGING_ROWS: u64 = 10_000;
/// Maximum aggregate encoded keys and values in network staging (64 MiB).
pub const MAX_BLOB_NETWORK_STAGING_BYTES: u64 = 64 * 1024 * 1024;
/// Maximum accepted bytes in one contiguous carrier append.
pub const MAX_BLOB_NETWORK_RANGE_BYTES: usize = 16 * 1024;
/// Conservative hard bound for one canonical selected kind-2 carrier.
///
/// The stable carrier is a 64-KiB ciphertext chunk plus its fixed fields and
/// bounded Merkle proof. Keeping a 128-KiB store bound leaves format headroom
/// without permitting a source-envelope-sized allocation in this namespace.
pub const MAX_BLOB_NETWORK_CARRIER_BYTES: u64 = 128 * 1024;
/// Maximum authenticated peers with a durable carrier-fetch scheduling cursor.
pub const MAX_BLOB_CARRIER_FETCH_CURSOR_PEERS: usize = 256;
/// Fixed typed kind-2 ObjectID length (`kind || digest`).
pub const BLOB_CARRIER_OBJECT_ID_BYTES: usize = 33;
/// Exact pending carrier-prefix key length (`source transfer || typed ObjectID`).
pub const BLOB_CARRIER_PREFIX_KEY_BYTES: usize = 32 + BLOB_CARRIER_OBJECT_ID_BYTES;
/// Fixed carrier cursor length (`source transfer || typed ObjectID`).
pub const BLOB_CARRIER_FETCH_CURSOR_BYTES: usize = 32 + BLOB_CARRIER_OBJECT_ID_BYTES;
/// Default aggregate expected chunk-file byte reservation cap (512 MiB).
pub const DEFAULT_MAX_BLOB_DEPOT_BYTES: u64 = 512 * 1024 * 1024;
/// Default aggregate durable chunk-metadata row cap.
///
/// Plaintext-digest or expected-record staging consumes this cap before a file
/// becomes committed.
pub const DEFAULT_MAX_BLOB_DEPOT_CHUNKS: u64 = 100_000;
/// Default aggregate durable epoch-specific import-row cap.
///
/// Every durable import row, public or unpublished, consumes this cap.
pub const DEFAULT_MAX_BLOB_DEPOT_VARIANTS: u64 = 4_096;

/// Dedicated durable-admission limits for one mission-bound Blob depot.
///
/// `max_bytes` reserves the canonical chunk-file bytes, including each fixed
/// file header, for every durable expected chunk record; committed files are a
/// subset. `max_chunks` counts all durable chunk metadata rows, including
/// digest/expected-record staging. `max_variants` counts every durable import
/// row, public or unpublished. Abandoned staging remains durable until a future
/// explicit garbage-collection design; writable reopen reclaims only unmarked
/// physical artifacts. These limits intentionally do not bound unmarked,
/// temporary, or hostile untracked filesystem allocation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BlobDepotLimits {
    max_bytes: u64,
    max_chunks: u64,
    max_variants: u64,
}

impl BlobDepotLimits {
    /// Conservative selected-profile depot limits.
    pub const DEFAULT: Self = Self {
        max_bytes: DEFAULT_MAX_BLOB_DEPOT_BYTES,
        max_chunks: DEFAULT_MAX_BLOB_DEPOT_CHUNKS,
        max_variants: DEFAULT_MAX_BLOB_DEPOT_VARIANTS,
    };

    /// Constructs nonzero aggregate physical depot limits.
    pub const fn new(
        max_bytes: u64,
        max_chunks: u64,
        max_variants: u64,
    ) -> Result<Self, BlobStoreError> {
        if max_bytes == 0 || max_chunks == 0 || max_variants == 0 {
            return Err(BlobStoreError::InvalidDepotLimits);
        }
        Ok(Self {
            max_bytes,
            max_chunks,
            max_variants,
        })
    }

    /// Maximum aggregate bytes reserved by durable expected chunk records.
    pub const fn max_bytes(self) -> u64 {
        self.max_bytes
    }

    /// Maximum durable chunk metadata rows, including unfinished staging.
    pub const fn max_chunks(self) -> u64 {
        self.max_chunks
    }

    /// Maximum durable import rows, public or unpublished.
    pub const fn max_variants(self) -> u64 {
        self.max_variants
    }
}

impl Default for BlobDepotLimits {
    fn default() -> Self {
        Self::DEFAULT
    }
}

/// Blob-specific durable-schema, policy, and depot failures.
#[derive(Debug)]
pub enum BlobStoreError {
    InvalidDepotLimits,
    InvalidLifecycleLimits,
    InvalidMaintenanceBudget,
    InvalidOperationKey {
        length: usize,
    },
    InvalidPublication(&'static str),
    Verification(String),
    OperationConflict,
    PublisherRevoked(NodeId),
    KeyEpochStale {
        current: u64,
        received: u64,
    },
    KeyEpochNotActive {
        current: u64,
        received: u64,
    },
    ReservationChanged,
    ReadPlanChanged,
    PublicationLimitExceeded {
        current: usize,
        limit: usize,
    },
    CausalFrontierLimitExceeded {
        current: usize,
        limit: usize,
    },
    OperationLimitExceeded {
        current: u64,
        limit: u64,
    },
    OperationByteLimitExceeded {
        current: u64,
        incoming: u64,
        limit: u64,
    },
    DepotByteLimitExceeded {
        current: u64,
        incoming: u64,
        limit: u64,
    },
    DepotChunkLimitExceeded {
        current: u64,
        limit: u64,
    },
    DepotVariantLimitExceeded {
        current: u64,
        limit: u64,
    },
    LineageFenceCapacity {
        required_rows: u64,
        required_bytes: u64,
        max_rows: u64,
        max_bytes: u64,
    },
    ReplayFenceCapacity {
        required_rows: u64,
        required_bytes: u64,
        max_rows: u64,
        max_bytes: u64,
    },
    PublicationLifecycleCapacity {
        required_rows: u64,
        max_rows: u64,
    },
    NetworkBlobTooLarge {
        total_len: u64,
        chunk_count: u64,
    },
    NetworkSourceTooLarge {
        sealed_len: usize,
        limit: usize,
    },
    NetworkStagingRowLimitExceeded {
        current: u64,
        incoming: u64,
        limit: u64,
    },
    NetworkStagingByteLimitExceeded {
        current: u64,
        incoming: u64,
        limit: u64,
    },
    InvalidCarrierObjectId,
    InvalidCarrierRange(&'static str),
    PendingSourceMissing,
    PendingSourceConflict,
    CarrierPrefixConflict,
    CarrierCursorPeerLimitExceeded {
        requested: usize,
        limit: usize,
    },
    CarrierCursorInvariant(&'static str),
    PhysicalLineageConflict,
    SourceRepresentationConflict,
    PhysicalLineageMigrationRequired,
    SchemaInvariant(&'static str),
    DepotIntegrity(&'static str),
    CompletionMismatch,
    Io(std::io::Error),
}

impl fmt::Display for BlobStoreError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidDepotLimits => formatter.write_str("Blob depot limits must be nonzero"),
            Self::InvalidLifecycleLimits => {
                formatter.write_str("Blob lifecycle limits must be nonzero")
            }
            Self::InvalidMaintenanceBudget => {
                formatter.write_str("Blob maintenance budget bounds must be nonzero")
            }
            Self::InvalidOperationKey { length } => write!(
                formatter,
                "Blob operation key length {length} is outside 1..={MAX_BLOB_OPERATION_KEY_BYTES}"
            ),
            Self::InvalidPublication(reason) => {
                write!(formatter, "invalid Blob publication: {reason}")
            }
            Self::Verification(reason) => write!(formatter, "Blob verification failed: {reason}"),
            Self::OperationConflict => {
                formatter.write_str("Blob operation key is bound to another intent")
            }
            Self::PublisherRevoked(publisher) => {
                write!(formatter, "Blob publisher {publisher:?} is revoked")
            }
            Self::KeyEpochStale { current, received } => write!(
                formatter,
                "Blob key epoch {received} is stale; current epoch is {current}"
            ),
            Self::KeyEpochNotActive { current, received } => write!(
                formatter,
                "Blob key epoch {received} is not active; current epoch is {current}"
            ),
            Self::ReservationChanged => {
                formatter.write_str("Blob reservation changed before commit")
            }
            Self::ReadPlanChanged => formatter.write_str("Blob read plan changed before use"),
            Self::PublicationLimitExceeded { current, limit } => write!(
                formatter,
                "Blob publication set has {current} rows at its {limit}-row limit"
            ),
            Self::CausalFrontierLimitExceeded { current, limit } => write!(
                formatter,
                "Blob causal frontier has {current} publishers at its {limit}-publisher limit"
            ),
            Self::OperationLimitExceeded { current, limit } => write!(
                formatter,
                "Blob operation ledger has {current} rows at its {limit}-row limit"
            ),
            Self::OperationByteLimitExceeded {
                current,
                incoming,
                limit,
            } => write!(
                formatter,
                "Blob operation ledger has {current} bytes and cannot admit {incoming} bytes under limit {limit}"
            ),
            Self::DepotByteLimitExceeded {
                current,
                incoming,
                limit,
            } => write!(
                formatter,
                "Blob depot has {current} bytes and cannot admit {incoming} bytes under limit {limit}"
            ),
            Self::DepotChunkLimitExceeded { current, limit } => write!(
                formatter,
                "Blob depot has {current} durable chunk rows at its {limit}-row limit"
            ),
            Self::DepotVariantLimitExceeded { current, limit } => write!(
                formatter,
                "Blob depot has {current} durable import rows at its {limit}-row limit"
            ),
            Self::LineageFenceCapacity {
                required_rows,
                required_bytes,
                max_rows,
                max_bytes,
            } => write!(
                formatter,
                "Blob lineage-fence authority requires {required_rows} rows / {required_bytes} bytes, above configured {max_rows} rows / {max_bytes} bytes"
            ),
            Self::ReplayFenceCapacity {
                required_rows,
                required_bytes,
                max_rows,
                max_bytes,
            } => write!(
                formatter,
                "Blob replay-fence authority requires {required_rows} rows / {required_bytes} bytes, above configured {max_rows} rows / {max_bytes} bytes"
            ),
            Self::PublicationLifecycleCapacity {
                required_rows,
                max_rows,
            } => write!(
                formatter,
                "Blob publication-lifecycle authority requires {required_rows} rows, above configured {max_rows} rows"
            ),
            Self::NetworkBlobTooLarge {
                total_len,
                chunk_count,
            } => write!(
                formatter,
                "network Blob has {total_len} bytes/{chunk_count} chunks; limits are {MAX_NETWORK_BLOB_BYTES} bytes/{MAX_NETWORK_BLOB_CHUNKS} chunks"
            ),
            Self::NetworkSourceTooLarge { sealed_len, limit } => write!(
                formatter,
                "network Blob source has {sealed_len} sealed bytes; limit is {limit}"
            ),
            Self::NetworkStagingRowLimitExceeded {
                current,
                incoming,
                limit,
            } => write!(
                formatter,
                "Blob network staging has {current} rows and cannot admit {incoming} rows under limit {limit}"
            ),
            Self::NetworkStagingByteLimitExceeded {
                current,
                incoming,
                limit,
            } => write!(
                formatter,
                "Blob network staging has {current} bytes and cannot admit {incoming} bytes under limit {limit}"
            ),
            Self::InvalidCarrierObjectId => {
                formatter.write_str("Blob carrier ObjectID is not an exact typed kind-2 identity")
            }
            Self::InvalidCarrierRange(reason) => {
                write!(formatter, "invalid Blob carrier range: {reason}")
            }
            Self::PendingSourceMissing => {
                formatter.write_str("Blob carrier has no complete verified pending source")
            }
            Self::PendingSourceConflict => {
                formatter.write_str("pending Blob source conflicts with durable staging")
            }
            Self::CarrierPrefixConflict => {
                formatter.write_str("Blob carrier prefix conflicts with durable staging")
            }
            Self::CarrierCursorPeerLimitExceeded { requested, limit } => write!(
                formatter,
                "Blob carrier cursor peer count {requested} exceeds limit {limit}"
            ),
            Self::CarrierCursorInvariant(reason) => {
                write!(formatter, "durable Blob carrier cursor invariant failed: {reason}")
            }
            Self::PhysicalLineageConflict => formatter.write_str(
                "Blob depot variant is bound to different same-epoch physical key lineage; publish at a new epoch",
            ),
            Self::SourceRepresentationConflict => formatter
                .write_str("Blob source representation conflicts with permanent replay authority"),
            Self::PhysicalLineageMigrationRequired => formatter.write_str(
                "legacy Blob depot staging has no unambiguous physical lineage; publish at a new epoch",
            ),
            Self::SchemaInvariant(reason) => {
                write!(formatter, "durable Blob schema invariant failed: {reason}")
            }
            Self::DepotIntegrity(reason) => {
                write!(formatter, "Blob depot integrity failed: {reason}")
            }
            Self::CompletionMismatch => {
                formatter.write_str("Blob depot completion does not match the verified publication")
            }
            Self::Io(error) => write!(formatter, "Blob depot I/O failed: {error}"),
        }
    }
}

impl Error for BlobStoreError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Io(error) => Some(error),
            _ => None,
        }
    }
}

impl From<std::io::Error> for BlobStoreError {
    fn from(value: std::io::Error) -> Self {
        Self::Io(value)
    }
}

fn blob_error(error: BlobStoreError) -> StoreError {
    StoreError::Blob(error)
}

fn blob_preflight_decode_error(error: StoreError, reason: &'static str) -> StoreError {
    match error {
        StoreError::SemanticInvariant(_) => blob_error(BlobStoreError::SchemaInvariant(reason)),
        error => error,
    }
}

/// Exact SHA-256 identity of one stable source-sealed Blob manifest envelope.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct BlobTransferId([u8; 32]);

impl BlobTransferId {
    pub const fn new(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

/// Exact stable kind-2 ObjectID accepted by Blob carrier staging.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct BlobCarrierObjectId([u8; BLOB_CARRIER_OBJECT_ID_BYTES]);

impl BlobCarrierObjectId {
    /// Validates the closed typed-object registry tag before constructing an ID.
    pub const fn new(bytes: [u8; BLOB_CARRIER_OBJECT_ID_BYTES]) -> Result<Self, BlobStoreError> {
        if bytes[0] != 2 {
            return Err(BlobStoreError::InvalidCarrierObjectId);
        }
        Ok(Self(bytes))
    }

    pub const fn as_bytes(&self) -> &[u8; BLOB_CARRIER_OBJECT_ID_BYTES] {
        &self.0
    }
}

/// Durable lexicographic carrier-fetch position for one authenticated peer.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct BlobCarrierFetchCursor {
    source: BlobTransferId,
    object: BlobCarrierObjectId,
}

impl BlobCarrierFetchCursor {
    pub const fn new(source: BlobTransferId, object: BlobCarrierObjectId) -> Self {
        Self { source, object }
    }

    pub const fn source(&self) -> BlobTransferId {
        self.source
    }

    pub const fn object(&self) -> BlobCarrierObjectId {
        self.object
    }

    fn encode(self) -> [u8; BLOB_CARRIER_FETCH_CURSOR_BYTES] {
        let mut encoded = [0u8; BLOB_CARRIER_FETCH_CURSOR_BYTES];
        encoded[..32].copy_from_slice(self.source.as_bytes());
        encoded[32..].copy_from_slice(self.object.as_bytes());
        encoded
    }

    fn decode(bytes: &[u8]) -> Result<Self, StoreError> {
        let bytes: [u8; BLOB_CARRIER_FETCH_CURSOR_BYTES] = bytes.try_into().map_err(|_| {
            blob_error(BlobStoreError::CarrierCursorInvariant(
                "carrier cursor value has invalid length",
            ))
        })?;
        let source = BlobTransferId::new(bytes[..32].try_into().map_err(|_| {
            blob_error(BlobStoreError::CarrierCursorInvariant(
                "carrier cursor source has invalid length",
            ))
        })?);
        let object = BlobCarrierObjectId::new(bytes[32..].try_into().map_err(|_| {
            blob_error(BlobStoreError::CarrierCursorInvariant(
                "carrier cursor ObjectID has invalid length",
            ))
        })?)
        .map_err(blob_error)?;
        Ok(Self { source, object })
    }
}

/// Durable status of one peer-neutral contiguous carrier prefix.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BlobCarrierPrefixStatus {
    source: BlobTransferId,
    object: BlobCarrierObjectId,
    total_len: u64,
    prefix_len: u64,
}

impl BlobCarrierPrefixStatus {
    pub const fn source(&self) -> BlobTransferId {
        self.source
    }

    pub const fn object(&self) -> BlobCarrierObjectId {
        self.object
    }

    pub const fn total_len(&self) -> u64 {
        self.total_len
    }

    pub const fn prefix_len(&self) -> u64 {
        self.prefix_len
    }

    pub const fn complete(&self) -> bool {
        self.prefix_len == self.total_len
    }

    /// Exact next missing range, capped at the selected 16-KiB append bound.
    pub fn exact_complement(&self) -> Option<std::ops::Range<u64>> {
        if self.complete() {
            return None;
        }
        let remaining = self.total_len.checked_sub(self.prefix_len)?;
        let bound = u64::try_from(MAX_BLOB_NETWORK_RANGE_BYTES).ok()?;
        let end = self.prefix_len.checked_add(remaining.min(bound))?;
        Some(self.prefix_len..end)
    }
}

/// Outcome of one idempotent contiguous-prefix append.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BlobCarrierAppendOutcome {
    Appended(BlobCarrierPrefixStatus),
    Duplicate(BlobCarrierPrefixStatus),
}

/// One exact canonical carrier claim retained with a verified pending source.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PendingBlobCarrier {
    pub object: BlobCarrierObjectId,
    pub total_len: u64,
    pub index: u64,
}

/// Bounded durable projection of one content-verified, not-yet-published source.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PendingBlobSource {
    pub transfer_id: BlobTransferId,
    pub semantic_id: BlobSemanticId,
    pub blob_id: BlobId,
    pub variant_id: BlobVariantId,
    pub manifest_digest: [u8; 32],
    pub route_lineage: [u8; 32],
    pub physical_lineage: [u8; 32],
    pub header: EnvelopeHeader,
    pub sealed: Vec<u8>,
    pub carriers: Vec<PendingBlobCarrier>,
}

/// Durable peer-neutral progress for one authenticated pending Blob source.
///
/// This store-layer value retains the existing authenticated source projection
/// so its caller can validate it against process-live capabilities. The selected
/// application projection must redact its route/physical lineages and publisher.
/// Byte counters describe canonical encrypted carriers, not plaintext bytes.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PendingBlobTransferProgress {
    pub source: BlobSourceProjection,
    pub total_carriers: u64,
    pub durable_carriers: u64,
    pub total_carrier_bytes: u64,
    pub durable_carrier_bytes: u64,
}

/// One internally consistent audited Blob storage and pending-transfer snapshot.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BlobTransferStatusSnapshot {
    pub stats: BlobStoreStats,
    pub pending: Vec<PendingBlobTransferProgress>,
}

/// Outcome of atomically staging one exact source and complete manifest plan.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BlobSourceStageOutcome {
    Inserted,
    Duplicate,
}

/// Result of verifying and installing a complete carrier prefix.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BlobCarrierCommitOutcome {
    Committed,
    Duplicate,
}

/// State-neutral authenticated source claim shared by pending and completed rows.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BlobSourceProjection {
    pub transfer_id: BlobTransferId,
    pub semantic_id: BlobSemanticId,
    pub publisher: NodeId,
    pub topic: Topic,
    pub scope: Scope,
    pub epoch: u64,
    pub sealed_len: u64,
    pub route_lineage: [u8; 32],
    pub physical_lineage: [u8; 32],
    pub manifest_digest: [u8; 32],
    pub blob_id: BlobId,
    pub total_len: u64,
    pub chunk_size: u32,
    pub chunk_count: u64,
    /// Digest of exact durable authenticated metadata plus the sealed length.
    pub metadata_fingerprint: [u8; 32],
}

impl BlobSourceProjection {
    /// Re-derives this compact projection from one exact content-verified
    /// source envelope instead of trusting independently decoded redb fields.
    ///
    /// This binds every encoded header field (including the causal counter and
    /// priority), the physical variant identity, both provider lineages, and
    /// the sealed length before a runtime cache may use the projection as an
    /// authentication capability.
    pub fn matches_verified(
        &self,
        blob: &ContentVerifiedBlobEnvelope,
        sealed: &[u8],
    ) -> Result<bool, StoreError> {
        blob.verify_exact_sealed(sealed)
            .map_err(|error| blob_error(BlobStoreError::Verification(error.to_string())))?;
        let sealed_len =
            u64::try_from(sealed.len()).map_err(|_| StoreError::PayloadByteAccountingOverflow)?;
        let metadata = BlobMetadata {
            transfer_id: BlobTransferId::new(blob.envelope_id()),
            semantic_id: BlobSemanticId::new(blob.item_id()),
            blob_id: blob.blob_id(),
            variant_id: blob_variant_id(
                blob.blob_id(),
                blob.manifest().content_group(),
                blob.manifest().content_epoch(),
            ),
            manifest_digest: *blob.manifest_digest(),
            route_lineage: Some(*blob.route_lineage().binding()),
            physical_lineage: Some(*blob.physical_lineage().binding()),
            header: blob.header().clone(),
        };
        Ok(self
            == &blob_source_projection(
                &metadata,
                sealed_len,
                depot::BlobSourceShape {
                    total_len: blob.manifest().total_len(),
                    chunk_size: blob.manifest().chunk_size(),
                    chunk_count: blob.manifest().chunk_count(),
                },
            )?)
    }
}

/// Durable lifecycle state wrapped around a state-neutral source projection.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BlobSourceRetention {
    Pending,
    Completed { acceptance_marker: u64 },
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RetainedBlobSource {
    pub source: BlobSourceProjection,
    pub retention: BlobSourceRetention,
}

/// Source-authenticated semantic identity of one signed Blob publication.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct BlobSemanticId([u8; 32]);

impl BlobSemanticId {
    pub const fn new(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

/// Physical encrypted-content partition for one Blob content group and epoch.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct BlobVariantId([u8; 32]);

impl BlobVariantId {
    pub const fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// Derives the exact physical partition for authenticated content metadata.
    pub fn for_content(blob_id: BlobId, content_group: &[u8; 32], epoch: u64) -> Self {
        let mut digest = Sha256::new();
        digest.update(BLOB_VARIANT_DOMAIN);
        digest.update(blob_id.as_bytes());
        digest.update(content_group);
        digest.update(epoch.to_be_bytes());
        Self::from_bytes(digest.finalize().into())
    }
}

pub(crate) fn blob_variant_id(
    blob_id: BlobId,
    content_group: &[u8; 32],
    epoch: u64,
) -> BlobVariantId {
    BlobVariantId::for_content(blob_id, content_group, epoch)
}

/// Bounded application idempotency key for one local Blob publication.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct BlobOperationKey(Vec<u8>);

impl BlobOperationKey {
    pub fn new(bytes: impl Into<Vec<u8>>) -> Result<Self, StoreError> {
        let bytes = bytes.into();
        if bytes.is_empty() || bytes.len() > MAX_BLOB_OPERATION_KEY_BYTES {
            return Err(blob_error(BlobStoreError::InvalidOperationKey {
                length: bytes.len(),
            }));
        }
        Ok(Self(bytes))
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

/// Canonical epoch-independent public request identity for Blob publication.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BlobPublicationIntent {
    publisher: NodeId,
    topic: Topic,
    scope: Scope,
    priority: Priority,
    blob_id: BlobId,
    digest: [u8; 32],
}

impl BlobPublicationIntent {
    pub fn new(
        publisher: NodeId,
        topic: Topic,
        scope: Scope,
        priority: Priority,
        blob_id: BlobId,
    ) -> Result<Self, StoreError> {
        let mut intent = Self {
            publisher,
            topic,
            scope,
            priority,
            blob_id,
            digest: [0; 32],
        };
        intent.digest = blob_publication_intent_digest(&intent)?;
        Ok(intent)
    }

    pub const fn publisher(&self) -> NodeId {
        self.publisher
    }

    pub const fn topic(&self) -> &Topic {
        &self.topic
    }

    pub const fn scope(&self) -> &Scope {
        &self.scope
    }

    pub const fn priority(&self) -> Priority {
        self.priority
    }

    pub const fn blob_id(&self) -> BlobId {
        self.blob_id
    }

    fn digest(&self) -> [u8; 32] {
        self.digest
    }
}

/// Exact borrowed inputs for one idempotent Blob publication operation.
pub struct BlobOperationRequest<'a> {
    operation: &'a BlobOperationKey,
    intent: &'a BlobPublicationIntent,
}

impl<'a> BlobOperationRequest<'a> {
    pub const fn new(operation: &'a BlobOperationKey, intent: &'a BlobPublicationIntent) -> Self {
        Self { operation, intent }
    }

    pub const fn operation(&self) -> &BlobOperationKey {
        self.operation
    }

    pub const fn intent(&self) -> &BlobPublicationIntent {
        self.intent
    }
}

/// Optimistic Blob publication reservation over shared causal ledgers.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BlobReservation {
    control_policy: ControlPolicySnapshot,
    publisher: NodeId,
    topic: Topic,
    scope: Scope,
    previous_counter: u64,
    counter: u64,
    context: VersionVector,
}

impl BlobReservation {
    pub const fn control_policy(&self) -> &ControlPolicySnapshot {
        &self.control_policy
    }

    pub const fn publisher(&self) -> NodeId {
        self.publisher
    }

    pub const fn counter(&self) -> u64 {
        self.counter
    }

    pub const fn context(&self) -> &VersionVector {
        &self.context
    }

    /// Builds the exact selected Blob manifest-envelope header.
    pub fn header(
        &self,
        priority: Priority,
        route: BlobRouteCommitment,
        manifest_len: u64,
        key_epoch: u64,
    ) -> Result<EnvelopeHeader, StoreError> {
        let header = EnvelopeHeader {
            class: SemanticDataClass::Blob,
            topic: self.topic.clone(),
            scope: self.scope.clone(),
            priority,
            stamp: CausalStamp {
                dot: Dot {
                    publisher: self.publisher,
                    counter: self.counter,
                },
                context: self.context.clone(),
            },
            event_sequence: None,
            logical_key: route.blob_id().as_bytes().to_vec(),
            blob_route: Some(route),
            ttl_ms: None,
            content_len: manifest_len,
            tombstone: false,
            key_epoch,
        };
        validate_blob_header(&header)?;
        Ok(header)
    }
}

/// One source-authenticated Blob publication and its exact retained envelope.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StoredBlob {
    pub transfer_id: BlobTransferId,
    pub semantic_id: BlobSemanticId,
    pub blob_id: BlobId,
    pub variant_id: BlobVariantId,
    pub manifest_digest: [u8; 32],
    /// Opaque exact source-route lineage; absent only for legacy metadata-v1.
    pub route_lineage: Option<[u8; 32]>,
    /// Opaque exact physical content lineage; absent only for legacy metadata-v1.
    pub physical_lineage: Option<[u8; 32]>,
    pub header: EnvelopeHeader,
    pub sealed: Vec<u8>,
    pub acceptance_marker: u64,
}

/// Result of one atomic idempotent Blob publication.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum BlobOnceOutcome {
    Inserted { blob: StoredBlob },
    BoundExisting { blob: StoredBlob },
    Existing { blob: StoredBlob },
}

impl BlobOnceOutcome {
    pub const fn blob(&self) -> &StoredBlob {
        match self {
            Self::Inserted { blob } | Self::BoundExisting { blob } | Self::Existing { blob } => {
                blob
            }
        }
    }

    pub const fn inserted(&self) -> bool {
        matches!(self, Self::Inserted { .. })
    }
}

/// Structural current-policy disposition in a bounded Blob read plan.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BlobPublicationDisposition {
    Current,
    Alternate,
}

/// One projection-only retained publication in an exact read plan.
///
/// Sealed source bytes are deliberately absent. Alternates can be matched to
/// startup-authenticated claims without allocating their envelopes; only the
/// uniquely selected current candidate is exact-loaded for plaintext use.
/// A live page therefore relies on its startup-authenticated alternate claim
/// plus this Store's exclusive-writer immutability and does not rehash every
/// inactive alternate envelope on every page.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BlobReadCandidate {
    projection: BlobSourceProjection,
    acceptance_marker: u64,
    disposition: Option<BlobPublicationDisposition>,
}

impl BlobReadCandidate {
    pub const fn projection(&self) -> &BlobSourceProjection {
        &self.projection
    }

    pub const fn acceptance_marker(&self) -> u64 {
        self.acceptance_marker
    }

    pub const fn disposition(&self) -> Option<BlobPublicationDisposition> {
        self.disposition
    }
}

/// Exact bounded publication set for one immutable Blob under settled policy.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BlobReadPlan {
    control_policy: ControlPolicySnapshot,
    topic: Topic,
    scope: Scope,
    blob_id: BlobId,
    candidates: Vec<BlobReadCandidate>,
}

impl BlobReadPlan {
    pub const fn control_policy(&self) -> &ControlPolicySnapshot {
        &self.control_policy
    }

    pub const fn topic(&self) -> &Topic {
        &self.topic
    }

    pub const fn scope(&self) -> &Scope {
        &self.scope
    }

    pub const fn blob_id(&self) -> BlobId {
        self.blob_id
    }

    pub fn candidates(&self) -> &[BlobReadCandidate] {
        &self.candidates
    }

    pub fn current(&self) -> Option<&BlobReadCandidate> {
        self.candidates
            .iter()
            .find(|candidate| candidate.disposition == Some(BlobPublicationDisposition::Current))
    }
}

/// Consistent redb and physical-depot counts for the Blob namespace.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct BlobStoreStats {
    pub publications: u64,
    pub acceptance_markers: u64,
    pub total_sealed_bytes: u64,
    pub last_acceptance_marker: u64,
    pub operations: u64,
    pub operation_bytes: u64,
    pub variants: u64,
    pub finalized_variants: u64,
    pub committed_chunks: u64,
    pub committed_file_bytes: u64,
    /// Exact final file bytes reserved by durable expected chunk records.
    pub reserved_file_bytes: u64,
    pub pending_sources: u64,
    pub carrier_prefixes: u64,
    pub network_staging_bytes: u64,
    pub carrier_fetch_cursors: u64,
    pub lineage_fences: u64,
    pub lineage_fence_bytes: u64,
    pub replay_fences: u64,
    pub replay_fence_bytes: u64,
    pub publication_lifecycle_rows: u64,
    pub variant_references: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct BlobMetadata {
    transfer_id: BlobTransferId,
    semantic_id: BlobSemanticId,
    blob_id: BlobId,
    variant_id: BlobVariantId,
    manifest_digest: [u8; 32],
    route_lineage: Option<[u8; 32]>,
    physical_lineage: Option<[u8; 32]>,
    header: EnvelopeHeader,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct BlobOperationRecord {
    transfer_id: BlobTransferId,
    intent_digest: [u8; 32],
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct PendingBlobSourceRecord {
    metadata: BlobMetadata,
    route_lineage: [u8; 32],
    physical_lineage: [u8; 32],
    carriers: Vec<PendingBlobCarrierRecord>,
    sealed: Vec<u8>,
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
struct PendingBlobCarrierRecord {
    object: BlobCarrierObjectId,
    total_len: u64,
    index: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct CompletedBlobRangeSourceSnapshot {
    metadata: BlobMetadata,
    projection: BlobSourceProjection,
    acceptance_marker: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct BlobCarrierPrefixRecord {
    source: BlobTransferId,
    total_len: u64,
    prefix: Vec<u8>,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
struct BlobNetworkStagingUsage {
    rows: u64,
    bytes: u64,
}

#[cfg(test)]
thread_local! {
    static TEST_BLOB_NETWORK_GLOBAL_AUDITS: std::cell::Cell<u64> = const {
        std::cell::Cell::new(0)
    };
    static TEST_BLOB_READ_PLAN_ROWS_VISITED: std::cell::Cell<u64> = const {
        std::cell::Cell::new(0)
    };
    static TEST_BLOB_SOURCE_BYTES_LOADED: std::cell::Cell<u64> = const {
        std::cell::Cell::new(0)
    };
    static TEST_BLOB_CAPACITY_CONTENT_ROWS_VISITED: std::cell::Cell<u64> = const {
        std::cell::Cell::new(0)
    };
    static TEST_BLOB_FRONTIER_ROWS_VISITED: std::cell::Cell<u64> = const {
        std::cell::Cell::new(0)
    };
    static TEST_PENDING_BLOB_SOURCE_ROWS_VISITED: std::cell::Cell<u64> = const {
        std::cell::Cell::new(0)
    };
    static TEST_BLOB_ADMISSION_PRE_COMMIT_FAULT: std::cell::Cell<bool> = const {
        std::cell::Cell::new(false)
    };
}

#[cfg(test)]
fn test_blob_network_global_audits() -> u64 {
    TEST_BLOB_NETWORK_GLOBAL_AUDITS.with(std::cell::Cell::get)
}

#[cfg(test)]
fn test_blob_read_work_counts() -> (u64, u64) {
    (
        TEST_BLOB_READ_PLAN_ROWS_VISITED.with(std::cell::Cell::get),
        TEST_BLOB_SOURCE_BYTES_LOADED.with(std::cell::Cell::get),
    )
}

#[cfg(test)]
fn test_blob_capacity_content_rows_visited() -> u64 {
    TEST_BLOB_CAPACITY_CONTENT_ROWS_VISITED.with(std::cell::Cell::get)
}

#[cfg(test)]
pub(crate) fn record_test_blob_frontier_row() {
    TEST_BLOB_FRONTIER_ROWS_VISITED.with(|count| count.set(count.get().saturating_add(1)));
}

#[cfg(test)]
fn test_blob_frontier_rows_visited() -> u64 {
    TEST_BLOB_FRONTIER_ROWS_VISITED.with(std::cell::Cell::get)
}

#[cfg(test)]
fn test_pending_blob_source_rows_visited() -> u64 {
    TEST_PENDING_BLOB_SOURCE_ROWS_VISITED.with(std::cell::Cell::get)
}

#[derive(Default)]
pub(crate) struct BlobAuditSnapshot {
    pub stats: BlobStoreStats,
}

impl Store {
    #[cfg(test)]
    fn set_blob_carrier_range_post_read_gate(
        &self,
        reached: std::sync::mpsc::SyncSender<()>,
        release: std::sync::mpsc::Receiver<()>,
    ) {
        *self
            .blob_carrier_range_post_read_gate
            .lock()
            .expect("Blob carrier-range post-read gate lock") = Some((reached, release));
    }

    #[cfg(test)]
    fn set_blob_carrier_commit_post_snapshot_gate(
        &self,
        reached: std::sync::mpsc::SyncSender<()>,
        release: std::sync::mpsc::Receiver<()>,
    ) {
        *self
            .blob_carrier_commit_post_snapshot_gate
            .lock()
            .expect("Blob carrier-commit post-snapshot gate lock") = Some((reached, release));
    }

    /// Returns the dedicated physical limits configured for this handle.
    pub const fn blob_depot_limits(&self) -> BlobDepotLimits {
        self.blob_depot_limits
    }

    /// Acquires the single mission-bound depot adapter used by the generic core engine.
    pub fn blob_depot(&self) -> Result<BlobDepot<'_>, StoreError> {
        self.require_live()?;
        self.require_bound_mission()?;
        BlobDepot::open(self)
    }

    /// Acquires the owner-bound mutation adapter for one local Blob publish
    /// without a global depot audit.
    ///
    /// Existing roots are opened under the common depot mutex with exact
    /// Store/backing/owner binding. A missing root is created only for a
    /// canonically empty durable Blob namespace.
    pub fn blob_depot_for_local_publish(&self) -> Result<BlobDepot<'_>, StoreError> {
        self.require_live()?;
        self.require_bound_mission()?;
        BlobDepot::open_network_mutation(self, true)
    }

    /// Mints a completion for one freshly verified local publish without a
    /// global depot audit or publication-row dependency.
    pub fn completed_local_blob(
        &self,
        blob: &ContentVerifiedBlobEnvelope,
        manifest_bytes: &[u8],
    ) -> Result<BlobDepotCompletion, StoreError> {
        self.require_live()?;
        self.require_bound_mission()?;
        let mut depot = BlobDepot::open_network_mutation(self, false)?;
        depot.completed_blob(blob, manifest_bytes)
    }

    /// Opens only the exact finalized depot variant authorized by `completion`.
    ///
    /// Unlike [`Self::blob_depot`], this page-read path does not perform a
    /// global Blob schema audit, create the depot root, or enter a write
    /// transaction. It still acquires the common depot mutex, rechecks live
    /// state and the exact Store/backing/owner binding, and rejects a stale or
    /// foreign nonconstructible completion capability.
    pub fn blob_depot_for_authenticated_read(
        &self,
        completion: &BlobDepotCompletion,
    ) -> Result<AuthenticatedBlobReadDepot<'_>, StoreError> {
        self.require_live()?;
        self.require_bound_mission()?;
        BlobDepot::open_authenticated_read(self, completion)
    }

    /// Mints one exact completion capability for an authenticated pending
    /// network source without opening the unrestricted globally audited depot.
    ///
    /// The common depot mutex is acquired before the pending snapshot. Current
    /// policy, source identity, sealed envelope, transfer plan, owner/backing
    /// binding, import, every committed chunk, and every physical file are
    /// rechecked while the lock remains held. The fixed root must already
    /// exist; this seam never creates it.
    pub fn completed_pending_blob_with_policy(
        &self,
        policy: &ControlPolicySnapshot,
        source: BlobTransferId,
        blob: &ContentVerifiedBlobEnvelope,
        manifest_bytes: &[u8],
        plan: &VerifiedBlobTransferPlan,
    ) -> Result<BlobDepotCompletion, StoreError> {
        self.require_live()?;
        let authority = self.require_bound_mission()?;
        let mut depot = BlobDepot::open_network_mutation(self, false)?;
        let read = self.database.begin_read()?;
        let pending = read
            .open_table(BLOB_PENDING_SOURCES)?
            .get(source.as_bytes().as_slice())?
            .map(|value| decode_pending_blob_source(value.value()))
            .transpose()?
            .ok_or_else(|| blob_error(BlobStoreError::PendingSourceMissing))?;
        enforce_blob_policy_read(&read, authority, policy, &pending.metadata.header)?;
        require_pending_blob_plan(&pending, plan)?;
        blob.verify_exact_sealed(&pending.sealed)
            .map_err(|error| blob_error(BlobStoreError::Verification(error.to_string())))?;
        if pending.metadata.transfer_id != source
            || BlobTransferId::new(blob.envelope_id()) != source
            || pending.metadata.semantic_id != BlobSemanticId::new(blob.item_id())
            || pending.metadata.blob_id != blob.blob_id()
            || pending.metadata.manifest_digest != *blob.manifest_digest()
            || pending.route_lineage != *blob.route_lineage().binding()
            || pending.physical_lineage != *blob.physical_lineage().binding()
            || plan.source_envelope().into_bytes() != *source.as_bytes()
        {
            return Err(blob_error(BlobStoreError::CompletionMismatch));
        }
        drop(read);
        depot.completed_blob(blob, manifest_bytes)
    }

    /// Mints one exact completion capability for a retained completed source
    /// without a global Blob audit or root creation.
    ///
    /// This policy-neutral seam is suitable for incremental startup replay:
    /// the caller supplies a source/content-verified envelope, while the Store
    /// rechecks the exact completed projection, acceptance marker, sealed row,
    /// owner/backing binding, finalized import, chunk markers, and files under
    /// the common depot mutex.
    pub fn completed_retained_blob(
        &self,
        projection: &BlobSourceProjection,
        retention: BlobSourceRetention,
        blob: &ContentVerifiedBlobEnvelope,
        manifest_bytes: &[u8],
        sealed: &[u8],
    ) -> Result<BlobDepotCompletion, StoreError> {
        self.require_live()?;
        self.require_bound_mission()?;
        let acceptance_marker = match retention {
            BlobSourceRetention::Completed { acceptance_marker } => acceptance_marker,
            BlobSourceRetention::Pending => {
                return Err(blob_error(BlobStoreError::CompletionMismatch));
            }
        };
        let mut depot = BlobDepot::open_network_mutation(self, false)?;
        let read = self.database.begin_read()?;
        let metadata = read
            .open_table(BLOB_PUBLICATIONS)?
            .get(projection.transfer_id.as_bytes().as_slice())?
            .map(|value| decode_blob_metadata(value.value()))
            .transpose()?
            .ok_or_else(|| blob_error(BlobStoreError::CompletionMismatch))?;
        let bytes = read.open_table(BLOB_BYTES)?;
        let exact_sealed = bytes
            .get(projection.transfer_id.as_bytes().as_slice())?
            .ok_or_else(|| blob_error(BlobStoreError::CompletionMismatch))?;
        let marker = read
            .open_table(BLOB_ACCEPTANCE_MARKERS)?
            .get(projection.transfer_id.as_bytes().as_slice())?
            .map(|value| value.value())
            .ok_or_else(|| blob_error(BlobStoreError::CompletionMismatch))?;
        let sealed_len = u64::try_from(exact_sealed.value().len())
            .map_err(|_| StoreError::PayloadByteAccountingOverflow)?;
        let shape = durable_blob_source_shape_read(&read, &metadata, true)?;
        let durable_projection = blob_source_projection(&metadata, sealed_len, shape)?;
        blob.verify_exact_sealed(sealed)
            .map_err(|error| blob_error(BlobStoreError::Verification(error.to_string())))?;
        if durable_projection != *projection
            || marker != acceptance_marker
            || exact_sealed.value() != sealed
            || BlobTransferId::new(blob.envelope_id()) != projection.transfer_id
            || !projection.matches_verified(blob, sealed)?
        {
            return Err(blob_error(BlobStoreError::CompletionMismatch));
        }
        drop(exact_sealed);
        drop(bytes);
        drop(read);
        depot.completed_blob(blob, manifest_bytes)
    }

    /// Reserves the next Blob publication dot under exact settled policy.
    pub fn reserve_blob_with_policy(
        &self,
        policy: &ControlPolicySnapshot,
        publisher: NodeId,
        topic: &Topic,
        scope: &Scope,
    ) -> Result<BlobReservation, StoreError> {
        self.require_live()?;
        let authority = self.require_bound_mission()?;
        let read = self.database.begin_read()?;
        require_control_policy_read(&read, authority, policy)?;
        if control_principal_revoked_read(&read, publisher)? {
            return Err(blob_error(BlobStoreError::PublisherRevoked(publisher)));
        }
        let previous_counter = read
            .open_table(PUBLISHER_HIGH_WATER)?
            .get(publisher.as_slice())?
            .map_or(0, |value| value.value());
        let counter = previous_counter.checked_add(1).ok_or_else(|| {
            blob_error(BlobStoreError::InvalidPublication(
                "publisher causal counter is exhausted",
            ))
        })?;
        let prefix = event_domain_prefix(topic, scope)?;
        let upper = blob_content_prefix_upper_bound(&prefix)?;
        let frontier = read.open_table(CAUSAL_FRONTIER)?;
        let mut context = VersionVector::default();
        let mut direct_publishers = 0usize;
        for row in frontier.range::<&[u8]>((
            std::ops::Bound::<&[u8]>::Included(prefix.as_slice()),
            std::ops::Bound::<&[u8]>::Excluded(upper.as_slice()),
        ))? {
            let (key, value) = row?;
            let key = key.value();
            #[cfg(test)]
            record_test_blob_frontier_row();
            if key.len() != prefix.len() + 32 || value.value() == 0 {
                return Err(blob_error(BlobStoreError::SchemaInvariant(
                    "causal frontier contains an invalid Blob-domain row",
                )));
            }
            direct_publishers = direct_publishers
                .checked_add(1)
                .ok_or(StoreError::ItemCountAccountingOverflow)?;
            if direct_publishers > MAX_CAUSAL_CONTEXT_ENTRIES {
                return Err(blob_error(BlobStoreError::SchemaInvariant(
                    "Blob causal frontier exceeds the proven context bound",
                )));
            }
            let context_publisher: NodeId = key[prefix.len()..].try_into().map_err(|_| {
                blob_error(BlobStoreError::SchemaInvariant(
                    "Blob causal frontier key is invalid",
                ))
            })?;
            context.observe(Dot {
                publisher: context_publisher,
                counter: value.value(),
            });
        }
        if context.counter(&publisher) == 0 && direct_publishers == MAX_CAUSAL_CONTEXT_ENTRIES {
            return Err(blob_error(BlobStoreError::InvalidPublication(
                "causal frontier publisher limit reached",
            )));
        }
        Ok(BlobReservation {
            control_policy: *policy,
            publisher,
            topic: topic.clone(),
            scope: scope.clone(),
            previous_counter,
            counter,
            context,
        })
    }

    /// Policy-bound idempotency preflight before allocating a current-epoch variant.
    pub fn blob_for_operation_with_policy(
        &self,
        policy: &ControlPolicySnapshot,
        request: &BlobOperationRequest<'_>,
    ) -> Result<Option<StoredBlob>, StoreError> {
        self.require_live()?;
        let authority = self.require_bound_mission()?;
        let read = self.database.begin_read()?;
        require_control_policy_read(&read, authority, policy)?;
        if control_principal_revoked_read(&read, request.intent.publisher)? {
            return Err(blob_error(BlobStoreError::PublisherRevoked(
                request.intent.publisher,
            )));
        }
        let existing = read
            .open_table(BLOB_OPERATIONS)?
            .get(request.operation.as_bytes())?
            .map(|value| {
                decode_blob_operation_record(value.value()).map_err(|error| {
                    blob_preflight_decode_error(error, "Blob operation row is malformed")
                })
            })
            .transpose()?;
        match existing {
            Some(existing) if existing.intent_digest != request.intent.digest() => {
                Err(blob_error(BlobStoreError::OperationConflict))
            }
            Some(existing) => load_blob_from_read(&read, existing.transfer_id)
                .map_err(|error| {
                    blob_preflight_decode_error(
                        error,
                        "Blob operation publication row is malformed",
                    )
                })?
                .map_or_else(
                    || {
                        Err(blob_error(BlobStoreError::SchemaInvariant(
                            "Blob operation points to a missing publication",
                        )))
                    },
                    |blob| Ok(Some(blob)),
                ),
            None => Ok(None),
        }
    }

    /// Resolves one operation without treating persisted metadata as live authority.
    pub fn blob_for_operation(
        &self,
        operation: &BlobOperationKey,
    ) -> Result<Option<StoredBlob>, StoreError> {
        self.require_bound_mission()?;
        let read = self.database.begin_read()?;
        let transfer = read
            .open_table(BLOB_OPERATIONS)?
            .get(operation.as_bytes())?
            .map(|value| {
                decode_blob_operation_record(value.value()).map(|record| record.transfer_id)
            })
            .transpose()?;
        transfer
            .map(|transfer| load_blob_from_read(&read, transfer))
            .transpose()
            .map(Option::flatten)
    }

    /// Privileged raw lookup by exact source-envelope transfer identity.
    pub fn get_blob(&self, transfer_id: BlobTransferId) -> Result<Option<StoredBlob>, StoreError> {
        self.require_bound_mission()?;
        let read = self.database.begin_read()?;
        load_blob_from_read(&read, transfer_id)
    }

    /// Privileged raw lookup by source-authenticated semantic publication identity.
    pub fn blob_by_semantic_id(
        &self,
        semantic_id: BlobSemanticId,
    ) -> Result<Option<StoredBlob>, StoreError> {
        self.require_bound_mission()?;
        let read = self.database.begin_read()?;
        let transfer = read
            .open_table(BLOB_SEMANTIC_ITEMS)?
            .get(semantic_id.as_bytes().as_slice())?
            .map(|value| parse_blob_transfer_id("Blob semantic item table", value.value()))
            .transpose()?;
        transfer
            .map(|transfer| load_blob_from_read(&read, transfer))
            .transpose()
            .map(Option::flatten)
    }

    /// Prepares every retained signed publication for one immutable Blob.
    pub fn prepare_blob_read_with_policy(
        &self,
        policy: &ControlPolicySnapshot,
        topic: &Topic,
        scope: &Scope,
        blob_id: BlobId,
    ) -> Result<BlobReadPlan, StoreError> {
        self.require_live()?;
        let authority = self.require_bound_mission()?;
        let read = self.database.begin_read()?;
        require_control_policy_read(&read, authority, policy)?;
        blob_read_plan_read(&read, *policy, topic, scope, blob_id).map_err(|error| {
            blob_preflight_decode_error(error, "Blob read projection row is malformed")
        })
    }

    /// Rechecks exact policy and the complete freshly verified Blob publication set.
    pub fn require_blob_read_plan_with_policy(
        &self,
        policy: &ControlPolicySnapshot,
        plan: &BlobReadPlan,
    ) -> Result<(), StoreError> {
        self.require_live()?;
        let authority = self.require_bound_mission()?;
        if policy != plan.control_policy() {
            return Err(blob_error(BlobStoreError::ReadPlanChanged));
        }
        let read = self.database.begin_read()?;
        require_control_policy_read(&read, authority, policy)?;
        let current =
            blob_read_plan_read(&read, *policy, plan.topic(), plan.scope(), plan.blob_id())?;
        if current != *plan {
            return Err(blob_error(BlobStoreError::ReadPlanChanged));
        }
        Ok(())
    }

    /// Exact-loads one projection-only read candidate under the same settled
    /// policy, cloning only that source's sealed envelope bytes.
    pub fn load_blob_read_candidate_with_policy(
        &self,
        policy: &ControlPolicySnapshot,
        candidate: &BlobReadCandidate,
    ) -> Result<StoredBlob, StoreError> {
        self.require_live()?;
        let authority = self.require_bound_mission()?;
        let read = self.database.begin_read()?;
        require_control_policy_read(&read, authority, policy)?;
        let stored = load_blob_from_read(&read, candidate.projection.transfer_id)?
            .ok_or_else(|| blob_error(BlobStoreError::CompletionMismatch))?;
        let metadata = BlobMetadata {
            transfer_id: stored.transfer_id,
            semantic_id: stored.semantic_id,
            blob_id: stored.blob_id,
            variant_id: stored.variant_id,
            manifest_digest: stored.manifest_digest,
            route_lineage: stored.route_lineage,
            physical_lineage: stored.physical_lineage,
            header: stored.header.clone(),
        };
        let shape = durable_blob_source_shape_read(&read, &metadata, true)?;
        let sealed_len = u64::try_from(stored.sealed.len())
            .map_err(|_| StoreError::PayloadByteAccountingOverflow)?;
        if stored.acceptance_marker != candidate.acceptance_marker
            || blob_source_projection(&metadata, sealed_len, shape)? != candidate.projection
        {
            return Err(blob_error(BlobStoreError::CompletionMismatch));
        }
        Ok(stored)
    }

    /// Returns a typed, disjoint inventory of signed Blob publication transfers.
    pub fn blob_inventory(&self) -> Result<Vec<BlobTransferId>, StoreError> {
        self.require_bound_mission()?;
        let read = self.database.begin_read()?;
        let table = read.open_table(BLOB_PUBLICATIONS)?;
        let mut inventory = Vec::with_capacity(
            usize::try_from(table.len()?).map_err(|_| StoreError::ItemCountAccountingOverflow)?,
        );
        for row in table.iter()? {
            let (key, _) = row?;
            inventory.push(parse_blob_transfer_id(
                "Blob publication table",
                key.value(),
            )?);
        }
        Ok(inventory)
    }

    /// Returns audited redb counters and verifies every marked depot artifact.
    pub fn blob_stats(&self) -> Result<BlobStoreStats, StoreError> {
        self.require_bound_mission()?;
        let read = self.database.begin_read()?;
        let stats = inspect_blob_tables_read(&read)?.stats;
        depot::audit_depot_read(
            &read,
            &self.path,
            self.backing_identity,
            self.blob_depot_owner_token,
            stats,
        )?;
        Ok(stats)
    }

    /// Atomically stages one complete source-authenticated manifest and its
    /// exact canonical carrier plan without making an application publication.
    pub fn stage_verified_blob_source_with_policy(
        &self,
        policy: &ControlPolicySnapshot,
        blob: &ContentVerifiedBlobEnvelope,
        sealed: &[u8],
        plan: &VerifiedBlobTransferPlan,
    ) -> Result<BlobSourceStageOutcome, StoreError> {
        self.require_live()?;
        let authority = self.require_bound_mission()?;
        if sealed.len() > MAX_BLOB_NETWORK_SOURCE_BYTES {
            return Err(blob_error(BlobStoreError::NetworkSourceTooLarge {
                sealed_len: sealed.len(),
                limit: MAX_BLOB_NETWORK_SOURCE_BYTES,
            }));
        }
        blob.verify_exact_sealed(sealed)
            .map_err(|error| blob_error(BlobStoreError::Verification(error.to_string())))?;
        blob.verify_exact_manifest(plan.manifest_bytes())
            .map_err(|error| blob_error(BlobStoreError::Verification(error.to_string())))?;
        if blob.mission_authority_id() != authority
            || plan.source_envelope().into_bytes() != blob.envelope_id()
            || plan.manifest() != blob.manifest()
            || plan.manifest_digest() != blob.manifest_digest()
            || plan.physical_lineage() != blob.physical_lineage()
        {
            return Err(blob_error(BlobStoreError::PendingSourceConflict));
        }
        let manifest = plan.manifest();
        if manifest.total_len() > MAX_NETWORK_BLOB_BYTES
            || manifest.chunk_count() > MAX_NETWORK_BLOB_CHUNKS
        {
            return Err(blob_error(BlobStoreError::NetworkBlobTooLarge {
                total_len: manifest.total_len(),
                chunk_count: manifest.chunk_count(),
            }));
        }

        let mut carriers = Vec::with_capacity(
            usize::try_from(manifest.chunk_count())
                .map_err(|_| StoreError::ItemCountAccountingOverflow)?,
        );
        for index in 0..manifest.chunk_count() {
            let core_id = plan
                .carrier_id(index)
                .map_err(|error| blob_error(BlobStoreError::Verification(error.to_string())))?;
            let object = BlobCarrierObjectId::new(core_id.wire_bytes()).map_err(blob_error)?;
            let total_len = plan
                .carrier_total_len(object.as_bytes())
                .map_err(|error| blob_error(BlobStoreError::Verification(error.to_string())))?;
            if total_len == 0 || total_len > MAX_BLOB_NETWORK_CARRIER_BYTES {
                return Err(blob_error(BlobStoreError::InvalidCarrierRange(
                    "authenticated carrier total violates the store bound",
                )));
            }
            carriers.push(PendingBlobCarrierRecord {
                object,
                total_len,
                index,
            });
        }
        carriers.sort_unstable_by_key(|carrier| carrier.object);
        if carriers
            .windows(2)
            .any(|pair| pair[0].object == pair[1].object)
        {
            return Err(blob_error(BlobStoreError::PendingSourceConflict));
        }

        let header = blob.header().clone();
        validate_blob_header(&header)?;
        let transfer_id = BlobTransferId::new(blob.envelope_id());
        let metadata = BlobMetadata {
            transfer_id,
            semantic_id: BlobSemanticId::new(blob.item_id()),
            blob_id: blob.blob_id(),
            variant_id: blob_variant_id(
                blob.blob_id(),
                manifest.content_group(),
                manifest.content_epoch(),
            ),
            manifest_digest: *blob.manifest_digest(),
            route_lineage: Some(*blob.route_lineage().binding()),
            physical_lineage: Some(*blob.physical_lineage().binding()),
            header,
        };
        let pending = PendingBlobSourceRecord {
            metadata,
            route_lineage: *blob.route_lineage().binding(),
            physical_lineage: *blob.physical_lineage().binding(),
            carriers,
            sealed: sealed.to_vec(),
        };
        let encoded = encode_pending_blob_source(&pending)?;

        // Ensure the mission-bound depot root/owner marker exists before the
        // redb import becomes durable, while retaining the single-owner lock.
        let _depot_guard = BlobDepot::open_network_mutation(self, true)?;
        self.require_live()?;
        let write = self.database.begin_write()?;
        enforce_live_write(&write)?;
        enforce_blob_policy_write(&write, authority, policy, &pending.metadata.header)?;
        let staging = blob_network_staging_usage_write(&write, authority)?;
        let owner_binding = depot::require_depot_owner_binding_write(
            &write,
            &self.path,
            self.backing_identity,
            self.blob_depot_owner_token,
        )?;
        let replay_fence = blob_replay_fence(&pending.metadata, &pending.sealed)?;

        if let Some(accepted) = load_blob_from_write(&write, transfer_id)? {
            if accepted.semantic_id != pending.metadata.semantic_id
                || accepted.blob_id != pending.metadata.blob_id
                || accepted.variant_id != pending.metadata.variant_id
                || accepted.manifest_digest != pending.metadata.manifest_digest
                || accepted.route_lineage != Some(pending.route_lineage)
                || accepted.physical_lineage != Some(pending.physical_lineage)
                || accepted.header != pending.metadata.header
                || accepted.sealed != pending.sealed
            {
                return Err(blob_error(BlobStoreError::PendingSourceConflict));
            }
            lifecycle::require_lineage_fence(
                &write,
                pending.metadata.variant_id,
                pending.physical_lineage,
                owner_binding,
            )?;
            if lifecycle::check_replay_fence(&write, replay_fence)?
                != lifecycle::ReplayFenceStatus::Exact
            {
                return Err(blob_error(BlobStoreError::SchemaInvariant(
                    "accepted Blob publication is missing its replay fence",
                )));
            }
            lifecycle::require_publication_row(&write)?;
            lifecycle::require_variant_reference(
                &write,
                pending.metadata.variant_id,
                lifecycle::VariantReferenceOwner::Publication,
                transfer_id,
            )?;
            return Ok(BlobSourceStageOutcome::Duplicate);
        }
        if lifecycle::check_replay_fence(&write, replay_fence)?
            == lifecycle::ReplayFenceStatus::Exact
        {
            return Err(blob_error(BlobStoreError::SchemaInvariant(
                "retained Blob replay fence is missing its live publication",
            )));
        }
        if transfer_id_exists_outside_blob(&write, transfer_id.as_bytes())? {
            return Err(StoreError::TransferNamespaceCollision {
                transfer_id: *transfer_id.as_bytes(),
            });
        }

        let existing = write
            .open_table(BLOB_PENDING_SOURCES)?
            .get(transfer_id.as_bytes().as_slice())?
            .map(|value| value.value().to_vec());
        if existing.as_deref().is_some_and(|value| value != encoded) {
            return Err(blob_error(BlobStoreError::PendingSourceConflict));
        }
        if existing.is_some() {
            lifecycle::require_lineage_fence(
                &write,
                pending.metadata.variant_id,
                pending.physical_lineage,
                owner_binding,
            )?;
            lifecycle::require_variant_reference(
                &write,
                pending.metadata.variant_id,
                lifecycle::VariantReferenceOwner::PendingSource,
                transfer_id,
            )?;
        } else {
            lifecycle::ensure_lineage_fence(
                &write,
                self.blob_lifecycle_limits,
                pending.metadata.variant_id,
                pending.physical_lineage,
                owner_binding,
            )?;
        }
        let incoming_rows = u64::from(existing.is_none());
        let incoming_bytes = if existing.is_none() {
            staging_entry_bytes(32, encoded.len())?
        } else {
            0
        };
        require_blob_network_staging_capacity(staging, incoming_rows, incoming_bytes)?;

        depot::stage_verified_plan_write(&write, self.blob_depot_limits, plan)?;
        if existing.is_none() {
            write
                .open_table(BLOB_PENDING_SOURCES)?
                .insert(transfer_id.as_bytes().as_slice(), encoded.as_slice())?;
            lifecycle::insert_variant_reference(
                &write,
                pending.metadata.variant_id,
                lifecycle::VariantReferenceOwner::PendingSource,
                transfer_id,
            )?;
            update_blob_network_staging_usage(
                &write,
                BlobNetworkStagingUsage {
                    rows: staging
                        .rows
                        .checked_add(1)
                        .ok_or(StoreError::ItemCountAccountingOverflow)?,
                    bytes: staging
                        .bytes
                        .checked_add(incoming_bytes)
                        .ok_or(StoreError::PayloadByteAccountingOverflow)?,
                },
            )?;
        }
        write.commit()?;
        Ok(if existing.is_some() {
            BlobSourceStageOutcome::Duplicate
        } else {
            BlobSourceStageOutcome::Inserted
        })
    }

    /// Loads one exact verified pending source without granting publication visibility.
    pub fn pending_blob_source(
        &self,
        source: BlobTransferId,
    ) -> Result<Option<PendingBlobSource>, StoreError> {
        self.require_live()?;
        self.require_bound_mission()?;
        let read = self.database.begin_read()?;
        read.open_table(BLOB_PENDING_SOURCES)?
            .get(source.as_bytes().as_slice())?
            .map(|value| decode_pending_blob_source(value.value()))
            .transpose()
            .map(|record| record.map(pending_blob_source_projection))
    }

    /// Loads one exact lifecycle-neutral source claim from completed or pending state.
    pub fn blob_source_projection(
        &self,
        source: BlobTransferId,
    ) -> Result<Option<RetainedBlobSource>, StoreError> {
        self.require_live()?;
        self.require_bound_mission()?;
        let read = self.database.begin_read()?;
        let completed = read
            .open_table(BLOB_PUBLICATIONS)?
            .get(source.as_bytes().as_slice())?
            .map(|value| decode_blob_metadata(value.value()))
            .transpose()?;
        let pending = read
            .open_table(BLOB_PENDING_SOURCES)?
            .get(source.as_bytes().as_slice())?
            .map(|value| decode_pending_blob_source(value.value()))
            .transpose()?;
        if completed.is_some() && pending.is_some() {
            return Err(blob_error(BlobStoreError::SchemaInvariant(
                "Blob source is simultaneously pending and completed",
            )));
        }
        if let Some(metadata) = completed {
            let sealed_len = read
                .open_table(BLOB_BYTES)?
                .get(source.as_bytes().as_slice())?
                .map(|value| u64::try_from(value.value().len()))
                .transpose()
                .map_err(|_| StoreError::PayloadByteAccountingOverflow)?
                .ok_or_else(|| {
                    blob_error(BlobStoreError::SchemaInvariant(
                        "completed Blob source is missing exact bytes",
                    ))
                })?;
            let acceptance_marker = read
                .open_table(BLOB_ACCEPTANCE_MARKERS)?
                .get(source.as_bytes().as_slice())?
                .map(|value| value.value())
                .ok_or_else(|| {
                    blob_error(BlobStoreError::SchemaInvariant(
                        "completed Blob source is missing its acceptance marker",
                    ))
                })?;
            let shape = durable_blob_source_shape_read(&read, &metadata, true)?;
            return Ok(Some(RetainedBlobSource {
                source: blob_source_projection(&metadata, sealed_len, shape)?,
                retention: BlobSourceRetention::Completed { acceptance_marker },
            }));
        }
        pending
            .map(|pending| {
                let sealed_len = u64::try_from(pending.sealed.len())
                    .map_err(|_| StoreError::PayloadByteAccountingOverflow)?;
                let shape = durable_blob_source_shape_read(&read, &pending.metadata, false)?;
                Ok::<_, StoreError>(RetainedBlobSource {
                    source: blob_source_projection(&pending.metadata, sealed_len, shape)?,
                    retention: BlobSourceRetention::Pending,
                })
            })
            .transpose()
    }

    /// Visits the bounded retained union from one redb snapshot.
    ///
    /// With a policy, stale epochs and revoked publishers are filtered after
    /// the exact policy is checked. `None` is intended for startup cache rebuild
    /// before control replay and carries no current-authorization assertion.
    pub fn visit_retained_blob_sources(
        &self,
        policy: Option<&ControlPolicySnapshot>,
        mut visitor: impl FnMut(&RetainedBlobSource),
    ) -> Result<(), StoreError> {
        self.require_live()?;
        let authority = self.require_bound_mission()?;
        let read = self.database.begin_read()?;
        if let Some(policy) = policy {
            require_control_policy_read(&read, authority, policy)?;
        }
        let mut retained = Vec::new();
        let mut seen = BTreeSet::new();
        for row in read.open_table(BLOB_PUBLICATIONS)?.iter()? {
            let (key, value) = row?;
            let source = parse_blob_transfer_id("Blob publication table", key.value())?;
            let metadata = decode_blob_metadata(value.value())?;
            // Metadata-v1 remains valid for local reads but has no provider-owned
            // lineages and is therefore deliberately invisible to semantic-v5
            // networking until an explicit authenticated migration succeeds.
            if metadata.route_lineage.is_none() || metadata.physical_lineage.is_none() {
                continue;
            }
            if policy.is_some() && !blob_header_is_current_read(&read, &metadata.header)? {
                continue;
            }
            let sealed_len = read
                .open_table(BLOB_BYTES)?
                .get(key.value())?
                .map(|value| u64::try_from(value.value().len()))
                .transpose()
                .map_err(|_| StoreError::PayloadByteAccountingOverflow)?
                .ok_or_else(|| {
                    blob_error(BlobStoreError::SchemaInvariant(
                        "completed Blob source is missing exact bytes",
                    ))
                })?;
            let acceptance_marker = read
                .open_table(BLOB_ACCEPTANCE_MARKERS)?
                .get(key.value())?
                .map(|value| value.value())
                .ok_or_else(|| {
                    blob_error(BlobStoreError::SchemaInvariant(
                        "completed Blob source is missing its acceptance marker",
                    ))
                })?;
            seen.insert(source);
            let shape = durable_blob_source_shape_read(&read, &metadata, true)?;
            retained.push(RetainedBlobSource {
                source: blob_source_projection(&metadata, sealed_len, shape)?,
                retention: BlobSourceRetention::Completed { acceptance_marker },
            });
        }
        for row in read.open_table(BLOB_PENDING_SOURCES)?.iter()? {
            let (key, value) = row?;
            let source = parse_blob_transfer_id("pending Blob source table", key.value())?;
            if seen.contains(&source) {
                return Err(blob_error(BlobStoreError::SchemaInvariant(
                    "Blob source is simultaneously pending and completed",
                )));
            }
            let pending = decode_pending_blob_source(value.value())?;
            if policy.is_some() && !blob_header_is_current_read(&read, &pending.metadata.header)? {
                continue;
            }
            let sealed_len = u64::try_from(pending.sealed.len())
                .map_err(|_| StoreError::PayloadByteAccountingOverflow)?;
            let shape = durable_blob_source_shape_read(&read, &pending.metadata, false)?;
            retained.push(RetainedBlobSource {
                source: blob_source_projection(&pending.metadata, sealed_len, shape)?,
                retention: BlobSourceRetention::Pending,
            });
        }
        retained.sort_unstable_by_key(|item| item.source.transfer_id);
        drop(read);
        for item in &retained {
            visitor(item);
        }
        Ok(())
    }

    /// Visits only pending Blob source projections from one redb snapshot.
    ///
    /// This never opens or scans completed publication/source-byte tables. A
    /// supplied policy is checked exactly and filters stale-epoch or revoked
    /// pending publishers; `None` is policy-neutral for cache cleanup before a
    /// caller performs its own authenticated current-lineage decision.
    pub fn visit_pending_blob_sources(
        &self,
        policy: Option<&ControlPolicySnapshot>,
        mut visitor: impl FnMut(&BlobSourceProjection),
    ) -> Result<(), StoreError> {
        self.require_live()?;
        let authority = self.require_bound_mission()?;
        let read = self.database.begin_read()?;
        if let Some(policy) = policy {
            require_control_policy_read(&read, authority, policy)?;
        }
        let pending = read.open_table(BLOB_PENDING_SOURCES)?;
        let mut projections = Vec::with_capacity(
            usize::try_from(pending.len()?).map_err(|_| StoreError::ItemCountAccountingOverflow)?,
        );
        for row in pending.iter()? {
            let (_, value) = row?;
            #[cfg(test)]
            TEST_PENDING_BLOB_SOURCE_ROWS_VISITED
                .with(|count| count.set(count.get().saturating_add(1)));
            let pending = decode_pending_blob_source(value.value())?;
            if policy.is_some() && !blob_header_is_current_read(&read, &pending.metadata.header)? {
                continue;
            }
            let sealed_len = u64::try_from(pending.sealed.len())
                .map_err(|_| StoreError::PayloadByteAccountingOverflow)?;
            let shape = durable_blob_source_shape_read(&read, &pending.metadata, false)?;
            projections.push(blob_source_projection(
                &pending.metadata,
                sealed_len,
                shape,
            )?);
        }
        projections.sort_unstable_by_key(|projection| projection.transfer_id);
        drop(pending);
        drop(read);
        for projection in &projections {
            visitor(projection);
        }
        Ok(())
    }

    /// Returns active completed sender projections under one exact policy snapshot.
    pub fn completed_blob_sender_inventory_with_policy(
        &self,
        policy: &ControlPolicySnapshot,
    ) -> Result<Vec<BlobSourceProjection>, StoreError> {
        let mut output = Vec::new();
        self.visit_retained_blob_sources(Some(policy), |item| {
            if matches!(item.retention, BlobSourceRetention::Completed { .. }) {
                output.push(item.source.clone());
            }
        })?;
        Ok(output)
    }

    /// Returns active pending source projections under one exact policy snapshot.
    pub fn pending_blob_source_inventory_with_policy(
        &self,
        policy: &ControlPolicySnapshot,
    ) -> Result<Vec<BlobSourceProjection>, StoreError> {
        let mut output = Vec::new();
        self.visit_pending_blob_sources(Some(policy), |source| output.push(source.clone()))?;
        Ok(output)
    }

    /// Returns one policy-filtered snapshot of durable pending transfer progress.
    ///
    /// A committed carrier contributes its complete canonical length after its
    /// prefix row has been retired. An uncommitted carrier contributes only its
    /// durable contiguous prefix. The result is ordered by internal transfer
    /// identity without exposing peer-specific fetch cursors.
    pub fn pending_blob_transfer_progress_with_policy(
        &self,
        policy: &ControlPolicySnapshot,
    ) -> Result<BlobTransferStatusSnapshot, StoreError> {
        self.require_live()?;
        let authority = self.require_bound_mission()?;
        let read = self.database.begin_read()?;
        require_control_policy_read(&read, authority, policy)?;
        let stats = inspect_blob_tables_read(&read)?.stats;
        depot::audit_depot_read(
            &read,
            &self.path,
            self.backing_identity,
            self.blob_depot_owner_token,
            stats,
        )?;
        let pending = read.open_table(BLOB_PENDING_SOURCES)?;
        let prefixes = read.open_table(BLOB_CARRIER_PREFIXES)?;
        let mut progress = Vec::with_capacity(
            usize::try_from(pending.len()?).map_err(|_| StoreError::ItemCountAccountingOverflow)?,
        );
        for row in pending.iter()? {
            let (_, value) = row?;
            let pending = decode_pending_blob_source(value.value())?;
            if !blob_header_is_current_read(&read, &pending.metadata.header)? {
                continue;
            }
            let sealed_len = u64::try_from(pending.sealed.len())
                .map_err(|_| StoreError::PayloadByteAccountingOverflow)?;
            let shape = durable_blob_source_shape_read(&read, &pending.metadata, false)?;
            let source = blob_source_projection(&pending.metadata, sealed_len, shape)?;
            let mut durable_carriers = 0u64;
            let mut total_carrier_bytes = 0u64;
            let mut durable_carrier_bytes = 0u64;
            for carrier in &pending.carriers {
                total_carrier_bytes = total_carrier_bytes
                    .checked_add(carrier.total_len)
                    .ok_or(StoreError::PayloadByteAccountingOverflow)?;
                if depot::pending_chunk_is_committed_read(
                    &read,
                    pending.metadata.variant_id,
                    carrier.index,
                )? {
                    durable_carriers = durable_carriers
                        .checked_add(1)
                        .ok_or(StoreError::ItemCountAccountingOverflow)?;
                    durable_carrier_bytes = durable_carrier_bytes
                        .checked_add(carrier.total_len)
                        .ok_or(StoreError::PayloadByteAccountingOverflow)?;
                    continue;
                }
                let key = blob_carrier_prefix_key(pending.metadata.transfer_id, carrier.object);
                let prefix_len = prefixes
                    .get(key.as_slice())?
                    .map(|value| decode_blob_carrier_prefix(value.value()))
                    .transpose()?
                    .map(|record| {
                        if record.source != pending.metadata.transfer_id
                            || record.total_len != carrier.total_len
                        {
                            return Err(blob_error(BlobStoreError::CarrierPrefixConflict));
                        }
                        u64::try_from(record.prefix.len())
                            .map_err(|_| StoreError::PayloadByteAccountingOverflow)
                    })
                    .transpose()?
                    .unwrap_or(0);
                durable_carrier_bytes = durable_carrier_bytes
                    .checked_add(prefix_len)
                    .ok_or(StoreError::PayloadByteAccountingOverflow)?;
            }
            progress.push(PendingBlobTransferProgress {
                source,
                total_carriers: u64::try_from(pending.carriers.len())
                    .map_err(|_| StoreError::ItemCountAccountingOverflow)?,
                durable_carriers,
                total_carrier_bytes,
                durable_carrier_bytes,
            });
        }
        progress.sort_unstable_by_key(|item| item.source.transfer_id);
        Ok(BlobTransferStatusSnapshot {
            stats,
            pending: progress,
        })
    }

    /// Selects at most one current pending source after `after`, wrapping once.
    ///
    /// Selection is lexicographic by transfer identity and uses one durable
    /// read snapshot. It returns only projection metadata; it never opens the
    /// depot, decrypts content, or finalizes a capacity-deferred source.
    pub fn next_pending_blob_source_with_policy(
        &self,
        policy: &ControlPolicySnapshot,
        after: Option<BlobTransferId>,
    ) -> Result<Option<BlobSourceProjection>, StoreError> {
        self.require_live()?;
        let authority = self.require_bound_mission()?;
        let read = self.database.begin_read()?;
        require_control_policy_read(&read, authority, policy)?;
        let pending = read.open_table(BLOB_PENDING_SOURCES)?;
        if let Some(after) = after {
            let bounds = (
                std::ops::Bound::<&[u8]>::Excluded(after.as_bytes().as_slice()),
                std::ops::Bound::<&[u8]>::Unbounded,
            );
            for row in pending.range::<&[u8]>(bounds)? {
                let (key, value) = row?;
                if let Some(projection) =
                    current_pending_projection_read(&read, key.value(), value.value())?
                {
                    return Ok(Some(projection));
                }
            }
            for row in pending.iter()? {
                let (key, value) = row?;
                if key.value() > after.as_bytes().as_slice() {
                    break;
                }
                if let Some(projection) =
                    current_pending_projection_read(&read, key.value(), value.value())?
                {
                    return Ok(Some(projection));
                }
            }
            return Ok(None);
        }
        for row in pending.iter()? {
            let (key, value) = row?;
            if let Some(projection) =
                current_pending_projection_read(&read, key.value(), value.value())?
            {
                return Ok(Some(projection));
            }
        }
        Ok(None)
    }

    /// Reads the durable Blob carrier-fetch position for one authenticated peer.
    pub fn blob_carrier_fetch_cursor(
        &self,
        peer: NodeId,
    ) -> Result<Option<BlobCarrierFetchCursor>, StoreError> {
        self.require_live()?;
        let authority = self.require_bound_mission()?;
        let read = self.database.begin_read()?;
        match read_mission_binding_read(&read)? {
            Some(bound) if bound == authority => {}
            Some(bound) => {
                return Err(StoreError::MissionAuthorityMismatch {
                    bound,
                    received: authority,
                });
            }
            None => return Err(StoreError::MissionNotBound),
        }
        read.open_table(BLOB_CARRIER_FETCH_CURSORS)?
            .get(peer.as_slice())?
            .map(|value| BlobCarrierFetchCursor::decode(value.value()))
            .transpose()
    }

    /// Compare-and-set advances one peer's Blob carrier-fetch position.
    ///
    /// The caller owns lexicographic successor and wrap selection. Replaying an
    /// already-current successor is idempotent success; a stale expectation is
    /// a zero-mutation `false` result.
    pub fn compare_and_advance_blob_carrier_fetch_cursor(
        &self,
        peer: NodeId,
        expected: Option<BlobCarrierFetchCursor>,
        new: BlobCarrierFetchCursor,
    ) -> Result<bool, StoreError> {
        self.require_live()?;
        let authority = self.require_bound_mission()?;
        let write = self.database.begin_write()?;
        enforce_live_write(&write)?;
        let cursor_count = blob_carrier_cursor_count_write(&write, authority)?;
        let current = write
            .open_table(BLOB_CARRIER_FETCH_CURSORS)?
            .get(peer.as_slice())?
            .map(|value| BlobCarrierFetchCursor::decode(value.value()))
            .transpose()?;
        if current == Some(new) {
            return Ok(true);
        }
        if current != expected {
            return Ok(false);
        }
        if current.is_none()
            && cursor_count
                >= u64::try_from(MAX_BLOB_CARRIER_FETCH_CURSOR_PEERS)
                    .map_err(|_| StoreError::ItemCountAccountingOverflow)?
        {
            return Err(blob_error(BlobStoreError::CarrierCursorPeerLimitExceeded {
                requested: MAX_BLOB_CARRIER_FETCH_CURSOR_PEERS + 1,
                limit: MAX_BLOB_CARRIER_FETCH_CURSOR_PEERS,
            }));
        }
        let encoded = new.encode();
        write
            .open_table(BLOB_CARRIER_FETCH_CURSORS)?
            .insert(peer.as_slice(), encoded.as_slice())?;
        write.commit()?;
        Ok(true)
    }

    /// Prunes carrier-fetch cursors for peers no longer in authenticated configuration.
    pub fn reconcile_blob_carrier_fetch_cursor_peers(
        &self,
        configured_peers: &[NodeId],
    ) -> Result<(), StoreError> {
        self.require_live()?;
        let authority = self.require_bound_mission()?;
        let configured = configured_peers.iter().copied().collect::<BTreeSet<_>>();
        if configured.len() > MAX_BLOB_CARRIER_FETCH_CURSOR_PEERS {
            return Err(blob_error(BlobStoreError::CarrierCursorPeerLimitExceeded {
                requested: configured.len(),
                limit: MAX_BLOB_CARRIER_FETCH_CURSOR_PEERS,
            }));
        }
        let write = self.database.begin_write()?;
        enforce_live_write(&write)?;
        blob_carrier_cursor_count_write(&write, authority)?;
        let stale = {
            let table = write.open_table(BLOB_CARRIER_FETCH_CURSORS)?;
            let mut stale = Vec::new();
            for row in table.iter()? {
                let (key, value) = row?;
                let peer: NodeId = key.value().try_into().map_err(|_| {
                    blob_error(BlobStoreError::CarrierCursorInvariant(
                        "carrier cursor peer key has invalid length",
                    ))
                })?;
                BlobCarrierFetchCursor::decode(value.value())?;
                if !configured.contains(&peer) {
                    stale.push(peer);
                }
            }
            stale
        };
        let mut table = write.open_table(BLOB_CARRIER_FETCH_CURSORS)?;
        for peer in stale {
            table.remove(peer.as_slice())?;
        }
        drop(table);
        write.commit()?;
        Ok(())
    }

    /// Returns exact durable progress for one peer-neutral carrier object.
    pub fn blob_carrier_prefix_status(
        &self,
        source: BlobTransferId,
        object: BlobCarrierObjectId,
    ) -> Result<Option<BlobCarrierPrefixStatus>, StoreError> {
        self.require_live()?;
        self.require_bound_mission()?;
        let read = self.database.begin_read()?;
        let key = blob_carrier_prefix_key(source, object);
        let record = read
            .open_table(BLOB_CARRIER_PREFIXES)?
            .get(key.as_slice())?
            .map(|value| decode_blob_carrier_prefix(value.value()))
            .transpose()?;
        match record {
            Some(record) if record.source != source => {
                Err(blob_error(BlobStoreError::CarrierPrefixConflict))
            }
            Some(record) => Ok(Some(carrier_prefix_status(object, &record)?)),
            None => Ok(None),
        }
    }

    /// Appends exactly the next missing contiguous carrier range under current policy.
    ///
    /// An exact already-durable subrange is an idempotent duplicate. Partial
    /// overlap, a changed source/total, a gap, or an over-16-KiB append fails
    /// without mutation. The durable receipt boundary is the committed redb
    /// transaction returned by this call.
    pub fn append_blob_carrier_prefix_with_policy(
        &self,
        policy: &ControlPolicySnapshot,
        source: BlobTransferId,
        object: BlobCarrierObjectId,
        total_len: u64,
        offset: u64,
        bytes: &[u8],
    ) -> Result<BlobCarrierAppendOutcome, StoreError> {
        self.require_live()?;
        let authority = self.require_bound_mission()?;
        if total_len == 0
            || total_len > MAX_BLOB_NETWORK_CARRIER_BYTES
            || canonical_blob_carrier_range_len(total_len, offset) != Some(bytes.len())
        {
            return Err(blob_error(BlobStoreError::InvalidCarrierRange(
                "range is not the exact canonical 16-KiB carrier complement",
            )));
        }
        let write = self.database.begin_write()?;
        enforce_live_write(&write)?;
        require_control_policy_write(&write, authority, policy)?;
        let staging = blob_network_staging_usage_write(&write, authority)?;
        let pending = write
            .open_table(BLOB_PENDING_SOURCES)?
            .get(source.as_bytes().as_slice())?
            .map(|value| decode_pending_blob_source(value.value()))
            .transpose()?
            .ok_or_else(|| blob_error(BlobStoreError::PendingSourceMissing))?;
        if pending.metadata.transfer_id != source
            || write
                .open_table(BLOB_PUBLICATIONS)?
                .get(source.as_bytes().as_slice())?
                .is_some()
        {
            return Err(blob_error(BlobStoreError::SchemaInvariant(
                "pending Blob source identity or visibility is inconsistent",
            )));
        }
        enforce_blob_policy_write(&write, authority, policy, &pending.metadata.header)?;
        let expected = pending_blob_carrier(&pending, object)
            .ok_or_else(|| blob_error(BlobStoreError::InvalidCarrierObjectId))?;
        if expected.total_len != total_len {
            return Err(blob_error(BlobStoreError::InvalidCarrierRange(
                "carrier total differs from the authenticated pending plan",
            )));
        }

        let key = blob_carrier_prefix_key(source, object);
        let existing_bytes = write
            .open_table(BLOB_CARRIER_PREFIXES)?
            .get(key.as_slice())?
            .map(|value| value.value().to_vec());
        let existing = existing_bytes
            .as_deref()
            .map(decode_blob_carrier_prefix)
            .transpose()?;
        if let Some(existing) = &existing {
            if existing.source != source || existing.total_len != total_len {
                return Err(blob_error(BlobStoreError::CarrierPrefixConflict));
            }
            let start = usize::try_from(offset).map_err(|_| {
                blob_error(BlobStoreError::InvalidCarrierRange(
                    "offset overflows usize",
                ))
            })?;
            let end = start.checked_add(bytes.len()).ok_or_else(|| {
                blob_error(BlobStoreError::InvalidCarrierRange("range overflows"))
            })?;
            if end <= existing.prefix.len() {
                if existing.prefix.get(start..end) == Some(bytes) {
                    return Ok(BlobCarrierAppendOutcome::Duplicate(carrier_prefix_status(
                        object, existing,
                    )?));
                }
                return Err(blob_error(BlobStoreError::CarrierPrefixConflict));
            }
            if offset
                != u64::try_from(existing.prefix.len())
                    .map_err(|_| StoreError::PayloadByteAccountingOverflow)?
            {
                return Err(blob_error(BlobStoreError::InvalidCarrierRange(
                    "append is not the exact contiguous complement",
                )));
            }
        } else if offset != 0 {
            return Err(blob_error(BlobStoreError::InvalidCarrierRange(
                "first append must start at byte zero",
            )));
        }

        let mut prefix = existing
            .as_ref()
            .map_or_else(Vec::new, |record| record.prefix.clone());
        prefix.extend_from_slice(bytes);
        let next = BlobCarrierPrefixRecord {
            source,
            total_len,
            prefix,
        };
        let encoded = encode_blob_carrier_prefix(&next)?;
        let old_bytes = existing_bytes
            .as_ref()
            .map(|value| staging_entry_bytes(BLOB_CARRIER_PREFIX_KEY_BYTES, value.len()))
            .transpose()?
            .unwrap_or(0);
        let new_bytes = staging_entry_bytes(BLOB_CARRIER_PREFIX_KEY_BYTES, encoded.len())?;
        let incoming_bytes = new_bytes
            .checked_sub(old_bytes)
            .ok_or(StoreError::PayloadByteAccountingOverflow)?;
        let incoming_rows = u64::from(existing.is_none());
        require_blob_network_staging_capacity(staging, incoming_rows, incoming_bytes)?;
        write
            .open_table(BLOB_CARRIER_PREFIXES)?
            .insert(key.as_slice(), encoded.as_slice())?;
        update_blob_network_staging_usage(
            &write,
            BlobNetworkStagingUsage {
                rows: staging
                    .rows
                    .checked_add(incoming_rows)
                    .ok_or(StoreError::ItemCountAccountingOverflow)?,
                bytes: staging
                    .bytes
                    .checked_add(incoming_bytes)
                    .ok_or(StoreError::PayloadByteAccountingOverflow)?,
            },
        )?;
        write.commit()?;
        Ok(BlobCarrierAppendOutcome::Appended(carrier_prefix_status(
            object, &next,
        )?))
    }

    /// Reads a complete staged carrier without consuming its durable prefix.
    pub fn complete_blob_carrier_bytes(
        &self,
        source: BlobTransferId,
        object: BlobCarrierObjectId,
    ) -> Result<Option<Vec<u8>>, StoreError> {
        self.require_live()?;
        self.require_bound_mission()?;
        let read = self.database.begin_read()?;
        let key = blob_carrier_prefix_key(source, object);
        let record = read
            .open_table(BLOB_CARRIER_PREFIXES)?
            .get(key.as_slice())?
            .map(|value| decode_blob_carrier_prefix(value.value()))
            .transpose()?;
        match record {
            Some(record) if record.source != source => {
                Err(blob_error(BlobStoreError::CarrierPrefixConflict))
            }
            Some(record) if u64::try_from(record.prefix.len()).ok() == Some(record.total_len) => {
                Ok(Some(record.prefix))
            }
            Some(_) | None => Ok(None),
        }
    }

    /// Atomically clears only one exact carrier object's durable progress.
    ///
    /// A source mismatch cannot delete another source's object. Missing state
    /// is an idempotent no-op suitable for terminal-authentication replay.
    pub fn abort_blob_carrier_prefix(
        &self,
        source: BlobTransferId,
        object: BlobCarrierObjectId,
    ) -> Result<bool, StoreError> {
        self.require_live()?;
        let authority = self.require_bound_mission()?;
        let write = self.database.begin_write()?;
        enforce_live_write(&write)?;
        let staging = blob_network_staging_usage_write(&write, authority)?;
        let key = blob_carrier_prefix_key(source, object);
        let encoded = write
            .open_table(BLOB_CARRIER_PREFIXES)?
            .get(key.as_slice())?
            .map(|value| value.value().to_vec());
        let Some(encoded) = encoded else {
            return Ok(false);
        };
        let record = decode_blob_carrier_prefix(&encoded)?;
        if record.source != source {
            return Err(blob_error(BlobStoreError::CarrierPrefixConflict));
        }
        let pending = write
            .open_table(BLOB_PENDING_SOURCES)?
            .get(source.as_bytes().as_slice())?
            .map(|value| decode_pending_blob_source(value.value()))
            .transpose()?
            .ok_or_else(|| {
                blob_error(BlobStoreError::SchemaInvariant(
                    "Blob carrier prefix is orphaned from its pending source",
                ))
            })?;
        if pending.metadata.transfer_id != source
            || pending_blob_carrier(&pending, object)
                .is_none_or(|expected| expected.total_len != record.total_len)
        {
            return Err(blob_error(BlobStoreError::SchemaInvariant(
                "Blob carrier prefix differs from its authenticated pending source",
            )));
        }
        write
            .open_table(BLOB_CARRIER_PREFIXES)?
            .remove(key.as_slice())?;
        let removed = staging_entry_bytes(BLOB_CARRIER_PREFIX_KEY_BYTES, encoded.len())?;
        update_blob_network_staging_usage(
            &write,
            BlobNetworkStagingUsage {
                rows: staging.rows.checked_sub(1).ok_or_else(|| {
                    blob_error(BlobStoreError::SchemaInvariant(
                        "Blob staging row counter underflows on abort",
                    ))
                })?,
                bytes: staging.bytes.checked_sub(removed).ok_or_else(|| {
                    blob_error(BlobStoreError::SchemaInvariant(
                        "Blob staging byte counter underflows on abort",
                    ))
                })?,
            },
        )?;
        write.commit()?;
        Ok(true)
    }

    /// Atomically removes one exact terminally poisoned pending source and all
    /// of its carrier prefixes.
    ///
    /// Depot import/chunk staging is deliberately retained and remains charged
    /// to the configured physical quotas. That fail-closed choice avoids an
    /// unbounded global reference scan on a contact-triggered abort and
    /// preserves the same-epoch physical-lineage fence. A future explicit
    /// garbage-collection protocol may reclaim such abandoned staging.
    pub fn abort_pending_blob_source(&self, source: BlobTransferId) -> Result<bool, StoreError> {
        self.require_live()?;
        let authority = self.require_bound_mission()?;
        let _depot_guard = self
            .blob_depot_lock
            .lock()
            .map_err(|_| blob_error(BlobStoreError::DepotIntegrity("depot lock is poisoned")))?;
        self.require_live()?;
        let write = self.database.begin_write()?;
        enforce_live_write(&write)?;
        let staging = blob_network_staging_usage_write(&write, authority)?;
        let encoded_pending = write
            .open_table(BLOB_PENDING_SOURCES)?
            .get(source.as_bytes().as_slice())?
            .map(|value| value.value().to_vec());
        let Some(encoded_pending) = encoded_pending else {
            return Ok(false);
        };
        let pending = decode_pending_blob_source(&encoded_pending)?;
        if pending.metadata.transfer_id != source {
            return Err(blob_error(BlobStoreError::SchemaInvariant(
                "pending Blob source key differs from its authenticated identity",
            )));
        }
        let owner_binding = depot::require_depot_owner_binding_write(
            &write,
            &self.path,
            self.backing_identity,
            self.blob_depot_owner_token,
        )?;
        lifecycle::require_lineage_fence(
            &write,
            pending.metadata.variant_id,
            pending.physical_lineage,
            owner_binding,
        )?;
        lifecycle::remove_variant_reference(
            &write,
            pending.metadata.variant_id,
            lifecycle::VariantReferenceOwner::PendingSource,
            source,
        )?;
        remove_pending_source_rows_write(&write, staging, source, &pending)?;
        write.commit()?;
        Ok(true)
    }

    /// Authenticates and installs one complete exact carrier, then retires only
    /// that source/object prefix. A crash after the depot commit but before the
    /// redb retirement is safe: replay observes the exact committed chunk and
    /// completes cleanup idempotently.
    pub fn commit_complete_blob_carrier_with_policy(
        &self,
        policy: &ControlPolicySnapshot,
        source: BlobTransferId,
        object: BlobCarrierObjectId,
        plan: &VerifiedBlobTransferPlan,
    ) -> Result<BlobCarrierCommitOutcome, StoreError> {
        self.require_live()?;
        let authority = self.require_bound_mission()?;
        let mut depot = BlobDepot::open_network_mutation(self, false)?;
        let (pending, staged) = {
            let read = self.database.begin_read()?;
            let pending = read
                .open_table(BLOB_PENDING_SOURCES)?
                .get(source.as_bytes().as_slice())?
                .map(|value| decode_pending_blob_source(value.value()))
                .transpose()?
                .ok_or_else(|| blob_error(BlobStoreError::PendingSourceMissing))?;
            if pending.metadata.transfer_id != source
                || read
                    .open_table(BLOB_PUBLICATIONS)?
                    .get(source.as_bytes().as_slice())?
                    .is_some()
            {
                return Err(blob_error(BlobStoreError::SchemaInvariant(
                    "pending Blob source identity or visibility is inconsistent",
                )));
            }
            enforce_blob_policy_read(&read, authority, policy, &pending.metadata.header)?;
            require_pending_blob_plan(&pending, plan)?;
            let expected = pending_blob_carrier(&pending, object)
                .ok_or_else(|| blob_error(BlobStoreError::InvalidCarrierObjectId))?;
            let key = blob_carrier_prefix_key(source, object);
            let staged = read
                .open_table(BLOB_CARRIER_PREFIXES)?
                .get(key.as_slice())?
                .map(|value| decode_blob_carrier_prefix(value.value()))
                .transpose()?;
            if let Some(record) = &staged
                && (record.source != source
                    || record.total_len != expected.total_len
                    || u64::try_from(record.prefix.len()).ok() != Some(record.total_len))
            {
                return Err(blob_error(BlobStoreError::InvalidCarrierRange(
                    "carrier prefix is incomplete or differs from its authenticated plan",
                )));
            }
            (pending, staged)
        };

        let expected = pending_blob_carrier(&pending, object)
            .ok_or_else(|| blob_error(BlobStoreError::InvalidCarrierObjectId))?;
        #[cfg(test)]
        if let Some((reached, release)) = self
            .blob_carrier_commit_post_snapshot_gate
            .lock()
            .map_err(|_| {
                blob_error(BlobStoreError::SchemaInvariant(
                    "Blob carrier-commit post-snapshot gate lock is poisoned",
                ))
            })?
            .take()
        {
            reached.send(()).map_err(|_| {
                blob_error(BlobStoreError::SchemaInvariant(
                    "Blob carrier-commit post-snapshot gate observer disappeared",
                ))
            })?;
            release.recv().map_err(|_| {
                blob_error(BlobStoreError::SchemaInvariant(
                    "Blob carrier-commit post-snapshot gate release disappeared",
                ))
            })?;
        }
        CoreBlobStore::begin_blob_with_lineage(
            &mut depot,
            plan.manifest(),
            plan.physical_lineage(),
        )?;
        let already_committed =
            CoreBlobStore::chunk_record(&mut depot, plan.manifest().id(), expected.index)?
                == Some(
                    plan.chunk_records()[usize::try_from(expected.index)
                        .map_err(|_| StoreError::ItemCountAccountingOverflow)?],
                );
        if let Some(staged) = &staged {
            let verified = plan
                .verify_carrier(object.as_bytes(), &staged.prefix)
                .map_err(|error| blob_error(BlobStoreError::Verification(error.to_string())))?;
            plan.install_verified_carrier(&mut depot, &verified)
                .map_err(|error| blob_error(BlobStoreError::Verification(error.to_string())))?;
        } else if !already_committed {
            return Err(blob_error(BlobStoreError::InvalidCarrierRange(
                "carrier prefix is not complete",
            )));
        }

        let mut all_committed = true;
        for (index, record) in plan.chunk_records().iter().copied().enumerate() {
            let index =
                u64::try_from(index).map_err(|_| StoreError::ItemCountAccountingOverflow)?;
            if CoreBlobStore::chunk_record(&mut depot, plan.manifest().id(), index)? != Some(record)
            {
                all_committed = false;
                break;
            }
        }
        if all_committed {
            CoreBlobStore::finalize_blob(
                &mut depot,
                plan.manifest().id(),
                *plan.manifest_digest(),
            )?;
        }
        if let Some(staged) = staged {
            let write = self.database.begin_write()?;
            enforce_live_write(&write)?;
            let staging = blob_network_staging_usage_write(&write, authority)?;
            let current_pending = write
                .open_table(BLOB_PENDING_SOURCES)?
                .get(source.as_bytes().as_slice())?
                .map(|value| decode_pending_blob_source(value.value()))
                .transpose()?
                .ok_or_else(|| blob_error(BlobStoreError::PendingSourceMissing))?;
            enforce_blob_policy_write(&write, authority, policy, &current_pending.metadata.header)?;
            require_pending_blob_plan(&current_pending, plan)?;
            let key = blob_carrier_prefix_key(source, object);
            let encoded = write
                .open_table(BLOB_CARRIER_PREFIXES)?
                .get(key.as_slice())?
                .map(|value| value.value().to_vec())
                .ok_or_else(|| blob_error(BlobStoreError::CarrierPrefixConflict))?;
            if decode_blob_carrier_prefix(&encoded)? != staged {
                return Err(blob_error(BlobStoreError::CarrierPrefixConflict));
            }
            write
                .open_table(BLOB_CARRIER_PREFIXES)?
                .remove(key.as_slice())?;
            let removed = staging_entry_bytes(BLOB_CARRIER_PREFIX_KEY_BYTES, encoded.len())?;
            update_blob_network_staging_usage(
                &write,
                BlobNetworkStagingUsage {
                    rows: staging.rows.checked_sub(1).ok_or_else(|| {
                        blob_error(BlobStoreError::SchemaInvariant(
                            "Blob staging row counter underflows on carrier commit",
                        ))
                    })?,
                    bytes: staging.bytes.checked_sub(removed).ok_or_else(|| {
                        blob_error(BlobStoreError::SchemaInvariant(
                            "Blob staging byte counter underflows on carrier commit",
                        ))
                    })?,
                },
            )?;
            write.commit()?;
        }
        Ok(if already_committed {
            BlobCarrierCommitOutcome::Duplicate
        } else {
            BlobCarrierCommitOutcome::Committed
        })
    }

    /// Returns exact uncommitted carrier work for one pending source.
    pub fn pending_blob_carrier_work_with_policy(
        &self,
        policy: &ControlPolicySnapshot,
        source: BlobTransferId,
        plan: &VerifiedBlobTransferPlan,
    ) -> Result<Vec<BlobCarrierPrefixStatus>, StoreError> {
        self.require_live()?;
        let authority = self.require_bound_mission()?;
        let read = self.database.begin_read()?;
        let pending = read
            .open_table(BLOB_PENDING_SOURCES)?
            .get(source.as_bytes().as_slice())?
            .map(|value| decode_pending_blob_source(value.value()))
            .transpose()?
            .ok_or_else(|| blob_error(BlobStoreError::PendingSourceMissing))?;
        enforce_blob_policy_read(&read, authority, policy, &pending.metadata.header)?;
        require_pending_blob_plan(&pending, plan)?;
        let committed = depot::committed_pending_plan_chunks_read(&read, plan)?;
        let prefixes = read.open_table(BLOB_CARRIER_PREFIXES)?;
        let mut work = Vec::new();
        for carrier in &pending.carriers {
            if committed.contains(&carrier.index) {
                continue;
            }
            let key = blob_carrier_prefix_key(source, carrier.object);
            let status = prefixes
                .get(key.as_slice())?
                .map(|value| decode_blob_carrier_prefix(value.value()))
                .transpose()?
                .map(|record| carrier_prefix_status(carrier.object, &record))
                .transpose()?
                .unwrap_or(BlobCarrierPrefixStatus {
                    source,
                    object: carrier.object,
                    total_len: carrier.total_len,
                    prefix_len: 0,
                });
            work.push(status);
        }
        work.sort_unstable_by_key(|status| status.object);
        Ok(work)
    }

    /// Exact number of carriers still missing from the durable depot.
    pub fn pending_blob_remaining_count_with_policy(
        &self,
        policy: &ControlPolicySnapshot,
        source: BlobTransferId,
        plan: &VerifiedBlobTransferPlan,
    ) -> Result<u64, StoreError> {
        u64::try_from(
            self.pending_blob_carrier_work_with_policy(policy, source, plan)?
                .len(),
        )
        .map_err(|_| StoreError::ItemCountAccountingOverflow)
    }

    /// Reads one bounded range only from an accepted, finalized, current source.
    ///
    /// The caller must first authenticate the peer's semantic-v5
    /// `BlobPeerContentProof` through the provider. This store seam separately
    /// rechecks durable policy/revocation/epoch and exact source lineages.
    // The explicit tuple is the authenticated carrier-range claim; grouping it
    // would obscure which fields are independently rechecked at this boundary.
    #[allow(clippy::too_many_arguments)]
    pub fn read_completed_blob_carrier_range_with_policy(
        &self,
        policy: &ControlPolicySnapshot,
        completion: &BlobDepotCompletion,
        lineage: &CurrentBlobLineage,
        source: BlobTransferId,
        object: BlobCarrierObjectId,
        offset: u64,
        max_bytes: usize,
        plan: &VerifiedBlobTransferPlan,
    ) -> Result<Option<(u64, Vec<u8>)>, StoreError> {
        self.require_live()?;
        let authority = self.require_bound_mission()?;
        if max_bytes == 0 || max_bytes > MAX_BLOB_NETWORK_RANGE_BYTES {
            return Err(blob_error(BlobStoreError::InvalidCarrierRange(
                "served range is empty or exceeds the 16-KiB bound",
            )));
        }
        if plan.source_envelope().into_bytes() != *source.as_bytes()
            || lineage.mission_authority_id() != authority
            || lineage.source_envelope().into_bytes() != *source.as_bytes()
            || lineage.blob_id() != plan.manifest().id()
            || lineage.manifest_digest() != plan.manifest_digest()
            || lineage.physical_lineage() != plan.physical_lineage()
            || completion.variant_id()
                != blob_variant_id(
                    plan.manifest().id(),
                    plan.manifest().content_group(),
                    plan.manifest().content_epoch(),
                )
            || completion.blob_id() != plan.manifest().id()
            || completion.content_epoch() != plan.manifest().content_epoch()
            || completion.manifest_digest() != plan.manifest_digest()
            || completion.physical_lineage() != plan.physical_lineage().binding()
            || completion.total_len() != plan.manifest().total_len()
            || completion.chunk_size() != plan.manifest().chunk_size()
            || completion.chunk_count() != plan.manifest().chunk_count()
        {
            return Err(blob_error(BlobStoreError::CompletionMismatch));
        }
        let carrier_total = plan
            .carrier_total_len(object.as_bytes())
            .map_err(|error| blob_error(BlobStoreError::Verification(error.to_string())))?;
        let range_bound = u64::try_from(MAX_BLOB_NETWORK_RANGE_BYTES)
            .map_err(|_| StoreError::ItemCountAccountingOverflow)?;
        let expected_len = carrier_total
            .checked_sub(offset)
            .filter(|remaining| *remaining > 0)
            .map(|remaining| remaining.min(range_bound));
        if !offset.is_multiple_of(range_bound)
            || expected_len
                != Some(
                    u64::try_from(max_bytes)
                        .map_err(|_| StoreError::ItemCountAccountingOverflow)?,
                )
        {
            return Err(blob_error(BlobStoreError::InvalidCarrierRange(
                "served range is not the canonical output-coupled carrier page",
            )));
        }
        let initial_stored = {
            let read = self.database.begin_read()?;
            require_control_policy_read(&read, authority, policy)?;
            let stored =
                completed_blob_range_source_snapshot_read(&read, source).map_err(|error| {
                    blob_preflight_decode_error(error, "completed Blob range source is malformed")
                })?;
            let Some(stored) = stored else {
                return Ok(None);
            };
            enforce_blob_policy_read(&read, authority, policy, &stored.metadata.header)?;
            if stored.metadata.variant_id != completion.variant_id()
                || stored.projection.blob_id != plan.manifest().id()
                || stored.projection.manifest_digest != *plan.manifest_digest()
                || stored.projection.route_lineage != *lineage.route_lineage().binding()
                || stored.projection.physical_lineage != *lineage.physical_lineage().binding()
                || stored.projection.total_len != plan.manifest().total_len()
                || stored.projection.chunk_size != plan.manifest().chunk_size()
                || stored.projection.chunk_count != plan.manifest().chunk_count()
            {
                return Err(blob_error(BlobStoreError::CompletionMismatch));
            }
            stored
        };
        let carrier_index = plan
            .carrier_index(object.as_bytes())
            .map_err(|error| blob_error(BlobStoreError::Verification(error.to_string())))?;
        let mut depot = self.blob_depot_for_authenticated_read(completion)?;
        depot.recheck_completion_range(completion, carrier_index, 1)?;
        let range = plan
            .read_carrier_range(&mut depot, object.as_bytes(), offset, max_bytes)
            .map_err(|error| blob_error(BlobStoreError::Verification(error.to_string())))?;
        drop(depot);
        #[cfg(test)]
        if let Some((reached, release)) = self
            .blob_carrier_range_post_read_gate
            .lock()
            .map_err(|_| {
                blob_error(BlobStoreError::SchemaInvariant(
                    "Blob carrier-range post-read gate lock is poisoned",
                ))
            })?
            .take()
        {
            reached.send(()).map_err(|_| {
                blob_error(BlobStoreError::SchemaInvariant(
                    "Blob carrier-range post-read gate observer disappeared",
                ))
            })?;
            release.recv().map_err(|_| {
                blob_error(BlobStoreError::SchemaInvariant(
                    "Blob carrier-range post-read gate release disappeared",
                ))
            })?;
        }
        let read = self.database.begin_read()?;
        require_control_policy_read(&read, authority, policy)?;
        let stored = completed_blob_range_source_snapshot_read(&read, source)
            .map_err(|error| {
                blob_preflight_decode_error(error, "completed Blob range source is malformed")
            })?
            .ok_or_else(|| blob_error(BlobStoreError::CompletionMismatch))?;
        enforce_blob_policy_read(&read, authority, policy, &stored.metadata.header)?;
        if stored != initial_stored {
            return Err(blob_error(BlobStoreError::CompletionMismatch));
        }
        Ok(Some(range))
    }

    /// Atomically promotes one exact pending network source into ordinary Blob
    /// visibility only after current lineage, physical depot, and freshly
    /// streamed content-authentication proofs all agree.
    pub fn apply_verified_blob_with_policy(
        &self,
        policy: &ControlPolicySnapshot,
        plan: &VerifiedBlobTransferPlan,
        lineage: &CurrentBlobLineage,
        depot_completion: &BlobDepotCompletion,
        content_completion: &VerifiedBlobContentCompletion,
    ) -> Result<ApplyOutcome, StoreError> {
        self.require_live()?;
        let authority = self.require_bound_mission()?;
        let source = BlobTransferId::new(plan.source_envelope().into_bytes());
        if lineage.mission_authority_id() != authority
            || lineage.source_envelope().into_bytes() != *source.as_bytes()
            || lineage.blob_id() != plan.manifest().id()
            || lineage.manifest_digest() != plan.manifest_digest()
            || lineage.physical_lineage() != plan.physical_lineage()
            || content_completion.mission_authority_id() != authority
            || content_completion.source_envelope().into_bytes() != *source.as_bytes()
            || content_completion.blob_id() != plan.manifest().id()
            || content_completion.manifest_digest() != plan.manifest_digest()
            || content_completion.physical_lineage() != plan.physical_lineage()
            || content_completion.chunk_count() != plan.manifest().chunk_count()
            || content_completion.plaintext_bytes() != plan.manifest().total_len()
            || content_completion.plaintext_bytes() > MAX_NETWORK_BLOB_BYTES
            || depot_completion.blob_id != plan.manifest().id()
            || depot_completion.manifest_digest != *plan.manifest_digest()
            || depot_completion.physical_lineage != *plan.physical_lineage().binding()
            || depot_completion.chunk_count != plan.manifest().chunk_count()
        {
            return Err(blob_error(BlobStoreError::CompletionMismatch));
        }

        // Capacity-deferred retries must not repeatedly scan an already
        // completed 64-MiB depot. This read-only redb preflight binds the
        // exact pending source, plan, and current policy, then checks every
        // ordinary publication capacity gate. The final write transaction
        // repeats all checks after the physical completion proof.
        {
            let preflight = self.database.begin_read()?;
            require_control_policy_read(&preflight, authority, policy)?;
            let pending = preflight
                .open_table(BLOB_PENDING_SOURCES)?
                .get(source.as_bytes().as_slice())?
                .map(|value| decode_pending_blob_source(value.value()))
                .transpose()?;
            let accepted = preflight
                .open_table(BLOB_PUBLICATIONS)?
                .get(source.as_bytes().as_slice())?
                .is_some();
            if pending.is_none() && !accepted {
                return Err(blob_error(BlobStoreError::PendingSourceMissing));
            }
            if let Some(pending) = pending.as_ref() {
                require_pending_blob_plan(pending, plan)?;
                enforce_blob_policy_read(&preflight, authority, policy, &pending.metadata.header)?;
                if pending.metadata.transfer_id != source
                    || pending.metadata.blob_id != plan.manifest().id()
                    || pending.metadata.manifest_digest != *plan.manifest_digest()
                    || pending.metadata.route_lineage != Some(*lineage.route_lineage().binding())
                    || pending.metadata.physical_lineage
                        != Some(*lineage.physical_lineage().binding())
                    || BlobTransferId::new(Sha256::digest(&pending.sealed).into()) != source
                {
                    return Err(blob_error(BlobStoreError::CompletionMismatch));
                }
                if !accepted {
                    require_blob_apply_capacity_read(
                        &preflight,
                        self.limits,
                        &pending.metadata,
                        u64::try_from(pending.sealed.len())
                            .map_err(|_| StoreError::PayloadByteAccountingOverflow)?,
                    )?;
                }
            }
        }

        let _depot_guard = self
            .blob_depot_lock
            .lock()
            .map_err(|_| blob_error(BlobStoreError::DepotIntegrity("depot lock is poisoned")))?;
        self.require_live()?;
        depot::verify_completion(self, depot_completion)?;

        let write = self.database.begin_write()?;
        enforce_live_write(&write)?;
        let staging = blob_network_staging_usage_write(&write, authority)?;
        let owner_binding = depot::require_depot_owner_binding_write(
            &write,
            &self.path,
            self.backing_identity,
            self.blob_depot_owner_token,
        )?;
        let pending = write
            .open_table(BLOB_PENDING_SOURCES)?
            .get(source.as_bytes().as_slice())?
            .map(|value| decode_pending_blob_source(value.value()))
            .transpose()?;
        let accepted = load_blob_from_write(&write, source)?;
        if pending.is_none() && accepted.is_none() {
            return Err(blob_error(BlobStoreError::PendingSourceMissing));
        }

        let (metadata, sealed) = if let Some(pending) = pending.as_ref() {
            require_pending_blob_plan(pending, plan)?;
            (&pending.metadata, pending.sealed.as_slice())
        } else {
            let accepted = accepted.as_ref().expect("checked pending or accepted");
            let metadata = write
                .open_table(BLOB_PUBLICATIONS)?
                .get(source.as_bytes().as_slice())?
                .map(|value| decode_blob_metadata(value.value()))
                .transpose()?
                .ok_or_else(|| {
                    blob_error(BlobStoreError::SchemaInvariant(
                        "completed Blob source lost its metadata",
                    ))
                })?;
            // Own the decoded metadata for the remainder of this branch.
            if metadata.transfer_id != accepted.transfer_id {
                return Err(blob_error(BlobStoreError::SchemaInvariant(
                    "completed Blob source identity differs from metadata",
                )));
            }
            // The accepted path is handled below without borrowing this local.
            enforce_blob_policy_write(&write, authority, policy, &metadata.header)?;
            if metadata.route_lineage != Some(*lineage.route_lineage().binding())
                || metadata.physical_lineage != Some(*lineage.physical_lineage().binding())
                || metadata.blob_id != plan.manifest().id()
                || metadata.manifest_digest != *plan.manifest_digest()
                || accepted.sealed.len() > MAX_BLOB_NETWORK_SOURCE_BYTES
            {
                return Err(blob_error(BlobStoreError::CompletionMismatch));
            }
            let physical_lineage = metadata
                .physical_lineage
                .ok_or_else(|| blob_error(BlobStoreError::PhysicalLineageMigrationRequired))?;
            lifecycle::require_lineage_fence(
                &write,
                metadata.variant_id,
                physical_lineage,
                owner_binding,
            )?;
            if lifecycle::check_replay_fence(
                &write,
                blob_replay_fence(&metadata, &accepted.sealed)?,
            )? != lifecycle::ReplayFenceStatus::Exact
            {
                return Err(blob_error(BlobStoreError::SchemaInvariant(
                    "accepted Blob publication is missing its replay fence",
                )));
            }
            lifecycle::require_publication_row(&write)?;
            lifecycle::require_variant_reference(
                &write,
                metadata.variant_id,
                lifecycle::VariantReferenceOwner::Publication,
                source,
            )?;
            return Ok(ApplyOutcome::Duplicate {
                acceptance_marker: accepted.acceptance_marker,
            });
        };

        enforce_blob_policy_write(&write, authority, policy, &metadata.header)?;
        if metadata.transfer_id != source
            || metadata.blob_id != plan.manifest().id()
            || metadata.manifest_digest != *plan.manifest_digest()
            || metadata.route_lineage != Some(*lineage.route_lineage().binding())
            || metadata.physical_lineage != Some(*lineage.physical_lineage().binding())
            || metadata.physical_lineage != Some(*plan.physical_lineage().binding())
            || BlobTransferId::new(Sha256::digest(sealed).into()) != source
        {
            return Err(blob_error(BlobStoreError::CompletionMismatch));
        }
        let physical_lineage = metadata
            .physical_lineage
            .ok_or_else(|| blob_error(BlobStoreError::PhysicalLineageMigrationRequired))?;
        lifecycle::require_lineage_fence(
            &write,
            metadata.variant_id,
            physical_lineage,
            owner_binding,
        )?;
        let replay_fence = blob_replay_fence(metadata, sealed)?;
        let replay_status = lifecycle::check_replay_fence(&write, replay_fence)?;

        if let Some(accepted) = accepted {
            if accepted.semantic_id != metadata.semantic_id
                || accepted.blob_id != metadata.blob_id
                || accepted.variant_id != metadata.variant_id
                || accepted.manifest_digest != metadata.manifest_digest
                || accepted.route_lineage != metadata.route_lineage
                || accepted.physical_lineage != metadata.physical_lineage
                || accepted.header != metadata.header
                || accepted.sealed != sealed
            {
                return Err(blob_error(BlobStoreError::PendingSourceConflict));
            }
            if replay_status != lifecycle::ReplayFenceStatus::Exact {
                return Err(blob_error(BlobStoreError::SchemaInvariant(
                    "accepted Blob publication is missing its replay fence",
                )));
            }
            lifecycle::require_publication_row(&write)?;
            lifecycle::require_variant_reference(
                &write,
                metadata.variant_id,
                lifecycle::VariantReferenceOwner::Publication,
                source,
            )?;
            lifecycle::remove_variant_reference(
                &write,
                metadata.variant_id,
                lifecycle::VariantReferenceOwner::PendingSource,
                source,
            )?;
            remove_pending_source_rows_write(
                &write,
                staging,
                source,
                pending.as_ref().expect("pending branch"),
            )?;
            write.commit()?;
            return Ok(ApplyOutcome::Duplicate {
                acceptance_marker: accepted.acceptance_marker,
            });
        }
        if replay_status == lifecycle::ReplayFenceStatus::Exact {
            return Err(blob_error(BlobStoreError::SchemaInvariant(
                "retained Blob replay fence is missing its live publication",
            )));
        }

        if transfer_id_exists_outside_blob(&write, source.as_bytes())? {
            return Err(StoreError::TransferNamespaceCollision {
                transfer_id: *source.as_bytes(),
            });
        }
        if semantic_id_exists_outside_blob(&write, metadata.semantic_id.as_bytes())? {
            return Err(StoreError::SemanticNamespaceCollision {
                semantic_id: *metadata.semantic_id.as_bytes(),
            });
        }
        if let Some(existing) = write
            .open_table(BLOB_SEMANTIC_ITEMS)?
            .get(metadata.semantic_id.as_bytes().as_slice())?
            .map(|value| parse_blob_transfer_id("Blob semantic item table", value.value()))
            .transpose()?
        {
            if existing != source {
                return Err(blob_error(BlobStoreError::PendingSourceConflict));
            }
            return Err(blob_error(BlobStoreError::SchemaInvariant(
                "Blob semantic index exists without its exact publication",
            )));
        }
        let dot_key = accepted_dot_key(metadata.header.stamp.dot);
        if let Some(existing) = write
            .open_table(ACCEPTED_DOTS)?
            .get(dot_key.as_slice())?
            .map(|value| parse_digest32("accepted dot table", value.value()))
            .transpose()?
        {
            if existing != *metadata.semantic_id.as_bytes() {
                return Err(StoreError::CausalEquivocation {
                    publisher: metadata.header.stamp.dot.publisher,
                    counter: metadata.header.stamp.dot.counter,
                });
            }
            return Err(blob_error(BlobStoreError::SchemaInvariant(
                "accepted Blob dot is missing its semantic index",
            )));
        }
        ensure_frontier_capacity(
            &write,
            &metadata.header.topic,
            &metadata.header.scope,
            metadata.header.stamp.dot.publisher,
            SemanticDataClass::Blob,
        )?;

        let content_prefix = blob_content_prefix(
            &metadata.header.topic,
            &metadata.header.scope,
            metadata.blob_id,
        )?;
        let content_upper = blob_content_prefix_upper_bound(&content_prefix)?;
        let mut publication_count = 0usize;
        let content = write.open_table(BLOB_CONTENT_INDEX)?;
        for row in content.range::<&[u8]>((
            std::ops::Bound::<&[u8]>::Included(content_prefix.as_slice()),
            std::ops::Bound::<&[u8]>::Excluded(content_upper.as_slice()),
        ))? {
            let _ = row?;
            #[cfg(test)]
            TEST_BLOB_CAPACITY_CONTENT_ROWS_VISITED
                .with(|count| count.set(count.get().saturating_add(1)));
            publication_count = publication_count
                .checked_add(1)
                .ok_or(StoreError::ItemCountAccountingOverflow)?;
            if publication_count >= MAX_BLOB_PUBLICATIONS_PER_CONTENT {
                break;
            }
        }
        drop(content);
        if publication_count >= MAX_BLOB_PUBLICATIONS_PER_CONTENT {
            return Err(blob_error(BlobStoreError::PublicationLimitExceeded {
                current: publication_count,
                limit: MAX_BLOB_PUBLICATIONS_PER_CONTENT,
            }));
        }

        let incoming =
            u64::try_from(sealed.len()).map_err(|_| StoreError::PayloadByteAccountingOverflow)?;
        let marker = {
            let mut aggregate = write.open_table(METADATA)?;
            require_ordinary_aggregate_capacity(&write, &aggregate, self.limits, 1, incoming)?;
            let current_items = aggregate
                .get(BLOB_ITEM_COUNT)?
                .map_or(0, |value| value.value());
            let current_bytes = aggregate
                .get(BLOB_TOTAL_BYTES)?
                .map_or(0, |value| value.value());
            let previous_marker = aggregate
                .get(LAST_BLOB_ACCEPTANCE_MARKER)?
                .map_or(0, |value| value.value());
            let marker = previous_marker
                .checked_add(1)
                .ok_or(StoreError::AcceptanceMarkerExhausted)?;
            aggregate.insert(
                BLOB_ITEM_COUNT,
                current_items
                    .checked_add(1)
                    .ok_or(StoreError::ItemCountAccountingOverflow)?,
            )?;
            aggregate.insert(
                BLOB_TOTAL_BYTES,
                current_bytes
                    .checked_add(incoming)
                    .ok_or(StoreError::PayloadByteAccountingOverflow)?,
            )?;
            aggregate.insert(LAST_BLOB_ACCEPTANCE_MARKER, marker)?;
            marker
        };
        lifecycle::ensure_replay_fence(&write, self.blob_lifecycle_limits, replay_fence)?;
        lifecycle::admit_publication_row(&write, self.blob_lifecycle_limits)?;
        lifecycle::move_variant_reference(
            &write,
            metadata.variant_id,
            source,
            lifecycle::VariantReferenceOwner::PendingSource,
            lifecycle::VariantReferenceOwner::Publication,
        )?;
        let encoded_metadata =
            lifecycle::live_publication_record(&write, &encode_blob_metadata(metadata.clone())?)?;
        write
            .open_table(BLOB_BYTES)?
            .insert(source.as_bytes().as_slice(), sealed)?;
        write
            .open_table(BLOB_ACCEPTANCE_MARKERS)?
            .insert(source.as_bytes().as_slice(), marker)?;
        write
            .open_table(BLOB_ACCEPTANCE_ORDER)?
            .insert(marker, source.as_bytes().as_slice())?;
        write
            .open_table(BLOB_PUBLICATIONS)?
            .insert(source.as_bytes().as_slice(), encoded_metadata.as_slice())?;
        write.open_table(BLOB_SEMANTIC_ITEMS)?.insert(
            metadata.semantic_id.as_bytes().as_slice(),
            source.as_bytes().as_slice(),
        )?;
        let content_key = blob_content_key(
            &metadata.header.topic,
            &metadata.header.scope,
            metadata.blob_id,
            metadata.semantic_id,
        )?;
        write
            .open_table(BLOB_CONTENT_INDEX)?
            .insert(content_key.as_slice(), source.as_bytes().as_slice())?;
        write.open_table(ACCEPTED_DOTS)?.insert(
            dot_key.as_slice(),
            metadata.semantic_id.as_bytes().as_slice(),
        )?;
        update_causal_high_water(
            &write,
            metadata.header.stamp.dot.publisher,
            &metadata.header.topic,
            &metadata.header.scope,
            metadata.header.stamp.dot.counter,
        )?;
        remove_pending_source_rows_write(
            &write,
            staging,
            source,
            pending.as_ref().expect("pending branch"),
        )?;
        write.commit()?;
        Ok(ApplyOutcome::Inserted {
            acceptance_marker: marker,
        })
    }

    /// Commits a signed Blob publication only after strong content and depot completion proofs.
    pub fn commit_reserved_blob_once_with_policy(
        &self,
        policy: &ControlPolicySnapshot,
        request: &BlobOperationRequest<'_>,
        reservation: &BlobReservation,
        blob: &ContentVerifiedBlobEnvelope,
        sealed: &[u8],
        completion: &BlobDepotCompletion,
    ) -> Result<BlobOnceOutcome, StoreError> {
        self.require_live()?;
        if policy != reservation.control_policy() {
            return Err(blob_error(BlobStoreError::ReservationChanged));
        }
        let prepared = PreparedBlobPublication::from_verified(blob, sealed, completion)?;
        validate_blob_reservation(reservation, &prepared)?;
        validate_blob_publication_intent(request.intent, &prepared)?;

        let _depot_guard = self
            .blob_depot_lock
            .lock()
            .map_err(|_| blob_error(BlobStoreError::DepotIntegrity("depot lock is poisoned")))?;
        self.require_live()?;
        depot::verify_completion(self, completion)?;

        let write = self.database.begin_write()?;
        enforce_live_write(&write)?;
        enforce_blob_policy_write(&write, prepared.mission_authority, policy, &prepared.header)?;
        let owner_binding = depot::require_depot_owner_binding_write(
            &write,
            &self.path,
            self.backing_identity,
            self.blob_depot_owner_token,
        )?;

        // Current authorization and exact active epoch are rechecked before an
        // operation replay may resolve an older, already committed publication.
        if let Some(existing) = write
            .open_table(BLOB_OPERATIONS)?
            .get(request.operation.as_bytes())?
            .map(|value| decode_blob_operation_record(value.value()))
            .transpose()?
        {
            if existing.intent_digest != request.intent.digest() {
                return Err(blob_error(BlobStoreError::OperationConflict));
            }
            let blob = load_blob_from_write(&write, existing.transfer_id)?.ok_or_else(|| {
                blob_error(BlobStoreError::SchemaInvariant(
                    "Blob operation points to a missing publication",
                ))
            })?;
            let physical_lineage = blob
                .physical_lineage
                .ok_or_else(|| blob_error(BlobStoreError::PhysicalLineageMigrationRequired))?;
            lifecycle::require_lineage_fence(
                &write,
                blob.variant_id,
                physical_lineage,
                owner_binding,
            )?;
            let source_len = u64::try_from(blob.sealed.len())
                .map_err(|_| StoreError::PayloadByteAccountingOverflow)?;
            if lifecycle::check_replay_fence(
                &write,
                lifecycle::ReplayFence::new(
                    blob.header.stamp.dot.publisher,
                    blob.header.stamp.dot.counter,
                    blob.semantic_id,
                    blob.transfer_id,
                    source_len,
                    Sha256::digest(&blob.sealed).into(),
                ),
            )? != lifecycle::ReplayFenceStatus::Exact
            {
                return Err(blob_error(BlobStoreError::SchemaInvariant(
                    "Blob operation publication is missing its replay fence",
                )));
            }
            lifecycle::require_publication_row(&write)?;
            lifecycle::require_variant_reference(
                &write,
                blob.variant_id,
                lifecycle::VariantReferenceOwner::Publication,
                blob.transfer_id,
            )?;
            return Ok(BlobOnceOutcome::Existing { blob });
        }

        let replay_fence = lifecycle::ReplayFence::new(
            prepared.header.stamp.dot.publisher,
            prepared.header.stamp.dot.counter,
            prepared.semantic_id,
            prepared.transfer_id,
            u64::try_from(prepared.sealed.len())
                .map_err(|_| StoreError::PayloadByteAccountingOverflow)?,
            Sha256::digest(&prepared.sealed).into(),
        );
        let replay_status = lifecycle::check_replay_fence(&write, replay_fence)?;
        lifecycle::require_lineage_fence(
            &write,
            prepared.variant_id,
            prepared.physical_lineage,
            owner_binding,
        )?;

        if transfer_id_exists_outside_blob(&write, prepared.transfer_id.as_bytes())? {
            return Err(StoreError::TransferNamespaceCollision {
                transfer_id: *prepared.transfer_id.as_bytes(),
            });
        }
        if semantic_id_exists_outside_blob(&write, prepared.semantic_id.as_bytes())? {
            return Err(StoreError::SemanticNamespaceCollision {
                semantic_id: *prepared.semantic_id.as_bytes(),
            });
        }

        let accepted_representation = {
            let semantic_items = write.open_table(BLOB_SEMANTIC_ITEMS)?;
            semantic_items
                .get(prepared.semantic_id.as_bytes().as_slice())?
                .map(|value| parse_blob_transfer_id("Blob semantic item table", value.value()))
                .transpose()?
        };
        if let Some(accepted) = accepted_representation {
            if accepted != prepared.transfer_id {
                return Err(blob_error(BlobStoreError::SourceRepresentationConflict));
            }
            let stored = load_blob_from_write(&write, accepted)?.ok_or_else(|| {
                blob_error(BlobStoreError::SchemaInvariant(
                    "Blob semantic item index points to a missing publication",
                ))
            })?;
            if stored.header != prepared.header
                || stored.sealed != prepared.sealed
                || stored.variant_id != prepared.variant_id
                || stored.manifest_digest != prepared.manifest_digest
                || stored.route_lineage != Some(prepared.route_lineage)
                || stored.physical_lineage != Some(prepared.physical_lineage)
            {
                return Err(blob_error(BlobStoreError::SourceRepresentationConflict));
            }
            if replay_status != lifecycle::ReplayFenceStatus::Exact {
                return Err(blob_error(BlobStoreError::SchemaInvariant(
                    "accepted Blob publication is missing its replay fence",
                )));
            }
            lifecycle::require_publication_row(&write)?;
            lifecycle::require_variant_reference(
                &write,
                stored.variant_id,
                lifecycle::VariantReferenceOwner::Publication,
                stored.transfer_id,
            )?;
            insert_blob_operation(&write, self.limits, request, prepared.transfer_id)?;
            write.commit()?;
            return Ok(BlobOnceOutcome::BoundExisting { blob: stored });
        }
        if replay_status == lifecycle::ReplayFenceStatus::Exact {
            return Err(blob_error(BlobStoreError::SchemaInvariant(
                "retained Blob replay fence is missing its live publication",
            )));
        }

        let current_counter = write
            .open_table(PUBLISHER_HIGH_WATER)?
            .get(reservation.publisher.as_slice())?
            .map_or(0, |value| value.value());
        if current_counter != reservation.previous_counter {
            return Err(blob_error(BlobStoreError::ReservationChanged));
        }
        let dot_key = accepted_dot_key(prepared.header.stamp.dot);
        if let Some(accepted) = write
            .open_table(ACCEPTED_DOTS)?
            .get(dot_key.as_slice())?
            .map(|value| parse_digest32("accepted dot table", value.value()))
            .transpose()?
        {
            if accepted != *prepared.semantic_id.as_bytes() {
                return Err(StoreError::CausalEquivocation {
                    publisher: prepared.header.stamp.dot.publisher,
                    counter: prepared.header.stamp.dot.counter,
                });
            }
            return Err(blob_error(BlobStoreError::SchemaInvariant(
                "accepted Blob dot is missing its semantic index",
            )));
        }
        ensure_frontier_capacity(
            &write,
            &prepared.header.topic,
            &prepared.header.scope,
            prepared.header.stamp.dot.publisher,
            SemanticDataClass::Blob,
        )?;
        if write
            .open_table(BLOB_PUBLICATIONS)?
            .get(prepared.transfer_id.as_bytes().as_slice())?
            .is_some()
            || write
                .open_table(BLOB_BYTES)?
                .get(prepared.transfer_id.as_bytes().as_slice())?
                .is_some()
            || write
                .open_table(BLOB_ACCEPTANCE_MARKERS)?
                .get(prepared.transfer_id.as_bytes().as_slice())?
                .is_some()
        {
            return Err(blob_error(BlobStoreError::SchemaInvariant(
                "Blob exact namespace contains an unindexed partial publication",
            )));
        }

        let pending = write
            .open_table(BLOB_PENDING_SOURCES)?
            .get(prepared.transfer_id.as_bytes().as_slice())?
            .map(|value| decode_pending_blob_source(value.value()))
            .transpose()?;
        let pending_staging = if let Some(pending) = pending.as_ref() {
            if pending.metadata.transfer_id != prepared.transfer_id
                || pending.metadata.semantic_id != prepared.semantic_id
                || pending.metadata.blob_id != prepared.blob_id
                || pending.metadata.variant_id != prepared.variant_id
                || pending.metadata.manifest_digest != prepared.manifest_digest
                || pending.metadata.route_lineage != Some(prepared.route_lineage)
                || pending.metadata.physical_lineage != Some(prepared.physical_lineage)
                || pending.metadata.header != prepared.header
                || pending.sealed != prepared.sealed
                || pending.route_lineage != prepared.route_lineage
                || pending.physical_lineage != prepared.physical_lineage
            {
                return Err(blob_error(BlobStoreError::PendingSourceConflict));
            }
            Some(blob_network_staging_usage_write(
                &write,
                prepared.mission_authority,
            )?)
        } else {
            None
        };

        let content_prefix = blob_content_prefix(
            &prepared.header.topic,
            &prepared.header.scope,
            prepared.blob_id,
        )?;
        let content_upper = blob_content_prefix_upper_bound(&content_prefix)?;
        let content = write.open_table(BLOB_CONTENT_INDEX)?;
        let mut publication_count = 0usize;
        for row in content.range::<&[u8]>((
            std::ops::Bound::<&[u8]>::Included(content_prefix.as_slice()),
            std::ops::Bound::<&[u8]>::Excluded(content_upper.as_slice()),
        ))? {
            let _ = row?;
            #[cfg(test)]
            TEST_BLOB_CAPACITY_CONTENT_ROWS_VISITED
                .with(|count| count.set(count.get().saturating_add(1)));
            publication_count = publication_count
                .checked_add(1)
                .ok_or(StoreError::ItemCountAccountingOverflow)?;
            if publication_count >= MAX_BLOB_PUBLICATIONS_PER_CONTENT {
                break;
            }
        }
        drop(content);
        if publication_count >= MAX_BLOB_PUBLICATIONS_PER_CONTENT {
            return Err(blob_error(BlobStoreError::PublicationLimitExceeded {
                current: publication_count,
                limit: MAX_BLOB_PUBLICATIONS_PER_CONTENT,
            }));
        }

        let incoming = u64::try_from(prepared.sealed.len())
            .map_err(|_| StoreError::PayloadByteAccountingOverflow)?;
        let marker = {
            let mut metadata = write.open_table(METADATA)?;
            require_ordinary_aggregate_capacity(&write, &metadata, self.limits, 1, incoming)?;
            let current_items = metadata
                .get(BLOB_ITEM_COUNT)?
                .map_or(0, |value| value.value());
            let current_bytes = metadata
                .get(BLOB_TOTAL_BYTES)?
                .map_or(0, |value| value.value());
            let previous_marker = metadata
                .get(LAST_BLOB_ACCEPTANCE_MARKER)?
                .map_or(0, |value| value.value());
            let marker = previous_marker
                .checked_add(1)
                .ok_or(StoreError::AcceptanceMarkerExhausted)?;
            metadata.insert(
                BLOB_ITEM_COUNT,
                current_items
                    .checked_add(1)
                    .ok_or(StoreError::ItemCountAccountingOverflow)?,
            )?;
            metadata.insert(
                BLOB_TOTAL_BYTES,
                current_bytes
                    .checked_add(incoming)
                    .ok_or(StoreError::PayloadByteAccountingOverflow)?,
            )?;
            metadata.insert(LAST_BLOB_ACCEPTANCE_MARKER, marker)?;
            marker
        };

        lifecycle::ensure_replay_fence(&write, self.blob_lifecycle_limits, replay_fence)?;
        lifecycle::admit_publication_row(&write, self.blob_lifecycle_limits)?;
        if pending.is_some() {
            lifecycle::move_variant_reference(
                &write,
                prepared.variant_id,
                prepared.transfer_id,
                lifecycle::VariantReferenceOwner::PendingSource,
                lifecycle::VariantReferenceOwner::Publication,
            )?;
        } else {
            lifecycle::insert_variant_reference(
                &write,
                prepared.variant_id,
                lifecycle::VariantReferenceOwner::Publication,
                prepared.transfer_id,
            )?;
        }
        let encoded_metadata =
            lifecycle::live_publication_record(&write, &prepared.encoded_metadata)?;
        write.open_table(BLOB_BYTES)?.insert(
            prepared.transfer_id.as_bytes().as_slice(),
            prepared.sealed.as_slice(),
        )?;
        write
            .open_table(BLOB_ACCEPTANCE_MARKERS)?
            .insert(prepared.transfer_id.as_bytes().as_slice(), marker)?;
        write
            .open_table(BLOB_ACCEPTANCE_ORDER)?
            .insert(marker, prepared.transfer_id.as_bytes().as_slice())?;
        write.open_table(BLOB_PUBLICATIONS)?.insert(
            prepared.transfer_id.as_bytes().as_slice(),
            encoded_metadata.as_slice(),
        )?;
        write.open_table(BLOB_SEMANTIC_ITEMS)?.insert(
            prepared.semantic_id.as_bytes().as_slice(),
            prepared.transfer_id.as_bytes().as_slice(),
        )?;
        let content_key = blob_content_key(
            &prepared.header.topic,
            &prepared.header.scope,
            prepared.blob_id,
            prepared.semantic_id,
        )?;
        write.open_table(BLOB_CONTENT_INDEX)?.insert(
            content_key.as_slice(),
            prepared.transfer_id.as_bytes().as_slice(),
        )?;
        write.open_table(ACCEPTED_DOTS)?.insert(
            dot_key.as_slice(),
            prepared.semantic_id.as_bytes().as_slice(),
        )?;
        update_causal_high_water(
            &write,
            prepared.header.stamp.dot.publisher,
            &prepared.header.topic,
            &prepared.header.scope,
            prepared.header.stamp.dot.counter,
        )?;
        insert_blob_operation(&write, self.limits, request, prepared.transfer_id)?;
        if let Some(pending) = pending.as_ref() {
            remove_pending_source_rows_write(
                &write,
                pending_staging.expect("pending source has staging accounting"),
                prepared.transfer_id,
                pending,
            )?;
        }
        #[cfg(test)]
        if TEST_BLOB_ADMISSION_PRE_COMMIT_FAULT.get() {
            return Err(blob_error(BlobStoreError::SchemaInvariant(
                "injected Blob admission pre-commit failure",
            )));
        }
        write.commit()?;

        Ok(BlobOnceOutcome::Inserted {
            blob: StoredBlob {
                transfer_id: prepared.transfer_id,
                semantic_id: prepared.semantic_id,
                blob_id: prepared.blob_id,
                variant_id: prepared.variant_id,
                manifest_digest: prepared.manifest_digest,
                route_lineage: Some(prepared.route_lineage),
                physical_lineage: Some(prepared.physical_lineage),
                header: prepared.header,
                sealed: prepared.sealed,
                acceptance_marker: marker,
            },
        })
    }
}

struct PreparedBlobPublication {
    mission_authority: NodeId,
    transfer_id: BlobTransferId,
    semantic_id: BlobSemanticId,
    blob_id: BlobId,
    variant_id: BlobVariantId,
    manifest_digest: [u8; 32],
    route_lineage: [u8; 32],
    physical_lineage: [u8; 32],
    header: EnvelopeHeader,
    sealed: Vec<u8>,
    encoded_metadata: Vec<u8>,
}

impl PreparedBlobPublication {
    fn from_verified(
        blob: &ContentVerifiedBlobEnvelope,
        sealed: &[u8],
        completion: &BlobDepotCompletion,
    ) -> Result<Self, StoreError> {
        blob.verify_exact_sealed(sealed)
            .map_err(|error| blob_error(BlobStoreError::Verification(error.to_string())))?;
        let header = blob.header().clone();
        validate_blob_header(&header)?;
        let manifest = blob.manifest();
        let blob_id = manifest.id();
        let route = header.blob_route.ok_or_else(|| {
            blob_error(BlobStoreError::InvalidPublication(
                "authenticated Blob route commitment is missing",
            ))
        })?;
        if route.blob_id() != blob_id
            || route.chunk_count() != manifest.chunk_count()
            || header.key_epoch != manifest.content_epoch()
            || header.content_len != blob.content_len()
            || header.logical_key.as_slice() != blob_id.as_bytes()
        {
            return Err(blob_error(BlobStoreError::CompletionMismatch));
        }
        let manifest_digest = *blob.manifest_digest();
        let variant_id =
            blob_variant_id(blob_id, manifest.content_group(), manifest.content_epoch());
        if completion.blob_id != blob_id
            || completion.variant_id != variant_id
            || completion.content_group != *manifest.content_group()
            || completion.epoch != manifest.content_epoch()
            || completion.physical_lineage != *blob.physical_lineage().binding()
            || completion.manifest_digest != manifest_digest
            || completion.chunk_count != manifest.chunk_count()
        {
            return Err(blob_error(BlobStoreError::CompletionMismatch));
        }
        let transfer_id = BlobTransferId::new(blob.envelope_id());
        let semantic_id = BlobSemanticId::new(blob.item_id());
        let route_lineage = *blob.route_lineage().binding();
        let physical_lineage = *blob.physical_lineage().binding();
        let encoded_metadata = encode_blob_metadata(BlobMetadata {
            transfer_id,
            semantic_id,
            blob_id,
            variant_id,
            manifest_digest,
            route_lineage: Some(route_lineage),
            physical_lineage: Some(physical_lineage),
            header: header.clone(),
        })?;
        Ok(Self {
            mission_authority: blob.mission_authority_id(),
            transfer_id,
            semantic_id,
            blob_id,
            variant_id,
            manifest_digest,
            route_lineage,
            physical_lineage,
            header,
            sealed: sealed.to_vec(),
            encoded_metadata,
        })
    }
}

const MAINTENANCE_PRIMARY_SOURCE_TAG: u8 = 1;
const MAINTENANCE_SECONDARY_SOURCE_TAG: u8 = 2;

#[derive(Debug)]
struct MaintenanceReferenceEvidence {
    key: Vec<u8>,
    value: Vec<u8>,
}

#[derive(Debug)]
struct MaintenancePublicationEvidence {
    import: Vec<u8>,
    lineage: Vec<u8>,
    reference: MaintenanceReferenceEvidence,
    source: Vec<u8>,
    marker: u64,
    semantic_index: Vec<u8>,
    content_index: Vec<u8>,
    replay: Vec<u8>,
    accepted_dot: Vec<u8>,
    publisher_high_water: u64,
    causal_frontier: u64,
    conflicting_pending: Option<Vec<u8>>,
}

#[derive(Debug)]
struct MaintenancePendingEvidence {
    import: Vec<u8>,
    lineage: Vec<u8>,
    reference: MaintenanceReferenceEvidence,
    conflicting_publication: Option<Vec<u8>>,
}

#[derive(Debug)]
struct MaintenanceCarrierEvidence {
    pending: Vec<u8>,
    pending_evidence: MaintenancePendingEvidence,
}

#[derive(Debug)]
struct MaintenanceImportEvidence {
    lineage: Vec<u8>,
    reference: Option<MaintenanceReferenceEvidence>,
}

#[derive(Debug)]
enum MaintenanceEvidence {
    Publication(MaintenancePublicationEvidence),
    Pending(MaintenancePendingEvidence),
    Carrier(MaintenanceCarrierEvidence),
    Import(MaintenanceImportEvidence),
    Operation { publication: Vec<u8> },
}

#[derive(Debug)]
struct MaintenancePageRow {
    position: Vec<u8>,
    key: Vec<u8>,
    value: Vec<u8>,
    evidence: MaintenanceEvidence,
}

#[derive(Debug)]
struct MaintenancePage {
    rows: Vec<MaintenancePageRow>,
    rows_examined: u64,
    bytes: u64,
    complete: bool,
}

#[cfg(test)]
fn maintenance_entry_bytes(key: &[u8], value: &[u8]) -> Result<u64, StoreError> {
    key.len()
        .checked_add(value.len())
        .and_then(|length| u64::try_from(length).ok())
        .ok_or(StoreError::PayloadByteAccountingOverflow)
}

#[derive(Clone, Copy)]
enum MaintenanceRowKind {
    Publication,
    Pending,
    Carrier,
    Import,
    Operation,
}

struct MaintenanceCharge {
    budget: BlobMaintenanceBudget,
    rows: u64,
    bytes: u64,
}

impl MaintenanceCharge {
    fn charge(&mut self, key: &[u8], value_len: usize) -> Result<bool, StoreError> {
        if self.rows >= self.budget.rows {
            return Ok(false);
        }
        let encoded_bytes = key
            .len()
            .checked_add(value_len)
            .and_then(|length| u64::try_from(length).ok())
            .ok_or(StoreError::PayloadByteAccountingOverflow)?;
        let next_bytes = self
            .bytes
            .checked_add(encoded_bytes)
            .ok_or(StoreError::PayloadByteAccountingOverflow)?;
        if next_bytes > self.budget.bytes {
            return Ok(false);
        }
        self.rows = self
            .rows
            .checked_add(1)
            .ok_or(StoreError::ItemCountAccountingOverflow)?;
        self.bytes = next_bytes;
        Ok(true)
    }
}

fn capture_required_maintenance_bytes(
    write: &redb::WriteTransaction,
    definition: TableDefinition<&'static [u8], &'static [u8]>,
    key: &[u8],
    missing: &'static str,
    charge: &mut MaintenanceCharge,
) -> Result<Option<Vec<u8>>, StoreError> {
    if charge.rows >= charge.budget.rows {
        return Ok(None);
    }
    let table = write.open_table(definition)?;
    let value = table
        .get(key)?
        .ok_or_else(|| blob_error(BlobStoreError::SchemaInvariant(missing)))?;
    if !charge.charge(key, value.value().len())? {
        return Ok(None);
    }
    Ok(Some(value.value().to_vec()))
}

fn capture_optional_maintenance_bytes(
    write: &redb::WriteTransaction,
    definition: TableDefinition<&'static [u8], &'static [u8]>,
    key: &[u8],
    charge: &mut MaintenanceCharge,
) -> Result<Result<Option<Vec<u8>>, ()>, StoreError> {
    if charge.rows >= charge.budget.rows || charge.bytes >= charge.budget.bytes {
        return Ok(Err(()));
    }
    let table = write.open_table(definition)?;
    let Some(value) = table.get(key)? else {
        return Ok(Ok(None));
    };
    if !charge.charge(key, value.value().len())? {
        return Ok(Err(()));
    }
    Ok(Ok(Some(value.value().to_vec())))
}

fn capture_required_maintenance_u64(
    write: &redb::WriteTransaction,
    definition: TableDefinition<&'static [u8], u64>,
    key: &[u8],
    missing: &'static str,
    charge: &mut MaintenanceCharge,
) -> Result<Option<u64>, StoreError> {
    if charge.rows >= charge.budget.rows {
        return Ok(None);
    }
    let table = write.open_table(definition)?;
    let value = table
        .get(key)?
        .ok_or_else(|| blob_error(BlobStoreError::SchemaInvariant(missing)))?;
    if !charge.charge(key, std::mem::size_of::<u64>())? {
        return Ok(None);
    }
    Ok(Some(value.value()))
}

fn variant_reference_key(
    variant: BlobVariantId,
    owner: lifecycle::VariantReferenceOwner,
    transfer: BlobTransferId,
) -> Vec<u8> {
    let mut key = Vec::with_capacity(65);
    key.extend_from_slice(variant.as_bytes());
    key.extend_from_slice(&owner.encode());
    key.extend_from_slice(transfer.as_bytes());
    key
}

fn capture_exact_maintenance_reference(
    write: &redb::WriteTransaction,
    variant: BlobVariantId,
    owner: lifecycle::VariantReferenceOwner,
    transfer: BlobTransferId,
    charge: &mut MaintenanceCharge,
) -> Result<Option<MaintenanceReferenceEvidence>, StoreError> {
    let key = variant_reference_key(variant, owner, transfer);
    let Some(value) = capture_required_maintenance_bytes(
        write,
        lifecycle::BLOB_VARIANT_REFERENCES,
        &key,
        "Blob lifecycle row is missing its exact variant reference",
        charge,
    )?
    else {
        return Ok(None);
    };
    Ok(Some(MaintenanceReferenceEvidence { key, value }))
}

fn capture_any_maintenance_reference(
    write: &redb::WriteTransaction,
    variant: BlobVariantId,
    charge: &mut MaintenanceCharge,
) -> Result<Result<Option<MaintenanceReferenceEvidence>, ()>, StoreError> {
    if charge.rows >= charge.budget.rows || charge.bytes >= charge.budget.bytes {
        return Ok(Err(()));
    }
    let references = write.open_table(lifecycle::BLOB_VARIANT_REFERENCES)?;
    let start = variant.as_bytes().as_slice();
    let mut upper = start.to_vec();
    let upper = upper
        .iter_mut()
        .rposition(|byte| *byte != u8::MAX)
        .map(|index| {
            upper[index] += 1;
            upper.truncate(index + 1);
            upper
        });
    let bounds = match upper.as_deref() {
        Some(upper) => (
            std::ops::Bound::Included(start),
            std::ops::Bound::Excluded(upper),
        ),
        None => (std::ops::Bound::Included(start), std::ops::Bound::Unbounded),
    };
    let Some((key, value)) = references.range::<&[u8]>(bounds)?.next().transpose()? else {
        return Ok(Ok(None));
    };
    debug_assert!(key.value().starts_with(start));
    if !charge.charge(key.value(), value.value().len())? {
        return Ok(Err(()));
    }
    Ok(Ok(Some(MaintenanceReferenceEvidence {
        key: key.value().to_vec(),
        value: value.value().to_vec(),
    })))
}

fn capture_maintenance_evidence(
    write: &redb::WriteTransaction,
    kind: MaintenanceRowKind,
    key: &[u8],
    value: &[u8],
    charge: &mut MaintenanceCharge,
) -> Result<Option<MaintenanceEvidence>, StoreError> {
    macro_rules! required_bytes {
        ($definition:expr, $key:expr, $missing:literal) => {
            match capture_required_maintenance_bytes(write, $definition, $key, $missing, charge)? {
                Some(value) => value,
                None => return Ok(None),
            }
        };
    }
    macro_rules! required_u64 {
        ($definition:expr, $key:expr, $missing:literal) => {
            match capture_required_maintenance_u64(write, $definition, $key, $missing, charge)? {
                Some(value) => value,
                None => return Ok(None),
            }
        };
    }

    Ok(Some(match kind {
        MaintenanceRowKind::Publication => {
            let transfer = parse_blob_transfer_id("Blob publication table", key)?;
            let publication = decode_blob_metadata(value)?;
            let conflicting_pending =
                match capture_optional_maintenance_bytes(write, BLOB_PENDING_SOURCES, key, charge)?
                {
                    Ok(value) => value,
                    Err(()) => return Ok(None),
                };
            let variant_key = publication.variant_id.as_bytes().as_slice();
            let import = required_bytes!(
                BLOB_IMPORTS,
                variant_key,
                "accepted Blob publication is missing its depot import"
            );
            let lineage = required_bytes!(
                lifecycle::BLOB_LINEAGE_FENCES,
                variant_key,
                "accepted Blob publication is missing its lineage fence"
            );
            let reference = match capture_exact_maintenance_reference(
                write,
                publication.variant_id,
                lifecycle::VariantReferenceOwner::Publication,
                transfer,
                charge,
            )? {
                Some(value) => value,
                None => return Ok(None),
            };
            let source = required_bytes!(
                BLOB_BYTES,
                key,
                "accepted Blob publication is missing exact source bytes"
            );
            let marker = required_u64!(
                BLOB_ACCEPTANCE_MARKERS,
                key,
                "accepted Blob publication is missing its acceptance marker"
            );
            let semantic_index = required_bytes!(
                BLOB_SEMANTIC_ITEMS,
                publication.semantic_id.as_bytes(),
                "accepted Blob publication is missing its semantic index"
            );
            let content_key = blob_content_key(
                &publication.header.topic,
                &publication.header.scope,
                publication.blob_id,
                publication.semantic_id,
            )?;
            let content_index = required_bytes!(
                BLOB_CONTENT_INDEX,
                content_key.as_slice(),
                "accepted Blob publication is missing its content index"
            );
            let dot_key = accepted_dot_key(publication.header.stamp.dot);
            let replay = required_bytes!(
                lifecycle::BLOB_REPLAY_FENCES,
                dot_key.as_slice(),
                "accepted Blob publication is missing its replay fence"
            );
            let accepted_dot = required_bytes!(
                ACCEPTED_DOTS,
                dot_key.as_slice(),
                "accepted Blob publication is missing its accepted-dot authority"
            );
            let publisher_high_water = required_u64!(
                PUBLISHER_HIGH_WATER,
                publication.header.stamp.dot.publisher.as_slice(),
                "accepted Blob publication is missing its publisher high-water"
            );
            let frontier_key = causal_frontier_key(
                &publication.header.topic,
                &publication.header.scope,
                publication.header.stamp.dot.publisher,
            )?;
            let causal_frontier = required_u64!(
                CAUSAL_FRONTIER,
                frontier_key.as_slice(),
                "accepted Blob publication is missing its causal frontier"
            );
            MaintenanceEvidence::Publication(MaintenancePublicationEvidence {
                import,
                lineage,
                reference,
                source,
                marker,
                semantic_index,
                content_index,
                replay,
                accepted_dot,
                publisher_high_water,
                causal_frontier,
                conflicting_pending,
            })
        }
        MaintenanceRowKind::Pending => {
            let transfer = parse_blob_transfer_id("pending Blob source table", key)?;
            let pending = decode_pending_blob_source(value)?;
            let conflicting_publication =
                match capture_optional_maintenance_bytes(write, BLOB_PUBLICATIONS, key, charge)? {
                    Ok(value) => value,
                    Err(()) => return Ok(None),
                };
            let variant_key = pending.metadata.variant_id.as_bytes().as_slice();
            let import = required_bytes!(
                BLOB_IMPORTS,
                variant_key,
                "pending Blob source is missing its depot import"
            );
            let lineage = required_bytes!(
                lifecycle::BLOB_LINEAGE_FENCES,
                variant_key,
                "pending Blob source is missing its lineage fence"
            );
            let reference = match capture_exact_maintenance_reference(
                write,
                pending.metadata.variant_id,
                lifecycle::VariantReferenceOwner::PendingSource,
                transfer,
                charge,
            )? {
                Some(value) => value,
                None => return Ok(None),
            };
            MaintenanceEvidence::Pending(MaintenancePendingEvidence {
                import,
                lineage,
                reference,
                conflicting_publication,
            })
        }
        MaintenanceRowKind::Carrier => {
            let (source, _) = parse_blob_carrier_prefix_key(key)?;
            let conflicting_publication = match capture_optional_maintenance_bytes(
                write,
                BLOB_PUBLICATIONS,
                source.as_bytes(),
                charge,
            )? {
                Ok(value) => value,
                Err(()) => return Ok(None),
            };
            let pending = required_bytes!(
                BLOB_PENDING_SOURCES,
                source.as_bytes(),
                "Blob carrier prefix points to a missing pending source"
            );
            let pending_record = decode_pending_blob_source(&pending)?;
            let variant_key = pending_record.metadata.variant_id.as_bytes().as_slice();
            let import = required_bytes!(
                BLOB_IMPORTS,
                variant_key,
                "pending Blob source is missing its depot import"
            );
            let lineage = required_bytes!(
                lifecycle::BLOB_LINEAGE_FENCES,
                variant_key,
                "pending Blob source is missing its lineage fence"
            );
            let reference = match capture_exact_maintenance_reference(
                write,
                pending_record.metadata.variant_id,
                lifecycle::VariantReferenceOwner::PendingSource,
                source,
                charge,
            )? {
                Some(value) => value,
                None => return Ok(None),
            };
            MaintenanceEvidence::Carrier(MaintenanceCarrierEvidence {
                pending,
                pending_evidence: MaintenancePendingEvidence {
                    import,
                    lineage,
                    reference,
                    conflicting_publication,
                },
            })
        }
        MaintenanceRowKind::Import => {
            let import = depot::maintenance_import_projection(key, value)?;
            let reference =
                match capture_any_maintenance_reference(write, import.variant_id, charge)? {
                    Ok(value) => value,
                    Err(()) => return Ok(None),
                };
            let lineage = required_bytes!(
                lifecycle::BLOB_LINEAGE_FENCES,
                import.variant_id.as_bytes(),
                "retained Blob import is missing its lineage fence"
            );
            MaintenanceEvidence::Import(MaintenanceImportEvidence { lineage, reference })
        }
        MaintenanceRowKind::Operation => {
            let operation = decode_blob_operation_record(value)?;
            let publication = required_bytes!(
                BLOB_PUBLICATIONS,
                operation.transfer_id.as_bytes(),
                "Blob lifecycle operation points to a missing publication"
            );
            MaintenanceEvidence::Operation { publication }
        }
    }))
}

#[allow(clippy::too_many_arguments)]
fn append_maintenance_range<'a>(
    write: &redb::WriteTransaction,
    definition: TableDefinition<&'static [u8], &'static [u8]>,
    kind: MaintenanceRowKind,
    tag: Option<u8>,
    lower: std::ops::Bound<&'a [u8]>,
    upper: std::ops::Bound<&'a [u8]>,
    total_rows: u64,
    rows: &mut Vec<MaintenancePageRow>,
    charge: &mut MaintenanceCharge,
) -> Result<bool, StoreError> {
    let table = write.open_table(definition)?;
    let mut range = table.range::<&[u8]>((lower, upper))?;
    loop {
        if charge.rows >= charge.budget.rows
            || u64::try_from(rows.len()).map_err(|_| StoreError::ItemCountAccountingOverflow)?
                >= total_rows
        {
            return Ok(false);
        }
        let Some(row) = range.next() else {
            return Ok(true);
        };
        let (key, value) = row?;
        if !charge.charge(key.value(), value.value().len())? {
            return Ok(false);
        }
        let key = key.value().to_vec();
        let value = value.value().to_vec();
        let Some(evidence) = capture_maintenance_evidence(write, kind, &key, &value, charge)?
        else {
            return Ok(false);
        };
        let mut position = Vec::with_capacity(key.len() + usize::from(tag.is_some()));
        if let Some(tag) = tag {
            position.push(tag);
        }
        position.extend_from_slice(&key);
        rows.push(MaintenancePageRow {
            position,
            key,
            value,
            evidence,
        });
    }
}

fn bounded_single_maintenance_page(
    write: &redb::WriteTransaction,
    definition: TableDefinition<&'static [u8], &'static [u8]>,
    kind: MaintenanceRowKind,
    after: Option<&[u8]>,
    budget: BlobMaintenanceBudget,
) -> Result<MaintenancePage, StoreError> {
    let total_rows = write.open_table(definition)?.len()?;
    let mut rows = Vec::new();
    let mut charge = MaintenanceCharge {
        budget,
        rows: 0,
        bytes: 0,
    };
    let first_complete = append_maintenance_range(
        write,
        definition,
        kind,
        None,
        after.map_or(std::ops::Bound::Unbounded, std::ops::Bound::Excluded),
        std::ops::Bound::Unbounded,
        total_rows,
        &mut rows,
        &mut charge,
    )?;
    if first_complete
        && u64::try_from(rows.len()).map_err(|_| StoreError::ItemCountAccountingOverflow)?
            < total_rows
        && let Some(after) = after
    {
        append_maintenance_range(
            write,
            definition,
            kind,
            None,
            std::ops::Bound::Unbounded,
            std::ops::Bound::Included(after),
            total_rows,
            &mut rows,
            &mut charge,
        )?;
    }
    let examined_rows =
        u64::try_from(rows.len()).map_err(|_| StoreError::ItemCountAccountingOverflow)?;
    Ok(MaintenancePage {
        complete: examined_rows == total_rows,
        rows,
        rows_examined: charge.rows,
        bytes: charge.bytes,
    })
}

fn bounded_composite_maintenance_page(
    write: &redb::WriteTransaction,
    primary: TableDefinition<&'static [u8], &'static [u8]>,
    primary_kind: MaintenanceRowKind,
    secondary: TableDefinition<&'static [u8], &'static [u8]>,
    secondary_kind: MaintenanceRowKind,
    after: Option<&[u8]>,
    budget: BlobMaintenanceBudget,
) -> Result<MaintenancePage, StoreError> {
    let total_rows = write
        .open_table(primary)?
        .len()?
        .checked_add(write.open_table(secondary)?.len()?)
        .ok_or(StoreError::ItemCountAccountingOverflow)?;
    let mut rows = Vec::new();
    let mut charge = MaintenanceCharge {
        budget,
        rows: 0,
        bytes: 0,
    };
    let mut append = |definition, kind, tag, lower, upper| {
        append_maintenance_range(
            write,
            definition,
            kind,
            Some(tag),
            lower,
            upper,
            total_rows,
            &mut rows,
            &mut charge,
        )
    };
    match after {
        None => {
            if append(
                primary,
                primary_kind,
                MAINTENANCE_PRIMARY_SOURCE_TAG,
                std::ops::Bound::Unbounded,
                std::ops::Bound::Unbounded,
            )? {
                append(
                    secondary,
                    secondary_kind,
                    MAINTENANCE_SECONDARY_SOURCE_TAG,
                    std::ops::Bound::Unbounded,
                    std::ops::Bound::Unbounded,
                )?;
            }
        }
        Some(after) => {
            let (&tag, key) = after.split_first().ok_or_else(|| {
                blob_error(BlobStoreError::SchemaInvariant(
                    "Blob maintenance composite cursor is empty",
                ))
            })?;
            match tag {
                MAINTENANCE_PRIMARY_SOURCE_TAG => {
                    if append(
                        primary,
                        primary_kind,
                        MAINTENANCE_PRIMARY_SOURCE_TAG,
                        std::ops::Bound::Excluded(key),
                        std::ops::Bound::Unbounded,
                    )? && append(
                        secondary,
                        secondary_kind,
                        MAINTENANCE_SECONDARY_SOURCE_TAG,
                        std::ops::Bound::Unbounded,
                        std::ops::Bound::Unbounded,
                    )? {
                        append(
                            primary,
                            primary_kind,
                            MAINTENANCE_PRIMARY_SOURCE_TAG,
                            std::ops::Bound::Unbounded,
                            std::ops::Bound::Included(key),
                        )?;
                    }
                }
                MAINTENANCE_SECONDARY_SOURCE_TAG => {
                    if append(
                        secondary,
                        secondary_kind,
                        MAINTENANCE_SECONDARY_SOURCE_TAG,
                        std::ops::Bound::Excluded(key),
                        std::ops::Bound::Unbounded,
                    )? && append(
                        primary,
                        primary_kind,
                        MAINTENANCE_PRIMARY_SOURCE_TAG,
                        std::ops::Bound::Unbounded,
                        std::ops::Bound::Unbounded,
                    )? {
                        append(
                            secondary,
                            secondary_kind,
                            MAINTENANCE_SECONDARY_SOURCE_TAG,
                            std::ops::Bound::Unbounded,
                            std::ops::Bound::Included(key),
                        )?;
                    }
                }
                _ => {
                    return Err(blob_error(BlobStoreError::SchemaInvariant(
                        "Blob maintenance composite cursor has an unknown source tag",
                    )));
                }
            }
        }
    }
    let examined_rows =
        u64::try_from(rows.len()).map_err(|_| StoreError::ItemCountAccountingOverflow)?;
    Ok(MaintenancePage {
        complete: examined_rows == total_rows,
        rows,
        rows_examined: charge.rows,
        bytes: charge.bytes,
    })
}

fn validate_maintenance_reference(
    evidence: &MaintenanceReferenceEvidence,
    variant: BlobVariantId,
    owner: lifecycle::VariantReferenceOwner,
    transfer: BlobTransferId,
) -> Result<(), StoreError> {
    if evidence.key != variant_reference_key(variant, owner, transfer) || !evidence.value.is_empty()
    {
        return Err(blob_error(BlobStoreError::SchemaInvariant(
            "Blob variant reference is not canonical",
        )));
    }
    Ok(())
}

fn validate_maintenance_publication(
    key: &[u8],
    value: &[u8],
    evidence: &MaintenancePublicationEvidence,
    owner_binding: [u8; 32],
) -> Result<(), StoreError> {
    let transfer = parse_blob_transfer_id("Blob publication table", key)?;
    let publication = decode_blob_metadata(value)?;
    if publication.transfer_id != transfer {
        return Err(blob_error(BlobStoreError::SchemaInvariant(
            "Blob publication key differs from its exact metadata",
        )));
    }
    let route = publication.header.blob_route.ok_or_else(|| {
        blob_error(BlobStoreError::SchemaInvariant(
            "accepted Blob publication is missing its route commitment",
        ))
    })?;
    let physical_lineage = publication.physical_lineage.ok_or_else(|| {
        blob_error(BlobStoreError::SchemaInvariant(
            "accepted Blob publication is missing authenticated physical lineage",
        ))
    })?;
    depot::audit_publication_import_evidence(
        &evidence.import,
        publication.variant_id,
        publication.blob_id,
        publication.header.key_epoch,
        publication.manifest_digest,
        route.chunk_count(),
        publication.physical_lineage,
    )?;
    lifecycle::validate_maintenance_lineage_evidence(
        physical_lineage,
        owner_binding,
        &evidence.lineage,
    )?;
    validate_maintenance_reference(
        &evidence.reference,
        publication.variant_id,
        lifecycle::VariantReferenceOwner::Publication,
        transfer,
    )?;
    if evidence.marker == 0
        || evidence.conflicting_pending.is_some()
        || BlobTransferId::new(Sha256::digest(&evidence.source).into()) != transfer
    {
        return Err(blob_error(BlobStoreError::SchemaInvariant(
            "live Blob publication has contradictory durable roots",
        )));
    }
    let indexed = parse_blob_transfer_id("Blob semantic item table", &evidence.semantic_index)?;
    if indexed != transfer {
        return Err(blob_error(BlobStoreError::SchemaInvariant(
            "live Blob publication is missing its semantic index",
        )));
    }
    let content = parse_blob_transfer_id("Blob content index", &evidence.content_index)?;
    if content != transfer {
        return Err(blob_error(BlobStoreError::SchemaInvariant(
            "live Blob publication is missing its content index",
        )));
    }
    let dot = publication.header.stamp.dot;
    let source_len = u64::try_from(evidence.source.len())
        .map_err(|_| StoreError::PayloadByteAccountingOverflow)?;
    lifecycle::validate_maintenance_replay_evidence(
        lifecycle::ReplayFence::new(
            dot.publisher,
            dot.counter,
            publication.semantic_id,
            transfer,
            source_len,
            Sha256::digest(&evidence.source).into(),
        ),
        &evidence.replay,
    )?;
    let accepted = parse_digest32("accepted dot table", &evidence.accepted_dot)?;
    if accepted != *publication.semantic_id.as_bytes() {
        return Err(blob_error(BlobStoreError::SchemaInvariant(
            "Blob publication accepted-dot authority names another semantic item",
        )));
    }
    if evidence.publisher_high_water < dot.counter {
        return Err(blob_error(BlobStoreError::SchemaInvariant(
            "Blob publication publisher high-water is missing or behind",
        )));
    }
    if evidence.causal_frontier < dot.counter {
        return Err(blob_error(BlobStoreError::SchemaInvariant(
            "Blob publication causal frontier is missing or behind",
        )));
    }
    Ok(())
}

fn validate_maintenance_pending_source(
    key: &[u8],
    value: &[u8],
    evidence: &MaintenancePendingEvidence,
    owner_binding: [u8; 32],
) -> Result<PendingBlobSourceRecord, StoreError> {
    let transfer = parse_blob_transfer_id("pending Blob source table", key)?;
    let pending = decode_pending_blob_source(value)?;
    if pending.metadata.transfer_id != transfer
        || pending.metadata.physical_lineage != Some(pending.physical_lineage)
        || evidence.conflicting_publication.is_some()
    {
        return Err(blob_error(BlobStoreError::SchemaInvariant(
            "pending Blob source has contradictory durable roots",
        )));
    }
    let import = depot::maintenance_import_projection(
        pending.metadata.variant_id.as_bytes(),
        &evidence.import,
    )?;
    if import.variant_id != pending.metadata.variant_id
        || import.physical_lineage != pending.physical_lineage
    {
        return Err(blob_error(BlobStoreError::SchemaInvariant(
            "pending Blob source conflicts with its depot import",
        )));
    }
    lifecycle::validate_maintenance_lineage_evidence(
        pending.physical_lineage,
        owner_binding,
        &evidence.lineage,
    )?;
    validate_maintenance_reference(
        &evidence.reference,
        pending.metadata.variant_id,
        lifecycle::VariantReferenceOwner::PendingSource,
        transfer,
    )?;
    Ok(pending)
}

fn validate_maintenance_carrier_prefix(
    key: &[u8],
    value: &[u8],
    evidence: &MaintenanceCarrierEvidence,
    owner_binding: [u8; 32],
) -> Result<(), StoreError> {
    let key: [u8; BLOB_CARRIER_PREFIX_KEY_BYTES] = key.try_into().map_err(|_| {
        blob_error(BlobStoreError::SchemaInvariant(
            "Blob carrier-prefix key has an invalid length",
        ))
    })?;
    let source = BlobTransferId::new(key[..32].try_into().expect("fixed source key"));
    let object = BlobCarrierObjectId::new(key[32..].try_into().expect("fixed ObjectID key"))
        .map_err(|_| {
            blob_error(BlobStoreError::SchemaInvariant(
                "Blob carrier-prefix key has an invalid typed identity",
            ))
        })?;
    let prefix = decode_blob_carrier_prefix(value)?;
    if prefix.source != source {
        return Err(blob_error(BlobStoreError::SchemaInvariant(
            "Blob carrier-prefix key differs from its source",
        )));
    }
    let pending = validate_maintenance_pending_source(
        source.as_bytes().as_slice(),
        &evidence.pending,
        &evidence.pending_evidence,
        owner_binding,
    )?;
    if !pending
        .carriers
        .iter()
        .any(|carrier| carrier.object == object && carrier.total_len == prefix.total_len)
    {
        return Err(blob_error(BlobStoreError::SchemaInvariant(
            "Blob carrier prefix conflicts with its pending source",
        )));
    }
    Ok(())
}

fn validate_maintenance_operation(
    key: &[u8],
    value: &[u8],
    publication: &[u8],
) -> Result<(), StoreError> {
    BlobOperationKey::new(key.to_vec())?;
    let operation = decode_blob_operation_record(value)?;
    let publication = decode_blob_metadata(publication)?;
    if publication.transfer_id != operation.transfer_id {
        return Err(blob_error(BlobStoreError::SchemaInvariant(
            "Blob lifecycle operation points to contradictory publication metadata",
        )));
    }
    Ok(())
}

impl Store {
    /// Runs one internal, durable, independently bounded maintenance selection
    /// turn. Destructive candidates are discovery-only in this increment.
    #[doc(hidden)]
    pub fn run_blob_maintenance_turn(
        &self,
        budget: BlobMaintenanceBudget,
    ) -> Result<BlobMaintenanceProgress, StoreError> {
        self.require_live()?;
        if budget.rows == 0 || budget.files == 0 || budget.bytes == 0 {
            return Err(blob_error(BlobStoreError::InvalidMaintenanceBudget));
        }
        let write = self.database.begin_write()?;
        enforce_live_write(&write)?;
        lifecycle::require_maintenance_accounting(&write)?;
        let cursor = lifecycle::load_maintenance_cursor(&write)?;
        let page = match cursor.class {
            BlobMaintenanceClass::ExpiredPublicationsAndPendingSources => {
                bounded_composite_maintenance_page(
                    &write,
                    BLOB_PUBLICATIONS,
                    MaintenanceRowKind::Publication,
                    BLOB_PENDING_SOURCES,
                    MaintenanceRowKind::Pending,
                    cursor.position.as_deref(),
                    budget,
                )?
            }
            BlobMaintenanceClass::InvalidPendingWork => bounded_composite_maintenance_page(
                &write,
                BLOB_PENDING_SOURCES,
                MaintenanceRowKind::Pending,
                BLOB_CARRIER_PREFIXES,
                MaintenanceRowKind::Carrier,
                cursor.position.as_deref(),
                budget,
            )?,
            BlobMaintenanceClass::UnreferencedLocalImportStaging
            | BlobMaintenanceClass::UnreferencedCompletedVariants => {
                bounded_single_maintenance_page(
                    &write,
                    BLOB_IMPORTS,
                    MaintenanceRowKind::Import,
                    cursor.position.as_deref(),
                    budget,
                )?
            }
            BlobMaintenanceClass::ExpiredRetirementRecords => bounded_single_maintenance_page(
                &write,
                BLOB_OPERATIONS,
                MaintenanceRowKind::Operation,
                cursor.position.as_deref(),
                budget,
            )?,
            BlobMaintenanceClass::ManifestBackedPhysicalDeletion => MaintenancePage {
                rows: Vec::new(),
                rows_examined: 0,
                bytes: 0,
                complete: true,
            },
        };

        let mut candidates = Vec::new();
        for row in &page.rows {
            match cursor.class {
                BlobMaintenanceClass::ExpiredPublicationsAndPendingSources => match row.position[0]
                {
                    MAINTENANCE_PRIMARY_SOURCE_TAG => {
                        let MaintenanceEvidence::Publication(evidence) = &row.evidence else {
                            return Err(blob_error(BlobStoreError::SchemaInvariant(
                                "Blob publication maintenance row has wrong evidence",
                            )));
                        };
                        validate_maintenance_publication(
                            &row.key,
                            &row.value,
                            evidence,
                            self.blob_depot_owner_binding,
                        )?;
                    }
                    MAINTENANCE_SECONDARY_SOURCE_TAG => {
                        let MaintenanceEvidence::Pending(evidence) = &row.evidence else {
                            return Err(blob_error(BlobStoreError::SchemaInvariant(
                                "Blob pending maintenance row has wrong evidence",
                            )));
                        };
                        validate_maintenance_pending_source(
                            &row.key,
                            &row.value,
                            evidence,
                            self.blob_depot_owner_binding,
                        )?;
                    }
                    _ => unreachable!("bounded composite page emits known tags"),
                },
                BlobMaintenanceClass::InvalidPendingWork => match row.position[0] {
                    MAINTENANCE_PRIMARY_SOURCE_TAG => {
                        let MaintenanceEvidence::Pending(evidence) = &row.evidence else {
                            return Err(blob_error(BlobStoreError::SchemaInvariant(
                                "Blob pending maintenance row has wrong evidence",
                            )));
                        };
                        validate_maintenance_pending_source(
                            &row.key,
                            &row.value,
                            evidence,
                            self.blob_depot_owner_binding,
                        )?;
                    }
                    MAINTENANCE_SECONDARY_SOURCE_TAG => {
                        let MaintenanceEvidence::Carrier(evidence) = &row.evidence else {
                            return Err(blob_error(BlobStoreError::SchemaInvariant(
                                "Blob carrier maintenance row has wrong evidence",
                            )));
                        };
                        validate_maintenance_carrier_prefix(
                            &row.key,
                            &row.value,
                            evidence,
                            self.blob_depot_owner_binding,
                        )?;
                    }
                    _ => unreachable!("bounded composite page emits known tags"),
                },
                BlobMaintenanceClass::UnreferencedLocalImportStaging
                | BlobMaintenanceClass::UnreferencedCompletedVariants => {
                    let MaintenanceEvidence::Import(evidence) = &row.evidence else {
                        return Err(blob_error(BlobStoreError::SchemaInvariant(
                            "Blob import maintenance row has wrong evidence",
                        )));
                    };
                    let import = depot::maintenance_import_projection(&row.key, &row.value)?;
                    lifecycle::validate_maintenance_lineage_evidence(
                        import.physical_lineage,
                        self.blob_depot_owner_binding,
                        &evidence.lineage,
                    )?;
                    if let Some(reference) = evidence.reference.as_ref() {
                        if reference.key.len() != 65
                            || !reference.key.starts_with(import.variant_id.as_bytes())
                            || !reference.value.is_empty()
                        {
                            return Err(blob_error(BlobStoreError::SchemaInvariant(
                                "Blob variant reference is not canonical",
                            )));
                        }
                        lifecycle::VariantReferenceOwner::decode(&reference.key[32..33])
                            .map_err(StoreError::Blob)?;
                    } else {
                        match (cursor.class, import.finalized) {
                            (BlobMaintenanceClass::UnreferencedLocalImportStaging, false) => {
                                candidates.push(BlobMaintenanceCandidate::UnreferencedLocalImport {
                                    staging_variant: import.variant_id,
                                })
                            }
                            (BlobMaintenanceClass::UnreferencedCompletedVariants, true) => {
                                candidates.push(
                                    BlobMaintenanceCandidate::UnreferencedCompletedVariant {
                                        variant: import.variant_id,
                                    },
                                )
                            }
                            _ => {}
                        }
                    }
                }
                BlobMaintenanceClass::ExpiredRetirementRecords => {
                    let MaintenanceEvidence::Operation { publication } = &row.evidence else {
                        return Err(blob_error(BlobStoreError::SchemaInvariant(
                            "Blob operation maintenance row has wrong evidence",
                        )));
                    };
                    validate_maintenance_operation(&row.key, &row.value, publication)?;
                }
                BlobMaintenanceClass::ManifestBackedPhysicalDeletion => {}
            }
        }

        let awaiting_later_handler = !candidates.is_empty();
        let next_position = if awaiting_later_handler {
            cursor.position.as_deref()
        } else if let Some(last) = page.rows.last() {
            Some(last.position.as_slice())
        } else if page.complete {
            None
        } else {
            cursor.position.as_deref()
        };
        lifecycle::advance_maintenance_cursor(&write, cursor.class, next_position)?;
        let progress = BlobMaintenanceProgress {
            class: cursor.class,
            rows_examined: page.rows_examined,
            files_examined: 0,
            bytes_examined: page.bytes,
            candidates,
            class_has_more_work: !page.complete || awaiting_later_handler,
            awaiting_later_handler,
        };
        write.commit()?;
        Ok(progress)
    }
}

fn validate_blob_reservation(
    reservation: &BlobReservation,
    prepared: &PreparedBlobPublication,
) -> Result<(), StoreError> {
    let header = &prepared.header;
    if header.stamp.dot.publisher != reservation.publisher
        || header.stamp.dot.counter != reservation.counter
        || header.topic != reservation.topic
        || header.scope != reservation.scope
        || header.stamp.context != reservation.context
    {
        return Err(blob_error(BlobStoreError::InvalidPublication(
            "sealed Blob does not match its durable reservation",
        )));
    }
    Ok(())
}

fn validate_blob_publication_intent(
    intent: &BlobPublicationIntent,
    prepared: &PreparedBlobPublication,
) -> Result<(), StoreError> {
    if prepared.header.stamp.dot.publisher != intent.publisher
        || prepared.header.topic != intent.topic
        || prepared.header.scope != intent.scope
        || prepared.header.priority != intent.priority
        || prepared.blob_id != intent.blob_id
    {
        return Err(blob_error(BlobStoreError::OperationConflict));
    }
    Ok(())
}

fn enforce_blob_policy_write(
    write: &redb::WriteTransaction,
    authority: NodeId,
    expected: &ControlPolicySnapshot,
    header: &EnvelopeHeader,
) -> Result<(), StoreError> {
    require_control_policy_write(write, authority, expected)?;
    let publisher = header.stamp.dot.publisher;
    if control_principal_revoked_write(write, publisher)? {
        return Err(blob_error(BlobStoreError::PublisherRevoked(publisher)));
    }
    let current_epoch = write
        .open_table(CONTROL_SCOPE_EPOCHS)?
        .get(header.scope.as_str())?
        .map(|value| decode_scope_epoch_index(value.value()))
        .transpose()?
        .map_or(1, |(epoch, _)| epoch);
    if header.key_epoch < current_epoch {
        return Err(blob_error(BlobStoreError::KeyEpochStale {
            current: current_epoch,
            received: header.key_epoch,
        }));
    }
    if header.key_epoch > current_epoch {
        return Err(blob_error(BlobStoreError::KeyEpochNotActive {
            current: current_epoch,
            received: header.key_epoch,
        }));
    }
    Ok(())
}

fn enforce_blob_policy_read(
    read: &redb::ReadTransaction,
    authority: NodeId,
    expected: &ControlPolicySnapshot,
    header: &EnvelopeHeader,
) -> Result<(), StoreError> {
    require_control_policy_read(read, authority, expected)?;
    let publisher = header.stamp.dot.publisher;
    if control_principal_revoked_read(read, publisher)? {
        return Err(blob_error(BlobStoreError::PublisherRevoked(publisher)));
    }
    let current_epoch = read
        .open_table(CONTROL_SCOPE_EPOCHS)?
        .get(header.scope.as_str())?
        .map(|value| decode_scope_epoch_index(value.value()))
        .transpose()?
        .map_or(1, |(epoch, _)| epoch);
    if header.key_epoch < current_epoch {
        return Err(blob_error(BlobStoreError::KeyEpochStale {
            current: current_epoch,
            received: header.key_epoch,
        }));
    }
    if header.key_epoch > current_epoch {
        return Err(blob_error(BlobStoreError::KeyEpochNotActive {
            current: current_epoch,
            received: header.key_epoch,
        }));
    }
    Ok(())
}

fn blob_header_is_current_read(
    read: &redb::ReadTransaction,
    header: &EnvelopeHeader,
) -> Result<bool, StoreError> {
    if control_principal_revoked_read(read, header.stamp.dot.publisher)? {
        return Ok(false);
    }
    let current_epoch = read
        .open_table(CONTROL_SCOPE_EPOCHS)?
        .get(header.scope.as_str())?
        .map(|value| decode_scope_epoch_index(value.value()))
        .transpose()?
        .map_or(1, |(epoch, _)| epoch);
    Ok(header.key_epoch == current_epoch)
}

fn durable_blob_source_shape_read(
    read: &redb::ReadTransaction,
    metadata: &BlobMetadata,
    completed: bool,
) -> Result<depot::BlobSourceShape, StoreError> {
    let route = metadata.header.blob_route.ok_or_else(|| {
        blob_error(BlobStoreError::SchemaInvariant(
            "retained Blob source is missing its authenticated route commitment",
        ))
    })?;
    let physical_lineage = metadata
        .physical_lineage
        .ok_or_else(|| blob_error(BlobStoreError::PhysicalLineageMigrationRequired))?;
    depot::blob_source_shape_read(
        read,
        metadata.variant_id,
        metadata.blob_id,
        metadata.header.key_epoch,
        physical_lineage,
        metadata.manifest_digest,
        route.chunk_count(),
        completed,
    )
}

fn require_blob_apply_capacity_read(
    read: &redb::ReadTransaction,
    limits: StoreLimits,
    metadata: &BlobMetadata,
    incoming: u64,
) -> Result<(), StoreError> {
    let frontier_prefix = event_domain_prefix(&metadata.header.topic, &metadata.header.scope)?;
    let frontier_upper = blob_content_prefix_upper_bound(&frontier_prefix)?;
    let frontier = read.open_table(CAUSAL_FRONTIER)?;
    let mut direct_publishers = 0usize;
    let mut incoming_present = false;
    for row in frontier.range::<&[u8]>((
        std::ops::Bound::<&[u8]>::Included(frontier_prefix.as_slice()),
        std::ops::Bound::<&[u8]>::Excluded(frontier_upper.as_slice()),
    ))? {
        let (key, value) = row?;
        let key = key.value();
        if key.len() != frontier_prefix.len() + 32 || value.value() == 0 {
            return Err(StoreError::SemanticInvariant(
                "causal frontier contains an invalid row",
            ));
        }
        direct_publishers = direct_publishers
            .checked_add(1)
            .ok_or(StoreError::ItemCountAccountingOverflow)?;
        if key[frontier_prefix.len()..] == metadata.header.stamp.dot.publisher {
            incoming_present = true;
        }
    }
    if direct_publishers > MAX_CAUSAL_CONTEXT_ENTRIES {
        return Err(StoreError::SemanticInvariant(
            "causal frontier exceeds the proven context bound",
        ));
    }
    if !incoming_present && direct_publishers == MAX_CAUSAL_CONTEXT_ENTRIES {
        return Err(blob_error(BlobStoreError::CausalFrontierLimitExceeded {
            current: direct_publishers,
            limit: MAX_CAUSAL_CONTEXT_ENTRIES,
        }));
    }

    let content_prefix = blob_content_prefix(
        &metadata.header.topic,
        &metadata.header.scope,
        metadata.blob_id,
    )?;
    let content_upper = blob_content_prefix_upper_bound(&content_prefix)?;
    let content = read.open_table(BLOB_CONTENT_INDEX)?;
    let mut publication_count = 0usize;
    for row in content.range::<&[u8]>((
        std::ops::Bound::<&[u8]>::Included(content_prefix.as_slice()),
        std::ops::Bound::<&[u8]>::Excluded(content_upper.as_slice()),
    ))? {
        let _ = row?;
        #[cfg(test)]
        TEST_BLOB_CAPACITY_CONTENT_ROWS_VISITED
            .with(|count| count.set(count.get().saturating_add(1)));
        publication_count = publication_count
            .checked_add(1)
            .ok_or(StoreError::ItemCountAccountingOverflow)?;
        if publication_count >= MAX_BLOB_PUBLICATIONS_PER_CONTENT {
            break;
        }
    }
    if publication_count >= MAX_BLOB_PUBLICATIONS_PER_CONTENT {
        return Err(blob_error(BlobStoreError::PublicationLimitExceeded {
            current: publication_count,
            limit: MAX_BLOB_PUBLICATIONS_PER_CONTENT,
        }));
    }

    let aggregate = read.open_table(METADATA)?;
    let total = aggregate_usage_from_metadata(&aggregate)?;
    if total
        .items
        .checked_add(1)
        .ok_or(StoreError::ItemCountAccountingOverflow)?
        > limits.max_items()
    {
        return Err(StoreError::ItemLimitExceeded {
            current: total.items,
            limit: limits.max_items(),
        });
    }
    if total
        .bytes
        .checked_add(incoming)
        .ok_or(StoreError::PayloadByteAccountingOverflow)?
        > limits.max_total_payload_bytes()
    {
        return Err(StoreError::PayloadByteLimitExceeded {
            current: total.bytes,
            incoming,
            limit: limits.max_total_payload_bytes(),
        });
    }
    let control = CustodyUsage {
        items: aggregate
            .get(CONTROL_ITEM_COUNT)?
            .map_or(0, |value| value.value()),
        bytes: aggregate
            .get(CONTROL_TOTAL_BYTES)?
            .map_or(0, |value| value.value())
            .checked_add(
                aggregate
                    .get(CONTROL_PUBLICATION_INTENT_TOTAL_BYTES)?
                    .map_or(0, |value| value.value()),
            )
            .ok_or(StoreError::PayloadByteAccountingOverflow)?,
    };
    let tombstone_payload = custody::selected_tombstone_payload_usage_read(read)?;
    let tombstone = CustodyUsage {
        items: tombstone_payload
            .items
            .checked_add(
                aggregate
                    .get(EVENT_TOMBSTONE_OPERATION_COUNT)?
                    .map_or(0, |value| value.value()),
            )
            .ok_or(StoreError::ItemCountAccountingOverflow)?,
        bytes: tombstone_payload
            .bytes
            .checked_add(
                aggregate
                    .get(EVENT_TOMBSTONE_OPERATION_TOTAL_BYTES)?
                    .map_or(0, |value| value.value()),
            )
            .ok_or(StoreError::PayloadByteAccountingOverflow)?,
    };
    let ordinary = CustodyUsage {
        items: total
            .items
            .checked_sub(control.items)
            .and_then(|value| value.checked_sub(tombstone.items))
            .ok_or(StoreError::SemanticInvariant(
                "classified aggregate item accounting exceeds total usage",
            ))?,
        bytes: total
            .bytes
            .checked_sub(control.bytes)
            .and_then(|value| value.checked_sub(tombstone.bytes))
            .ok_or(StoreError::SemanticInvariant(
                "classified aggregate byte accounting exceeds total usage",
            ))?,
    };
    let (item_reserve, byte_reserve) = custody::custody_emergency_reserve(limits);
    let max_items = limits
        .max_items()
        .checked_sub(item_reserve)
        .ok_or(StoreError::ItemCountAccountingOverflow)?;
    if ordinary
        .items
        .checked_add(1)
        .ok_or(StoreError::ItemCountAccountingOverflow)?
        > max_items
    {
        return Err(StoreError::ItemLimitExceeded {
            current: ordinary.items,
            limit: max_items,
        });
    }
    let max_bytes = limits
        .max_total_payload_bytes()
        .checked_sub(byte_reserve)
        .ok_or(StoreError::PayloadByteAccountingOverflow)?;
    if ordinary
        .bytes
        .checked_add(incoming)
        .ok_or(StoreError::PayloadByteAccountingOverflow)?
        > max_bytes
    {
        return Err(StoreError::PayloadByteLimitExceeded {
            current: ordinary.bytes,
            incoming,
            limit: max_bytes,
        });
    }
    Ok(())
}

fn blob_source_projection(
    metadata: &BlobMetadata,
    sealed_len: u64,
    shape: depot::BlobSourceShape,
) -> Result<BlobSourceProjection, StoreError> {
    let route_lineage = metadata
        .route_lineage
        .ok_or_else(|| blob_error(BlobStoreError::PhysicalLineageMigrationRequired))?;
    let physical_lineage = metadata
        .physical_lineage
        .ok_or_else(|| blob_error(BlobStoreError::PhysicalLineageMigrationRequired))?;
    let route = metadata.header.blob_route.ok_or_else(|| {
        blob_error(BlobStoreError::SchemaInvariant(
            "retained Blob source is missing its authenticated route commitment",
        ))
    })?;
    let expected_chunks = shape
        .total_len
        .checked_add(u64::from(shape.chunk_size).saturating_sub(1))
        .filter(|_| shape.chunk_size != 0)
        .map(|bytes| bytes / u64::from(shape.chunk_size));
    if shape.total_len == 0
        || shape.chunk_size != SELECTED_BLOB_CHUNK_SIZE
        || shape.chunk_count == 0
        || shape.chunk_count != route.chunk_count()
        || expected_chunks != Some(shape.chunk_count)
    {
        return Err(blob_error(BlobStoreError::SchemaInvariant(
            "retained Blob source has a noncanonical durable content shape",
        )));
    }
    let encoded = encode_blob_metadata(metadata.clone())?;
    let mut digest = Sha256::new();
    digest.update(BLOB_SOURCE_PROJECTION_DOMAIN);
    digest.update(&encoded);
    digest.update(sealed_len.to_be_bytes());
    digest.update(shape.total_len.to_be_bytes());
    digest.update(shape.chunk_size.to_be_bytes());
    digest.update(shape.chunk_count.to_be_bytes());
    Ok(BlobSourceProjection {
        transfer_id: metadata.transfer_id,
        semantic_id: metadata.semantic_id,
        publisher: metadata.header.stamp.dot.publisher,
        topic: metadata.header.topic.clone(),
        scope: metadata.header.scope.clone(),
        epoch: metadata.header.key_epoch,
        sealed_len,
        route_lineage,
        physical_lineage,
        manifest_digest: metadata.manifest_digest,
        blob_id: metadata.blob_id,
        total_len: shape.total_len,
        chunk_size: shape.chunk_size,
        chunk_count: shape.chunk_count,
        metadata_fingerprint: digest.finalize().into(),
    })
}

fn blob_replay_fence(
    metadata: &BlobMetadata,
    sealed: &[u8],
) -> Result<lifecycle::ReplayFence, StoreError> {
    let source_len =
        u64::try_from(sealed.len()).map_err(|_| StoreError::PayloadByteAccountingOverflow)?;
    let dot = metadata.header.stamp.dot;
    Ok(lifecycle::ReplayFence::new(
        dot.publisher,
        dot.counter,
        metadata.semantic_id,
        metadata.transfer_id,
        source_len,
        Sha256::digest(sealed).into(),
    ))
}

fn insert_blob_operation(
    write: &redb::WriteTransaction,
    limits: StoreLimits,
    request: &BlobOperationRequest<'_>,
    transfer_id: BlobTransferId,
) -> Result<(), StoreError> {
    let encoded = encode_blob_operation_record(BlobOperationRecord {
        transfer_id,
        intent_digest: request.intent.digest(),
    });
    let incoming = request
        .operation
        .as_bytes()
        .len()
        .checked_add(encoded.len())
        .and_then(|value| u64::try_from(value).ok())
        .ok_or(StoreError::PayloadByteAccountingOverflow)?;
    let mut metadata = write.open_table(METADATA)?;
    let current_count = metadata
        .get(BLOB_OPERATION_COUNT)?
        .map_or(0, |value| value.value());
    let next_count = current_count
        .checked_add(1)
        .ok_or(StoreError::ItemCountAccountingOverflow)?;
    if next_count > MAX_BLOB_OPERATIONS {
        return Err(blob_error(BlobStoreError::OperationLimitExceeded {
            current: current_count,
            limit: MAX_BLOB_OPERATIONS,
        }));
    }
    let current_bytes = metadata
        .get(BLOB_OPERATION_TOTAL_BYTES)?
        .map_or(0, |value| value.value());
    let next_bytes = current_bytes
        .checked_add(incoming)
        .ok_or(StoreError::PayloadByteAccountingOverflow)?;
    if next_bytes > MAX_BLOB_OPERATION_BYTES {
        return Err(blob_error(BlobStoreError::OperationByteLimitExceeded {
            current: current_bytes,
            incoming,
            limit: MAX_BLOB_OPERATION_BYTES,
        }));
    }
    require_ordinary_aggregate_capacity(write, &metadata, limits, 1, incoming)?;
    metadata.insert(BLOB_OPERATION_COUNT, next_count)?;
    metadata.insert(BLOB_OPERATION_TOTAL_BYTES, next_bytes)?;
    drop(metadata);
    write
        .open_table(BLOB_OPERATIONS)?
        .insert(request.operation.as_bytes(), encoded.as_slice())?;
    Ok(())
}

fn blob_read_plan_read(
    read: &redb::ReadTransaction,
    policy: ControlPolicySnapshot,
    topic: &Topic,
    scope: &Scope,
    blob_id: BlobId,
) -> Result<BlobReadPlan, StoreError> {
    let prefix = blob_content_prefix(topic, scope, blob_id)?;
    let upper = blob_content_prefix_upper_bound(&prefix)?;
    let content = read.open_table(BLOB_CONTENT_INDEX)?;
    let mut rows = Vec::new();
    for row in content.range::<&[u8]>((
        std::ops::Bound::<&[u8]>::Included(prefix.as_slice()),
        std::ops::Bound::<&[u8]>::Excluded(upper.as_slice()),
    ))? {
        let (key, value) = row?;
        #[cfg(test)]
        TEST_BLOB_READ_PLAN_ROWS_VISITED.with(|count| count.set(count.get().saturating_add(1)));
        if rows.len() >= MAX_BLOB_PUBLICATIONS_PER_CONTENT {
            return Err(blob_error(BlobStoreError::PublicationLimitExceeded {
                current: rows.len() + 1,
                limit: MAX_BLOB_PUBLICATIONS_PER_CONTENT,
            }));
        }
        let transfer = parse_blob_transfer_id("Blob content index", value.value())?;
        rows.push(blob_read_candidate_projection_read(
            read,
            transfer,
            key.value(),
        )?);
    }
    rows.sort_by_key(|candidate| candidate.projection.semantic_id);
    let current_epoch = read
        .open_table(CONTROL_SCOPE_EPOCHS)?
        .get(scope.as_str())?
        .map(|value| decode_scope_epoch_index(value.value()))
        .transpose()?
        .map_or(1, |(epoch, _)| epoch);
    let mut active = Vec::with_capacity(rows.len());
    for candidate in &rows {
        active.push(
            candidate.projection.epoch == current_epoch
                && !control_principal_revoked_read(read, candidate.projection.publisher)?,
        );
    }
    let selected = rows
        .iter()
        .zip(&active)
        .filter(|(_, active)| **active)
        .map(|(candidate, _)| candidate.projection.semantic_id)
        .max();
    let candidates = rows
        .into_iter()
        .zip(active)
        .map(|(mut candidate, active)| {
            candidate.disposition = if !active {
                None
            } else if Some(candidate.projection.semantic_id) == selected {
                Some(BlobPublicationDisposition::Current)
            } else {
                Some(BlobPublicationDisposition::Alternate)
            };
            candidate
        })
        .collect();
    Ok(BlobReadPlan {
        control_policy: policy,
        topic: topic.clone(),
        scope: scope.clone(),
        blob_id,
        candidates,
    })
}

fn blob_read_candidate_projection_read(
    read: &redb::ReadTransaction,
    transfer_id: BlobTransferId,
    indexed_content_key: &[u8],
) -> Result<BlobReadCandidate, StoreError> {
    let metadata = read
        .open_table(BLOB_PUBLICATIONS)?
        .get(transfer_id.as_bytes().as_slice())?
        .map(|value| decode_blob_metadata(value.value()))
        .transpose()?
        .ok_or_else(|| {
            blob_error(BlobStoreError::SchemaInvariant(
                "Blob content index points to a missing publication",
            ))
        })?;
    if metadata.transfer_id != transfer_id
        || blob_content_key(
            &metadata.header.topic,
            &metadata.header.scope,
            metadata.blob_id,
            metadata.semantic_id,
        )? != indexed_content_key
    {
        return Err(blob_error(BlobStoreError::SchemaInvariant(
            "Blob content index disagrees with its exact publication",
        )));
    }
    let sealed_len = {
        let bytes = read.open_table(BLOB_BYTES)?;
        let sealed = bytes
            .get(transfer_id.as_bytes().as_slice())?
            .ok_or_else(|| {
                blob_error(BlobStoreError::SchemaInvariant(
                    "Blob publication is missing exact source bytes",
                ))
            })?;
        u64::try_from(sealed.value().len())
            .map_err(|_| StoreError::PayloadByteAccountingOverflow)?
    };
    let acceptance_marker = read
        .open_table(BLOB_ACCEPTANCE_MARKERS)?
        .get(transfer_id.as_bytes().as_slice())?
        .map(|value| value.value())
        .ok_or_else(|| {
            blob_error(BlobStoreError::SchemaInvariant(
                "Blob publication is missing its acceptance marker",
            ))
        })?;
    if acceptance_marker == 0 {
        return Err(blob_error(BlobStoreError::SchemaInvariant(
            "Blob publication has an invalid acceptance marker",
        )));
    }
    let shape = durable_blob_source_shape_read(read, &metadata, true)?;
    Ok(BlobReadCandidate {
        projection: blob_source_projection(&metadata, sealed_len, shape)?,
        acceptance_marker,
        disposition: None,
    })
}

fn completed_blob_range_source_snapshot_read(
    read: &redb::ReadTransaction,
    transfer_id: BlobTransferId,
) -> Result<Option<CompletedBlobRangeSourceSnapshot>, StoreError> {
    let Some(metadata) = read
        .open_table(BLOB_PUBLICATIONS)?
        .get(transfer_id.as_bytes().as_slice())?
        .map(|value| decode_blob_metadata(value.value()))
        .transpose()?
    else {
        return Ok(None);
    };
    if metadata.transfer_id != transfer_id {
        return Err(blob_error(BlobStoreError::CompletionMismatch));
    }
    let sealed_len = {
        let bytes = read.open_table(BLOB_BYTES)?;
        let sealed = bytes
            .get(transfer_id.as_bytes().as_slice())?
            .ok_or_else(|| blob_error(BlobStoreError::CompletionMismatch))?;
        if BlobTransferId::new(Sha256::digest(sealed.value()).into()) != transfer_id {
            return Err(blob_error(BlobStoreError::CompletionMismatch));
        }
        u64::try_from(sealed.value().len())
            .map_err(|_| StoreError::PayloadByteAccountingOverflow)?
    };
    let acceptance_marker = read
        .open_table(BLOB_ACCEPTANCE_MARKERS)?
        .get(transfer_id.as_bytes().as_slice())?
        .map(|value| value.value())
        .filter(|marker| *marker != 0)
        .ok_or_else(|| blob_error(BlobStoreError::CompletionMismatch))?;
    let shape = durable_blob_source_shape_read(read, &metadata, true)?;
    Ok(Some(CompletedBlobRangeSourceSnapshot {
        projection: blob_source_projection(&metadata, sealed_len, shape)?,
        metadata,
        acceptance_marker,
    }))
}

fn load_blob_from_read(
    read: &redb::ReadTransaction,
    transfer_id: BlobTransferId,
) -> Result<Option<StoredBlob>, StoreError> {
    let metadata = read
        .open_table(BLOB_PUBLICATIONS)?
        .get(transfer_id.as_bytes().as_slice())?
        .map(|value| decode_blob_metadata(value.value()))
        .transpose()?;
    metadata
        .map(|metadata| {
            let sealed = read
                .open_table(BLOB_BYTES)?
                .get(transfer_id.as_bytes().as_slice())?
                .map(|value| {
                    #[cfg(test)]
                    TEST_BLOB_SOURCE_BYTES_LOADED
                        .with(|count| count.set(count.get().saturating_add(1)));
                    value.value().to_vec()
                })
                .ok_or_else(|| {
                    blob_error(BlobStoreError::SchemaInvariant(
                        "Blob publication is missing exact source bytes",
                    ))
                })?;
            let marker = read
                .open_table(BLOB_ACCEPTANCE_MARKERS)?
                .get(transfer_id.as_bytes().as_slice())?
                .map(|value| value.value())
                .ok_or_else(|| {
                    blob_error(BlobStoreError::SchemaInvariant(
                        "Blob publication is missing its acceptance marker",
                    ))
                })?;
            Ok(StoredBlob {
                transfer_id,
                semantic_id: metadata.semantic_id,
                blob_id: metadata.blob_id,
                variant_id: metadata.variant_id,
                manifest_digest: metadata.manifest_digest,
                route_lineage: metadata.route_lineage,
                physical_lineage: metadata.physical_lineage,
                header: metadata.header,
                sealed,
                acceptance_marker: marker,
            })
        })
        .transpose()
}

fn load_blob_from_write(
    write: &redb::WriteTransaction,
    transfer_id: BlobTransferId,
) -> Result<Option<StoredBlob>, StoreError> {
    let metadata = write
        .open_table(BLOB_PUBLICATIONS)?
        .get(transfer_id.as_bytes().as_slice())?
        .map(|value| decode_blob_metadata(value.value()))
        .transpose()?;
    let blob = metadata
        .map(|metadata| -> Result<StoredBlob, StoreError> {
            let sealed = write
                .open_table(BLOB_BYTES)?
                .get(transfer_id.as_bytes().as_slice())?
                .map(|value| value.value().to_vec())
                .ok_or_else(|| {
                    blob_error(BlobStoreError::SchemaInvariant(
                        "Blob publication is missing exact source bytes",
                    ))
                })?;
            let marker = write
                .open_table(BLOB_ACCEPTANCE_MARKERS)?
                .get(transfer_id.as_bytes().as_slice())?
                .map(|value| value.value())
                .ok_or_else(|| {
                    blob_error(BlobStoreError::SchemaInvariant(
                        "Blob publication is missing its acceptance marker",
                    ))
                })?;
            Ok(StoredBlob {
                transfer_id,
                semantic_id: metadata.semantic_id,
                blob_id: metadata.blob_id,
                variant_id: metadata.variant_id,
                manifest_digest: metadata.manifest_digest,
                route_lineage: metadata.route_lineage,
                physical_lineage: metadata.physical_lineage,
                header: metadata.header,
                sealed,
                acceptance_marker: marker,
            })
        })
        .transpose()?;
    if let Some(blob) = blob.as_ref() {
        require_blob_causal_authority_write(write, blob)?;
    }
    Ok(blob)
}

/// Point-checks the exact causal authority required by one live publication.
/// High-water and frontier values may be ahead because later publications
/// advance them, but neither may be absent or behind the publication's dot.
fn require_blob_causal_authority_write(
    write: &redb::WriteTransaction,
    blob: &StoredBlob,
) -> Result<(), StoreError> {
    let dot = blob.header.stamp.dot;
    let dot_key = accepted_dot_key(dot);
    let accepted = write
        .open_table(ACCEPTED_DOTS)?
        .get(dot_key.as_slice())?
        .map(|value| parse_digest32("accepted dot table", value.value()))
        .transpose()?
        .ok_or_else(|| {
            blob_error(BlobStoreError::SchemaInvariant(
                "Blob publication is missing its accepted-dot authority",
            ))
        })?;
    if accepted != *blob.semantic_id.as_bytes() {
        return Err(blob_error(BlobStoreError::SchemaInvariant(
            "Blob publication accepted-dot authority names another semantic item",
        )));
    }
    if write
        .open_table(PUBLISHER_HIGH_WATER)?
        .get(dot.publisher.as_slice())?
        .map_or(0, |value| value.value())
        < dot.counter
    {
        return Err(blob_error(BlobStoreError::SchemaInvariant(
            "Blob publication publisher high-water is missing or behind",
        )));
    }
    let frontier_key = causal_frontier_key(
        &blob.header.topic,
        &blob.header.scope,
        blob.header.stamp.dot.publisher,
    )?;
    if write
        .open_table(CAUSAL_FRONTIER)?
        .get(frontier_key.as_slice())?
        .map_or(0, |value| value.value())
        < dot.counter
    {
        return Err(blob_error(BlobStoreError::SchemaInvariant(
            "Blob publication causal frontier is missing or behind",
        )));
    }
    Ok(())
}

/// Compact publication identity used by the durable application-delivery ledger.
///
/// This deliberately excludes source bytes and depot/provider details.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct BlobSubscriptionIdentity {
    pub transfer_id: BlobTransferId,
    pub semantic_id: BlobSemanticId,
    pub topic: Topic,
    pub scope: Scope,
    pub acceptance_marker: u64,
}

fn blob_subscription_identity_from_metadata(
    metadata: &BlobMetadata,
    acceptance_marker: u64,
) -> Result<BlobSubscriptionIdentity, StoreError> {
    if acceptance_marker == 0 {
        return Err(blob_error(BlobStoreError::SchemaInvariant(
            "Blob subscription identity has a zero acceptance marker",
        )));
    }
    Ok(BlobSubscriptionIdentity {
        transfer_id: metadata.transfer_id,
        semantic_id: metadata.semantic_id,
        topic: metadata.header.topic.clone(),
        scope: metadata.header.scope.clone(),
        acceptance_marker,
    })
}

pub(crate) fn blob_subscription_identity_for_transfer_write(
    write: &redb::WriteTransaction,
    transfer_id: BlobTransferId,
) -> Result<Option<BlobSubscriptionIdentity>, StoreError> {
    let Some(metadata) = write
        .open_table(BLOB_PUBLICATIONS)?
        .get(transfer_id.as_bytes().as_slice())?
        .map(|value| decode_blob_metadata(value.value()))
        .transpose()?
    else {
        return Ok(None);
    };
    if metadata.transfer_id != transfer_id {
        return Err(blob_error(BlobStoreError::SchemaInvariant(
            "Blob subscription identity differs from its publication key",
        )));
    }
    let marker = write
        .open_table(BLOB_ACCEPTANCE_MARKERS)?
        .get(transfer_id.as_bytes().as_slice())?
        .map(|value| value.value())
        .ok_or_else(|| {
            blob_error(BlobStoreError::SchemaInvariant(
                "Blob subscription identity is missing its acceptance marker",
            ))
        })?;
    if write
        .open_table(BLOB_SEMANTIC_ITEMS)?
        .get(metadata.semantic_id.as_bytes().as_slice())?
        .map(|value| value.value().to_vec())
        .as_deref()
        != Some(transfer_id.as_bytes().as_slice())
    {
        return Err(blob_error(BlobStoreError::SchemaInvariant(
            "Blob subscription identity differs from its semantic index",
        )));
    }
    Ok(Some(blob_subscription_identity_from_metadata(
        &metadata, marker,
    )?))
}

pub(crate) fn blob_subscription_identity_write(
    write: &redb::WriteTransaction,
    semantic_id: BlobSemanticId,
) -> Result<Option<BlobSubscriptionIdentity>, StoreError> {
    let transfer = write
        .open_table(BLOB_SEMANTIC_ITEMS)?
        .get(semantic_id.as_bytes().as_slice())?
        .map(|value| parse_blob_transfer_id("Blob semantic item table", value.value()))
        .transpose()?;
    transfer
        .map(|transfer| blob_subscription_identity_for_transfer_write(write, transfer))
        .transpose()
        .map(Option::flatten)
}

pub(crate) fn blob_subscription_identity_read(
    read: &redb::ReadTransaction,
    semantic_id: BlobSemanticId,
) -> Result<Option<BlobSubscriptionIdentity>, StoreError> {
    let Some(transfer) = read
        .open_table(BLOB_SEMANTIC_ITEMS)?
        .get(semantic_id.as_bytes().as_slice())?
        .map(|value| parse_blob_transfer_id("Blob semantic item table", value.value()))
        .transpose()?
    else {
        return Ok(None);
    };
    let metadata = read
        .open_table(BLOB_PUBLICATIONS)?
        .get(transfer.as_bytes().as_slice())?
        .map(|value| decode_blob_metadata(value.value()))
        .transpose()?
        .ok_or_else(|| {
            blob_error(BlobStoreError::SchemaInvariant(
                "Blob semantic index points to a missing publication",
            ))
        })?;
    if metadata.transfer_id != transfer || metadata.semantic_id != semantic_id {
        return Err(blob_error(BlobStoreError::SchemaInvariant(
            "Blob semantic index differs from its publication",
        )));
    }
    let marker = read
        .open_table(BLOB_ACCEPTANCE_MARKERS)?
        .get(transfer.as_bytes().as_slice())?
        .map(|value| value.value())
        .ok_or_else(|| {
            blob_error(BlobStoreError::SchemaInvariant(
                "Blob subscription identity is missing its acceptance marker",
            ))
        })?;
    Ok(Some(blob_subscription_identity_from_metadata(
        &metadata, marker,
    )?))
}

pub(crate) fn blob_subscription_projection_read(
    read: &redb::ReadTransaction,
    transfer_id: BlobTransferId,
) -> Result<Option<(BlobSourceProjection, u64)>, StoreError> {
    let Some(metadata) = read
        .open_table(BLOB_PUBLICATIONS)?
        .get(transfer_id.as_bytes().as_slice())?
        .map(|value| decode_blob_metadata(value.value()))
        .transpose()?
    else {
        return Ok(None);
    };
    if metadata.transfer_id != transfer_id {
        return Err(blob_error(BlobStoreError::SchemaInvariant(
            "Blob subscription projection differs from its publication key",
        )));
    }
    let content_key = blob_content_key(
        &metadata.header.topic,
        &metadata.header.scope,
        metadata.blob_id,
        metadata.semantic_id,
    )?;
    if read
        .open_table(BLOB_CONTENT_INDEX)?
        .get(content_key.as_slice())?
        .map(|value| value.value().to_vec())
        .as_deref()
        != Some(transfer_id.as_bytes().as_slice())
    {
        return Err(blob_error(BlobStoreError::SchemaInvariant(
            "Blob subscription projection differs from its content index",
        )));
    }
    let candidate = blob_read_candidate_projection_read(read, transfer_id, &content_key)?;
    Ok(Some((candidate.projection, candidate.acceptance_marker)))
}

pub(crate) fn blob_subscription_projection_matches_write(
    write: &redb::WriteTransaction,
    transfer_id: BlobTransferId,
    acceptance_marker: u64,
    projection: &BlobSourceProjection,
) -> Result<bool, StoreError> {
    let Some(metadata) = write
        .open_table(BLOB_PUBLICATIONS)?
        .get(transfer_id.as_bytes().as_slice())?
        .map(|value| decode_blob_metadata(value.value()))
        .transpose()?
    else {
        return Ok(false);
    };
    if metadata.transfer_id != transfer_id {
        return Ok(false);
    }
    let Some(sealed_len) = write
        .open_table(BLOB_BYTES)?
        .get(transfer_id.as_bytes().as_slice())?
        .map(|value| u64::try_from(value.value().len()))
        .transpose()
        .map_err(|_| StoreError::PayloadByteAccountingOverflow)?
    else {
        return Ok(false);
    };
    if write
        .open_table(BLOB_SEMANTIC_ITEMS)?
        .get(metadata.semantic_id.as_bytes().as_slice())?
        .map(|value| value.value().to_vec())
        .as_deref()
        != Some(transfer_id.as_bytes().as_slice())
    {
        return Ok(false);
    }
    let content_key = blob_content_key(
        &metadata.header.topic,
        &metadata.header.scope,
        metadata.blob_id,
        metadata.semantic_id,
    )?;
    if write
        .open_table(BLOB_CONTENT_INDEX)?
        .get(content_key.as_slice())?
        .map(|value| value.value().to_vec())
        .as_deref()
        != Some(transfer_id.as_bytes().as_slice())
    {
        return Ok(false);
    }
    if write
        .open_table(BLOB_ACCEPTANCE_MARKERS)?
        .get(transfer_id.as_bytes().as_slice())?
        .map(|value| value.value())
        != Some(acceptance_marker)
    {
        return Ok(false);
    }
    let route = metadata.header.blob_route.ok_or_else(|| {
        blob_error(BlobStoreError::SchemaInvariant(
            "retained Blob source is missing its authenticated route commitment",
        ))
    })?;
    let physical_lineage = metadata
        .physical_lineage
        .ok_or_else(|| blob_error(BlobStoreError::PhysicalLineageMigrationRequired))?;
    let shape = depot::blob_source_shape_write(
        write,
        metadata.variant_id,
        metadata.blob_id,
        metadata.header.key_epoch,
        physical_lineage,
        metadata.manifest_digest,
        route.chunk_count(),
        true,
    )?;
    Ok(blob_source_projection(&metadata, sealed_len, shape)? == *projection)
}

pub(crate) fn blob_subscription_exact_source_matches_write(
    write: &redb::WriteTransaction,
    transfer_id: BlobTransferId,
) -> Result<bool, StoreError> {
    let bytes = write.open_table(BLOB_BYTES)?;
    let Some(sealed) = bytes.get(transfer_id.as_bytes().as_slice())? else {
        return Ok(false);
    };
    Ok(BlobTransferId::new(Sha256::digest(sealed.value()).into()) == transfer_id)
}

fn transfer_id_exists_outside_blob(
    write: &redb::WriteTransaction,
    id: &[u8; 32],
) -> Result<bool, StoreError> {
    Ok(write.open_table(EVENTS)?.get(id.as_slice())?.is_some()
        || write.open_table(STATES)?.get(id.as_slice())?.is_some()
        || write.open_table(RECORDS)?.get(id.as_slice())?.is_some()
        || write.open_table(ROUTE_CACHE)?.get(id.as_slice())?.is_some()
        || write
            .open_table(CONTROL_RECORDS)?
            .get(id.as_slice())?
            .is_some())
}

fn semantic_id_exists_outside_blob(
    write: &redb::WriteTransaction,
    id: &[u8; 32],
) -> Result<bool, StoreError> {
    if write
        .open_table(SEMANTIC_ITEMS)?
        .get(id.as_slice())?
        .is_some()
        || write
            .open_table(STATE_SEMANTIC_ITEMS)?
            .get(id.as_slice())?
            .is_some()
        || write
            .open_table(RECORD_SEMANTIC_ITEMS)?
            .get(id.as_slice())?
            .is_some()
    {
        return Ok(true);
    }
    if custody::retired_route_semantic_exists_write(write, id)? {
        return Ok(true);
    }
    for row in write.open_table(ROUTE_CACHE_CLAIMS)?.iter()? {
        let (_, claim) = row?;
        if decode_event_metadata(claim.value())?.semantic_id.as_bytes() == id {
            return Ok(true);
        }
    }
    Ok(false)
}

pub(crate) fn blob_schema_present_write(
    write: &redb::WriteTransaction,
) -> Result<bool, StoreError> {
    let tables = blob_table_names();
    if write
        .list_multimap_tables()?
        .any(|table| tables.contains(&table.name()))
    {
        return Err(blob_error(BlobStoreError::SchemaInvariant(
            "mission-scoped Blob schema has the wrong table kind",
        )));
    }
    let existing = write
        .list_tables()?
        .map(|table| table.name().to_owned())
        .collect::<BTreeSet<_>>();
    let legacy = legacy_blob_table_names();
    let legacy_present = legacy
        .iter()
        .filter(|table| existing.contains(**table))
        .count();
    let network = network_blob_table_names();
    let network_present = network
        .iter()
        .filter(|table| existing.contains(**table))
        .count();
    let metadata = write.open_table(METADATA)?;
    let global = blob_global_metadata_fields();
    let global_present = global
        .iter()
        .map(|field| metadata.get(*field).map(|value| value.is_some()))
        .collect::<Result<Vec<_>, _>>()?;
    drop(metadata);
    if legacy_present == 0 && network_present == 0 && global_present.iter().all(|present| !present)
    {
        lifecycle::require_blob_lifecycle_absent_write(write)?;
        return Ok(false);
    }
    if legacy_present != legacy.len()
        || !matches!(network_present, 0 | 4)
        || global_present.iter().any(|present| !present)
    {
        return Err(blob_error(BlobStoreError::SchemaInvariant(
            "mission-scoped Blob schema group is incomplete",
        )));
    }
    if network_present == 0 {
        initialize_blob_network_schema(write)?;
    }
    Ok(true)
}

pub(crate) fn audit_blob_tables_write(
    write: &redb::WriteTransaction,
    shared: &mut StateAuditSnapshot,
) -> Result<BlobAuditSnapshot, StoreError> {
    if !blob_schema_present_write(write)? {
        initialize_blob_schema(write)?;
    }
    let publications = write.open_table(BLOB_PUBLICATIONS)?;
    let bytes = write.open_table(BLOB_BYTES)?;
    let markers = write.open_table(BLOB_ACCEPTANCE_MARKERS)?;
    let semantic_items = write.open_table(BLOB_SEMANTIC_ITEMS)?;
    let content = write.open_table(BLOB_CONTENT_INDEX)?;
    let operations = write.open_table(BLOB_OPERATIONS)?;
    let accepted_dots = write.open_table(ACCEPTED_DOTS)?;
    let publisher_high = write.open_table(PUBLISHER_HIGH_WATER)?;
    let frontier = write.open_table(CAUSAL_FRONTIER)?;
    let mut stats = BlobStoreStats::default();
    let mut marker_values = BTreeSet::new();
    let mut expected_content = BTreeMap::new();
    let mut content_counts = BTreeMap::<Vec<u8>, usize>::new();

    for row in publications.iter()? {
        let (key, value) = row?;
        let transfer_id = parse_blob_transfer_id("Blob publication table", key.value())?;
        let publication = decode_blob_metadata(value.value())?;
        if publication.transfer_id != transfer_id {
            return Err(blob_error(BlobStoreError::SchemaInvariant(
                "Blob metadata transfer identity differs from its key",
            )));
        }
        let route = publication.header.blob_route.ok_or_else(|| {
            blob_error(BlobStoreError::SchemaInvariant(
                "accepted Blob publication is missing its route commitment",
            ))
        })?;
        depot::audit_publication_import_write(
            write,
            publication.variant_id,
            publication.blob_id,
            publication.header.key_epoch,
            publication.manifest_digest,
            route.chunk_count(),
            publication.physical_lineage,
        )?;
        if transfer_id_exists_outside_blob(write, transfer_id.as_bytes())? {
            return Err(StoreError::TransferNamespaceCollision {
                transfer_id: *transfer_id.as_bytes(),
            });
        }
        if semantic_id_exists_outside_blob(write, publication.semantic_id.as_bytes())? {
            return Err(StoreError::SemanticNamespaceCollision {
                semantic_id: *publication.semantic_id.as_bytes(),
            });
        }
        let exact = bytes.get(key.value())?.ok_or_else(|| {
            blob_error(BlobStoreError::SchemaInvariant(
                "Blob metadata is missing exact source bytes",
            ))
        })?;
        if BlobTransferId::new(Sha256::digest(exact.value()).into()) != transfer_id {
            return Err(blob_error(BlobStoreError::SchemaInvariant(
                "Blob source bytes fail exact transfer identity audit",
            )));
        }
        let marker = markers
            .get(key.value())?
            .map(|value| value.value())
            .ok_or_else(|| {
                blob_error(BlobStoreError::SchemaInvariant(
                    "Blob metadata is missing its acceptance marker",
                ))
            })?;
        if marker == 0 || !marker_values.insert(marker) {
            return Err(blob_error(BlobStoreError::SchemaInvariant(
                "Blob acceptance markers must be nonzero and unique",
            )));
        }
        let indexed = semantic_items
            .get(publication.semantic_id.as_bytes().as_slice())?
            .map(|value| parse_blob_transfer_id("Blob semantic item table", value.value()))
            .transpose()?
            .ok_or_else(|| {
                blob_error(BlobStoreError::SchemaInvariant(
                    "Blob publication is missing its semantic index",
                ))
            })?;
        if indexed != transfer_id {
            return Err(blob_error(BlobStoreError::SchemaInvariant(
                "Blob semantic index points to another publication",
            )));
        }
        let content_key = blob_content_key(
            &publication.header.topic,
            &publication.header.scope,
            publication.blob_id,
            publication.semantic_id,
        )?;
        if expected_content.insert(content_key, transfer_id).is_some() {
            return Err(blob_error(BlobStoreError::SchemaInvariant(
                "multiple Blob publications claim one content index key",
            )));
        }
        let content_prefix = blob_content_prefix(
            &publication.header.topic,
            &publication.header.scope,
            publication.blob_id,
        )?;
        let content_count = content_counts.entry(content_prefix).or_default();
        *content_count = content_count
            .checked_add(1)
            .ok_or(StoreError::ItemCountAccountingOverflow)?;
        if *content_count > MAX_BLOB_PUBLICATIONS_PER_CONTENT {
            return Err(blob_error(BlobStoreError::SchemaInvariant(
                "Blob content publication count exceeds its durable safety cap",
            )));
        }
        let dot = publication.header.stamp.dot;
        let dot_key = accepted_dot_key(dot).to_vec();
        if shared
            .expected_dots
            .insert(dot_key.clone(), *publication.semantic_id.as_bytes())
            .is_some()
        {
            return Err(blob_error(BlobStoreError::SchemaInvariant(
                "multiple semantic classes claim one accepted causal dot",
            )));
        }
        let accepted = accepted_dots
            .get(dot_key.as_slice())?
            .map(|value| parse_digest32("accepted dot table", value.value()))
            .transpose()?
            .ok_or_else(|| {
                blob_error(BlobStoreError::SchemaInvariant(
                    "Blob publication is missing its accepted-dot row",
                ))
            })?;
        if accepted != *publication.semantic_id.as_bytes() {
            return Err(blob_error(BlobStoreError::SchemaInvariant(
                "accepted-dot ledger points to another semantic publication",
            )));
        }
        let durable_high = publisher_high
            .get(dot.publisher.as_slice())?
            .map_or(0, |value| value.value());
        if durable_high < dot.counter {
            return Err(blob_error(BlobStoreError::SchemaInvariant(
                "publisher high-water is behind an accepted Blob dot",
            )));
        }
        shared
            .expected_publisher_high
            .entry(dot.publisher.to_vec())
            .and_modify(|current| *current = (*current).max(dot.counter))
            .or_insert(dot.counter);
        let frontier_key = causal_frontier_key(
            &publication.header.topic,
            &publication.header.scope,
            dot.publisher,
        )?;
        if frontier
            .get(frontier_key.as_slice())?
            .map_or(0, |value| value.value())
            < dot.counter
        {
            return Err(blob_error(BlobStoreError::SchemaInvariant(
                "causal frontier is behind an accepted Blob dot",
            )));
        }
        shared
            .expected_frontier
            .entry(frontier_key)
            .and_modify(|current| *current = (*current).max(dot.counter))
            .or_insert(dot.counter);
        shared
            .domain_publishers
            .entry(event_domain_prefix(
                &publication.header.topic,
                &publication.header.scope,
            )?)
            .or_default()
            .insert(dot.publisher);
        stats.publications = stats
            .publications
            .checked_add(1)
            .ok_or(StoreError::ItemCountAccountingOverflow)?;
        stats.total_sealed_bytes = stats
            .total_sealed_bytes
            .checked_add(
                u64::try_from(exact.value().len())
                    .map_err(|_| StoreError::PayloadByteAccountingOverflow)?,
            )
            .ok_or(StoreError::PayloadByteAccountingOverflow)?;
        stats.last_acceptance_marker = stats.last_acceptance_marker.max(marker);
    }
    if stats.last_acceptance_marker != stats.publications
        || marker_values.iter().copied().ne(1..=stats.publications)
    {
        return Err(blob_error(BlobStoreError::SchemaInvariant(
            "Blob acceptance markers are not a contiguous allocation history",
        )));
    }
    stats.acceptance_markers = markers.len()?;
    if bytes.len()? != stats.publications
        || markers.len()? != stats.publications
        || semantic_items.len()? != stats.publications
        || content.len()? != stats.publications
    {
        return Err(blob_error(BlobStoreError::SchemaInvariant(
            "Blob publication schema has missing or orphan rows",
        )));
    }
    for row in content.iter()? {
        let (key, value) = row?;
        let transfer = parse_blob_transfer_id("Blob content index", value.value())?;
        if expected_content.get(key.value()) != Some(&transfer) {
            return Err(blob_error(BlobStoreError::SchemaInvariant(
                "Blob content index contains an orphan or mismatched row",
            )));
        }
    }
    for row in operations.iter()? {
        let (key, value) = row?;
        BlobOperationKey::new(key.value().to_vec())?;
        let operation = decode_blob_operation_record(value.value())?;
        if publications
            .get(operation.transfer_id.as_bytes().as_slice())?
            .is_none()
        {
            return Err(blob_error(BlobStoreError::SchemaInvariant(
                "Blob operation points to a missing publication",
            )));
        }
        stats.operations = stats
            .operations
            .checked_add(1)
            .ok_or(StoreError::ItemCountAccountingOverflow)?;
        stats.operation_bytes = stats
            .operation_bytes
            .checked_add(
                key.value()
                    .len()
                    .checked_add(value.value().len())
                    .and_then(|value| u64::try_from(value).ok())
                    .ok_or(StoreError::PayloadByteAccountingOverflow)?,
            )
            .ok_or(StoreError::PayloadByteAccountingOverflow)?;
    }
    if stats.operations > MAX_BLOB_OPERATIONS || stats.operation_bytes > MAX_BLOB_OPERATION_BYTES {
        return Err(blob_error(BlobStoreError::SchemaInvariant(
            "Blob operation usage exceeds its durable safety caps",
        )));
    }
    let depot_stats = depot::audit_depot_metadata_write(write)?;
    stats.variants = depot_stats.variants;
    stats.finalized_variants = depot_stats.finalized_variants;
    stats.committed_chunks = depot_stats.committed_chunks;
    stats.committed_file_bytes = depot_stats.committed_file_bytes;
    stats.reserved_file_bytes = depot_stats.reserved_file_bytes;
    let network = audit_blob_network_tables_write_with_publications(
        write,
        read_mission_binding(write)?,
        &publications,
    )?;
    stats.pending_sources = network.pending_sources;
    stats.carrier_prefixes = network.carrier_prefixes;
    stats.network_staging_bytes = network.staging.bytes;
    stats.carrier_fetch_cursors = network.carrier_cursors;
    let mut metadata = write.open_table(METADATA)?;
    audit_or_initialize_counter(&mut metadata, BLOB_ITEM_COUNT, stats.publications)?;
    audit_or_initialize_counter(&mut metadata, BLOB_TOTAL_BYTES, stats.total_sealed_bytes)?;
    audit_or_initialize_counter(
        &mut metadata,
        LAST_BLOB_ACCEPTANCE_MARKER,
        stats.last_acceptance_marker,
    )?;
    audit_or_initialize_counter(&mut metadata, BLOB_OPERATION_COUNT, stats.operations)?;
    audit_or_initialize_counter(
        &mut metadata,
        BLOB_OPERATION_TOTAL_BYTES,
        stats.operation_bytes,
    )?;
    Ok(BlobAuditSnapshot { stats })
}

pub(crate) fn inspect_blob_tables_read(
    read: &redb::ReadTransaction,
) -> Result<BlobAuditSnapshot, StoreError> {
    let tables = blob_table_names();
    if read
        .list_multimap_tables()?
        .any(|table| tables.contains(&table.name()))
    {
        return Err(blob_error(BlobStoreError::SchemaInvariant(
            "mission-scoped Blob schema has the wrong table kind",
        )));
    }
    let existing = read
        .list_tables()?
        .map(|table| table.name().to_owned())
        .collect::<BTreeSet<_>>();
    let legacy = legacy_blob_table_names();
    let legacy_present = legacy
        .iter()
        .filter(|table| existing.contains(**table))
        .count();
    let network = network_blob_table_names();
    let network_present = network
        .iter()
        .filter(|table| existing.contains(**table))
        .count();
    let metadata = read.open_table(METADATA)?;
    let global = blob_global_metadata_fields();
    let global_present = global
        .iter()
        .map(|field| metadata.get(*field).map(|value| value.is_some()))
        .collect::<Result<Vec<_>, _>>()?;
    if legacy_present == 0 && network_present == 0 && global_present.iter().all(|present| !present)
    {
        lifecycle::require_blob_lifecycle_absent_read(read)?;
        return Ok(BlobAuditSnapshot::default());
    }
    if legacy_present != legacy.len()
        || !matches!(network_present, 0 | 4)
        || global_present.iter().any(|present| !present)
    {
        return Err(blob_error(BlobStoreError::SchemaInvariant(
            "mission-scoped Blob schema group is incomplete",
        )));
    }
    drop(metadata);

    // The read-only audit uses a temporary shared snapshot and verifies Blob
    // rows directly; the caller later checks the complete shared ledgers after
    // combining Event, State, Record, and Blob expectations.
    let publications = read.open_table(BLOB_PUBLICATIONS)?;
    let bytes = read.open_table(BLOB_BYTES)?;
    let markers = read.open_table(BLOB_ACCEPTANCE_MARKERS)?;
    let semantic = read.open_table(BLOB_SEMANTIC_ITEMS)?;
    let content = read.open_table(BLOB_CONTENT_INDEX)?;
    let operations = read.open_table(BLOB_OPERATIONS)?;
    let mut stats = BlobStoreStats::default();
    let mut marker_values = BTreeSet::new();
    let mut expected_content = BTreeMap::new();
    let mut content_counts = BTreeMap::<Vec<u8>, usize>::new();
    for row in publications.iter()? {
        let (key, value) = row?;
        let transfer = parse_blob_transfer_id("Blob publication table", key.value())?;
        let publication = decode_blob_metadata(value.value())?;
        if publication.transfer_id != transfer {
            return Err(blob_error(BlobStoreError::SchemaInvariant(
                "Blob metadata transfer identity differs from its key",
            )));
        }
        let route = publication.header.blob_route.ok_or_else(|| {
            blob_error(BlobStoreError::SchemaInvariant(
                "accepted Blob publication is missing its route commitment",
            ))
        })?;
        depot::audit_publication_import_read(
            read,
            publication.variant_id,
            publication.blob_id,
            publication.header.key_epoch,
            publication.manifest_digest,
            route.chunk_count(),
            publication.physical_lineage,
        )?;
        let exact = bytes.get(key.value())?.ok_or_else(|| {
            blob_error(BlobStoreError::SchemaInvariant(
                "Blob metadata is missing exact source bytes",
            ))
        })?;
        if BlobTransferId::new(Sha256::digest(exact.value()).into()) != transfer {
            return Err(blob_error(BlobStoreError::SchemaInvariant(
                "Blob source bytes fail exact transfer identity audit",
            )));
        }
        let marker = markers
            .get(key.value())?
            .map(|value| value.value())
            .ok_or_else(|| {
                blob_error(BlobStoreError::SchemaInvariant(
                    "Blob metadata is missing its acceptance marker",
                ))
            })?;
        if marker == 0 || !marker_values.insert(marker) {
            return Err(blob_error(BlobStoreError::SchemaInvariant(
                "Blob acceptance markers must be nonzero and unique",
            )));
        }
        let indexed = semantic
            .get(publication.semantic_id.as_bytes().as_slice())?
            .map(|value| parse_blob_transfer_id("Blob semantic item table", value.value()))
            .transpose()?
            .ok_or_else(|| {
                blob_error(BlobStoreError::SchemaInvariant(
                    "Blob publication is missing its semantic index",
                ))
            })?;
        if indexed != transfer {
            return Err(blob_error(BlobStoreError::SchemaInvariant(
                "Blob semantic index points to another publication",
            )));
        }
        expected_content.insert(
            blob_content_key(
                &publication.header.topic,
                &publication.header.scope,
                publication.blob_id,
                publication.semantic_id,
            )?,
            transfer,
        );
        let content_prefix = blob_content_prefix(
            &publication.header.topic,
            &publication.header.scope,
            publication.blob_id,
        )?;
        let content_count = content_counts.entry(content_prefix).or_default();
        *content_count = content_count
            .checked_add(1)
            .ok_or(StoreError::ItemCountAccountingOverflow)?;
        if *content_count > MAX_BLOB_PUBLICATIONS_PER_CONTENT {
            return Err(blob_error(BlobStoreError::SchemaInvariant(
                "Blob content publication count exceeds its durable safety cap",
            )));
        }
        stats.publications += 1;
        stats.total_sealed_bytes = stats
            .total_sealed_bytes
            .checked_add(
                u64::try_from(exact.value().len())
                    .map_err(|_| StoreError::PayloadByteAccountingOverflow)?,
            )
            .ok_or(StoreError::PayloadByteAccountingOverflow)?;
        stats.last_acceptance_marker = stats.last_acceptance_marker.max(marker);
    }
    stats.acceptance_markers = markers.len()?;
    if stats.last_acceptance_marker != stats.publications
        || marker_values.iter().copied().ne(1..=stats.publications)
        || bytes.len()? != stats.publications
        || markers.len()? != stats.publications
        || semantic.len()? != stats.publications
        || content.len()? != stats.publications
    {
        return Err(blob_error(BlobStoreError::SchemaInvariant(
            "Blob publication schema has missing, orphan, or noncontiguous rows",
        )));
    }
    for row in content.iter()? {
        let (key, value) = row?;
        let transfer = parse_blob_transfer_id("Blob content index", value.value())?;
        if expected_content.get(key.value()) != Some(&transfer) {
            return Err(blob_error(BlobStoreError::SchemaInvariant(
                "Blob content index contains an orphan or mismatched row",
            )));
        }
    }
    for row in operations.iter()? {
        let (key, value) = row?;
        BlobOperationKey::new(key.value().to_vec())?;
        let operation = decode_blob_operation_record(value.value())?;
        if publications
            .get(operation.transfer_id.as_bytes().as_slice())?
            .is_none()
        {
            return Err(blob_error(BlobStoreError::SchemaInvariant(
                "Blob operation points to a missing publication",
            )));
        }
        stats.operations += 1;
        stats.operation_bytes = stats
            .operation_bytes
            .checked_add(
                key.value()
                    .len()
                    .checked_add(value.value().len())
                    .and_then(|value| u64::try_from(value).ok())
                    .ok_or(StoreError::PayloadByteAccountingOverflow)?,
            )
            .ok_or(StoreError::PayloadByteAccountingOverflow)?;
    }
    if stats.operations > MAX_BLOB_OPERATIONS || stats.operation_bytes > MAX_BLOB_OPERATION_BYTES {
        return Err(blob_error(BlobStoreError::SchemaInvariant(
            "Blob operation usage exceeds its durable safety caps",
        )));
    }
    let depot_stats = depot::inspect_depot_metadata_read(read)?;
    stats.variants = depot_stats.variants;
    stats.finalized_variants = depot_stats.finalized_variants;
    stats.committed_chunks = depot_stats.committed_chunks;
    stats.committed_file_bytes = depot_stats.committed_file_bytes;
    stats.reserved_file_bytes = depot_stats.reserved_file_bytes;
    if network_present == network.len() {
        let network = inspect_blob_network_tables_read_with_publications(read, &publications)?;
        stats.pending_sources = network.pending_sources;
        stats.carrier_prefixes = network.carrier_prefixes;
        stats.network_staging_bytes = network.staging.bytes;
        stats.carrier_fetch_cursors = network.carrier_cursors;
    }
    let metadata = read.open_table(METADATA)?;
    for (field, reconstructed) in [
        (BLOB_ITEM_COUNT, stats.publications),
        (BLOB_TOTAL_BYTES, stats.total_sealed_bytes),
        (LAST_BLOB_ACCEPTANCE_MARKER, stats.last_acceptance_marker),
        (BLOB_OPERATION_COUNT, stats.operations),
        (BLOB_OPERATION_TOTAL_BYTES, stats.operation_bytes),
    ] {
        let durable = metadata
            .get(field)?
            .ok_or(StoreError::MissingAccountingMetadata { field })?
            .value();
        if durable != reconstructed {
            return Err(StoreError::AccountingMismatch {
                field,
                durable,
                reconstructed,
            });
        }
    }
    lifecycle::inspect_blob_lifecycle_read(read)?.apply_to_stats(&mut stats);
    Ok(BlobAuditSnapshot { stats })
}

/// Extends the exact shared causal-ledger reconstruction used by strict inspection.
pub(crate) fn inspect_blob_tables_read_with_shared(
    read: &redb::ReadTransaction,
    shared: &mut StateAuditSnapshot,
) -> Result<BlobAuditSnapshot, StoreError> {
    let snapshot = inspect_blob_tables_read(read)?;
    let table_names = read
        .list_tables()?
        .map(|table| table.name().to_owned())
        .collect::<BTreeSet<_>>();
    if !table_names.contains(BLOB_PUBLICATIONS.name()) {
        return Ok(snapshot);
    }
    let publications = read.open_table(BLOB_PUBLICATIONS)?;
    let accepted_dots = table_names
        .contains(ACCEPTED_DOTS.name())
        .then(|| read.open_table(ACCEPTED_DOTS))
        .transpose()?;
    let publisher_high = table_names
        .contains(PUBLISHER_HIGH_WATER.name())
        .then(|| read.open_table(PUBLISHER_HIGH_WATER))
        .transpose()?;
    let frontier = table_names
        .contains(CAUSAL_FRONTIER.name())
        .then(|| read.open_table(CAUSAL_FRONTIER))
        .transpose()?;
    let events = table_names
        .contains(EVENTS.name())
        .then(|| read.open_table(EVENTS))
        .transpose()?;
    let states = table_names
        .contains(STATES.name())
        .then(|| read.open_table(STATES))
        .transpose()?;
    let records = table_names
        .contains(RECORDS.name())
        .then(|| read.open_table(RECORDS))
        .transpose()?;
    let route_cache = table_names
        .contains(ROUTE_CACHE.name())
        .then(|| read.open_table(ROUTE_CACHE))
        .transpose()?;
    let controls = table_names
        .contains(CONTROL_RECORDS.name())
        .then(|| read.open_table(CONTROL_RECORDS))
        .transpose()?;
    let event_semantic = table_names
        .contains(SEMANTIC_ITEMS.name())
        .then(|| read.open_table(SEMANTIC_ITEMS))
        .transpose()?;
    let state_semantic = table_names
        .contains(STATE_SEMANTIC_ITEMS.name())
        .then(|| read.open_table(STATE_SEMANTIC_ITEMS))
        .transpose()?;
    let record_semantic = table_names
        .contains(RECORD_SEMANTIC_ITEMS.name())
        .then(|| read.open_table(RECORD_SEMANTIC_ITEMS))
        .transpose()?;
    let route_semantic_ids = if table_names.contains(ROUTE_CACHE_CLAIMS.name()) {
        read.open_table(ROUTE_CACHE_CLAIMS)?
            .iter()?
            .map(|row| {
                let (_, claim) = row?;
                Ok(*decode_event_metadata(claim.value())?.semantic_id.as_bytes())
            })
            .collect::<Result<BTreeSet<_>, StoreError>>()?
    } else {
        BTreeSet::new()
    };
    for row in publications.iter()? {
        let (key, value) = row?;
        let publication = decode_blob_metadata(value.value())?;
        if events
            .as_ref()
            .map(|table| table.get(key.value()))
            .transpose()?
            .flatten()
            .is_some()
            || states
                .as_ref()
                .map(|table| table.get(key.value()))
                .transpose()?
                .flatten()
                .is_some()
            || records
                .as_ref()
                .map(|table| table.get(key.value()))
                .transpose()?
                .flatten()
                .is_some()
            || route_cache
                .as_ref()
                .map(|table| table.get(key.value()))
                .transpose()?
                .flatten()
                .is_some()
            || controls
                .as_ref()
                .map(|table| table.get(key.value()))
                .transpose()?
                .flatten()
                .is_some()
        {
            return Err(StoreError::TransferNamespaceCollision {
                transfer_id: *publication.transfer_id.as_bytes(),
            });
        }
        let semantic = publication.semantic_id.as_bytes().as_slice();
        if event_semantic
            .as_ref()
            .map(|table| table.get(semantic))
            .transpose()?
            .flatten()
            .is_some()
            || state_semantic
                .as_ref()
                .map(|table| table.get(semantic))
                .transpose()?
                .flatten()
                .is_some()
            || record_semantic
                .as_ref()
                .map(|table| table.get(semantic))
                .transpose()?
                .flatten()
                .is_some()
            || route_semantic_ids.contains(publication.semantic_id.as_bytes())
        {
            return Err(StoreError::SemanticNamespaceCollision {
                semantic_id: *publication.semantic_id.as_bytes(),
            });
        }
        let dot = publication.header.stamp.dot;
        let dot_key = accepted_dot_key(dot).to_vec();
        if shared
            .expected_dots
            .insert(dot_key.clone(), *publication.semantic_id.as_bytes())
            .is_some()
        {
            return Err(blob_error(BlobStoreError::SchemaInvariant(
                "multiple semantic classes claim one accepted causal dot",
            )));
        }
        let accepted = accepted_dots
            .as_ref()
            .ok_or_else(|| {
                blob_error(BlobStoreError::SchemaInvariant(
                    "Blob publications exist without the shared accepted-dot ledger",
                ))
            })?
            .get(dot_key.as_slice())?
            .map(|value| parse_digest32("accepted dot table", value.value()))
            .transpose()?
            .ok_or_else(|| {
                blob_error(BlobStoreError::SchemaInvariant(
                    "Blob publication is missing its accepted-dot row",
                ))
            })?;
        if accepted != *publication.semantic_id.as_bytes() {
            return Err(blob_error(BlobStoreError::SchemaInvariant(
                "accepted-dot ledger points to another semantic publication",
            )));
        }
        if publisher_high
            .as_ref()
            .ok_or_else(|| {
                blob_error(BlobStoreError::SchemaInvariant(
                    "Blob publications exist without the shared publisher high-water ledger",
                ))
            })?
            .get(dot.publisher.as_slice())?
            .map_or(0, |value| value.value())
            < dot.counter
        {
            return Err(blob_error(BlobStoreError::SchemaInvariant(
                "publisher high-water is behind an accepted Blob dot",
            )));
        }
        shared
            .expected_publisher_high
            .entry(dot.publisher.to_vec())
            .and_modify(|current| *current = (*current).max(dot.counter))
            .or_insert(dot.counter);
        let frontier_key = causal_frontier_key(
            &publication.header.topic,
            &publication.header.scope,
            dot.publisher,
        )?;
        if frontier
            .as_ref()
            .ok_or_else(|| {
                blob_error(BlobStoreError::SchemaInvariant(
                    "Blob publications exist without the shared causal frontier",
                ))
            })?
            .get(frontier_key.as_slice())?
            .map_or(0, |value| value.value())
            < dot.counter
        {
            return Err(blob_error(BlobStoreError::SchemaInvariant(
                "causal frontier is behind an accepted Blob dot",
            )));
        }
        shared
            .expected_frontier
            .entry(frontier_key)
            .and_modify(|current| *current = (*current).max(dot.counter))
            .or_insert(dot.counter);
        shared
            .domain_publishers
            .entry(event_domain_prefix(
                &publication.header.topic,
                &publication.header.scope,
            )?)
            .or_default()
            .insert(dot.publisher);
    }
    Ok(snapshot)
}

fn initialize_blob_schema(write: &redb::WriteTransaction) -> Result<(), StoreError> {
    let _ = write.open_table(BLOB_PUBLICATIONS)?;
    let _ = write.open_table(BLOB_BYTES)?;
    let _ = write.open_table(BLOB_SEMANTIC_ITEMS)?;
    let _ = write.open_table(BLOB_CONTENT_INDEX)?;
    let _ = write.open_table(BLOB_ACCEPTANCE_MARKERS)?;
    let _ = write.open_table(BLOB_OPERATIONS)?;
    let _ = write.open_table(BLOB_IMPORTS)?;
    let _ = write.open_table(BLOB_CHUNKS)?;
    {
        let owner_token = generate_depot_owner_token()?;
        let mut depot = write.open_table(BLOB_DEPOT_METADATA)?;
        depot.insert(DEPOT_SCHEMA_VERSION, BLOB_DEPOT_SCHEMA_VERSION)?;
        depot.insert(DEPOT_VARIANT_COUNT, 0)?;
        depot.insert(DEPOT_COMMITTED_CHUNK_COUNT, 0)?;
        depot.insert(DEPOT_COMMITTED_FILE_BYTES, 0)?;
        depot.insert(DEPOT_RESERVED_FILE_BYTES, 0)?;
        for (field, chunk) in depot_owner_token_fields()
            .into_iter()
            .zip(owner_token.chunks_exact(8))
        {
            depot.insert(
                field,
                u64::from_be_bytes(chunk.try_into().map_err(|_| {
                    blob_error(BlobStoreError::SchemaInvariant(
                        "Blob depot owner token chunk has invalid length",
                    ))
                })?),
            )?;
        }
    }
    let mut metadata = write.open_table(METADATA)?;
    for field in blob_global_metadata_fields() {
        metadata.insert(field, 0)?;
    }
    initialize_blob_network_schema(write)?;
    Ok(())
}

fn initialize_blob_network_schema(write: &redb::WriteTransaction) -> Result<(), StoreError> {
    let _ = write.open_table(BLOB_PENDING_SOURCES)?;
    let _ = write.open_table(BLOB_CARRIER_PREFIXES)?;
    let _ = write.open_table(BLOB_CARRIER_FETCH_CURSORS)?;
    let mut metadata = write.open_table(BLOB_NETWORK_METADATA)?;
    if metadata.get(BLOB_NETWORK_SCHEMA_VERSION_FIELD)?.is_none() {
        metadata.insert(
            BLOB_NETWORK_SCHEMA_VERSION_FIELD,
            BLOB_NETWORK_SCHEMA_VERSION,
        )?;
        metadata.insert(BLOB_NETWORK_STAGING_ROWS, 0)?;
        metadata.insert(BLOB_NETWORK_STAGING_BYTES, 0)?;
    }
    Ok(())
}

fn legacy_blob_table_names() -> [&'static str; 9] {
    [
        BLOB_PUBLICATIONS.name(),
        BLOB_BYTES.name(),
        BLOB_SEMANTIC_ITEMS.name(),
        BLOB_CONTENT_INDEX.name(),
        BLOB_ACCEPTANCE_MARKERS.name(),
        BLOB_OPERATIONS.name(),
        BLOB_IMPORTS.name(),
        BLOB_CHUNKS.name(),
        BLOB_DEPOT_METADATA.name(),
    ]
}

fn network_blob_table_names() -> [&'static str; 4] {
    [
        BLOB_PENDING_SOURCES.name(),
        BLOB_CARRIER_PREFIXES.name(),
        BLOB_NETWORK_METADATA.name(),
        BLOB_CARRIER_FETCH_CURSORS.name(),
    ]
}

fn blob_table_names() -> [&'static str; 13] {
    let legacy = legacy_blob_table_names();
    let network = network_blob_table_names();
    [
        legacy[0], legacy[1], legacy[2], legacy[3], legacy[4], legacy[5], legacy[6], legacy[7],
        legacy[8], network[0], network[1], network[2], network[3],
    ]
}

fn blob_global_metadata_fields() -> [&'static str; 5] {
    [
        BLOB_ITEM_COUNT,
        BLOB_TOTAL_BYTES,
        LAST_BLOB_ACCEPTANCE_MARKER,
        BLOB_OPERATION_COUNT,
        BLOB_OPERATION_TOTAL_BYTES,
    ]
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
struct BlobNetworkAudit {
    pending_sources: u64,
    carrier_prefixes: u64,
    carrier_cursors: u64,
    staging: BlobNetworkStagingUsage,
}

// Audit receives already-open tables so writable/read-only callers cannot
// accidentally reopen a live redb handle while enforcing cross-table links.
#[allow(clippy::too_many_arguments)]
fn audit_blob_network_rows(
    pending: &impl ReadableTable<&'static [u8], &'static [u8]>,
    carriers: &impl ReadableTable<&'static [u8], &'static [u8]>,
    metadata: &impl ReadableTable<&'static str, u64>,
    cursors: &impl ReadableTable<&'static [u8], &'static [u8]>,
    publications: &impl ReadableTable<&'static [u8], &'static [u8]>,
    imports: &impl ReadableTable<&'static [u8], &'static [u8]>,
    chunks: &impl ReadableTable<&'static [u8], &'static [u8]>,
    mission_authority: Option<NodeId>,
) -> Result<BlobNetworkAudit, StoreError> {
    #[cfg(test)]
    TEST_BLOB_NETWORK_GLOBAL_AUDITS.with(|count| count.set(count.get().saturating_add(1)));
    let pending_sources = pending.len()?;
    let carrier_prefixes = carriers.len()?;
    let rows = pending_sources
        .checked_add(carrier_prefixes)
        .ok_or(StoreError::ItemCountAccountingOverflow)?;
    if rows > MAX_BLOB_NETWORK_STAGING_ROWS {
        return Err(blob_error(BlobStoreError::SchemaInvariant(
            "Blob network staging exceeds its row cap",
        )));
    }
    let mut bytes = 0u64;
    let mut sources = BTreeMap::new();
    for row in pending.iter()? {
        let (key, value) = row?;
        let source = parse_blob_transfer_id("pending Blob source table", key.value())?;
        let record = decode_pending_blob_source(value.value())?;
        let Some(route) = record.metadata.header.blob_route else {
            return Err(blob_error(BlobStoreError::SchemaInvariant(
                "pending Blob source key or network profile is inconsistent",
            )));
        };
        if record.metadata.transfer_id != source
            || route.chunk_count() == 0
            || route.chunk_count() > MAX_NETWORK_BLOB_CHUNKS
        {
            return Err(blob_error(BlobStoreError::SchemaInvariant(
                "pending Blob source key or network profile is inconsistent",
            )));
        }
        if publications.get(key.value())?.is_some() {
            return Err(blob_error(BlobStoreError::SchemaInvariant(
                "Blob source is simultaneously pending and completed",
            )));
        }
        depot::audit_pending_network_plan(
            imports,
            chunks,
            source,
            record.metadata.variant_id,
            record.metadata.blob_id,
            record.metadata.header.key_epoch,
            record.metadata.manifest_digest,
            record.physical_lineage,
            route,
            &record.carriers,
        )?;
        sources.insert(source, record);
        bytes = bytes
            .checked_add(staging_entry_bytes(key.value().len(), value.value().len())?)
            .ok_or(StoreError::PayloadByteAccountingOverflow)?;
    }
    for row in carriers.iter()? {
        let (key, value) = row?;
        let (source, object) = parse_blob_carrier_prefix_key(key.value())?;
        let record = decode_blob_carrier_prefix(value.value())?;
        if record.source != source {
            return Err(blob_error(BlobStoreError::SchemaInvariant(
                "Blob carrier prefix key differs from its exact source",
            )));
        }
        let Some(pending) = sources.get(&source) else {
            return Err(blob_error(BlobStoreError::SchemaInvariant(
                "Blob carrier prefix is orphaned from its pending source",
            )));
        };
        if pending_blob_carrier(pending, object)
            .is_none_or(|expected| expected.total_len != record.total_len)
        {
            return Err(blob_error(BlobStoreError::SchemaInvariant(
                "Blob carrier prefix is not a member of its authenticated pending plan",
            )));
        }
        bytes = bytes
            .checked_add(staging_entry_bytes(key.value().len(), value.value().len())?)
            .ok_or(StoreError::PayloadByteAccountingOverflow)?;
    }
    if bytes > MAX_BLOB_NETWORK_STAGING_BYTES {
        return Err(blob_error(BlobStoreError::SchemaInvariant(
            "Blob network staging exceeds its byte cap",
        )));
    }
    if metadata.len()? != 3
        || metadata
            .get(BLOB_NETWORK_SCHEMA_VERSION_FIELD)?
            .map(|value| value.value())
            != Some(BLOB_NETWORK_SCHEMA_VERSION)
    {
        return Err(blob_error(BlobStoreError::SchemaInvariant(
            "Blob network metadata schema is incomplete or unknown",
        )));
    }
    let durable_rows = metadata
        .get(BLOB_NETWORK_STAGING_ROWS)?
        .map(|value| value.value())
        .ok_or_else(|| {
            blob_error(BlobStoreError::SchemaInvariant(
                "Blob network row counter is missing",
            ))
        })?;
    let durable_bytes = metadata
        .get(BLOB_NETWORK_STAGING_BYTES)?
        .map(|value| value.value())
        .ok_or_else(|| {
            blob_error(BlobStoreError::SchemaInvariant(
                "Blob network byte counter is missing",
            ))
        })?;
    if durable_rows != rows || durable_bytes != bytes {
        return Err(blob_error(BlobStoreError::SchemaInvariant(
            "Blob network staging counters disagree with exact rows",
        )));
    }

    let carrier_cursors = cursors.len()?;
    if carrier_cursors
        > u64::try_from(MAX_BLOB_CARRIER_FETCH_CURSOR_PEERS)
            .map_err(|_| StoreError::ItemCountAccountingOverflow)?
    {
        return Err(blob_error(BlobStoreError::CarrierCursorInvariant(
            "carrier cursor table exceeds its peer bound",
        )));
    }
    if carrier_cursors != 0 && mission_authority.is_none() {
        return Err(blob_error(BlobStoreError::CarrierCursorInvariant(
            "unbound store contains Blob carrier cursors",
        )));
    }
    for row in cursors.iter()? {
        let (key, value) = row?;
        let _: NodeId = key.value().try_into().map_err(|_| {
            blob_error(BlobStoreError::CarrierCursorInvariant(
                "carrier cursor peer key has invalid length",
            ))
        })?;
        BlobCarrierFetchCursor::decode(value.value())?;
    }
    if rows != 0 && mission_authority.is_none() {
        return Err(blob_error(BlobStoreError::SchemaInvariant(
            "unbound store contains Blob network staging",
        )));
    }
    Ok(BlobNetworkAudit {
        pending_sources,
        carrier_prefixes,
        carrier_cursors,
        staging: BlobNetworkStagingUsage { rows, bytes },
    })
}

fn audit_blob_network_tables_write_with_publications(
    write: &redb::WriteTransaction,
    mission_authority: Option<NodeId>,
    publications: &impl ReadableTable<&'static [u8], &'static [u8]>,
) -> Result<BlobNetworkAudit, StoreError> {
    let pending = write.open_table(BLOB_PENDING_SOURCES)?;
    let carriers = write.open_table(BLOB_CARRIER_PREFIXES)?;
    let metadata = write.open_table(BLOB_NETWORK_METADATA)?;
    let cursors = write.open_table(BLOB_CARRIER_FETCH_CURSORS)?;
    let imports = write.open_table(BLOB_IMPORTS)?;
    let chunks = write.open_table(BLOB_CHUNKS)?;
    audit_blob_network_rows(
        &pending,
        &carriers,
        &metadata,
        &cursors,
        publications,
        &imports,
        &chunks,
        mission_authority,
    )
}

fn inspect_blob_network_tables_read_with_publications(
    read: &redb::ReadTransaction,
    publications: &impl ReadableTable<&'static [u8], &'static [u8]>,
) -> Result<BlobNetworkAudit, StoreError> {
    let pending = read.open_table(BLOB_PENDING_SOURCES)?;
    let carriers = read.open_table(BLOB_CARRIER_PREFIXES)?;
    let metadata = read.open_table(BLOB_NETWORK_METADATA)?;
    let cursors = read.open_table(BLOB_CARRIER_FETCH_CURSORS)?;
    let imports = read.open_table(BLOB_IMPORTS)?;
    let chunks = read.open_table(BLOB_CHUNKS)?;
    audit_blob_network_rows(
        &pending,
        &carriers,
        &metadata,
        &cursors,
        publications,
        &imports,
        &chunks,
        read_mission_binding_read(read)?,
    )
}

/// Rechecks only the durable authority and aggregate staging counters needed
/// by one exact network mutation. A full row audit is performed when the Store
/// opens; every hot mutation subsequently updates these counters atomically
/// with its touched rows.
fn blob_network_staging_usage_write(
    write: &redb::WriteTransaction,
    authority: NodeId,
) -> Result<BlobNetworkStagingUsage, StoreError> {
    match read_mission_binding(write)? {
        Some(bound) if bound == authority => {}
        Some(bound) => {
            return Err(StoreError::MissionAuthorityMismatch {
                bound,
                received: authority,
            });
        }
        None => return Err(StoreError::MissionNotBound),
    }
    let metadata = write.open_table(BLOB_NETWORK_METADATA)?;
    if metadata.len()? != 3
        || metadata
            .get(BLOB_NETWORK_SCHEMA_VERSION_FIELD)?
            .map(|value| value.value())
            != Some(BLOB_NETWORK_SCHEMA_VERSION)
    {
        return Err(blob_error(BlobStoreError::SchemaInvariant(
            "Blob network metadata schema is incomplete or unknown",
        )));
    }
    let rows = metadata
        .get(BLOB_NETWORK_STAGING_ROWS)?
        .map(|value| value.value())
        .ok_or_else(|| {
            blob_error(BlobStoreError::SchemaInvariant(
                "Blob network row counter is missing",
            ))
        })?;
    let bytes = metadata
        .get(BLOB_NETWORK_STAGING_BYTES)?
        .map(|value| value.value())
        .ok_or_else(|| {
            blob_error(BlobStoreError::SchemaInvariant(
                "Blob network byte counter is missing",
            ))
        })?;
    if rows > MAX_BLOB_NETWORK_STAGING_ROWS || bytes > MAX_BLOB_NETWORK_STAGING_BYTES {
        return Err(blob_error(BlobStoreError::SchemaInvariant(
            "Blob network staging counters exceed their durable caps",
        )));
    }
    Ok(BlobNetworkStagingUsage { rows, bytes })
}

fn blob_carrier_cursor_count_write(
    write: &redb::WriteTransaction,
    authority: NodeId,
) -> Result<u64, StoreError> {
    match read_mission_binding(write)? {
        Some(bound) if bound == authority => {}
        Some(bound) => {
            return Err(StoreError::MissionAuthorityMismatch {
                bound,
                received: authority,
            });
        }
        None => return Err(StoreError::MissionNotBound),
    }
    let count = write.open_table(BLOB_CARRIER_FETCH_CURSORS)?.len()?;
    if count
        > u64::try_from(MAX_BLOB_CARRIER_FETCH_CURSOR_PEERS)
            .map_err(|_| StoreError::ItemCountAccountingOverflow)?
    {
        return Err(blob_error(BlobStoreError::CarrierCursorInvariant(
            "carrier cursor table exceeds its peer bound",
        )));
    }
    Ok(count)
}

pub(crate) const fn depot_owner_token_fields() -> [&'static str; 4] {
    [
        DEPOT_OWNER_TOKEN_0,
        DEPOT_OWNER_TOKEN_1,
        DEPOT_OWNER_TOKEN_2,
        DEPOT_OWNER_TOKEN_3,
    ]
}

pub(crate) const fn depot_owner_binding_fields() -> [&'static str; 4] {
    [
        DEPOT_OWNER_BINDING_0,
        DEPOT_OWNER_BINDING_1,
        DEPOT_OWNER_BINDING_2,
        DEPOT_OWNER_BINDING_3,
    ]
}

fn generate_depot_owner_token() -> Result<[u8; 32], StoreError> {
    // An all-zero token is reserved as structurally invalid. Retry a bounded
    // number of independent OS draws so initialization can never commit a
    // token that the next audit must reject.
    for _ in 0..4 {
        let mut token = [0u8; 32];
        getrandom::fill(&mut token).map_err(|_| {
            blob_error(BlobStoreError::DepotIntegrity(
                "operating-system entropy is unavailable for the Blob depot owner token",
            ))
        })?;
        if token != [0; 32] {
            return Ok(token);
        }
    }
    Err(blob_error(BlobStoreError::DepotIntegrity(
        "operating-system entropy returned an invalid Blob depot owner token",
    )))
}

fn validate_blob_header(header: &EnvelopeHeader) -> Result<(), StoreError> {
    let route = header.blob_route.ok_or_else(|| {
        blob_error(BlobStoreError::InvalidPublication(
            "Blob route commitment is missing",
        ))
    })?;
    if header.class != SemanticDataClass::Blob
        || header.event_sequence.is_some()
        || header.ttl_ms.is_some()
        || header.tombstone
        || header.content_len == 0
        || header.content_len > MAX_BLOB_MANIFEST_BYTES
        || header.key_epoch == 0
        || route.chunk_count() == 0
        || route.chunk_count() > MAX_SELECTED_BLOB_CHUNKS
        || header.logical_key.as_slice() != route.blob_id().as_bytes()
        || header.stamp.dot.counter == 0
        || header.stamp.context.len() > MAX_CAUSAL_CONTEXT_ENTRIES
        || header
            .stamp
            .context
            .iter()
            .any(|(_, counter)| *counter == 0)
        || header.stamp.context.counter(&header.stamp.dot.publisher) >= header.stamp.dot.counter
    {
        return Err(blob_error(BlobStoreError::InvalidPublication(
            "authenticated Blob header violates the selected profile",
        )));
    }
    Ok(())
}

fn encode_blob_metadata(metadata: BlobMetadata) -> Result<Vec<u8>, StoreError> {
    validate_blob_header(&metadata.header)?;
    let route = metadata.header.blob_route.ok_or_else(|| {
        blob_error(BlobStoreError::InvalidPublication(
            "Blob route commitment is missing",
        ))
    })?;
    if route.blob_id() != metadata.blob_id {
        return Err(blob_error(BlobStoreError::InvalidPublication(
            "Blob metadata identity differs from its route commitment",
        )));
    }
    if metadata.route_lineage.is_some() != metadata.physical_lineage.is_some()
        || metadata
            .route_lineage
            .is_some_and(|lineage| lineage == [0; 32])
        || metadata
            .physical_lineage
            .is_some_and(|lineage| lineage == [0; 32])
    {
        return Err(blob_error(BlobStoreError::InvalidPublication(
            "Blob metadata has an incomplete or invalid lineage binding",
        )));
    }
    let mut output = Vec::new();
    output.push(BLOB_METADATA_VERSION);
    output.extend_from_slice(metadata.transfer_id.as_bytes());
    output.extend_from_slice(metadata.semantic_id.as_bytes());
    output.extend_from_slice(metadata.blob_id.as_bytes());
    output.extend_from_slice(metadata.variant_id.as_bytes());
    output.extend_from_slice(&metadata.manifest_digest);
    output.push(u8::from(metadata.route_lineage.is_some()));
    if let (Some(route_lineage), Some(physical_lineage)) =
        (metadata.route_lineage, metadata.physical_lineage)
    {
        output.extend_from_slice(&route_lineage);
        output.extend_from_slice(&physical_lineage);
    }
    output.push(metadata.header.priority as u8);
    output.extend_from_slice(&metadata.header.stamp.dot.publisher);
    output.extend_from_slice(&metadata.header.stamp.dot.counter.to_be_bytes());
    output.extend_from_slice(&metadata.header.content_len.to_be_bytes());
    output.extend_from_slice(&metadata.header.key_epoch.to_be_bytes());
    output.extend_from_slice(&route.chunk_count().to_be_bytes());
    output.extend_from_slice(route.root());
    push_short_bytes(&mut output, metadata.header.topic.as_str().as_bytes())?;
    push_short_bytes(&mut output, metadata.header.scope.as_str().as_bytes())?;
    let context_len = u32::try_from(metadata.header.stamp.context.len()).map_err(|_| {
        blob_error(BlobStoreError::InvalidPublication(
            "causal context exceeds durable encoding bound",
        ))
    })?;
    output.extend_from_slice(&context_len.to_be_bytes());
    for (publisher, counter) in metadata.header.stamp.context.iter() {
        output.extend_from_slice(publisher);
        output.extend_from_slice(&counter.to_be_bytes());
    }
    Ok(output)
}

pub(crate) fn decode_blob_metadata(bytes: &[u8]) -> Result<BlobMetadata, StoreError> {
    let bytes = lifecycle::publication_payload(bytes).map_err(blob_error)?;
    let mut cursor = MetadataCursor::new(bytes);
    let version = cursor.u8()?;
    if version != BLOB_METADATA_VERSION_V1 && version != BLOB_METADATA_VERSION {
        return Err(blob_error(BlobStoreError::SchemaInvariant(
            "unknown Blob metadata encoding version",
        )));
    }
    let transfer_id = BlobTransferId::new(cursor.array()?);
    let semantic_id = BlobSemanticId::new(cursor.array()?);
    let blob_id = BlobId::from_bytes(cursor.array()?);
    let variant_id = BlobVariantId::from_bytes(cursor.array()?);
    let manifest_digest = cursor.array()?;
    let (route_lineage, physical_lineage) = if version == BLOB_METADATA_VERSION_V1 {
        (None, None)
    } else {
        match cursor.u8()? {
            0 => (None, None),
            1 => {
                let route: [u8; 32] = cursor.array()?;
                let physical: [u8; 32] = cursor.array()?;
                if route == [0; 32] || physical == [0; 32] {
                    return Err(blob_error(BlobStoreError::SchemaInvariant(
                        "Blob metadata has an invalid lineage binding",
                    )));
                }
                (Some(route), Some(physical))
            }
            _ => {
                return Err(blob_error(BlobStoreError::SchemaInvariant(
                    "Blob metadata has an invalid lineage flag",
                )));
            }
        }
    };
    let priority = Priority::from_wire(cursor.u8()?).ok_or_else(|| {
        blob_error(BlobStoreError::SchemaInvariant(
            "unknown authenticated Blob priority",
        ))
    })?;
    let publisher = cursor.array()?;
    let counter = cursor.u64()?;
    let content_len = cursor.u64()?;
    let key_epoch = cursor.u64()?;
    let chunk_count = cursor.u64()?;
    let root = cursor.array()?;
    let topic = Topic::new(cursor.short_string()?).map_err(|_| {
        blob_error(BlobStoreError::SchemaInvariant(
            "invalid Blob topic encoding",
        ))
    })?;
    let scope = Scope::new(cursor.short_string()?).map_err(|_| {
        blob_error(BlobStoreError::SchemaInvariant(
            "invalid Blob scope encoding",
        ))
    })?;
    let context_len = usize::try_from(cursor.u32()?).map_err(|_| {
        blob_error(BlobStoreError::SchemaInvariant(
            "invalid Blob causal context length",
        ))
    })?;
    if context_len > MAX_CAUSAL_CONTEXT_ENTRIES {
        return Err(blob_error(BlobStoreError::SchemaInvariant(
            "Blob causal context exceeds its bound",
        )));
    }
    let mut context = VersionVector::default();
    for _ in 0..context_len {
        let context_publisher = cursor.array()?;
        let context_counter = cursor.u64()?;
        if context_counter == 0 || context.counter(&context_publisher) != 0 {
            return Err(blob_error(BlobStoreError::SchemaInvariant(
                "Blob causal context is not canonical",
            )));
        }
        context.observe(Dot {
            publisher: context_publisher,
            counter: context_counter,
        });
    }
    cursor.finish()?;
    let route = BlobRouteCommitment::from_parts(blob_id, chunk_count, root).map_err(|_| {
        blob_error(BlobStoreError::SchemaInvariant(
            "invalid Blob route commitment encoding",
        ))
    })?;
    let header = EnvelopeHeader {
        class: SemanticDataClass::Blob,
        topic,
        scope,
        priority,
        stamp: CausalStamp {
            dot: Dot { publisher, counter },
            context,
        },
        event_sequence: None,
        logical_key: blob_id.as_bytes().to_vec(),
        blob_route: Some(route),
        ttl_ms: None,
        content_len,
        tombstone: false,
        key_epoch,
    };
    validate_blob_header(&header).map_err(|_| {
        blob_error(BlobStoreError::SchemaInvariant(
            "decoded Blob metadata is internally inconsistent",
        ))
    })?;
    Ok(BlobMetadata {
        transfer_id,
        semantic_id,
        blob_id,
        variant_id,
        manifest_digest,
        route_lineage,
        physical_lineage,
        header,
    })
}

fn encode_pending_blob_source(record: &PendingBlobSourceRecord) -> Result<Vec<u8>, StoreError> {
    if record.route_lineage == [0; 32]
        || record.physical_lineage == [0; 32]
        || record.metadata.route_lineage != Some(record.route_lineage)
        || record.metadata.physical_lineage != Some(record.physical_lineage)
        || BlobTransferId::new(Sha256::digest(&record.sealed).into()) != record.metadata.transfer_id
        || record.sealed.len() > MAX_BLOB_NETWORK_SOURCE_BYTES
        || record.carriers.is_empty()
        || u64::try_from(record.carriers.len()).ok()
            != record
                .metadata
                .header
                .blob_route
                .map(|route| route.chunk_count())
        || record
            .carriers
            .windows(2)
            .any(|pair| pair[0].object >= pair[1].object)
        || record.carriers.iter().any(|carrier| {
            carrier.total_len == 0
                || carrier.total_len > MAX_BLOB_NETWORK_CARRIER_BYTES
                || carrier.index >= record.carriers.len() as u64
        })
        || record
            .carriers
            .iter()
            .map(|carrier| carrier.index)
            .collect::<BTreeSet<_>>()
            .len()
            != record.carriers.len()
    {
        return Err(blob_error(BlobStoreError::PendingSourceConflict));
    }
    let metadata = encode_blob_metadata(record.metadata.clone())?;
    let metadata_len = u32::try_from(metadata.len()).map_err(|_| {
        blob_error(BlobStoreError::InvalidPublication(
            "pending Blob metadata exceeds its encoding bound",
        ))
    })?;
    let carrier_count = u32::try_from(record.carriers.len()).map_err(|_| {
        blob_error(BlobStoreError::InvalidPublication(
            "pending Blob carrier count exceeds its encoding bound",
        ))
    })?;
    let mut encoded = Vec::with_capacity(
        1usize
            .checked_add(64)
            .and_then(|value| value.checked_add(4))
            .and_then(|value| value.checked_add(metadata.len()))
            .and_then(|value| value.checked_add(4))
            .and_then(|value| {
                value.checked_add(
                    record
                        .carriers
                        .len()
                        .checked_mul(BLOB_CARRIER_OBJECT_ID_BYTES + 16)?,
                )
            })
            .and_then(|value| value.checked_add(record.sealed.len()))
            .ok_or(StoreError::PayloadByteAccountingOverflow)?,
    );
    encoded.push(PENDING_BLOB_SOURCE_VERSION);
    encoded.extend_from_slice(&record.route_lineage);
    encoded.extend_from_slice(&record.physical_lineage);
    encoded.extend_from_slice(&metadata_len.to_be_bytes());
    encoded.extend_from_slice(&metadata);
    encoded.extend_from_slice(&carrier_count.to_be_bytes());
    for carrier in &record.carriers {
        encoded.extend_from_slice(carrier.object.as_bytes());
        encoded.extend_from_slice(&carrier.total_len.to_be_bytes());
        encoded.extend_from_slice(&carrier.index.to_be_bytes());
    }
    encoded.extend_from_slice(&record.sealed);
    Ok(encoded)
}

fn decode_pending_blob_source(bytes: &[u8]) -> Result<PendingBlobSourceRecord, StoreError> {
    let mut cursor = MetadataCursor::new(bytes);
    if cursor.u8()? != PENDING_BLOB_SOURCE_VERSION {
        return Err(blob_error(BlobStoreError::SchemaInvariant(
            "unknown pending Blob source encoding version",
        )));
    }
    let route_lineage = cursor.array()?;
    let physical_lineage = cursor.array()?;
    if route_lineage == [0; 32] || physical_lineage == [0; 32] {
        return Err(blob_error(BlobStoreError::SchemaInvariant(
            "pending Blob source has an invalid lineage binding",
        )));
    }
    let metadata_len = usize::try_from(cursor.u32()?).map_err(|_| {
        blob_error(BlobStoreError::SchemaInvariant(
            "pending Blob metadata length overflows",
        ))
    })?;
    let metadata = decode_blob_metadata(cursor.take(metadata_len)?)?;
    if metadata.route_lineage != Some(route_lineage)
        || metadata.physical_lineage != Some(physical_lineage)
    {
        return Err(blob_error(BlobStoreError::SchemaInvariant(
            "pending Blob source metadata differs from its lineage binding",
        )));
    }
    let carrier_count = usize::try_from(cursor.u32()?).map_err(|_| {
        blob_error(BlobStoreError::SchemaInvariant(
            "pending Blob carrier count overflows",
        ))
    })?;
    if carrier_count == 0
        || carrier_count > usize::try_from(MAX_NETWORK_BLOB_CHUNKS).unwrap_or(usize::MAX)
        || u64::try_from(carrier_count).ok()
            != metadata.header.blob_route.map(|route| route.chunk_count())
    {
        return Err(blob_error(BlobStoreError::SchemaInvariant(
            "pending Blob carrier count differs from its route",
        )));
    }
    let mut carriers = Vec::with_capacity(carrier_count);
    for _ in 0..carrier_count {
        let object = BlobCarrierObjectId::new(cursor.array()?).map_err(|_| {
            blob_error(BlobStoreError::SchemaInvariant(
                "pending Blob carrier has an invalid typed identity",
            ))
        })?;
        let total_len = cursor.u64()?;
        let index = cursor.u64()?;
        if total_len == 0 || total_len > MAX_BLOB_NETWORK_CARRIER_BYTES {
            return Err(blob_error(BlobStoreError::SchemaInvariant(
                "pending Blob carrier total violates its bound",
            )));
        }
        carriers.push(PendingBlobCarrierRecord {
            object,
            total_len,
            index,
        });
    }
    if carriers
        .windows(2)
        .any(|pair| pair[0].object >= pair[1].object)
        || carriers
            .iter()
            .any(|carrier| carrier.index >= carrier_count as u64)
        || carriers
            .iter()
            .map(|carrier| carrier.index)
            .collect::<BTreeSet<_>>()
            .len()
            != carriers.len()
    {
        return Err(blob_error(BlobStoreError::SchemaInvariant(
            "pending Blob carriers are not canonical and unique",
        )));
    }
    let sealed = cursor.take(cursor.remaining())?.to_vec();
    cursor.finish()?;
    if sealed.is_empty()
        || sealed.len() > MAX_BLOB_NETWORK_SOURCE_BYTES
        || BlobTransferId::new(Sha256::digest(&sealed).into()) != metadata.transfer_id
    {
        return Err(blob_error(BlobStoreError::SchemaInvariant(
            "pending Blob source fails its exact transfer identity",
        )));
    }
    Ok(PendingBlobSourceRecord {
        metadata,
        route_lineage,
        physical_lineage,
        carriers,
        sealed,
    })
}

fn current_pending_projection_read(
    read: &redb::ReadTransaction,
    key: &[u8],
    value: &[u8],
) -> Result<Option<BlobSourceProjection>, StoreError> {
    let source = parse_blob_transfer_id("pending Blob source table", key)?;
    let pending = decode_pending_blob_source(value)?;
    if pending.metadata.transfer_id != source {
        return Err(blob_error(BlobStoreError::SchemaInvariant(
            "pending Blob source key differs from its exact metadata",
        )));
    }
    if !blob_header_is_current_read(read, &pending.metadata.header)? {
        return Ok(None);
    }
    let sealed_len = u64::try_from(pending.sealed.len())
        .map_err(|_| StoreError::PayloadByteAccountingOverflow)?;
    let shape = durable_blob_source_shape_read(read, &pending.metadata, false)?;
    Ok(Some(blob_source_projection(
        &pending.metadata,
        sealed_len,
        shape,
    )?))
}

fn encode_blob_carrier_prefix(record: &BlobCarrierPrefixRecord) -> Result<Vec<u8>, StoreError> {
    let prefix_len = u64::try_from(record.prefix.len()).ok();
    let range_bound = u64::try_from(MAX_BLOB_NETWORK_RANGE_BYTES)
        .map_err(|_| StoreError::PayloadByteAccountingOverflow)?;
    if record.total_len == 0
        || record.total_len > MAX_BLOB_NETWORK_CARRIER_BYTES
        || record.prefix.is_empty()
        || prefix_len.is_none_or(|length| {
            length > record.total_len || (length < record.total_len && length % range_bound != 0)
        })
    {
        return Err(blob_error(BlobStoreError::InvalidCarrierRange(
            "durable prefix is neither aligned partial progress nor an exact complete tail",
        )));
    }
    let prefix_len = u32::try_from(record.prefix.len()).map_err(|_| {
        blob_error(BlobStoreError::InvalidCarrierRange(
            "durable prefix length overflows",
        ))
    })?;
    let mut encoded = Vec::with_capacity(
        1usize
            .checked_add(32 + 8 + 4)
            .and_then(|value| value.checked_add(record.prefix.len()))
            .ok_or(StoreError::PayloadByteAccountingOverflow)?,
    );
    encoded.push(BLOB_CARRIER_PREFIX_VERSION);
    encoded.extend_from_slice(record.source.as_bytes());
    encoded.extend_from_slice(&record.total_len.to_be_bytes());
    encoded.extend_from_slice(&prefix_len.to_be_bytes());
    encoded.extend_from_slice(&record.prefix);
    Ok(encoded)
}

fn decode_blob_carrier_prefix(bytes: &[u8]) -> Result<BlobCarrierPrefixRecord, StoreError> {
    let mut cursor = MetadataCursor::new(bytes);
    if cursor.u8()? != BLOB_CARRIER_PREFIX_VERSION {
        return Err(blob_error(BlobStoreError::SchemaInvariant(
            "unknown Blob carrier-prefix encoding version",
        )));
    }
    let source = BlobTransferId::new(cursor.array()?);
    let total_len = cursor.u64()?;
    let prefix_len = usize::try_from(cursor.u32()?).map_err(|_| {
        blob_error(BlobStoreError::SchemaInvariant(
            "Blob carrier-prefix length overflows",
        ))
    })?;
    let prefix = cursor.take(prefix_len)?.to_vec();
    cursor.finish()?;
    let record = BlobCarrierPrefixRecord {
        source,
        total_len,
        prefix,
    };
    encode_blob_carrier_prefix(&record).map_err(|_| {
        blob_error(BlobStoreError::SchemaInvariant(
            "Blob carrier-prefix row violates its durable bound",
        ))
    })?;
    Ok(record)
}

fn canonical_blob_carrier_range_len(total_len: u64, offset: u64) -> Option<usize> {
    let bound = u64::try_from(MAX_BLOB_NETWORK_RANGE_BYTES).ok()?;
    if total_len == 0 || offset >= total_len || !offset.is_multiple_of(bound) {
        return None;
    }
    usize::try_from((total_len - offset).min(bound)).ok()
}

fn staging_entry_bytes(key_len: usize, value_len: usize) -> Result<u64, StoreError> {
    key_len
        .checked_add(value_len)
        .and_then(|value| u64::try_from(value).ok())
        .ok_or(StoreError::PayloadByteAccountingOverflow)
}

fn blob_carrier_prefix_key(
    source: BlobTransferId,
    object: BlobCarrierObjectId,
) -> [u8; BLOB_CARRIER_PREFIX_KEY_BYTES] {
    let mut key = [0u8; BLOB_CARRIER_PREFIX_KEY_BYTES];
    key[..32].copy_from_slice(source.as_bytes());
    key[32..].copy_from_slice(object.as_bytes());
    key
}

fn parse_blob_carrier_prefix_key(
    bytes: &[u8],
) -> Result<(BlobTransferId, BlobCarrierObjectId), StoreError> {
    let bytes: [u8; BLOB_CARRIER_PREFIX_KEY_BYTES] = bytes.try_into().map_err(|_| {
        blob_error(BlobStoreError::SchemaInvariant(
            "Blob carrier-prefix key has invalid length",
        ))
    })?;
    let source = BlobTransferId::new(bytes[..32].try_into().map_err(|_| {
        blob_error(BlobStoreError::SchemaInvariant(
            "Blob carrier-prefix source key has invalid length",
        ))
    })?);
    let object = BlobCarrierObjectId::new(bytes[32..].try_into().map_err(|_| {
        blob_error(BlobStoreError::SchemaInvariant(
            "Blob carrier-prefix ObjectID key has invalid length",
        ))
    })?)
    .map_err(|_| {
        blob_error(BlobStoreError::SchemaInvariant(
            "Blob carrier-prefix key has an invalid kind",
        ))
    })?;
    Ok((source, object))
}

fn pending_blob_carrier(
    source: &PendingBlobSourceRecord,
    object: BlobCarrierObjectId,
) -> Option<PendingBlobCarrierRecord> {
    source
        .carriers
        .binary_search_by_key(&object, |carrier| carrier.object)
        .ok()
        .map(|index| source.carriers[index])
}

fn pending_blob_source_projection(record: PendingBlobSourceRecord) -> PendingBlobSource {
    PendingBlobSource {
        transfer_id: record.metadata.transfer_id,
        semantic_id: record.metadata.semantic_id,
        blob_id: record.metadata.blob_id,
        variant_id: record.metadata.variant_id,
        manifest_digest: record.metadata.manifest_digest,
        route_lineage: record.route_lineage,
        physical_lineage: record.physical_lineage,
        header: record.metadata.header,
        sealed: record.sealed,
        carriers: record
            .carriers
            .into_iter()
            .map(|carrier| PendingBlobCarrier {
                object: carrier.object,
                total_len: carrier.total_len,
                index: carrier.index,
            })
            .collect(),
    }
}

fn remove_pending_source_rows_write(
    write: &redb::WriteTransaction,
    staging: BlobNetworkStagingUsage,
    source: BlobTransferId,
    expected: &PendingBlobSourceRecord,
) -> Result<(), StoreError> {
    let encoded_pending = write
        .open_table(BLOB_PENDING_SOURCES)?
        .get(source.as_bytes().as_slice())?
        .map(|value| value.value().to_vec())
        .ok_or_else(|| blob_error(BlobStoreError::PendingSourceMissing))?;
    if decode_pending_blob_source(&encoded_pending)? != *expected {
        return Err(blob_error(BlobStoreError::PendingSourceConflict));
    }
    if expected.metadata.transfer_id != source {
        return Err(blob_error(BlobStoreError::PendingSourceConflict));
    }
    let mut prefix_rows = Vec::with_capacity(expected.carriers.len());
    let mut removed_bytes = staging_entry_bytes(32, encoded_pending.len())?;
    for carrier in &expected.carriers {
        let key = blob_carrier_prefix_key(source, carrier.object);
        let encoded = write
            .open_table(BLOB_CARRIER_PREFIXES)?
            .get(key.as_slice())?
            .map(|value| value.value().to_vec());
        if let Some(encoded) = encoded {
            let record = decode_blob_carrier_prefix(&encoded)?;
            if record.source != source || record.total_len != carrier.total_len {
                return Err(blob_error(BlobStoreError::SchemaInvariant(
                    "Blob carrier prefix differs from its authenticated pending source",
                )));
            }
            removed_bytes = removed_bytes
                .checked_add(staging_entry_bytes(key.len(), encoded.len())?)
                .ok_or(StoreError::PayloadByteAccountingOverflow)?;
            prefix_rows.push(key);
        }
    }
    write
        .open_table(BLOB_PENDING_SOURCES)?
        .remove(source.as_bytes().as_slice())?;
    {
        let mut prefixes = write.open_table(BLOB_CARRIER_PREFIXES)?;
        for key in &prefix_rows {
            prefixes.remove(key.as_slice())?;
        }
    }
    let removed_rows = 1u64
        .checked_add(
            u64::try_from(prefix_rows.len())
                .map_err(|_| StoreError::ItemCountAccountingOverflow)?,
        )
        .ok_or(StoreError::ItemCountAccountingOverflow)?;
    update_blob_network_staging_usage(
        write,
        BlobNetworkStagingUsage {
            rows: staging.rows.checked_sub(removed_rows).ok_or_else(|| {
                blob_error(BlobStoreError::SchemaInvariant(
                    "Blob staging row counter underflows on source removal",
                ))
            })?,
            bytes: staging.bytes.checked_sub(removed_bytes).ok_or_else(|| {
                blob_error(BlobStoreError::SchemaInvariant(
                    "Blob staging byte counter underflows on source removal",
                ))
            })?,
        },
    )
}

fn require_pending_blob_plan(
    pending: &PendingBlobSourceRecord,
    plan: &VerifiedBlobTransferPlan,
) -> Result<(), StoreError> {
    if plan.source_envelope().into_bytes() != *pending.metadata.transfer_id.as_bytes()
        || plan.manifest().id() != pending.metadata.blob_id
        || *plan.manifest_digest() != pending.metadata.manifest_digest
        || *plan.physical_lineage().binding() != pending.physical_lineage
        || blob_variant_id(
            plan.manifest().id(),
            plan.manifest().content_group(),
            plan.manifest().content_epoch(),
        ) != pending.metadata.variant_id
        || plan.manifest().chunk_count() as usize != pending.carriers.len()
    {
        return Err(blob_error(BlobStoreError::PendingSourceConflict));
    }
    for carrier in &pending.carriers {
        let index = plan
            .carrier_index(carrier.object.as_bytes())
            .map_err(|_| blob_error(BlobStoreError::PendingSourceConflict))?;
        let total_len = plan
            .carrier_total_len(carrier.object.as_bytes())
            .map_err(|_| blob_error(BlobStoreError::PendingSourceConflict))?;
        if index != carrier.index || total_len != carrier.total_len {
            return Err(blob_error(BlobStoreError::PendingSourceConflict));
        }
    }
    Ok(())
}

fn carrier_prefix_status(
    object: BlobCarrierObjectId,
    record: &BlobCarrierPrefixRecord,
) -> Result<BlobCarrierPrefixStatus, StoreError> {
    Ok(BlobCarrierPrefixStatus {
        source: record.source,
        object,
        total_len: record.total_len,
        prefix_len: u64::try_from(record.prefix.len())
            .map_err(|_| StoreError::PayloadByteAccountingOverflow)?,
    })
}

fn require_blob_network_staging_capacity(
    current: BlobNetworkStagingUsage,
    incoming_rows: u64,
    incoming_bytes: u64,
) -> Result<(), StoreError> {
    if current
        .rows
        .checked_add(incoming_rows)
        .ok_or(StoreError::ItemCountAccountingOverflow)?
        > MAX_BLOB_NETWORK_STAGING_ROWS
    {
        return Err(blob_error(BlobStoreError::NetworkStagingRowLimitExceeded {
            current: current.rows,
            incoming: incoming_rows,
            limit: MAX_BLOB_NETWORK_STAGING_ROWS,
        }));
    }
    if current
        .bytes
        .checked_add(incoming_bytes)
        .ok_or(StoreError::PayloadByteAccountingOverflow)?
        > MAX_BLOB_NETWORK_STAGING_BYTES
    {
        return Err(blob_error(
            BlobStoreError::NetworkStagingByteLimitExceeded {
                current: current.bytes,
                incoming: incoming_bytes,
                limit: MAX_BLOB_NETWORK_STAGING_BYTES,
            },
        ));
    }
    Ok(())
}

fn update_blob_network_staging_usage(
    write: &redb::WriteTransaction,
    usage: BlobNetworkStagingUsage,
) -> Result<(), StoreError> {
    let mut metadata = write.open_table(BLOB_NETWORK_METADATA)?;
    metadata.insert(BLOB_NETWORK_STAGING_ROWS, usage.rows)?;
    metadata.insert(BLOB_NETWORK_STAGING_BYTES, usage.bytes)?;
    Ok(())
}

fn encode_blob_operation_record(record: BlobOperationRecord) -> Vec<u8> {
    let mut output = Vec::with_capacity(65);
    output.push(BLOB_OPERATION_VERSION);
    output.extend_from_slice(record.transfer_id.as_bytes());
    output.extend_from_slice(&record.intent_digest);
    output
}

fn decode_blob_operation_record(bytes: &[u8]) -> Result<BlobOperationRecord, StoreError> {
    let bytes = lifecycle::operation_payload(bytes).map_err(blob_error)?;
    let mut cursor = MetadataCursor::new(bytes);
    if cursor.u8()? != BLOB_OPERATION_VERSION {
        return Err(blob_error(BlobStoreError::SchemaInvariant(
            "unknown Blob operation encoding version",
        )));
    }
    let record = BlobOperationRecord {
        transfer_id: BlobTransferId::new(cursor.array()?),
        intent_digest: cursor.array()?,
    };
    cursor.finish()?;
    Ok(record)
}

fn blob_publication_intent_digest(intent: &BlobPublicationIntent) -> Result<[u8; 32], StoreError> {
    let topic_len = u16::try_from(intent.topic.as_str().len()).map_err(|_| {
        blob_error(BlobStoreError::InvalidPublication(
            "topic exceeds intent encoding bound",
        ))
    })?;
    let scope_len = u16::try_from(intent.scope.as_str().len()).map_err(|_| {
        blob_error(BlobStoreError::InvalidPublication(
            "scope exceeds intent encoding bound",
        ))
    })?;
    let mut digest = Sha256::new();
    digest.update(BLOB_PUBLICATION_INTENT_DOMAIN);
    digest.update(intent.publisher);
    digest.update(topic_len.to_be_bytes());
    digest.update(intent.topic.as_str().as_bytes());
    digest.update(scope_len.to_be_bytes());
    digest.update(intent.scope.as_str().as_bytes());
    digest.update([intent.priority as u8]);
    digest.update(intent.blob_id.as_bytes());
    Ok(digest.finalize().into())
}

fn blob_content_prefix(
    topic: &Topic,
    scope: &Scope,
    blob_id: BlobId,
) -> Result<Vec<u8>, StoreError> {
    let topic_len = u16::try_from(topic.as_str().len()).map_err(|_| {
        blob_error(BlobStoreError::InvalidPublication(
            "topic exceeds content-index encoding bound",
        ))
    })?;
    let scope_len = u16::try_from(scope.as_str().len()).map_err(|_| {
        blob_error(BlobStoreError::InvalidPublication(
            "scope exceeds content-index encoding bound",
        ))
    })?;
    let mut output = Vec::with_capacity(2 + topic.as_str().len() + 2 + scope.as_str().len() + 32);
    output.extend_from_slice(&topic_len.to_be_bytes());
    output.extend_from_slice(topic.as_str().as_bytes());
    output.extend_from_slice(&scope_len.to_be_bytes());
    output.extend_from_slice(scope.as_str().as_bytes());
    output.extend_from_slice(blob_id.as_bytes());
    Ok(output)
}

fn blob_content_prefix_upper_bound(prefix: &[u8]) -> Result<Vec<u8>, StoreError> {
    let mut upper = prefix.to_vec();
    let index = upper
        .iter()
        .rposition(|byte| *byte != u8::MAX)
        .ok_or_else(|| {
            blob_error(BlobStoreError::SchemaInvariant(
                "Blob content-index prefix has no finite successor",
            ))
        })?;
    upper[index] = upper[index]
        .checked_add(1)
        .expect("successor byte was checked below u8::MAX");
    upper.truncate(index + 1);
    Ok(upper)
}

fn blob_content_key(
    topic: &Topic,
    scope: &Scope,
    blob_id: BlobId,
    semantic_id: BlobSemanticId,
) -> Result<Vec<u8>, StoreError> {
    let mut key = blob_content_prefix(topic, scope, blob_id)?;
    key.extend_from_slice(semantic_id.as_bytes());
    Ok(key)
}

fn parse_blob_transfer_id(
    _table: &'static str,
    bytes: &[u8],
) -> Result<BlobTransferId, StoreError> {
    let bytes: [u8; 32] = bytes.try_into().map_err(|_| {
        blob_error(BlobStoreError::SchemaInvariant(
            "Blob transfer identifier has invalid length",
        ))
    })?;
    Ok(BlobTransferId::new(bytes))
}

#[cfg(test)]
mod tests {
    use std::io::Cursor;
    use std::path::{Path, PathBuf};
    use std::sync::Arc;
    use std::sync::atomic::{AtomicU64, Ordering};

    use aster_mesh::{
        BlobContentVerification, BlobMetadata as CoreBlobMetadata, BlobStore as CoreBlobStore,
        EventContentVerification, FinishedBlob, ProvisioningAccess, ReferenceEnvelopeSealer,
        ReferenceProvisioner, ScopeRekeyRecipient, prepare_blob,
    };

    use super::*;

    static NEXT_BLOB_ROOT: AtomicU64 = AtomicU64::new(1);

    struct BlobTestRoot {
        path: PathBuf,
        database: PathBuf,
    }

    impl BlobTestRoot {
        fn new(label: &str) -> Self {
            let sequence = NEXT_BLOB_ROOT.fetch_add(1, Ordering::Relaxed);
            let path = std::env::temp_dir().join(format!(
                "aster-redb-blob-{label}-{}-{sequence}",
                std::process::id()
            ));
            std::fs::create_dir(&path).expect("create Blob test state root");
            let database = path.join("state.redb");
            Self { path, database }
        }

        fn depot(&self) -> PathBuf {
            self.path.join("blob-depot-v1")
        }

        fn chunk_path(&self, variant: BlobVariantId, index: u64) -> PathBuf {
            self.depot()
                .join(test_hex32(variant.as_bytes()))
                .join(format!("{index:020}.chunk"))
        }
    }

    impl Drop for BlobTestRoot {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.path);
        }
    }

    struct BlobServices {
        provisioner: ReferenceProvisioner,
        publisher: ReferenceEnvelopeSealer,
        reader: ReferenceEnvelopeSealer,
        authority: NodeId,
    }

    fn blob_topic() -> Topic {
        Topic::new("selected-blob").expect("Blob topic")
    }

    fn blob_scope() -> Scope {
        Scope::new("mission/selected-blob").expect("Blob scope")
    }

    fn test_hex32(bytes: &[u8; 32]) -> String {
        const HEX: &[u8; 16] = b"0123456789abcdef";
        let mut output = String::with_capacity(64);
        for byte in bytes {
            output.push(char::from(HEX[usize::from(byte >> 4)]));
            output.push(char::from(HEX[usize::from(byte & 0x0f)]));
        }
        output
    }

    fn blob_services(seed: u8) -> BlobServices {
        let mut provisioner = ReferenceProvisioner::from_seed([seed; 32]).expect("provisioner");
        let access = ProvisioningAccess::member(blob_scope(), vec![1, 2, 3], vec![blob_topic()])
            .expect("Blob member access");
        let publisher = provisioner
            .issue_control_authority(1, std::slice::from_ref(&access))
            .and_then(ReferenceEnvelopeSealer::open)
            .expect("Blob publisher");
        let reader = provisioner
            .issue_node(2, &[access])
            .and_then(ReferenceEnvelopeSealer::open)
            .expect("Blob reader");
        let authority = publisher.mission_authority_id();
        BlobServices {
            provisioner,
            publisher,
            reader,
            authority,
        }
    }

    fn prepared_blob(bytes: &[u8]) -> aster_mesh::PreparedBlob {
        prepare_blob(
            &mut Cursor::new(bytes),
            SELECTED_BLOB_CHUNK_SIZE,
            CoreBlobMetadata::new(Some("application/octet-stream".into()), vec![7, 9])
                .expect("Blob identity metadata"),
        )
        .expect("prepare Blob")
    }

    fn finish_variant(
        store: &Store,
        publisher: &ReferenceEnvelopeSealer,
        prepared: &aster_mesh::PreparedBlob,
        plaintext: &[u8],
        epoch: u64,
    ) -> Result<FinishedBlob, String> {
        let depot = store.blob_depot().map_err(|error| error.to_string())?;
        let mut service = publisher
            .blob_service_with_store(&blob_scope(), &blob_topic(), epoch, depot)
            .map_err(|error| error.to_string())?;
        let manifest = service
            .install_prepared(prepared)
            .map_err(|error| error.to_string())?;
        let progress = service
            .encrypt_some(&mut Cursor::new(plaintext), &manifest, u64::MAX)
            .map_err(|error| error.to_string())?;
        if !progress.complete {
            return Err("Blob encryption stopped before completion".into());
        }
        service
            .finish_manifest(&manifest)
            .map_err(|error| error.to_string())
    }

    struct BlobProof {
        policy: ControlPolicySnapshot,
        reservation: BlobReservation,
        blob: ContentVerifiedBlobEnvelope,
        manifest_bytes: Vec<u8>,
        sealed: Vec<u8>,
        completion: BlobDepotCompletion,
    }

    fn prepare_blob_proof(
        store: &Store,
        services: &mut BlobServices,
        prepared: &aster_mesh::PreparedBlob,
        plaintext: &[u8],
        epoch: u64,
    ) -> BlobProof {
        let policy = store.control_policy_snapshot().expect("Blob policy");
        let reservation = store
            .reserve_blob_with_policy(
                &policy,
                services.publisher.identity(),
                &blob_topic(),
                &blob_scope(),
            )
            .expect("Blob reservation");
        let finished = finish_variant(store, &services.publisher, prepared, plaintext, epoch)
            .expect("finish Blob depot variant");
        let header = reservation
            .header(
                Priority::Immediate,
                finished.route_commitment(),
                u64::try_from(finished.manifest_bytes().len()).expect("manifest length"),
                epoch,
            )
            .expect("Blob header");
        let sealed = services
            .publisher
            .seal_blob_manifest(&header, finished.manifest_bytes())
            .expect("seal Blob manifest")
            .bytes;
        let route = services
            .reader
            .verify_blob(&sealed)
            .expect("verify Blob route");
        let (blob, manifest_bytes) = match services
            .reader
            .verify_blob_content(route, &sealed)
            .expect("verify Blob content")
        {
            BlobContentVerification::ContentVerified {
                blob,
                manifest_bytes,
            } => (blob, manifest_bytes),
            BlobContentVerification::RouteOnly(_) => panic!("member unexpectedly route-only"),
        };
        let completion = store
            .blob_depot()
            .and_then(|mut depot| depot.completed_blob(&blob, &manifest_bytes))
            .expect("complete exact Blob depot variant");
        BlobProof {
            policy,
            reservation,
            blob,
            manifest_bytes,
            sealed,
            completion,
        }
    }

    fn publish_blob(
        store: &Store,
        services: &mut BlobServices,
        prepared: &aster_mesh::PreparedBlob,
        plaintext: &[u8],
        epoch: u64,
        operation_bytes: &[u8],
    ) -> (StoredBlob, BlobOperationKey, BlobPublicationIntent) {
        let operation = BlobOperationKey::new(operation_bytes.to_vec()).expect("operation key");
        let intent = BlobPublicationIntent::new(
            services.publisher.identity(),
            blob_topic(),
            blob_scope(),
            Priority::Immediate,
            prepared.id(),
        )
        .expect("Blob intent");
        let request = BlobOperationRequest::new(&operation, &intent);
        let policy = store.control_policy_snapshot().expect("Blob policy");
        assert_eq!(
            store
                .blob_for_operation_with_policy(&policy, &request)
                .expect("operation preflight"),
            None
        );
        let proof = prepare_blob_proof(store, services, prepared, plaintext, epoch);
        assert_eq!(proof.policy, policy);
        let outcome = store
            .commit_reserved_blob_once_with_policy(
                &policy,
                &request,
                &proof.reservation,
                &proof.blob,
                &proof.sealed,
                &proof.completion,
            )
            .expect("commit Blob publication");
        assert!(outcome.inserted());
        (outcome.blob().clone(), operation, intent)
    }

    fn transfer_all_blob_carriers(
        source: &Store,
        target: &Store,
        policy: &ControlPolicySnapshot,
        plan: &VerifiedBlobTransferPlan,
    ) {
        let transfer = BlobTransferId::new(plan.source_envelope().into_bytes());
        let mut source_depot = source.blob_depot().expect("source depot");
        CoreBlobStore::begin_blob_with_lineage(
            &mut source_depot,
            plan.manifest(),
            plan.physical_lineage(),
        )
        .expect("activate source plan");
        for index in 0..plan.manifest().chunk_count() {
            let carrier = plan
                .build_carrier(&mut source_depot, index)
                .expect("build exact carrier");
            let object = BlobCarrierObjectId::new(carrier.object_id().wire_bytes())
                .expect("typed carrier id");
            let total = u64::try_from(carrier.bytes().len()).expect("carrier total");
            let mut offset = 0u64;
            for range in carrier.bytes().chunks(MAX_BLOB_NETWORK_RANGE_BYTES) {
                let audits = test_blob_network_global_audits();
                target
                    .append_blob_carrier_prefix_with_policy(
                        policy, transfer, object, total, offset, range,
                    )
                    .expect("append exact carrier range");
                assert_eq!(
                    test_blob_network_global_audits(),
                    audits,
                    "one carrier append cannot perform a global Blob-network audit"
                );
                offset += u64::try_from(range.len()).expect("range length");
            }
            let audits = test_blob_network_global_audits();
            target
                .commit_complete_blob_carrier_with_policy(policy, transfer, object, plan)
                .expect("commit exact carrier");
            assert_eq!(
                test_blob_network_global_audits(),
                audits,
                "one carrier commit cannot perform a global Blob-network audit"
            );
        }
    }

    #[test]
    fn pending_carrier_work_for_multiple_sources_is_redb_only_and_read_only() {
        let source_root = BlobTestRoot::new("pending-work-source");
        let target_root = BlobTestRoot::new("pending-work-target");
        let mut services = blob_services(0xb0);
        let source = Store::open_for_mission(&source_root.database, services.authority)
            .expect("pending-work source store");
        let target = Store::open_for_mission(&target_root.database, services.authority)
            .expect("pending-work target store");
        let policy = target
            .control_policy_snapshot()
            .expect("pending-work policy");
        for index in 0..8u8 {
            let plaintext = vec![0x80 | index; 64 + usize::from(index)];
            let prepared = prepared_blob(&plaintext);
            publish_blob(
                &target,
                &mut services,
                &prepared,
                &plaintext,
                1,
                format!("pending-work-completed-{index}").as_bytes(),
            );
            publish_blob(
                &source,
                &mut services,
                &prepared,
                &plaintext,
                1,
                format!("pending-work-source-history-{index}").as_bytes(),
            );
        }
        let mut pending = Vec::new();
        for plaintext in [
            vec![0x31; SELECTED_BLOB_CHUNK_SIZE as usize + 7],
            vec![0x52; 2 * SELECTED_BLOB_CHUNK_SIZE as usize + 11],
        ] {
            let prepared = prepared_blob(&plaintext);
            let proof = prepare_blob_proof(&source, &mut services, &prepared, &plaintext, 1);
            let plan = proof
                .blob
                .transfer_plan(&proof.manifest_bytes)
                .expect("pending-work transfer plan");
            let transfer = BlobTransferId::new(proof.blob.envelope_id());
            assert_eq!(
                target
                    .stage_verified_blob_source_with_policy(
                        &policy,
                        &proof.blob,
                        &proof.sealed,
                        &plan,
                    )
                    .expect("stage pending-work source"),
                BlobSourceStageOutcome::Inserted
            );
            let (published, _, _) = commit_blob_proof(
                &source,
                &services,
                &proof,
                format!("pending-work-source-{}", pending.len()).as_bytes(),
            );
            assert!(published.inserted());
            pending.push((transfer, plan));
        }

        let pending_visits_before = test_pending_blob_source_rows_visited();
        let mut pending_only = Vec::new();
        target
            .visit_pending_blob_sources(None, |source| pending_only.push(source.transfer_id))
            .expect("visit pending-only projections");
        pending_only.sort_unstable();
        assert_eq!(pending_only, {
            let mut expected = pending
                .iter()
                .map(|(transfer, _)| *transfer)
                .collect::<Vec<_>>();
            expected.sort_unstable();
            expected
        });
        assert_eq!(
            test_pending_blob_source_rows_visited() - pending_visits_before,
            u64::try_from(pending.len()).expect("pending row count"),
            "completed sources leaked into the pending-only visitor"
        );

        let before_io = depot::test_depot_io_counts(&target);
        let before_stats = target.blob_stats().expect("pending-work initial stats");
        let mut ordered_sources = pending
            .iter()
            .map(|(transfer, _)| *transfer)
            .collect::<Vec<_>>();
        ordered_sources.sort_unstable();
        assert_eq!(
            target
                .next_pending_blob_source_with_policy(&policy, None)
                .expect("select first pending source")
                .map(|source| source.transfer_id),
            ordered_sources.first().copied()
        );
        assert_eq!(
            target
                .next_pending_blob_source_with_policy(&policy, ordered_sources.first().copied())
                .expect("select successor pending source")
                .map(|source| source.transfer_id),
            ordered_sources.get(1).copied()
        );
        assert_eq!(
            target
                .next_pending_blob_source_with_policy(&policy, ordered_sources.get(1).copied())
                .expect("wrap pending source selection")
                .map(|source| source.transfer_id),
            ordered_sources.first().copied()
        );
        for (transfer, plan) in &pending {
            let work = target
                .pending_blob_carrier_work_with_policy(&policy, *transfer, plan)
                .expect("enumerate exact pending carrier work");
            assert_eq!(
                u64::try_from(work.len()).expect("pending work count"),
                plan.manifest().chunk_count()
            );
            assert_eq!(
                target
                    .pending_blob_remaining_count_with_policy(&policy, *transfer, plan)
                    .expect("count exact pending carrier work"),
                plan.manifest().chunk_count()
            );
        }
        assert_eq!(
            depot::test_depot_io_counts(&target),
            before_io,
            "pending work queries cannot open, audit, or mutate the physical depot"
        );
        assert_eq!(
            target.blob_stats().expect("pending-work final stats"),
            before_stats,
            "pending work queries are durable-state neutral"
        );
    }

    #[test]
    fn pending_transfer_progress_counts_durable_prefixes_and_committed_carriers_across_reopen() {
        // Break caught: a status implementation that counts only prefix rows
        // reports progress falling back to zero after a complete carrier moves
        // into the durable depot.
        let source_root = BlobTestRoot::new("transfer-progress-source");
        let target_root = BlobTestRoot::new("transfer-progress-target");
        let mut services = blob_services(0xb1);
        let source = Store::open_for_mission(&source_root.database, services.authority)
            .expect("transfer-progress source store");
        let target = Store::open_for_mission(&target_root.database, services.authority)
            .expect("transfer-progress target store");
        let policy = target
            .control_policy_snapshot()
            .expect("transfer-progress policy");
        let plaintext = vec![0x63; SELECTED_BLOB_CHUNK_SIZE as usize + 7];
        let prepared = prepared_blob(&plaintext);
        let proof = prepare_blob_proof(&source, &mut services, &prepared, &plaintext, 1);
        let plan = proof
            .blob
            .transfer_plan(&proof.manifest_bytes)
            .expect("transfer-progress plan");
        let transfer = BlobTransferId::new(proof.blob.envelope_id());
        target
            .stage_verified_blob_source_with_policy(&policy, &proof.blob, &proof.sealed, &plan)
            .expect("stage transfer-progress source");

        let waiting = target
            .pending_blob_transfer_progress_with_policy(&policy)
            .expect("waiting transfer progress");
        assert_eq!(waiting.pending.len(), 1);
        assert_eq!(waiting.pending[0].source.transfer_id, transfer);
        assert_eq!(waiting.pending[0].total_carriers, 2);
        assert_eq!(waiting.pending[0].durable_carriers, 0);
        assert_eq!(waiting.pending[0].durable_carrier_bytes, 0);
        assert!(waiting.pending[0].total_carrier_bytes > 0);

        let mut source_depot = source.blob_depot().expect("source transfer depot");
        CoreBlobStore::begin_blob_with_lineage(
            &mut source_depot,
            plan.manifest(),
            plan.physical_lineage(),
        )
        .expect("activate source transfer plan");
        let carrier = plan
            .build_carrier(&mut source_depot, 0)
            .expect("build first transfer carrier");
        let object = BlobCarrierObjectId::new(carrier.object_id().wire_bytes())
            .expect("typed first carrier");
        let total_len = u64::try_from(carrier.bytes().len()).expect("first carrier length");
        let first_range_len = carrier.bytes().len().min(MAX_BLOB_NETWORK_RANGE_BYTES);
        target
            .append_blob_carrier_prefix_with_policy(
                &policy,
                transfer,
                object,
                total_len,
                0,
                &carrier.bytes()[..first_range_len],
            )
            .expect("append first transfer range");

        let partial = target
            .pending_blob_transfer_progress_with_policy(&policy)
            .expect("partial transfer progress");
        assert_eq!(partial.pending[0].durable_carriers, 0);
        assert_eq!(
            partial.pending[0].durable_carrier_bytes,
            u64::try_from(first_range_len).expect("first range length")
        );

        for (range_index, range) in carrier
            .bytes()
            .chunks(MAX_BLOB_NETWORK_RANGE_BYTES)
            .enumerate()
            .skip(1)
        {
            let offset =
                u64::try_from(range_index * MAX_BLOB_NETWORK_RANGE_BYTES).expect("carrier offset");
            target
                .append_blob_carrier_prefix_with_policy(
                    &policy, transfer, object, total_len, offset, range,
                )
                .expect("append remaining transfer range");
        }
        target
            .commit_complete_blob_carrier_with_policy(&policy, transfer, object, &plan)
            .expect("commit first transfer carrier");

        let committed = target
            .pending_blob_transfer_progress_with_policy(&policy)
            .expect("committed transfer progress");
        assert_eq!(committed.pending[0].durable_carriers, 1);
        assert_eq!(committed.pending[0].durable_carrier_bytes, total_len);
        drop(target);

        let reopened = Store::open_for_mission(&target_root.database, services.authority)
            .expect("reopen transfer-progress target");
        assert_eq!(
            reopened
                .pending_blob_transfer_progress_with_policy(&policy)
                .expect("reopened transfer progress"),
            committed
        );
    }

    #[test]
    fn carrier_cursor_read_and_cas_are_global_audit_free() {
        let root = BlobTestRoot::new("carrier-cursor-hot-path");
        let services = blob_services(0xaf);
        let store = Store::open_for_mission(&root.database, services.authority)
            .expect("carrier cursor store");
        let peer = services.publisher.identity();
        let source = BlobTransferId::new([0x41; 32]);
        let mut object = [0x52; BLOB_CARRIER_OBJECT_ID_BYTES];
        object[0] = 2;
        let cursor = BlobCarrierFetchCursor::new(
            source,
            BlobCarrierObjectId::new(object).expect("typed carrier cursor object"),
        );

        let audits = test_blob_network_global_audits();
        assert_eq!(
            store
                .blob_carrier_fetch_cursor(peer)
                .expect("absent cursor read"),
            None
        );
        assert_eq!(
            test_blob_network_global_audits(),
            audits,
            "an unavailable range that does not call CAS cannot trigger a global audit"
        );

        assert!(
            store
                .compare_and_advance_blob_carrier_fetch_cursor(peer, None, cursor)
                .expect("insert exact cursor")
        );
        assert_eq!(
            test_blob_network_global_audits(),
            audits,
            "cursor CAS cannot trigger a global Blob-network audit"
        );
        assert_eq!(
            store
                .blob_carrier_fetch_cursor(peer)
                .expect("load inserted cursor"),
            Some(cursor)
        );
        assert!(
            store
                .compare_and_advance_blob_carrier_fetch_cursor(peer, None, cursor)
                .expect("idempotent cursor replay")
        );
        assert_eq!(test_blob_network_global_audits(), audits);
    }

    #[test]
    fn carrier_commit_serializes_abort_after_its_exact_snapshot() {
        let source_root = BlobTestRoot::new("carrier-commit-abort-source");
        let target_root = BlobTestRoot::new("carrier-commit-abort-target");
        let mut services = blob_services(0xae);
        let source = Store::open_for_mission(&source_root.database, services.authority)
            .expect("commit-abort source store");
        let target = Store::open_for_mission(&target_root.database, services.authority)
            .expect("commit-abort target store");
        let plaintext = vec![0x6e; SELECTED_BLOB_CHUNK_SIZE as usize];
        let prepared = prepared_blob(&plaintext);
        let proof = prepare_blob_proof(&source, &mut services, &prepared, &plaintext, 1);
        let plan = proof
            .blob
            .transfer_plan(&proof.manifest_bytes)
            .expect("commit-abort transfer plan");
        let policy = target
            .control_policy_snapshot()
            .expect("commit-abort policy");
        let transfer = BlobTransferId::new(proof.blob.envelope_id());
        target
            .stage_verified_blob_source_with_policy(&policy, &proof.blob, &proof.sealed, &plan)
            .expect("stage commit-abort source");
        let carrier = {
            let mut depot = source.blob_depot().expect("source carrier depot");
            CoreBlobStore::begin_blob_with_lineage(
                &mut depot,
                plan.manifest(),
                plan.physical_lineage(),
            )
            .expect("activate source carrier plan");
            plan.build_carrier(&mut depot, 0)
                .expect("build commit-abort carrier")
        };
        let object = BlobCarrierObjectId::new(carrier.object_id().wire_bytes())
            .expect("commit-abort carrier id");
        let total_len = u64::try_from(carrier.bytes().len()).expect("carrier length");
        let mut offset = 0u64;
        for range in carrier.bytes().chunks(MAX_BLOB_NETWORK_RANGE_BYTES) {
            target
                .append_blob_carrier_prefix_with_policy(
                    &policy, transfer, object, total_len, offset, range,
                )
                .expect("stage complete carrier prefix");
            offset += u64::try_from(range.len()).expect("carrier range length");
        }

        let (reached_send, reached_receive) = std::sync::mpsc::sync_channel(0);
        let (release_send, release_receive) = std::sync::mpsc::sync_channel(0);
        target.set_blob_carrier_commit_post_snapshot_gate(reached_send, release_receive);
        let abort_started = std::sync::Barrier::new(2);
        let (abort_done_send, abort_done_receive) = std::sync::mpsc::channel();
        let audits = test_blob_network_global_audits();
        std::thread::scope(|scope| {
            let commit = scope.spawn(|| {
                target.commit_complete_blob_carrier_with_policy(&policy, transfer, object, &plan)
            });
            reached_receive
                .recv_timeout(std::time::Duration::from_secs(5))
                .expect("commit reached its depot-locked exact snapshot");
            let abort = scope.spawn(|| {
                abort_started.wait();
                let result = target.abort_pending_blob_source(transfer);
                abort_done_send
                    .send(())
                    .expect("report completed abort attempt");
                result
            });
            abort_started.wait();
            assert!(matches!(
                abort_done_receive.recv_timeout(std::time::Duration::from_millis(100)),
                Err(std::sync::mpsc::RecvTimeoutError::Timeout)
            ));
            release_send
                .send(())
                .expect("release depot-locked carrier commit");
            assert_eq!(
                commit
                    .join()
                    .expect("join carrier commit")
                    .expect("commit carrier before abort"),
                BlobCarrierCommitOutcome::Committed
            );
            assert!(
                abort
                    .join()
                    .expect("join pending abort")
                    .expect("abort after carrier commit")
            );
        });
        assert_eq!(
            test_blob_network_global_audits(),
            audits,
            "commit/abort serialization cannot invoke a global network audit"
        );
        assert!(
            target
                .pending_blob_source(transfer)
                .expect("pending source after abort")
                .is_none()
        );
    }

    #[test]
    fn network_blob_stages_transfers_promotes_serves_and_reopens() {
        let source_root = BlobTestRoot::new("network-source");
        let target_root = BlobTestRoot::new("network-target");
        let mut services = blob_services(0xb1);
        let source = Store::open_for_mission(&source_root.database, services.authority)
            .expect("source store");
        let target = Store::open_for_mission(&target_root.database, services.authority)
            .expect("target store");
        let plaintext = vec![0x5a; SELECTED_BLOB_CHUNK_SIZE as usize + 31];
        let prepared = prepared_blob(&plaintext);
        let proof = prepare_blob_proof(&source, &mut services, &prepared, &plaintext, 1);
        let plan = proof
            .blob
            .transfer_plan(&proof.manifest_bytes)
            .expect("authenticated transfer plan");
        let policy = target.control_policy_snapshot().expect("target policy");
        let stage_audits = test_blob_network_global_audits();
        assert_eq!(
            target
                .stage_verified_blob_source_with_policy(&policy, &proof.blob, &proof.sealed, &plan,)
                .expect("stage source"),
            BlobSourceStageOutcome::Inserted
        );
        assert_eq!(
            test_blob_network_global_audits(),
            stage_audits,
            "source staging cannot perform a global Blob-network audit"
        );
        let before = target
            .blob_source_projection(BlobTransferId::new(proof.blob.envelope_id()))
            .expect("pending projection")
            .expect("pending source");
        assert_eq!(before.retention, BlobSourceRetention::Pending);
        assert!(
            target
                .get_blob(before.source.transfer_id)
                .expect("not visible")
                .is_none()
        );

        let first = plan.carrier_id(0).expect("first carrier");
        let first = BlobCarrierObjectId::new(first.wire_bytes()).expect("first object");
        let first_total = plan
            .carrier_total_len(first.as_bytes())
            .expect("first carrier total");
        let hostile = BlobCarrierObjectId::new([2; BLOB_CARRIER_OBJECT_ID_BYTES])
            .expect("syntactic hostile object");
        assert!(matches!(
            target.append_blob_carrier_prefix_with_policy(
                &policy,
                before.source.transfer_id,
                hostile,
                1,
                0,
                &[0],
            ),
            Err(StoreError::Blob(BlobStoreError::InvalidCarrierObjectId))
        ));
        let before_noncanonical = target.blob_stats().expect("pre-append staging stats");
        assert!(matches!(
            target.append_blob_carrier_prefix_with_policy(
                &policy,
                before.source.transfer_id,
                first,
                first_total,
                0,
                &[0],
            ),
            Err(StoreError::Blob(BlobStoreError::InvalidCarrierRange(_)))
        ));
        assert!(
            target
                .blob_carrier_prefix_status(before.source.transfer_id, first)
                .expect("noncanonical prefix status")
                .is_none()
        );
        assert_eq!(
            target.blob_stats().expect("post-rejection staging stats"),
            before_noncanonical
        );
        let mut malformed_durable_prefix = Vec::new();
        malformed_durable_prefix.push(BLOB_CARRIER_PREFIX_VERSION);
        malformed_durable_prefix.extend_from_slice(before.source.transfer_id.as_bytes());
        malformed_durable_prefix.extend_from_slice(&first_total.to_be_bytes());
        malformed_durable_prefix.extend_from_slice(&1u32.to_be_bytes());
        malformed_durable_prefix.push(0);
        assert!(matches!(
            decode_blob_carrier_prefix(&malformed_durable_prefix),
            Err(StoreError::Blob(BlobStoreError::SchemaInvariant(_)))
        ));
        assert!(matches!(
            target.append_blob_carrier_prefix_with_policy(
                &policy,
                before.source.transfer_id,
                first,
                first_total + 1,
                0,
                &[0],
            ),
            Err(StoreError::Blob(BlobStoreError::InvalidCarrierRange(_)))
        ));

        transfer_all_blob_carriers(&source, &target, &policy, &plan);
        assert_eq!(
            target
                .pending_blob_remaining_count_with_policy(
                    &policy,
                    before.source.transfer_id,
                    &plan,
                )
                .expect("remaining carriers"),
            0
        );
        let before_completion_io = depot::test_depot_io_counts(&target);
        let depot_completion = target
            .completed_pending_blob_with_policy(
                &policy,
                before.source.transfer_id,
                &proof.blob,
                &proof.manifest_bytes,
                &plan,
            )
            .expect("target pending depot completion");
        let after_completion_io = depot::test_depot_io_counts(&target);
        assert_eq!(
            after_completion_io.full_open_audits, before_completion_io.full_open_audits,
            "pending completion mint cannot perform a global depot audit"
        );
        assert_eq!(
            after_completion_io.root_creations, before_completion_io.root_creations,
            "pending completion mint cannot create a depot root"
        );
        let content_completion = {
            let depot = target
                .blob_depot_for_authenticated_read(&depot_completion)
                .expect("target authenticated content depot");
            let mut service = services
                .reader
                .blob_service_with_store(&blob_scope(), &blob_topic(), 1, depot)
                .expect("target reader service");
            service
                .verify_blob_content_completion(&proof.blob, &proof.manifest_bytes)
                .expect("fresh full content proof")
        };
        let lineage = services
            .reader
            .verify_current_blob_lineage(&proof.blob)
            .expect("current lineages");
        let apply_audits = test_blob_network_global_audits();
        let applied = target
            .apply_verified_blob_with_policy(
                &policy,
                &plan,
                &lineage,
                &depot_completion,
                &content_completion,
            )
            .expect("promote Blob");
        assert_eq!(
            test_blob_network_global_audits(),
            apply_audits,
            "source promotion cannot perform a global Blob-network audit"
        );
        assert!(matches!(applied, ApplyOutcome::Inserted { .. }));
        let after = target
            .blob_source_projection(before.source.transfer_id)
            .expect("completed projection")
            .expect("completed source");
        assert!(matches!(
            after.retention,
            BlobSourceRetention::Completed { .. }
        ));
        assert_eq!(
            after.source.metadata_fingerprint, before.source.metadata_fingerprint,
            "pending-to-completed projection is state-neutral"
        );
        assert!(
            target
                .pending_blob_source(before.source.transfer_id)
                .expect("pending gone")
                .is_none()
        );
        assert!(matches!(
            target
                .apply_verified_blob_with_policy(
                    &policy,
                    &plan,
                    &lineage,
                    &depot_completion,
                    &content_completion,
                )
                .expect("duplicate promotion"),
            ApplyOutcome::Duplicate { .. }
        ));
        let before_malformed_io = depot::test_depot_io_counts(&target);
        let malformed = target
            .read_completed_blob_carrier_range_with_policy(
                &policy,
                &depot_completion,
                &lineage,
                before.source.transfer_id,
                first,
                1,
                1,
                &plan,
            )
            .expect_err("noncanonical carrier range must fail before depot open");
        assert!(matches!(
            malformed,
            StoreError::Blob(BlobStoreError::InvalidCarrierRange(_))
        ));
        assert_eq!(
            depot::test_depot_io_counts(&target),
            before_malformed_io,
            "malformed range tuple cannot open or mutate the depot"
        );
        let before_range_io = depot::test_depot_io_counts(&target);
        let before_range_source_work = test_blob_read_work_counts();
        let range = target
            .read_completed_blob_carrier_range_with_policy(
                &policy,
                &depot_completion,
                &lineage,
                before.source.transfer_id,
                first,
                0,
                MAX_BLOB_NETWORK_RANGE_BYTES,
                &plan,
            )
            .expect("serve range")
            .expect("completed carrier");
        assert!(!range.1.is_empty());
        let after_range_io = depot::test_depot_io_counts(&target);
        assert_eq!(
            after_range_io.full_open_audits,
            before_range_io.full_open_audits
        );
        assert_eq!(
            after_range_io.begin_write_transactions,
            before_range_io.begin_write_transactions
        );
        assert_eq!(
            after_range_io.root_creations,
            before_range_io.root_creations
        );
        assert_eq!(
            after_range_io.authenticated_read_opens,
            before_range_io.authenticated_read_opens + 1
        );
        assert_eq!(
            test_blob_read_work_counts().1,
            before_range_source_work.1,
            "carrier range pre/post checks cannot clone source-envelope bytes"
        );

        let accepted = target
            .get_blob(before.source.transfer_id)
            .expect("load accepted range source")
            .expect("accepted range source")
            .acceptance_marker;
        let (reached_send, reached_receive) = std::sync::mpsc::sync_channel(0);
        let (release_send, release_receive) = std::sync::mpsc::sync_channel(0);
        target.set_blob_carrier_range_post_read_gate(reached_send, release_receive);
        let before_fault_io = depot::test_depot_io_counts(&target);
        let postcheck_error = std::thread::scope(|scope| {
            let served = scope.spawn(|| {
                target.read_completed_blob_carrier_range_with_policy(
                    &policy,
                    &depot_completion,
                    &lineage,
                    before.source.transfer_id,
                    first,
                    0,
                    MAX_BLOB_NETWORK_RANGE_BYTES,
                    &plan,
                )
            });
            reached_receive
                .recv_timeout(std::time::Duration::from_secs(5))
                .expect("range reached its final source postcheck");
            let mutation = (|| -> Result<(), StoreError> {
                let write = target.database.begin_write()?;
                write.open_table(BLOB_ACCEPTANCE_MARKERS)?.insert(
                    before.source.transfer_id.as_bytes().as_slice(),
                    accepted
                        .checked_add(1)
                        .ok_or(StoreError::AcceptanceMarkerExhausted)?,
                )?;
                write.commit()?;
                Ok(())
            })();
            release_send
                .send(())
                .expect("release final source postcheck");
            mutation.expect("commit post-read source mutation");
            served
                .join()
                .expect("join post-read range")
                .expect_err("exact post-read source drift must fail closed")
        });
        assert!(matches!(
            postcheck_error,
            StoreError::Blob(BlobStoreError::CompletionMismatch)
        ));
        let restore = target
            .database
            .begin_write()
            .expect("begin acceptance marker restoration");
        restore
            .open_table(BLOB_ACCEPTANCE_MARKERS)
            .expect("open marker table for restoration")
            .insert(before.source.transfer_id.as_bytes().as_slice(), accepted)
            .expect("restore acceptance marker");
        restore
            .commit()
            .expect("commit acceptance marker restoration");
        let after_fault_io = depot::test_depot_io_counts(&target);
        assert_eq!(
            after_fault_io.full_open_audits,
            before_fault_io.full_open_audits
        );
        assert_eq!(
            after_fault_io.begin_write_transactions,
            before_fault_io.begin_write_transactions
        );
        assert_eq!(
            after_fault_io.root_creations,
            before_fault_io.root_creations
        );
        assert_eq!(
            after_fault_io.authenticated_read_opens,
            before_fault_io.authenticated_read_opens + 1
        );
        drop(target);
        let reopened = Store::open_for_mission(&target_root.database, services.authority)
            .expect("reopen target");
        assert_eq!(
            reopened
                .completed_blob_sender_inventory_with_policy(&policy)
                .expect("reopened sender inventory")
                .len(),
            1
        );
    }

    #[test]
    fn pending_blob_audit_binds_exact_manifest_route_and_carriers_on_all_open_paths() {
        for terminal in [false, true] {
            let source_root = BlobTestRoot::new(if terminal {
                "pending-plan-terminal-source"
            } else {
                "pending-plan-live-source"
            });
            let target_root = BlobTestRoot::new(if terminal {
                "pending-plan-terminal-target"
            } else {
                "pending-plan-live-target"
            });
            let mut services = blob_services(if terminal { 0xc3 } else { 0xc2 });
            let source = Store::open_for_mission(&source_root.database, services.authority)
                .expect("pending-plan source");
            let mut target = Store::open_for_mission(&target_root.database, services.authority)
                .expect("pending-plan target");
            let plaintext = vec![0xc2; SELECTED_BLOB_CHUNK_SIZE as usize + 29];
            let prepared = prepared_blob(&plaintext);
            let proof = prepare_blob_proof(&source, &mut services, &prepared, &plaintext, 1);
            let plan = proof
                .blob
                .transfer_plan(&proof.manifest_bytes)
                .expect("pending-plan transfer plan");
            let policy = target
                .control_policy_snapshot()
                .expect("pending-plan policy");
            target
                .stage_verified_blob_source_with_policy(&policy, &proof.blob, &proof.sealed, &plan)
                .expect("stage exact pending plan");
            let variant = BlobVariantId::for_content(
                plan.manifest().id(),
                plan.manifest().content_group(),
                plan.manifest().content_epoch(),
            );
            if terminal {
                let intent = ZeroizationIntent::new(
                    b"pending-plan mission descriptor".to_vec(),
                    b"pending-plan identity descriptor".to_vec(),
                )
                .expect("pending-plan terminal intent");
                target
                    .begin_zeroization(&intent)
                    .expect("enter pending-plan terminal state");
            }
            drop(target);

            let database = Database::open(&target_root.database)
                .expect("raw pending-plan corruption database");
            let write = database
                .begin_write()
                .expect("pending-plan corruption write");
            depot::corrupt_expected_chunk_ciphertext_digest_for_test(&write, variant, 0)
                .expect("mutate one self-consistent expected record");
            write.commit().expect("commit pending-plan corruption");
            drop(database);
            let database_before = blob_database_digest(&target_root.database);
            let depot_before = depot_file_snapshot(&target_root.depot());

            let error = Store::inspect_existing(&target_root.database)
                .expect_err("read-only audit rejects changed canonical plan");
            assert_blob_schema_invariant(&error);
            if terminal {
                let cleanup = Store::open_for_zeroization(&target_root.database)
                    .expect("open terminal cleanup handle");
                let error = cleanup
                    .inspect_preserved()
                    .expect_err("terminal preserved audit rejects changed canonical plan");
                assert_blob_schema_invariant(&error);
            } else {
                let error = match Store::open_for_mission(&target_root.database, services.authority)
                {
                    Ok(_) => panic!("writable audit rejects changed canonical plan"),
                    Err(error) => error,
                };
                assert_blob_schema_invariant(&error);
            }
            assert_eq!(
                blob_database_digest(&target_root.database),
                database_before,
                "rejected exact-plan audit must not repair durable rows"
            );
            assert_eq!(
                depot_file_snapshot(&target_root.depot()),
                depot_before,
                "rejected exact-plan audit must not alter depot artifacts"
            );
        }
    }

    #[test]
    fn pending_blob_audit_rejects_self_consistent_missing_depot_plan_without_repair() {
        let source_root = BlobTestRoot::new("pending-missing-plan-source");
        let target_root = BlobTestRoot::new("pending-missing-plan-target");
        let mut services = blob_services(0xc4);
        let source = Store::open_for_mission(&source_root.database, services.authority)
            .expect("missing-plan source");
        let target = Store::open_for_mission(&target_root.database, services.authority)
            .expect("missing-plan target");
        let plaintext = vec![0xc4; SELECTED_BLOB_CHUNK_SIZE as usize + 11];
        let prepared = prepared_blob(&plaintext);
        let proof = prepare_blob_proof(&source, &mut services, &prepared, &plaintext, 1);
        let plan = proof
            .blob
            .transfer_plan(&proof.manifest_bytes)
            .expect("missing-plan transfer plan");
        let policy = target
            .control_policy_snapshot()
            .expect("missing-plan policy");
        target
            .stage_verified_blob_source_with_policy(&policy, &proof.blob, &proof.sealed, &plan)
            .expect("stage missing-plan fixture");
        let variant = BlobVariantId::for_content(
            plan.manifest().id(),
            plan.manifest().content_group(),
            plan.manifest().content_epoch(),
        );
        drop(target);

        let database = Database::open(&target_root.database).expect("raw missing-plan database");
        let write = database
            .begin_write()
            .expect("missing-plan corruption write");
        let chunk_keys = {
            let chunks = write.open_table(BLOB_CHUNKS).expect("missing-plan chunks");
            chunks
                .iter()
                .expect("missing-plan chunk rows")
                .map(|row| row.expect("missing-plan chunk row").0.value().to_vec())
                .filter(|key| key.starts_with(variant.as_bytes()))
                .collect::<Vec<_>>()
        };
        {
            let mut chunks = write
                .open_table(BLOB_CHUNKS)
                .expect("remove missing-plan chunks");
            for key in chunk_keys {
                chunks
                    .remove(key.as_slice())
                    .expect("remove expected chunk row");
            }
        }
        write
            .open_table(BLOB_IMPORTS)
            .expect("missing-plan imports")
            .remove(variant.as_bytes().as_slice())
            .expect("remove missing-plan import");
        {
            let mut metadata = write
                .open_table(BLOB_DEPOT_METADATA)
                .expect("missing-plan depot metadata");
            metadata
                .insert(DEPOT_VARIANT_COUNT, 0)
                .expect("zero missing-plan variant counter");
            metadata
                .insert(DEPOT_RESERVED_FILE_BYTES, 0)
                .expect("zero missing-plan reservation counter");
        }
        write.commit().expect("commit self-consistent missing plan");
        drop(database);
        let database_before = blob_database_digest(&target_root.database);
        let depot_before = depot_file_snapshot(&target_root.depot());

        let error = Store::inspect_existing(&target_root.database)
            .expect_err("read-only audit rejects missing pending plan");
        assert_blob_schema_invariant(&error);
        let error = match Store::open_for_mission(&target_root.database, services.authority) {
            Ok(_) => panic!("writable audit rejects missing pending plan"),
            Err(error) => error,
        };
        assert_blob_schema_invariant(&error);
        assert_eq!(
            blob_database_digest(&target_root.database),
            database_before,
            "missing-plan rejection must not recreate depot rows"
        );
        assert_eq!(depot_file_snapshot(&target_root.depot()), depot_before);
    }

    #[test]
    fn pending_and_completed_blob_namespaces_are_exclusive_without_repair() {
        let source_root = BlobTestRoot::new("pending-completed-source");
        let target_root = BlobTestRoot::new("pending-completed-target");
        let mut services = blob_services(0xc5);
        let source = Store::open_for_mission(&source_root.database, services.authority)
            .expect("pending-completed source");
        let target = Store::open_for_mission(&target_root.database, services.authority)
            .expect("pending-completed target");
        let plaintext = vec![0xc5; SELECTED_BLOB_CHUNK_SIZE as usize + 7];
        let prepared = prepared_blob(&plaintext);
        let proof = prepare_blob_proof(&source, &mut services, &prepared, &plaintext, 1);
        let plan = proof
            .blob
            .transfer_plan(&proof.manifest_bytes)
            .expect("pending-completed transfer plan");
        let policy = target
            .control_policy_snapshot()
            .expect("pending-completed policy");
        target
            .stage_verified_blob_source_with_policy(&policy, &proof.blob, &proof.sealed, &plan)
            .expect("stage pending-completed fixture");
        let transfer = BlobTransferId::new(proof.blob.envelope_id());
        let pending_encoded = {
            let read = target
                .database
                .begin_read()
                .expect("pending-completed source read");
            read.open_table(BLOB_PENDING_SOURCES)
                .expect("pending-completed sources")
                .get(transfer.as_bytes().as_slice())
                .expect("pending-completed source lookup")
                .expect("pending-completed source row")
                .value()
                .to_vec()
        };
        transfer_all_blob_carriers(&source, &target, &policy, &plan);
        let depot_completion = target
            .blob_depot()
            .and_then(|mut depot| depot.completed_blob(&proof.blob, &proof.manifest_bytes))
            .expect("pending-completed depot completion");
        let content_completion = {
            let mut depot = target
                .blob_depot()
                .expect("pending-completed content depot");
            CoreBlobStore::begin_blob_with_lineage(
                &mut depot,
                plan.manifest(),
                plan.physical_lineage(),
            )
            .expect("activate pending-completed content plan");
            let mut service = services
                .reader
                .blob_service_with_store(&blob_scope(), &blob_topic(), 1, depot)
                .expect("pending-completed reader service");
            service
                .verify_blob_content_completion(&proof.blob, &proof.manifest_bytes)
                .expect("pending-completed content proof")
        };
        let lineage = services
            .reader
            .verify_current_blob_lineage(&proof.blob)
            .expect("pending-completed lineage");
        assert!(matches!(
            target
                .apply_verified_blob_with_policy(
                    &policy,
                    &plan,
                    &lineage,
                    &depot_completion,
                    &content_completion,
                )
                .expect("promote pending-completed fixture"),
            ApplyOutcome::Inserted { .. }
        ));
        drop(target);

        let database =
            Database::open(&target_root.database).expect("raw pending-completed database");
        let write = database
            .begin_write()
            .expect("pending-completed corruption write");
        write
            .open_table(BLOB_PENDING_SOURCES)
            .expect("pending-completed pending table")
            .insert(transfer.as_bytes().as_slice(), pending_encoded.as_slice())
            .expect("restore duplicate pending row");
        let staging_bytes = staging_entry_bytes(transfer.as_bytes().len(), pending_encoded.len())
            .expect("pending-completed staging bytes");
        {
            let mut metadata = write
                .open_table(BLOB_NETWORK_METADATA)
                .expect("pending-completed network metadata");
            metadata
                .insert(BLOB_NETWORK_STAGING_ROWS, 1)
                .expect("pending-completed row counter");
            metadata
                .insert(BLOB_NETWORK_STAGING_BYTES, staging_bytes)
                .expect("pending-completed byte counter");
        }
        write
            .commit()
            .expect("commit pending-completed namespace collision");
        drop(database);
        let database_before = blob_database_digest(&target_root.database);
        let depot_before = depot_file_snapshot(&target_root.depot());

        let error = Store::inspect_existing(&target_root.database)
            .expect_err("read-only audit rejects pending-completed collision");
        assert_blob_schema_invariant(&error);
        let error = match Store::open_for_mission(&target_root.database, services.authority) {
            Ok(_) => panic!("writable audit rejects pending-completed collision"),
            Err(error) => error,
        };
        assert_blob_schema_invariant(&error);
        assert_eq!(blob_database_digest(&target_root.database), database_before);
        assert_eq!(depot_file_snapshot(&target_root.depot()), depot_before);
    }

    #[test]
    fn legacy_metadata_v1_blob_is_rejected_when_current_lifecycle_authority_requires_lineage() {
        let root = BlobTestRoot::new("legacy-metadata-v1-network-omit");
        let mut services = blob_services(0xb1);
        let plaintext = b"legacy local Blob remains readable".to_vec();
        let prepared = prepared_blob(&plaintext);
        let store = Store::open_for_mission(&root.database, services.authority)
            .expect("legacy source store");
        let (stored, _, _) = publish_blob(
            &store,
            &mut services,
            &prepared,
            &plaintext,
            1,
            b"legacy-metadata-v1",
        );
        drop(store);

        let database = Database::open(&root.database).expect("raw legacy database");
        let write = database.begin_write().expect("legacy metadata write");
        let mut publications = write
            .open_table(BLOB_PUBLICATIONS)
            .expect("legacy publications");
        let encoded = publications
            .get(stored.transfer_id.as_bytes().as_slice())
            .expect("legacy metadata read")
            .expect("legacy metadata row")
            .value()
            .to_vec();
        assert_eq!(&encoded[..2], &[3, 1]);
        assert_eq!(encoded[2], BLOB_METADATA_VERSION);
        assert_eq!(encoded[163], 1, "current metadata must carry both lineages");
        let mut legacy = Vec::with_capacity(encoded.len() - 65);
        legacy.extend_from_slice(&encoded[..2]);
        legacy.push(BLOB_METADATA_VERSION_V1);
        legacy.extend_from_slice(&encoded[3..163]);
        legacy.extend_from_slice(&encoded[228..]);
        publications
            .insert(stored.transfer_id.as_bytes().as_slice(), legacy.as_slice())
            .expect("write legacy metadata-v1 row");
        drop(publications);
        write.commit().expect("commit legacy metadata-v1 row");
        drop(database);

        let before = blob_current_admission_digest_path(&root.database);
        assert!(matches!(
            Store::inspect_existing(&root.database),
            Err(StoreError::Blob(BlobStoreError::SchemaInvariant(_)))
        ));
        assert!(matches!(
            Store::open_for_mission(&root.database, services.authority),
            Err(StoreError::Blob(BlobStoreError::SchemaInvariant(_)))
        ));
        assert_eq!(blob_current_admission_digest_path(&root.database), before);
    }

    #[test]
    fn network_blob_reservation_deduplicates_and_terminal_abort_retains_bounded_staging() {
        let source_root = BlobTestRoot::new("network-reservation-source");
        let target_root = BlobTestRoot::new("network-reservation-target");
        let mut services = blob_services(0xb2);
        let source = Store::open_for_mission(&source_root.database, services.authority)
            .expect("source store");
        let plaintext = vec![0x61; SELECTED_BLOB_CHUNK_SIZE as usize];
        let prepared = prepared_blob(&plaintext);
        let first = prepare_blob_proof(&source, &mut services, &prepared, &plaintext, 1);
        let second = prepare_blob_proof(&source, &mut services, &prepared, &plaintext, 1);
        let first_plan = first
            .blob
            .transfer_plan(&first.manifest_bytes)
            .expect("first plan");
        let second_plan = second
            .blob
            .transfer_plan(&second.manifest_bytes)
            .expect("second plan");
        let reserved_limit = source
            .blob_stats()
            .expect("source stats")
            .reserved_file_bytes;
        let competing_plaintext = vec![0x62; SELECTED_BLOB_CHUNK_SIZE as usize];
        let competing_prepared = prepared_blob(&competing_plaintext);
        let competing = prepare_blob_proof(
            &source,
            &mut services,
            &competing_prepared,
            &competing_plaintext,
            1,
        );
        let competing_plan = competing
            .blob
            .transfer_plan(&competing.manifest_bytes)
            .expect("competing plan");
        let target = Store::open_with_limits_and_blob_depot_limits_for_mission(
            &target_root.database,
            StoreLimits::default(),
            BlobDepotLimits::new(reserved_limit, 16, 4).expect("target depot limits"),
            services.authority,
        )
        .expect("target store");
        let policy = target.control_policy_snapshot().expect("target policy");
        target
            .stage_verified_blob_source_with_policy(
                &policy,
                &first.blob,
                &first.sealed,
                &first_plan,
            )
            .expect("first stage");
        let reserved = target
            .blob_stats()
            .expect("first reservation")
            .reserved_file_bytes;
        target
            .stage_verified_blob_source_with_policy(
                &policy,
                &second.blob,
                &second.sealed,
                &second_plan,
            )
            .expect("shared-variant stage");
        assert_eq!(
            target
                .blob_stats()
                .expect("deduplicated reservation")
                .reserved_file_bytes,
            reserved
        );
        let before_competing = target.blob_stats().expect("before competing reservation");
        assert!(matches!(
            target.stage_verified_blob_source_with_policy(
                &policy,
                &competing.blob,
                &competing.sealed,
                &competing_plan,
            ),
            Err(StoreError::Blob(
                BlobStoreError::DepotByteLimitExceeded { .. }
            ))
        ));
        assert_eq!(
            target
                .blob_stats()
                .expect("competing plan made no mutation"),
            before_competing
        );
        assert!(
            target
                .pending_blob_source(BlobTransferId::new(competing.blob.envelope_id()))
                .expect("competing source absent")
                .is_none()
        );
        drop(target);
        let target = Store::open_with_limits_and_blob_depot_limits_for_mission(
            &target_root.database,
            StoreLimits::default(),
            BlobDepotLimits::new(reserved_limit, 16, 4).expect("retry limits"),
            services.authority,
        )
        .expect("reopen after competing rejection");
        assert_eq!(
            target.blob_stats().expect("reopened competing rejection"),
            before_competing
        );
        assert!(
            target
                .pending_blob_source(BlobTransferId::new(first.blob.envelope_id()))
                .expect("reopened first shared source")
                .is_some()
        );
        assert!(
            target
                .pending_blob_source(BlobTransferId::new(second.blob.envelope_id()))
                .expect("reopened second shared source")
                .is_some()
        );
        assert!(
            target
                .pending_blob_source(BlobTransferId::new(competing.blob.envelope_id()))
                .expect("reopened competing source absent")
                .is_none()
        );
        let abort_audits = test_blob_network_global_audits();
        assert!(
            target
                .abort_pending_blob_source(BlobTransferId::new(first.blob.envelope_id()))
                .expect("abort first shared source")
        );
        assert_eq!(test_blob_network_global_audits(), abort_audits);
        assert_eq!(
            target
                .blob_stats()
                .expect("shared reservation retained")
                .reserved_file_bytes,
            reserved
        );
        let final_abort_audits = test_blob_network_global_audits();
        assert!(
            target
                .abort_pending_blob_source(BlobTransferId::new(second.blob.envelope_id()))
                .expect("abort final source")
        );
        assert_eq!(test_blob_network_global_audits(), final_abort_audits);
        assert_eq!(
            target
                .blob_stats()
                .expect("abandoned reservation retained")
                .reserved_file_bytes,
            reserved
        );
        drop(target);
        let reopened = Store::open_with_limits_and_blob_depot_limits_for_mission(
            &target_root.database,
            StoreLimits::default(),
            BlobDepotLimits::new(reserved_limit, 16, 4).expect("reopen limits"),
            services.authority,
        )
        .expect("reopen bounded abandoned target");
        let stats = reopened.blob_stats().expect("reopened stats");
        assert_eq!(stats.reserved_file_bytes, reserved);
        assert_eq!(stats.pending_sources, 0);
        for transfer in [
            BlobTransferId::new(first.blob.envelope_id()),
            BlobTransferId::new(second.blob.envelope_id()),
        ] {
            assert!(
                reopened
                    .blob_source_projection(transfer)
                    .expect("abandoned source projection")
                    .is_none(),
                "quota-charged depot staging is not a pending or completed source"
            );
            assert!(
                reopened
                    .get_blob(transfer)
                    .expect("abandoned source visibility")
                    .is_none(),
                "quota-charged depot staging cannot gain semantic visibility"
            );
        }
        assert_eq!(
            stats.variants, 1,
            "the bounded variant slot remains charged to its lineage fence"
        );
    }

    #[test]
    fn network_blob_same_epoch_physical_lineage_requires_epoch_advance() {
        let old_source_root = BlobTestRoot::new("same-epoch-old-source");
        let new_source_root = BlobTestRoot::new("same-epoch-new-source");
        let target_root = BlobTestRoot::new("same-epoch-target");
        let mut services = blob_services(0xb3);
        let old_source = Store::open_for_mission(&old_source_root.database, services.authority)
            .expect("old source");
        let target =
            Store::open_for_mission(&target_root.database, services.authority).expect("target");
        let plaintext = b"same immutable Blob across same-epoch replacement".to_vec();
        let prepared = prepared_blob(&plaintext);
        let old = prepare_blob_proof(&old_source, &mut services, &prepared, &plaintext, 1);
        let old_plan = old
            .blob
            .transfer_plan(&old.manifest_bytes)
            .expect("old plan");
        let policy = target.control_policy_snapshot().expect("target policy");
        target
            .stage_verified_blob_source_with_policy(&policy, &old.blob, &old.sealed, &old_plan)
            .expect("stage old lineage");
        transfer_all_blob_carriers(&old_source, &target, &policy, &old_plan);
        let old_stats = target.blob_stats().expect("old target stats");
        let old_transfer = BlobTransferId::new(old.blob.envelope_id());
        let old_variant = BlobVariantId::for_content(
            old_plan.manifest().id(),
            old_plan.manifest().content_group(),
            old_plan.manifest().content_epoch(),
        );
        assert!(target_root.chunk_path(old_variant, 0).is_file());
        assert!(
            target
                .abort_pending_blob_source(old_transfer)
                .expect("abort old lineage")
        );
        assert!(
            target_root.chunk_path(old_variant, 0).is_file(),
            "abandoned ciphertext remains quota-charged without an explicit GC protocol"
        );
        let retired_stats = target.blob_stats().expect("retired lineage stats");
        assert_eq!(retired_stats.variants, 1);
        assert_eq!(
            retired_stats.finalized_variants,
            old_stats.finalized_variants
        );
        assert_eq!(retired_stats.committed_chunks, old_stats.committed_chunks);
        assert_eq!(
            retired_stats.committed_file_bytes,
            old_stats.committed_file_bytes
        );
        assert_eq!(
            retired_stats.reserved_file_bytes,
            old_stats.reserved_file_bytes
        );
        assert_eq!(retired_stats.pending_sources, 0);
        assert!(retired_stats.network_staging_bytes < old_stats.network_staging_bytes);
        drop(target);

        let target = Store::open_for_mission(&target_root.database, services.authority)
            .expect("reopen retired lineage target");
        assert_eq!(
            target.blob_stats().expect("reopened retired lineage"),
            retired_stats
        );
        assert_eq!(
            target
                .stage_verified_blob_source_with_policy(&policy, &old.blob, &old.sealed, &old_plan,)
                .expect("retry exact retired lineage"),
            BlobSourceStageOutcome::Inserted
        );
        assert!(
            target
                .abort_pending_blob_source(old_transfer)
                .expect("retire exact retry")
        );
        assert_eq!(
            target.blob_stats().expect("exact retry retired"),
            retired_stats
        );

        let registry = services
            .provisioner
            .export_rekey_registry()
            .expect("same-epoch registry");
        let (control, _) = services
            .publisher
            .seal_chained_scope_rekey_control_from_registry(
                &registry,
                0,
                blob_scope(),
                1,
                vec![
                    ScopeRekeyRecipient::member(services.publisher.identity(), vec![blob_topic()])
                        .expect("publisher recipient"),
                    ScopeRekeyRecipient::member(services.reader.identity(), vec![blob_topic()])
                        .expect("reader recipient"),
                ],
                1,
                None,
            )
            .expect("same-epoch control");
        for provider in [&mut services.publisher, &mut services.reader] {
            let verified = provider
                .verify_control(&control)
                .expect("verify same-epoch control");
            let ready = provider
                .prepare_committed_control_activation(&verified, &control)
                .expect("prepare same-epoch control");
            provider
                .activate_committed_control(ready, false)
                .expect("activate same-epoch control");
        }

        let new_source = Store::open_for_mission(&new_source_root.database, services.authority)
            .expect("new source");
        let replacement = prepare_blob_proof(&new_source, &mut services, &prepared, &plaintext, 1);
        assert_eq!(replacement.blob.blob_id(), old.blob.blob_id());
        assert_ne!(
            replacement.blob.physical_lineage(),
            old.blob.physical_lineage()
        );
        let replacement_plan = replacement
            .blob
            .transfer_plan(&replacement.manifest_bytes)
            .expect("replacement plan");
        assert!(matches!(
            target.stage_verified_blob_source_with_policy(
                &policy,
                &replacement.blob,
                &replacement.sealed,
                &replacement_plan,
            ),
            Err(StoreError::Blob(BlobStoreError::PhysicalLineageConflict))
        ));
        assert_eq!(
            target.blob_stats().expect("unchanged target"),
            retired_stats
        );
        assert!(
            target
                .pending_blob_source(old_transfer)
                .expect("old source retired")
                .is_none()
        );
        assert!(
            target
                .pending_blob_source(BlobTransferId::new(replacement.blob.envelope_id()))
                .expect("replacement absent")
                .is_none()
        );
        drop(target);
        let mut reopened = Store::open_for_mission(&target_root.database, services.authority)
            .expect("reopen unchanged target");
        assert_eq!(
            reopened.blob_stats().expect("reopened stats"),
            retired_stats
        );

        let same_epoch_verified = services
            .reader
            .verify_control(&control)
            .expect("verify same-epoch control for store");
        reopened
            .ingest_verified_control(&same_epoch_verified, &control)
            .expect("commit same-epoch control");
        let (epoch_two_control, _) = services
            .publisher
            .seal_chained_scope_rekey_control_from_registry(
                &registry,
                0,
                blob_scope(),
                2,
                vec![
                    ScopeRekeyRecipient::member(services.publisher.identity(), vec![blob_topic()])
                        .expect("epoch-two publisher recipient"),
                    ScopeRekeyRecipient::member(services.reader.identity(), vec![blob_topic()])
                        .expect("epoch-two reader recipient"),
                ],
                2,
                Some(same_epoch_verified.envelope_id()),
            )
            .expect("epoch-two control");
        let epoch_two_verified = services
            .reader
            .verify_control(&epoch_two_control)
            .expect("verify epoch-two control");
        reopened
            .ingest_verified_control(&epoch_two_verified, &epoch_two_control)
            .expect("commit epoch-two control");
        for provider in [&mut services.publisher, &mut services.reader] {
            let verified = provider
                .verify_control(&epoch_two_control)
                .expect("verify committed epoch-two control");
            let ready = provider
                .prepare_committed_control_activation(&verified, &epoch_two_control)
                .expect("prepare committed epoch-two control");
            provider
                .activate_committed_control(ready, false)
                .expect("activate committed epoch-two control");
        }

        let epoch_two_source_root = BlobTestRoot::new("epoch-two-lineage-source");
        let epoch_two_source =
            Store::open_for_mission(&epoch_two_source_root.database, services.authority)
                .expect("epoch-two source");
        let epoch_two =
            prepare_blob_proof(&epoch_two_source, &mut services, &prepared, &plaintext, 2);
        let epoch_two_plan = epoch_two
            .blob
            .transfer_plan(&epoch_two.manifest_bytes)
            .expect("epoch-two plan");
        let epoch_two_policy = reopened
            .control_policy_snapshot()
            .expect("epoch-two target policy");
        assert_eq!(
            reopened
                .stage_verified_blob_source_with_policy(
                    &epoch_two_policy,
                    &epoch_two.blob,
                    &epoch_two.sealed,
                    &epoch_two_plan,
                )
                .expect("numeric epoch advance"),
            BlobSourceStageOutcome::Inserted
        );
        assert_eq!(
            reopened
                .blob_stats()
                .expect("epoch-two variant accounting")
                .variants,
            2,
            "the retired epoch-one fence and active epoch-two variant share the cap"
        );
        assert!(
            reopened
                .abort_pending_blob_source(BlobTransferId::new(epoch_two.blob.envelope_id()))
                .expect("retire epoch-two source")
        );
        let terminal_stats = reopened
            .blob_stats()
            .expect("two retired lineage reservations");
        assert_eq!(terminal_stats.variants, 2);
        assert_eq!(terminal_stats.pending_sources, 0);
        let intent = ZeroizationIntent::new(
            b"lineage-fence mission descriptor".to_vec(),
            b"lineage-fence identity descriptor".to_vec(),
        )
        .expect("terminal lineage-fence intent");
        reopened
            .begin_zeroization(&intent)
            .expect("enter terminal state with lineage fences");
        drop(reopened);
        let cleanup = Store::open_for_zeroization(&target_root.database)
            .expect("open terminal lineage-fence inspection");
        assert_eq!(
            cleanup
                .inspect_preserved()
                .expect("terminal audit preserves lineage fences")
                .blob_stats,
            terminal_stats
        );
    }

    #[test]
    fn network_blob_promotion_capacity_failure_keeps_retryable_pending_state() {
        let source_root = BlobTestRoot::new("promotion-capacity-source");
        let target_root = BlobTestRoot::new("promotion-capacity-target");
        let mut services = blob_services(0xb4);
        let source =
            Store::open_for_mission(&source_root.database, services.authority).expect("source");
        let tight = StoreLimits::new(1, 1).expect("tight ordinary limits");
        let target = Store::open_with_limits_and_blob_depot_limits_for_mission(
            &target_root.database,
            tight,
            BlobDepotLimits::default(),
            services.authority,
        )
        .expect("tight target");
        let plaintext = vec![0x74; 512];
        let prepared = prepared_blob(&plaintext);
        let proof = prepare_blob_proof(&source, &mut services, &prepared, &plaintext, 1);
        let plan = proof
            .blob
            .transfer_plan(&proof.manifest_bytes)
            .expect("plan");
        let policy = target.control_policy_snapshot().expect("target policy");
        target
            .stage_verified_blob_source_with_policy(&policy, &proof.blob, &proof.sealed, &plan)
            .expect("stage under dedicated network quota");
        transfer_all_blob_carriers(&source, &target, &policy, &plan);
        let depot_completion = target
            .blob_depot()
            .and_then(|mut depot| depot.completed_blob(&proof.blob, &proof.manifest_bytes))
            .expect("depot complete");
        let content_completion = {
            let mut depot = target.blob_depot().expect("content depot");
            CoreBlobStore::begin_blob_with_lineage(
                &mut depot,
                plan.manifest(),
                plan.physical_lineage(),
            )
            .expect("activate content depot");
            let mut service = services
                .reader
                .blob_service_with_store(&blob_scope(), &blob_topic(), 1, depot)
                .expect("reader service");
            service
                .verify_blob_content_completion(&proof.blob, &proof.manifest_bytes)
                .expect("content completion")
        };
        let lineage = services
            .reader
            .verify_current_blob_lineage(&proof.blob)
            .expect("current lineage");
        let transfer = BlobTransferId::new(proof.blob.envelope_id());
        let before = target.blob_stats().expect("before capacity failure");
        let before_io = depot::test_depot_io_counts(&target);
        assert!(matches!(
            target.apply_verified_blob_with_policy(
                &policy,
                &plan,
                &lineage,
                &depot_completion,
                &content_completion,
            ),
            Err(StoreError::ItemLimitExceeded { .. })
                | Err(StoreError::PayloadByteLimitExceeded { .. })
        ));
        assert_eq!(
            depot::test_depot_io_counts(&target).full_completion_rechecks,
            before_io.full_completion_rechecks,
            "capacity-deferred promotion cannot rescan completed Blob files"
        );
        assert_eq!(target.blob_stats().expect("no mutation"), before);
        assert!(target.get_blob(transfer).expect("no publication").is_none());
        assert!(
            target
                .pending_blob_source(transfer)
                .expect("pending retained")
                .is_some()
        );
        drop(target);

        let reopened = Store::open_with_limits_and_blob_depot_limits_for_mission(
            &target_root.database,
            tight,
            BlobDepotLimits::default(),
            services.authority,
        )
        .expect("reopen tight target");
        assert_eq!(reopened.blob_stats().expect("reopened no mutation"), before);
        assert!(
            reopened
                .pending_blob_source(transfer)
                .expect("retryable pending")
                .is_some()
        );
        reopened
            .blob_depot()
            .and_then(|mut depot| depot.completed_blob(&proof.blob, &proof.manifest_bytes))
            .expect("depot completion survives reopen");
    }

    #[test]
    fn network_blob_promotion_frontier_capacity_is_typed_and_transactional() {
        let source_root = BlobTestRoot::new("promotion-frontier-source");
        let target_root = BlobTestRoot::new("promotion-frontier-target");
        let mut services = blob_services(0xb5);
        let source = Store::open_for_mission(&source_root.database, services.authority)
            .expect("frontier source");
        let target = Store::open_for_mission(&target_root.database, services.authority)
            .expect("frontier target");
        let plaintext = vec![0x75; 512];
        let prepared = prepared_blob(&plaintext);
        let proof = prepare_blob_proof(&source, &mut services, &prepared, &plaintext, 1);
        let plan = proof
            .blob
            .transfer_plan(&proof.manifest_bytes)
            .expect("frontier plan");
        let policy = target.control_policy_snapshot().expect("frontier policy");
        target
            .stage_verified_blob_source_with_policy(&policy, &proof.blob, &proof.sealed, &plan)
            .expect("frontier stage");
        transfer_all_blob_carriers(&source, &target, &policy, &plan);
        let depot_completion = target
            .blob_depot()
            .and_then(|mut depot| depot.completed_blob(&proof.blob, &proof.manifest_bytes))
            .expect("frontier depot completion");
        let content_completion = {
            let mut depot = target.blob_depot().expect("frontier content depot");
            CoreBlobStore::begin_blob_with_lineage(
                &mut depot,
                plan.manifest(),
                plan.physical_lineage(),
            )
            .expect("activate frontier content depot");
            let mut service = services
                .reader
                .blob_service_with_store(&blob_scope(), &blob_topic(), 1, depot)
                .expect("frontier reader service");
            service
                .verify_blob_content_completion(&proof.blob, &proof.manifest_bytes)
                .expect("frontier content completion")
        };
        let lineage = services
            .reader
            .verify_current_blob_lineage(&proof.blob)
            .expect("frontier current lineage");

        let incoming_publisher = services.publisher.identity();
        let write = target
            .database
            .begin_write()
            .expect("begin Blob frontier seed");
        let mut frontier = write.open_table(CAUSAL_FRONTIER).expect("Blob frontier");
        let mut inserted = 0usize;
        let mut candidate = 0u64;
        while inserted < MAX_CAUSAL_CONTEXT_ENTRIES {
            let mut publisher = [0xbd; 32];
            publisher[24..].copy_from_slice(&candidate.to_be_bytes());
            candidate += 1;
            if publisher == incoming_publisher {
                continue;
            }
            let key = causal_frontier_key(&blob_topic(), &blob_scope(), publisher)
                .expect("Blob frontier key");
            frontier
                .insert(key.as_slice(), 1)
                .expect("seed Blob frontier");
            inserted += 1;
        }
        drop(frontier);
        write.commit().expect("commit Blob frontier seed");

        let transfer = BlobTransferId::new(proof.blob.envelope_id());
        let before = target.blob_stats().expect("before frontier rejection");
        assert!(matches!(
            target.apply_verified_blob_with_policy(
                &policy,
                &plan,
                &lineage,
                &depot_completion,
                &content_completion,
            ),
            Err(StoreError::Blob(
                BlobStoreError::CausalFrontierLimitExceeded {
                    current: MAX_CAUSAL_CONTEXT_ENTRIES,
                    limit: MAX_CAUSAL_CONTEXT_ENTRIES,
                }
            ))
        ));
        assert_eq!(target.blob_stats().expect("frontier no mutation"), before);
        assert!(
            target
                .get_blob(transfer)
                .expect("frontier invisible")
                .is_none()
        );
        assert!(
            target
                .pending_blob_source(transfer)
                .expect("frontier pending retained")
                .is_some()
        );
    }

    fn reserved_event(
        store: &Store,
        services: &mut BlobServices,
        policy: &ControlPolicySnapshot,
        payload: &[u8],
    ) -> (
        EventReservation,
        aster_mesh::ContentVerifiedEventEnvelope,
        Vec<u8>,
    ) {
        let reservation = store
            .reserve_event_with_policy(
                policy,
                services.publisher.identity(),
                &blob_topic(),
                &blob_scope(),
            )
            .expect("Event reservation after Blob");
        let header = reservation
            .header(
                Priority::Immediate,
                b"after/blob".to_vec(),
                None,
                u64::try_from(payload.len()).expect("Event length"),
                false,
                1,
            )
            .expect("Event header");
        let sealed = services
            .publisher
            .seal_event(&header, payload)
            .expect("seal Event");
        let route = services
            .reader
            .verify_event(&sealed.bytes)
            .expect("verify Event route");
        let event = match services
            .reader
            .verify_event_content(route, &sealed.bytes)
            .expect("verify Event content")
        {
            EventContentVerification::ContentVerified { event, .. } => event,
            EventContentVerification::RouteOnly(_) => panic!("member unexpectedly route-only"),
        };
        (reservation, event, sealed.bytes)
    }

    fn assert_depot_integrity(error: &StoreError) {
        assert!(matches!(
            error,
            StoreError::Blob(BlobStoreError::DepotIntegrity(_))
        ));
    }

    fn assert_blob_schema_invariant(error: &StoreError) {
        assert!(matches!(
            error,
            StoreError::Blob(BlobStoreError::SchemaInvariant(_))
        ));
    }

    fn directory_entry_count(path: &Path) -> usize {
        std::fs::read_dir(path)
            .expect("read depot directory")
            .count()
    }

    fn file_digest(path: &Path) -> [u8; 32] {
        Sha256::digest(std::fs::read(path).expect("read digest fixture")).into()
    }

    fn blob_database_digest(path: &Path) -> [u8; 32] {
        let database = redb::Builder::new()
            .open_read_only(path)
            .expect("read-only Blob digest database");
        let read = database.begin_read().expect("Blob digest transaction");
        blob_database_digest_read(&read)
    }

    fn blob_database_digest_read(read: &redb::ReadTransaction) -> [u8; 32] {
        let mut digest = Sha256::new();
        macro_rules! bytes_table {
            ($definition:expr) => {
                for row in read
                    .open_table($definition)
                    .expect("Blob digest bytes table")
                    .iter()
                    .expect("Blob digest bytes rows")
                {
                    let (key, value) = row.expect("Blob digest bytes row");
                    digest.update(
                        u64::try_from(key.value().len())
                            .expect("Blob digest key length")
                            .to_be_bytes(),
                    );
                    digest.update(key.value());
                    digest.update(
                        u64::try_from(value.value().len())
                            .expect("Blob digest value length")
                            .to_be_bytes(),
                    );
                    digest.update(value.value());
                }
            };
        }
        macro_rules! byte_u64_table {
            ($definition:expr) => {
                for row in read
                    .open_table($definition)
                    .expect("Blob digest byte/u64 table")
                    .iter()
                    .expect("Blob digest byte/u64 rows")
                {
                    let (key, value) = row.expect("Blob digest byte/u64 row");
                    digest.update(
                        u64::try_from(key.value().len())
                            .expect("Blob digest key length")
                            .to_be_bytes(),
                    );
                    digest.update(key.value());
                    digest.update(value.value().to_be_bytes());
                }
            };
        }
        bytes_table!(BLOB_PUBLICATIONS);
        bytes_table!(BLOB_BYTES);
        bytes_table!(BLOB_SEMANTIC_ITEMS);
        bytes_table!(BLOB_CONTENT_INDEX);
        bytes_table!(BLOB_OPERATIONS);
        bytes_table!(BLOB_IMPORTS);
        bytes_table!(BLOB_CHUNKS);
        bytes_table!(BLOB_PENDING_SOURCES);
        bytes_table!(BLOB_CARRIER_PREFIXES);
        bytes_table!(BLOB_CARRIER_FETCH_CURSORS);
        bytes_table!(ACCEPTED_DOTS);
        byte_u64_table!(BLOB_ACCEPTANCE_MARKERS);
        byte_u64_table!(PUBLISHER_HIGH_WATER);
        byte_u64_table!(CAUSAL_FRONTIER);
        for row in read
            .open_table(BLOB_DEPOT_METADATA)
            .expect("Blob depot digest metadata")
            .iter()
            .expect("Blob depot digest rows")
        {
            let (key, value) = row.expect("Blob depot digest row");
            digest.update(key.value().as_bytes());
            digest.update(value.value().to_be_bytes());
        }
        for row in read
            .open_table(BLOB_NETWORK_METADATA)
            .expect("Blob digest network metadata")
            .iter()
            .expect("Blob digest network rows")
        {
            let (key, value) = row.expect("Blob digest network row");
            digest.update(key.value().as_bytes());
            digest.update(value.value().to_be_bytes());
        }
        for field in blob_global_metadata_fields() {
            digest.update(field.as_bytes());
            digest.update(
                read.open_table(METADATA)
                    .expect("Blob digest global metadata")
                    .get(field)
                    .expect("Blob digest global read")
                    .map_or(u64::MAX, |value| value.value())
                    .to_be_bytes(),
            );
        }
        digest.finalize().into()
    }

    fn blob_current_admission_digest(store: &Store) -> [u8; 32] {
        let read = store
            .database
            .begin_read()
            .expect("current Blob admission digest transaction");
        blob_current_admission_digest_read(&read)
    }

    fn blob_current_admission_digest_path(path: &Path) -> [u8; 32] {
        let database = redb::Builder::new()
            .open_read_only(path)
            .expect("read-only current Blob admission database");
        let read = database
            .begin_read()
            .expect("current Blob admission digest transaction");
        blob_current_admission_digest_read(&read)
    }

    fn blob_current_admission_digest_read(read: &redb::ReadTransaction) -> [u8; 32] {
        let application_digest = blob_database_digest_read(read);
        let mut digest = Sha256::new();
        digest.update(application_digest);
        for row in read
            .open_table(BLOB_ACCEPTANCE_ORDER)
            .expect("Blob acceptance-order table")
            .iter()
            .expect("Blob acceptance-order rows")
        {
            let (key, value) = row.expect("Blob acceptance-order row");
            digest.update(key.value().to_be_bytes());
            digest.update(value.value());
        }
        for definition in [
            lifecycle::BLOB_VARIANT_REFERENCES,
            lifecycle::BLOB_LINEAGE_FENCES,
            lifecycle::BLOB_REPLAY_FENCES,
        ] {
            for row in read
                .open_table(definition)
                .expect("Blob lifecycle bytes table")
                .iter()
                .expect("Blob lifecycle bytes rows")
            {
                let (key, value) = row.expect("Blob lifecycle bytes row");
                digest.update(
                    u64::try_from(key.value().len())
                        .expect("Blob lifecycle key length")
                        .to_be_bytes(),
                );
                digest.update(key.value());
                digest.update(
                    u64::try_from(value.value().len())
                        .expect("Blob lifecycle value length")
                        .to_be_bytes(),
                );
                digest.update(value.value());
            }
        }
        for row in read
            .open_table(lifecycle::BLOB_LIFECYCLE_METADATA)
            .expect("Blob lifecycle metadata table")
            .iter()
            .expect("Blob lifecycle metadata rows")
        {
            let (key, value) = row.expect("Blob lifecycle metadata row");
            digest.update(key.value().as_bytes());
            digest.update(value.value().to_be_bytes());
        }
        for row in read
            .open_table(lifecycle::BLOB_MAINTENANCE_CURSORS)
            .expect("Blob lifecycle cursor table")
            .iter()
            .expect("Blob lifecycle cursor rows")
        {
            let (key, value) = row.expect("Blob lifecycle cursor row");
            digest.update([key.value()]);
            digest.update(value.value());
        }
        digest.finalize().into()
    }

    fn blob_lifecycle_tables_present(path: &Path) -> BTreeSet<String> {
        let database = redb::Builder::new()
            .open_read_only(path)
            .expect("read lifecycle table names");
        database
            .begin_read()
            .expect("lifecycle table-name transaction")
            .list_tables()
            .expect("lifecycle table names")
            .map(|table| table.name().to_owned())
            .filter(|name| {
                [
                    lifecycle::BLOB_LIFECYCLE_METADATA.name(),
                    lifecycle::BLOB_VARIANT_REFERENCES.name(),
                    lifecycle::BLOB_LINEAGE_FENCES.name(),
                    lifecycle::BLOB_REPLAY_FENCES.name(),
                    lifecycle::BLOB_MAINTENANCE_CURSORS.name(),
                ]
                .contains(&name.as_str())
            })
            .collect()
    }

    fn with_blob_lifecycle_predecessor_setup<T>(setup: impl FnOnce() -> T) -> T {
        lifecycle::TEST_BLOB_LIFECYCLE_MIGRATION_DISABLED.set(true);
        let output = setup();
        lifecycle::TEST_BLOB_LIFECYCLE_MIGRATION_DISABLED.set(false);
        output
    }

    fn strip_blob_lifecycle_schema_for_test(path: &Path) {
        let database = Database::open(path).expect("raw lifecycle predecessor database");
        let write = database
            .begin_write()
            .expect("raw lifecycle predecessor write");
        let existing = write
            .list_tables()
            .expect("predecessor table names")
            .map(|table| table.name().to_owned())
            .collect::<BTreeSet<_>>();
        if existing.contains(lifecycle::BLOB_LIFECYCLE_METADATA.name()) {
            write
                .delete_table(lifecycle::BLOB_LIFECYCLE_METADATA)
                .expect("delete lifecycle metadata");
        }
        if existing.contains(lifecycle::BLOB_VARIANT_REFERENCES.name()) {
            write
                .delete_table(lifecycle::BLOB_VARIANT_REFERENCES)
                .expect("delete lifecycle references");
        }
        if existing.contains(lifecycle::BLOB_LINEAGE_FENCES.name()) {
            write
                .delete_table(lifecycle::BLOB_LINEAGE_FENCES)
                .expect("delete lifecycle lineage fences");
        }
        if existing.contains(lifecycle::BLOB_REPLAY_FENCES.name()) {
            write
                .delete_table(lifecycle::BLOB_REPLAY_FENCES)
                .expect("delete lifecycle replay fences");
        }
        if existing.contains(lifecycle::BLOB_MAINTENANCE_CURSORS.name()) {
            write
                .delete_table(lifecycle::BLOB_MAINTENANCE_CURSORS)
                .expect("delete lifecycle cursors");
        }

        let publications = write
            .open_table(BLOB_PUBLICATIONS)
            .expect("predecessor publications");
        let publication_rows = publications
            .iter()
            .expect("predecessor publication rows")
            .map(|row| {
                let (key, value) = row.expect("predecessor publication row");
                (key.value().to_vec(), value.value().to_vec())
            })
            .collect::<Vec<_>>();
        drop(publications);
        let mut publications = write
            .open_table(BLOB_PUBLICATIONS)
            .expect("rewrite predecessor publications");
        for (key, value) in publication_rows {
            if value.len() >= 3 && value[0] == 3 && value[1] == 1 && matches!(value[2], 1 | 2) {
                publications
                    .insert(key.as_slice(), &value[2..])
                    .expect("unwrap predecessor publication");
            }
        }
        drop(publications);

        let operations = write
            .open_table(BLOB_OPERATIONS)
            .expect("predecessor operations");
        let operation_rows = operations
            .iter()
            .expect("predecessor operation rows")
            .map(|row| {
                let (key, value) = row.expect("predecessor operation row");
                (key.value().to_vec(), value.value().to_vec())
            })
            .collect::<Vec<_>>();
        drop(operations);
        let mut operations = write
            .open_table(BLOB_OPERATIONS)
            .expect("rewrite predecessor operations");
        for (key, value) in operation_rows {
            if value.len() >= 3 && value[0] == 2 && value[1] == 1 && value[2] == 1 {
                operations
                    .insert(key.as_slice(), &value[2..])
                    .expect("unwrap predecessor operation");
            }
        }
        drop(operations);
        write.commit().expect("commit lifecycle predecessor");
    }

    fn assert_blob_lifecycle_current_shape(
        path: &Path,
        lineage_rows: u64,
        replay_rows: u64,
        reference_rows: u64,
        publication_rows: u64,
        operation_rows: u64,
    ) {
        let expected = [
            lifecycle::BLOB_LIFECYCLE_METADATA.name(),
            lifecycle::BLOB_VARIANT_REFERENCES.name(),
            lifecycle::BLOB_LINEAGE_FENCES.name(),
            lifecycle::BLOB_REPLAY_FENCES.name(),
            lifecycle::BLOB_MAINTENANCE_CURSORS.name(),
        ]
        .into_iter()
        .map(str::to_owned)
        .collect::<BTreeSet<_>>();
        assert_eq!(blob_lifecycle_tables_present(path), expected);
        let database = redb::Builder::new()
            .open_read_only(path)
            .expect("read migrated lifecycle database");
        let read = database.begin_read().expect("read migrated lifecycle");
        assert_eq!(
            read.open_table(lifecycle::BLOB_LINEAGE_FENCES)
                .expect("lineage fences")
                .len()
                .expect("lineage fence count"),
            lineage_rows
        );
        assert_eq!(
            read.open_table(lifecycle::BLOB_REPLAY_FENCES)
                .expect("replay fences")
                .len()
                .expect("replay fence count"),
            replay_rows
        );
        assert_eq!(
            read.open_table(lifecycle::BLOB_VARIANT_REFERENCES)
                .expect("variant references")
                .len()
                .expect("variant reference count"),
            reference_rows
        );
        assert_eq!(
            read.open_table(lifecycle::BLOB_MAINTENANCE_CURSORS)
                .expect("maintenance cursors")
                .len()
                .expect("maintenance cursor count"),
            7
        );
        let publications = read
            .open_table(BLOB_PUBLICATIONS)
            .expect("wrapped publications");
        assert_eq!(
            publications.len().expect("publication count"),
            publication_rows
        );
        for row in publications.iter().expect("publication rows") {
            let (_, value) = row.expect("publication row");
            assert_eq!(&value.value()[..2], &[3, 1]);
        }
        let operations = read
            .open_table(BLOB_OPERATIONS)
            .expect("wrapped operations");
        assert_eq!(operations.len().expect("operation count"), operation_rows);
        for row in operations.iter().expect("operation rows") {
            let (_, value) = row.expect("operation row");
            assert_eq!(
                lifecycle::OperationState::decode(&value.value()[..1])
                    .expect("active operation wrapper"),
                lifecycle::OperationState::Active
            );
        }
    }

    fn blob_lifecycle_digest(path: &Path) -> [u8; 32] {
        let database = redb::Builder::new()
            .open_read_only(path)
            .expect("read lifecycle digest database");
        let read = database.begin_read().expect("lifecycle digest transaction");
        let mut digest = Sha256::new();
        for row in read
            .open_table(lifecycle::BLOB_LIFECYCLE_METADATA)
            .expect("lifecycle digest metadata")
            .iter()
            .expect("lifecycle digest metadata rows")
        {
            let (key, value) = row.expect("lifecycle digest metadata row");
            digest.update(key.value().as_bytes());
            digest.update(value.value().to_be_bytes());
        }
        for table in [
            lifecycle::BLOB_VARIANT_REFERENCES,
            lifecycle::BLOB_LINEAGE_FENCES,
            lifecycle::BLOB_REPLAY_FENCES,
        ] {
            digest.update(table.name().as_bytes());
            for row in read
                .open_table(table)
                .expect("lifecycle digest table")
                .iter()
                .expect("lifecycle digest rows")
            {
                let (key, value) = row.expect("lifecycle digest row");
                digest.update(key.value());
                digest.update(value.value());
            }
        }
        for row in read
            .open_table(lifecycle::BLOB_MAINTENANCE_CURSORS)
            .expect("lifecycle digest cursors")
            .iter()
            .expect("lifecycle digest cursor rows")
        {
            let (key, value) = row.expect("lifecycle digest cursor row");
            digest.update([key.value()]);
            digest.update(value.value());
        }
        digest.finalize().into()
    }

    fn commit_blob_proof(
        store: &Store,
        services: &BlobServices,
        proof: &BlobProof,
        operation_bytes: &[u8],
    ) -> (BlobOnceOutcome, BlobOperationKey, BlobPublicationIntent) {
        let operation = BlobOperationKey::new(operation_bytes.to_vec()).expect("operation key");
        let intent = BlobPublicationIntent::new(
            services.publisher.identity(),
            blob_topic(),
            blob_scope(),
            Priority::Immediate,
            proof.blob.blob_id(),
        )
        .expect("Blob intent");
        let request = BlobOperationRequest::new(&operation, &intent);
        let outcome = store
            .commit_reserved_blob_once_with_policy(
                &proof.policy,
                &request,
                &proof.reservation,
                &proof.blob,
                &proof.sealed,
                &proof.completion,
            )
            .expect("commit Blob proof");
        (outcome, operation, intent)
    }

    fn assert_blob_lifecycle_reference(
        store: &Store,
        variant: BlobVariantId,
        owner_tag: u8,
        transfer: BlobTransferId,
        expected: bool,
    ) {
        let mut key = Vec::with_capacity(65);
        key.extend_from_slice(variant.as_bytes());
        key.push(owner_tag);
        key.extend_from_slice(transfer.as_bytes());
        let read = store
            .database
            .begin_read()
            .expect("lifecycle reference read");
        let present = read
            .open_table(lifecycle::BLOB_VARIANT_REFERENCES)
            .expect("lifecycle reference table")
            .get(key.as_slice())
            .expect("lifecycle reference lookup")
            .map(|value| value.value().to_vec());
        assert_eq!(present.as_deref(), expected.then_some(&[][..]));
    }

    #[derive(Clone, Copy)]
    enum BlobCausalPointCorruption {
        ConflictingAcceptedDot,
        LaggingPublisherHighWater,
        MissingFrontier,
    }

    fn corrupt_blob_causal_point(
        store: &Store,
        blob: &StoredBlob,
        corruption: BlobCausalPointCorruption,
    ) {
        let dot = blob.header.stamp.dot;
        let write = store
            .database
            .begin_write()
            .expect("causal point corruption transaction");
        match corruption {
            BlobCausalPointCorruption::ConflictingAcceptedDot => {
                let conflicting = [0xa7; 32];
                assert_ne!(conflicting, *blob.semantic_id.as_bytes());
                write
                    .open_table(ACCEPTED_DOTS)
                    .expect("accepted-dot table")
                    .insert(accepted_dot_key(dot).as_slice(), conflicting.as_slice())
                    .expect("conflict accepted dot");
            }
            BlobCausalPointCorruption::LaggingPublisherHighWater => {
                assert_ne!(dot.counter, 0);
                write
                    .open_table(PUBLISHER_HIGH_WATER)
                    .expect("publisher high-water table")
                    .insert(dot.publisher.as_slice(), dot.counter - 1)
                    .expect("lag publisher high-water");
            }
            BlobCausalPointCorruption::MissingFrontier => {
                let key =
                    causal_frontier_key(&blob.header.topic, &blob.header.scope, dot.publisher)
                        .expect("causal frontier key");
                write
                    .open_table(CAUSAL_FRONTIER)
                    .expect("causal frontier table")
                    .remove(key.as_slice())
                    .expect("remove causal frontier")
                    .expect("causal frontier row");
            }
        }
        write.commit().expect("commit causal point corruption");
    }

    #[test]
    fn blob_lifecycle_admission_review_replay_without_live_root_fails_closed() {
        let root = BlobTestRoot::new("lifecycle-review-replay-root");
        let mut services = blob_services(0xe0);
        let plaintext = b"replay authority cannot stand in for a live publication".to_vec();
        let prepared = prepared_blob(&plaintext);
        let store =
            Store::open_for_mission(&root.database, services.authority).expect("replay-root store");
        let proof = prepare_blob_proof(&store, &mut services, &prepared, &plaintext, 1);
        let (outcome, _, _) = commit_blob_proof(&store, &services, &proof, b"review-replay-root");
        assert!(outcome.inserted());
        let transfer = BlobTransferId::new(proof.blob.envelope_id());
        let plan = proof
            .blob
            .transfer_plan(&proof.manifest_bytes)
            .expect("replay-root transfer plan");

        let write = store
            .database
            .begin_write()
            .expect("remove live publication root");
        let removed = write
            .open_table(BLOB_PUBLICATIONS)
            .expect("publication table")
            .remove(transfer.as_bytes().as_slice())
            .expect("remove publication root")
            .map(|value| value.value().to_vec());
        assert!(removed.is_some());
        write.commit().expect("commit missing publication root");
        let before = blob_current_admission_digest(&store);

        let error = store
            .stage_verified_blob_source_with_policy(
                &proof.policy,
                &proof.blob,
                &proof.sealed,
                &plan,
            )
            .expect_err("replay authority without its live root must fail closed");
        assert_blob_schema_invariant(&error);
        assert_eq!(blob_current_admission_digest(&store), before);
    }

    #[test]
    fn blob_lifecycle_admission_review_local_retries_require_each_causal_point() {
        for (index, corruption) in [
            BlobCausalPointCorruption::ConflictingAcceptedDot,
            BlobCausalPointCorruption::LaggingPublisherHighWater,
            BlobCausalPointCorruption::MissingFrontier,
        ]
        .into_iter()
        .enumerate()
        {
            let root = BlobTestRoot::new(&format!("lifecycle-review-local-causal-{index}"));
            let mut services = blob_services(0xe1 + u8::try_from(index).expect("case index"));
            let plaintext = format!("local causal retry case {index}").into_bytes();
            let prepared = prepared_blob(&plaintext);
            let store = Store::open_for_mission(&root.database, services.authority)
                .expect("local causal store");
            let proof = prepare_blob_proof(&store, &mut services, &prepared, &plaintext, 1);
            let (outcome, operation, intent) = commit_blob_proof(
                &store,
                &services,
                &proof,
                format!("review-local-causal-{index}").as_bytes(),
            );
            let stored = outcome.blob().clone();
            corrupt_blob_causal_point(&store, &stored, corruption);
            let before = blob_current_admission_digest(&store);

            let exact_request = BlobOperationRequest::new(&operation, &intent);
            let exact_error = store
                .commit_reserved_blob_once_with_policy(
                    &proof.policy,
                    &exact_request,
                    &proof.reservation,
                    &proof.blob,
                    &proof.sealed,
                    &proof.completion,
                )
                .expect_err("exact operation retry requires durable causal points");
            assert_blob_schema_invariant(&exact_error);
            assert_eq!(blob_current_admission_digest(&store), before);

            let bound_operation =
                BlobOperationKey::new(format!("review-local-bound-causal-{index}").into_bytes())
                    .expect("bound-existing operation");
            let bound_request = BlobOperationRequest::new(&bound_operation, &intent);
            let bound_error = store
                .commit_reserved_blob_once_with_policy(
                    &proof.policy,
                    &bound_request,
                    &proof.reservation,
                    &proof.blob,
                    &proof.sealed,
                    &proof.completion,
                )
                .expect_err("same-publication binding requires durable causal points");
            assert_blob_schema_invariant(&bound_error);
            assert_eq!(blob_current_admission_digest(&store), before);
            assert!(
                store
                    .blob_for_operation(&bound_operation)
                    .expect("bound operation lookup")
                    .is_none()
            );
        }
    }

    #[test]
    fn blob_lifecycle_admission_review_accepted_stage_requires_causal_points() {
        let root = BlobTestRoot::new("lifecycle-review-stage-causal");
        let mut services = blob_services(0xe4);
        let plaintext = b"accepted stage duplicate causal evidence".to_vec();
        let prepared = prepared_blob(&plaintext);
        let store = Store::open_for_mission(&root.database, services.authority)
            .expect("accepted-stage store");
        let proof = prepare_blob_proof(&store, &mut services, &prepared, &plaintext, 1);
        let (outcome, _, _) = commit_blob_proof(&store, &services, &proof, b"review-stage-causal");
        let stored = outcome.blob().clone();
        let plan = proof
            .blob
            .transfer_plan(&proof.manifest_bytes)
            .expect("accepted-stage transfer plan");
        corrupt_blob_causal_point(
            &store,
            &stored,
            BlobCausalPointCorruption::ConflictingAcceptedDot,
        );
        let before = blob_current_admission_digest(&store);

        let error = store
            .stage_verified_blob_source_with_policy(
                &proof.policy,
                &proof.blob,
                &proof.sealed,
                &plan,
            )
            .expect_err("accepted stage duplicate requires causal authority");
        assert_blob_schema_invariant(&error);
        assert_eq!(blob_current_admission_digest(&store), before);
    }

    #[test]
    fn blob_lifecycle_admission_review_accepted_promotion_requires_causal_points() {
        let root = BlobTestRoot::new("lifecycle-review-promotion-causal");
        let mut services = blob_services(0xe5);
        let plaintext = b"accepted promotion duplicate causal evidence".to_vec();
        let prepared = prepared_blob(&plaintext);
        let store = Store::open_for_mission(&root.database, services.authority)
            .expect("accepted-promotion store");
        let proof = prepare_blob_proof(&store, &mut services, &prepared, &plaintext, 1);
        let (outcome, _, _) =
            commit_blob_proof(&store, &services, &proof, b"review-promotion-causal");
        let stored = outcome.blob().clone();
        let plan = proof
            .blob
            .transfer_plan(&proof.manifest_bytes)
            .expect("accepted-promotion transfer plan");
        let content_completion = {
            let mut depot = store.blob_depot().expect("accepted-promotion depot");
            CoreBlobStore::begin_blob_with_lineage(
                &mut depot,
                plan.manifest(),
                plan.physical_lineage(),
            )
            .expect("activate accepted-promotion depot");
            let mut service = services
                .reader
                .blob_service_with_store(&blob_scope(), &blob_topic(), 1, depot)
                .expect("accepted-promotion reader service");
            service
                .verify_blob_content_completion(&proof.blob, &proof.manifest_bytes)
                .expect("accepted-promotion content completion")
        };
        let lineage = services
            .reader
            .verify_current_blob_lineage(&proof.blob)
            .expect("accepted-promotion lineage");
        corrupt_blob_causal_point(&store, &stored, BlobCausalPointCorruption::MissingFrontier);
        let before = blob_current_admission_digest(&store);

        let error = store
            .apply_verified_blob_with_policy(
                &proof.policy,
                &plan,
                &lineage,
                &proof.completion,
                &content_completion,
            )
            .expect_err("accepted promotion duplicate requires causal authority");
        assert_blob_schema_invariant(&error);
        assert_eq!(blob_current_admission_digest(&store), before);
    }

    #[test]
    fn blob_lifecycle_admission_local_publication_retry_shared_variant_and_restart() {
        let root = BlobTestRoot::new("lifecycle-admission-local");
        let mut services = blob_services(0xd1);
        let plaintext = vec![0x41; SELECTED_BLOB_CHUNK_SIZE as usize + 29];
        let prepared = prepared_blob(&plaintext);
        let store = Store::open_for_mission(&root.database, services.authority)
            .expect("lifecycle local store");

        let first_proof = prepare_blob_proof(&store, &mut services, &prepared, &plaintext, 1);
        let (first, first_operation, first_intent) =
            commit_blob_proof(&store, &services, &first_proof, b"lifecycle-local-first");
        assert!(matches!(first, BlobOnceOutcome::Inserted { .. }));
        let first_blob = first.blob().clone();
        let first_stats = store.blob_stats().expect("first lifecycle authority");
        assert_eq!(first_stats.lineage_fences, 1);
        assert_eq!(first_stats.replay_fences, 1);
        assert_eq!(first_stats.publication_lifecycle_rows, 1);
        assert_eq!(first_stats.variant_references, 1);
        assert_blob_lifecycle_reference(
            &store,
            first_blob.variant_id,
            1,
            first_blob.transfer_id,
            true,
        );

        let first_request = BlobOperationRequest::new(&first_operation, &first_intent);
        let retry = store
            .commit_reserved_blob_once_with_policy(
                &first_proof.policy,
                &first_request,
                &first_proof.reservation,
                &first_proof.blob,
                &first_proof.sealed,
                &first_proof.completion,
            )
            .expect("exact local retry");
        assert!(matches!(retry, BlobOnceOutcome::Existing { .. }));
        assert_eq!(
            store.blob_stats().expect("retry lifecycle authority"),
            first_stats
        );

        let second_proof = prepare_blob_proof(&store, &mut services, &prepared, &plaintext, 1);
        let (second, _, _) =
            commit_blob_proof(&store, &services, &second_proof, b"lifecycle-local-second");
        assert!(matches!(second, BlobOnceOutcome::Inserted { .. }));
        let second_blob = second.blob().clone();
        assert_eq!(second_blob.variant_id, first_blob.variant_id);
        assert_ne!(second_blob.transfer_id, first_blob.transfer_id);
        let shared_stats = store.blob_stats().expect("shared lifecycle authority");
        assert_eq!(shared_stats.lineage_fences, 1);
        assert_eq!(shared_stats.replay_fences, 2);
        assert_eq!(shared_stats.publication_lifecycle_rows, 2);
        assert_eq!(shared_stats.variant_references, 2);
        assert_blob_lifecycle_reference(
            &store,
            second_blob.variant_id,
            1,
            second_blob.transfer_id,
            true,
        );
        drop(store);

        let reopened = Store::open_for_mission(&root.database, services.authority)
            .expect("reopen local lifecycle store");
        assert_eq!(
            reopened.blob_stats().expect("reopened lifecycle authority"),
            shared_stats
        );
        assert_eq!(
            reopened
                .blob_for_operation(&first_operation)
                .expect("reopened exact operation")
                .expect("reopened publication")
                .transfer_id,
            first_blob.transfer_id
        );
    }

    #[test]
    fn blob_lifecycle_admission_injected_failure_preserves_complete_before_image() {
        let root = BlobTestRoot::new("lifecycle-admission-rollback");
        let mut services = blob_services(0xd6);
        let plaintext = b"atomic admission before-image".to_vec();
        let prepared = prepared_blob(&plaintext);
        let store = Store::open_for_mission(&root.database, services.authority)
            .expect("atomic admission store");
        let proof = prepare_blob_proof(&store, &mut services, &prepared, &plaintext, 1);
        let operation =
            BlobOperationKey::new(b"lifecycle-admission-rollback".to_vec()).expect("operation");
        let intent = BlobPublicationIntent::new(
            services.publisher.identity(),
            blob_topic(),
            blob_scope(),
            Priority::Immediate,
            proof.blob.blob_id(),
        )
        .expect("Blob intent");
        let request = BlobOperationRequest::new(&operation, &intent);
        let before_stats = store.blob_stats().expect("before-image lifecycle stats");
        let before_digest = blob_current_admission_digest(&store);

        TEST_BLOB_ADMISSION_PRE_COMMIT_FAULT.set(true);
        let result = store.commit_reserved_blob_once_with_policy(
            &proof.policy,
            &request,
            &proof.reservation,
            &proof.blob,
            &proof.sealed,
            &proof.completion,
        );
        TEST_BLOB_ADMISSION_PRE_COMMIT_FAULT.set(false);

        assert!(
            matches!(
                &result,
                Err(StoreError::Blob(BlobStoreError::SchemaInvariant(
                    "injected Blob admission pre-commit failure"
                )))
            ),
            "unexpected injected admission result: {result:?}"
        );
        assert_eq!(
            blob_current_admission_digest(&store),
            before_digest,
            "all authority and application rows roll back together"
        );
        assert_eq!(
            store.blob_stats().expect("after-failure lifecycle stats"),
            before_stats
        );
        assert!(
            store
                .blob_for_operation(&operation)
                .expect("failed operation lookup")
                .is_none()
        );
        assert!(
            store
                .get_blob(BlobTransferId::new(proof.blob.envelope_id()))
                .expect("failed publication lookup")
                .is_none()
        );
        drop(store);

        let reopened = Store::open_for_mission(&root.database, services.authority)
            .expect("restart after injected admission failure");
        assert_eq!(
            reopened
                .blob_stats()
                .expect("restarted before-image lifecycle stats"),
            before_stats
        );
    }

    #[test]
    fn blob_lifecycle_local_publication_promotes_exact_pending_source_atomically() {
        for (index, inject_failure) in [false, true].into_iter().enumerate() {
            let root = BlobTestRoot::new(&format!("lifecycle-local-pending-{index}"));
            let mut services = blob_services(0x76 + u8::try_from(index).expect("case index"));
            let plaintext = vec![0x51 + u8::try_from(index).expect("case index"); 333];
            let prepared = prepared_blob(&plaintext);
            let store = Store::open_for_mission(&root.database, services.authority)
                .expect("local pending store");
            let proof = prepare_blob_proof(&store, &mut services, &prepared, &plaintext, 1);
            let plan = proof
                .blob
                .transfer_plan(&proof.manifest_bytes)
                .expect("local pending plan");
            let transfer = BlobTransferId::new(proof.blob.envelope_id());
            assert_eq!(
                store
                    .stage_verified_blob_source_with_policy(
                        &proof.policy,
                        &proof.blob,
                        &proof.sealed,
                        &plan,
                    )
                    .expect("stage exact local pending source"),
                BlobSourceStageOutcome::Inserted
            );
            let (carrier_object, carrier_total, carrier_prefix) = {
                let mut depot = store.blob_depot().expect("local pending depot");
                CoreBlobStore::begin_blob_with_lineage(
                    &mut depot,
                    plan.manifest(),
                    plan.physical_lineage(),
                )
                .expect("activate local pending plan");
                let carrier = plan
                    .build_carrier(&mut depot, 0)
                    .expect("build local pending carrier");
                let object = BlobCarrierObjectId::new(carrier.object_id().wire_bytes())
                    .expect("typed local pending carrier");
                let total = u64::try_from(carrier.bytes().len()).expect("carrier total");
                let prefix = carrier
                    .bytes()
                    .chunks(MAX_BLOB_NETWORK_RANGE_BYTES)
                    .next()
                    .expect("nonempty local pending carrier")
                    .to_vec();
                (object, total, prefix)
            };
            assert!(matches!(
                store
                    .append_blob_carrier_prefix_with_policy(
                        &proof.policy,
                        transfer,
                        carrier_object,
                        carrier_total,
                        0,
                        &carrier_prefix,
                    )
                    .expect("append local pending carrier prefix"),
                BlobCarrierAppendOutcome::Appended(_)
            ));
            let before_stats = store.blob_stats().expect("staged local pending stats");
            let before_digest = blob_current_admission_digest(&store);
            assert_eq!(before_stats.pending_sources, 1);
            assert_eq!(before_stats.carrier_prefixes, 1);
            assert_blob_lifecycle_reference(&store, proof.completion.variant_id, 2, transfer, true);

            let operation = BlobOperationKey::new(format!("local-pending-{index}").into_bytes())
                .expect("local pending operation");
            let intent = BlobPublicationIntent::new(
                services.publisher.identity(),
                blob_topic(),
                blob_scope(),
                Priority::Immediate,
                proof.blob.blob_id(),
            )
            .expect("local pending intent");
            let request = BlobOperationRequest::new(&operation, &intent);
            TEST_BLOB_ADMISSION_PRE_COMMIT_FAULT.set(inject_failure);
            let result = store.commit_reserved_blob_once_with_policy(
                &proof.policy,
                &request,
                &proof.reservation,
                &proof.blob,
                &proof.sealed,
                &proof.completion,
            );
            TEST_BLOB_ADMISSION_PRE_COMMIT_FAULT.set(false);

            if inject_failure {
                assert_blob_schema_invariant(&result.expect_err("injected local pending failure"));
                assert_eq!(blob_current_admission_digest(&store), before_digest);
                assert_eq!(
                    store.blob_stats().expect("rolled-back pending stats"),
                    before_stats
                );
                assert!(
                    store
                        .pending_blob_source(transfer)
                        .expect("rolled-back pending lookup")
                        .is_some()
                );
                assert!(
                    store
                        .blob_carrier_prefix_status(transfer, carrier_object)
                        .expect("rolled-back prefix lookup")
                        .is_some()
                );
                assert_blob_lifecycle_reference(
                    &store,
                    proof.completion.variant_id,
                    2,
                    transfer,
                    true,
                );
                assert_blob_lifecycle_reference(
                    &store,
                    proof.completion.variant_id,
                    1,
                    transfer,
                    false,
                );
            } else {
                assert!(
                    result
                        .expect("publish exact local pending source")
                        .inserted()
                );
                let stats = store.blob_stats().expect("promoted local pending stats");
                assert_eq!(stats.pending_sources, 0);
                assert_eq!(stats.carrier_prefixes, 0);
                assert_eq!(stats.network_staging_bytes, 0);
                assert!(
                    store
                        .pending_blob_source(transfer)
                        .expect("promoted pending lookup")
                        .is_none()
                );
                assert!(
                    store
                        .blob_carrier_prefix_status(transfer, carrier_object)
                        .expect("promoted prefix lookup")
                        .is_none()
                );
                assert_blob_lifecycle_reference(
                    &store,
                    proof.completion.variant_id,
                    2,
                    transfer,
                    false,
                );
                assert_blob_lifecycle_reference(
                    &store,
                    proof.completion.variant_id,
                    1,
                    transfer,
                    true,
                );
            }
            drop(store);
            Store::open_for_mission(&root.database, services.authority)
                .expect("immediate reopen after local pending commit attempt");
        }
    }

    #[test]
    fn blob_lifecycle_admission_pending_retry_abort_promotion_and_conflicts() {
        let source_root = BlobTestRoot::new("lifecycle-admission-network-source");
        let target_root = BlobTestRoot::new("lifecycle-admission-network-target");
        let mut services = blob_services(0xd2);
        let source = Store::open_for_mission(&source_root.database, services.authority)
            .expect("lifecycle source store");
        let target = Store::open_for_mission(&target_root.database, services.authority)
            .expect("lifecycle target store");
        let plaintext = vec![0x52; SELECTED_BLOB_CHUNK_SIZE as usize + 37];
        let prepared = prepared_blob(&plaintext);

        let first = prepare_blob_proof(&source, &mut services, &prepared, &plaintext, 1);
        let (first_source_publication, _, _) =
            commit_blob_proof(&source, &services, &first, b"lifecycle-source-first");
        assert!(first_source_publication.inserted());
        let second = prepare_blob_proof(&source, &mut services, &prepared, &plaintext, 1);
        let (second_source_publication, _, _) =
            commit_blob_proof(&source, &services, &second, b"lifecycle-source-second");
        assert!(second_source_publication.inserted());
        let first_plan = first
            .blob
            .transfer_plan(&first.manifest_bytes)
            .expect("first lifecycle transfer plan");
        let second_plan = second
            .blob
            .transfer_plan(&second.manifest_bytes)
            .expect("second lifecycle transfer plan");
        let first_transfer = BlobTransferId::new(first.blob.envelope_id());
        let second_transfer = BlobTransferId::new(second.blob.envelope_id());
        let variant = BlobVariantId::for_content(
            first_plan.manifest().id(),
            first_plan.manifest().content_group(),
            first_plan.manifest().content_epoch(),
        );
        let policy = target.control_policy_snapshot().expect("target policy");

        assert_eq!(
            target
                .stage_verified_blob_source_with_policy(
                    &policy,
                    &first.blob,
                    &first.sealed,
                    &first_plan,
                )
                .expect("stage first pending source"),
            BlobSourceStageOutcome::Inserted
        );
        let first_pending_stats = target.blob_stats().expect("first pending lifecycle");
        assert_eq!(first_pending_stats.lineage_fences, 1);
        assert_eq!(first_pending_stats.replay_fences, 0);
        assert_eq!(first_pending_stats.publication_lifecycle_rows, 0);
        assert_eq!(first_pending_stats.variant_references, 1);
        assert_blob_lifecycle_reference(&target, variant, 2, first_transfer, true);
        assert_eq!(
            target
                .stage_verified_blob_source_with_policy(
                    &policy,
                    &first.blob,
                    &first.sealed,
                    &first_plan,
                )
                .expect("retry first pending source"),
            BlobSourceStageOutcome::Duplicate
        );
        assert_eq!(
            target.blob_stats().expect("pending retry lifecycle"),
            first_pending_stats
        );

        assert_eq!(
            target
                .stage_verified_blob_source_with_policy(
                    &policy,
                    &second.blob,
                    &second.sealed,
                    &second_plan,
                )
                .expect("stage shared pending source"),
            BlobSourceStageOutcome::Inserted
        );
        assert_eq!(
            target
                .blob_stats()
                .expect("shared pending lifecycle")
                .variant_references,
            2
        );
        assert_blob_lifecycle_reference(&target, variant, 2, second_transfer, true);
        assert!(
            target
                .abort_pending_blob_source(second_transfer)
                .expect("abort exact pending source")
        );
        let after_abort = target.blob_stats().expect("pending abort lifecycle");
        assert_eq!(after_abort.lineage_fences, 1);
        assert_eq!(after_abort.variant_references, 1);
        assert_blob_lifecycle_reference(&target, variant, 2, second_transfer, false);

        transfer_all_blob_carriers(&source, &target, &policy, &first_plan);
        let depot_completion = target
            .completed_pending_blob_with_policy(
                &policy,
                first_transfer,
                &first.blob,
                &first.manifest_bytes,
                &first_plan,
            )
            .expect("pending completion");
        let content_completion = {
            let depot = target
                .blob_depot_for_authenticated_read(&depot_completion)
                .expect("authenticated target depot");
            let mut service = services
                .reader
                .blob_service_with_store(&blob_scope(), &blob_topic(), 1, depot)
                .expect("target content verifier");
            service
                .verify_blob_content_completion(&first.blob, &first.manifest_bytes)
                .expect("fresh target content completion")
        };
        let lineage = services
            .reader
            .verify_current_blob_lineage(&first.blob)
            .expect("current target lineage");
        let promoted = target
            .apply_verified_blob_with_policy(
                &policy,
                &first_plan,
                &lineage,
                &depot_completion,
                &content_completion,
            )
            .expect("promote pending source");
        assert!(matches!(promoted, ApplyOutcome::Inserted { .. }));
        let promoted_stats = target.blob_stats().expect("promoted lifecycle");
        assert_eq!(promoted_stats.lineage_fences, 1);
        assert_eq!(promoted_stats.replay_fences, 1);
        assert_eq!(promoted_stats.publication_lifecycle_rows, 1);
        assert_eq!(promoted_stats.variant_references, 1);
        assert_blob_lifecycle_reference(&target, variant, 2, first_transfer, false);
        assert_blob_lifecycle_reference(&target, variant, 1, first_transfer, true);
        assert!(matches!(
            target
                .apply_verified_blob_with_policy(
                    &policy,
                    &first_plan,
                    &lineage,
                    &depot_completion,
                    &content_completion,
                )
                .expect("duplicate promotion"),
            ApplyOutcome::Duplicate { .. }
        ));
        assert_eq!(
            target.blob_stats().expect("duplicate promotion lifecycle"),
            promoted_stats
        );

        let resealed = services
            .publisher
            .seal_blob_manifest(first.blob.header(), &first.manifest_bytes)
            .expect("re-seal exact Blob semantics")
            .bytes;
        let reroute = services
            .reader
            .verify_blob(&resealed)
            .expect("verify re-sealed route");
        let (represented, represented_manifest) = match services
            .reader
            .verify_blob_content(reroute, &resealed)
            .expect("verify re-sealed content")
        {
            BlobContentVerification::ContentVerified {
                blob,
                manifest_bytes,
            } => (blob, manifest_bytes),
            BlobContentVerification::RouteOnly(_) => panic!("member unexpectedly route-only"),
        };
        assert_eq!(represented.item_id(), first.blob.item_id());
        assert_ne!(represented.envelope_id(), first.blob.envelope_id());
        let represented_plan = represented
            .transfer_plan(&represented_manifest)
            .expect("represented transfer plan");
        let representation_error = target
            .stage_verified_blob_source_with_policy(
                &policy,
                &represented,
                &resealed,
                &represented_plan,
            )
            .expect_err("same semantic publication with another source must fail");
        assert_eq!(
            representation_error.to_string(),
            "Blob source representation conflicts with permanent replay authority"
        );

        let equivocation_plaintext = b"same publisher dot with different Blob semantics";
        let equivocation_prepared = prepared_blob(equivocation_plaintext);
        let equivocation_finished = finish_variant(
            &source,
            &services.publisher,
            &equivocation_prepared,
            equivocation_plaintext,
            1,
        )
        .expect("finish equivocation variant");
        let equivocation_header = first
            .reservation
            .header(
                Priority::Immediate,
                equivocation_finished.route_commitment(),
                u64::try_from(equivocation_finished.manifest_bytes().len())
                    .expect("equivocation manifest length"),
                1,
            )
            .expect("equivocation header");
        let equivocation_sealed = services
            .publisher
            .seal_blob_manifest(&equivocation_header, equivocation_finished.manifest_bytes())
            .expect("seal equivocation source")
            .bytes;
        let equivocation_route = services
            .reader
            .verify_blob(&equivocation_sealed)
            .expect("verify equivocation route");
        let (equivocation_blob, equivocation_manifest) = match services
            .reader
            .verify_blob_content(equivocation_route, &equivocation_sealed)
            .expect("verify equivocation content")
        {
            BlobContentVerification::ContentVerified {
                blob,
                manifest_bytes,
            } => (blob, manifest_bytes),
            BlobContentVerification::RouteOnly(_) => panic!("member unexpectedly route-only"),
        };
        assert_ne!(equivocation_blob.item_id(), first.blob.item_id());
        assert_eq!(
            equivocation_blob.header().stamp.dot,
            first.blob.header().stamp.dot
        );
        let equivocation_plan = equivocation_blob
            .transfer_plan(&equivocation_manifest)
            .expect("equivocation transfer plan");
        assert!(matches!(
            target.stage_verified_blob_source_with_policy(
                &policy,
                &equivocation_blob,
                &equivocation_sealed,
                &equivocation_plan,
            ),
            Err(StoreError::CausalEquivocation { .. })
        ));
        assert_eq!(
            target.blob_stats().expect("conflict lifecycle"),
            promoted_stats
        );
        drop(target);

        let reopened = Store::open_for_mission(&target_root.database, services.authority)
            .expect("reopen promoted lifecycle store");
        assert_eq!(
            reopened.blob_stats().expect("reopened promoted lifecycle"),
            promoted_stats
        );
        assert_blob_lifecycle_reference(&reopened, variant, 1, first_transfer, true);
    }

    #[test]
    fn blob_lifecycle_admission_separate_caps_are_atomic_and_matching_fences_remain_usable() {
        let lineage_source_root = BlobTestRoot::new("lifecycle-lineage-cap-source");
        let lineage_target_root = BlobTestRoot::new("lifecycle-lineage-cap-target");
        let mut lineage_services = blob_services(0xd3);
        let lineage_source =
            Store::open_for_mission(&lineage_source_root.database, lineage_services.authority)
                .expect("lineage source");
        let lineage_limits =
            BlobLifecycleLimits::new(1, 97, 4, 4 * 185, 4).expect("lineage lifecycle limits");
        let lineage_target = Store::open_with_all_limits_for_mission(
            &lineage_target_root.database,
            StoreLimits::default(),
            BlobDepotLimits::default(),
            EventOperationLimits::DEFAULT,
            lineage_limits,
            lineage_services.authority,
        )
        .expect("lineage target");
        let first_plaintext = b"first permanent lineage";
        let first_prepared = prepared_blob(first_plaintext);
        let first = prepare_blob_proof(
            &lineage_source,
            &mut lineage_services,
            &first_prepared,
            first_plaintext,
            1,
        );
        let first_plan = first
            .blob
            .transfer_plan(&first.manifest_bytes)
            .expect("first lineage plan");
        let lineage_policy = lineage_target
            .control_policy_snapshot()
            .expect("lineage policy");
        assert_eq!(
            lineage_target
                .stage_verified_blob_source_with_policy(
                    &lineage_policy,
                    &first.blob,
                    &first.sealed,
                    &first_plan,
                )
                .expect("fill lineage fence"),
            BlobSourceStageOutcome::Inserted
        );
        let first_transfer = BlobTransferId::new(first.blob.envelope_id());
        assert!(
            lineage_target
                .abort_pending_blob_source(first_transfer)
                .expect("abort first lineage root")
        );
        let fenced = lineage_target
            .blob_stats()
            .expect("lineage fence retained without root");
        assert_eq!(fenced.lineage_fences, 1);
        assert_eq!(fenced.variant_references, 0);
        assert_eq!(
            lineage_target
                .stage_verified_blob_source_with_policy(
                    &lineage_policy,
                    &first.blob,
                    &first.sealed,
                    &first_plan,
                )
                .expect("matching lineage remains usable at capacity"),
            BlobSourceStageOutcome::Inserted
        );
        assert!(
            lineage_target
                .abort_pending_blob_source(first_transfer)
                .expect("abort matching lineage retry")
        );
        assert_eq!(
            lineage_target
                .blob_stats()
                .expect("matching lineage cleanup"),
            fenced
        );
        let second_plaintext = b"new lineage beyond its permanent cap";
        let second_prepared = prepared_blob(second_plaintext);
        let second = prepare_blob_proof(
            &lineage_source,
            &mut lineage_services,
            &second_prepared,
            second_plaintext,
            1,
        );
        let second_plan = second
            .blob
            .transfer_plan(&second.manifest_bytes)
            .expect("second lineage plan");
        assert!(matches!(
            lineage_target.stage_verified_blob_source_with_policy(
                &lineage_policy,
                &second.blob,
                &second.sealed,
                &second_plan,
            ),
            Err(StoreError::Blob(
                BlobStoreError::LineageFenceCapacity { .. }
            ))
        ));
        assert_eq!(
            lineage_target
                .blob_stats()
                .expect("lineage capacity is non-mutating"),
            fenced
        );

        let replay_root = BlobTestRoot::new("lifecycle-replay-cap");
        let mut replay_services = blob_services(0xd4);
        let replay_limits =
            BlobLifecycleLimits::new(4, 4 * 97, 1, 185, 4).expect("replay lifecycle limits");
        let replay_store = Store::open_with_all_limits_for_mission(
            &replay_root.database,
            StoreLimits::default(),
            BlobDepotLimits::default(),
            EventOperationLimits::DEFAULT,
            replay_limits,
            replay_services.authority,
        )
        .expect("replay store");
        let replay_plaintext = b"shared variant at replay capacity";
        let replay_prepared = prepared_blob(replay_plaintext);
        let replay_first = prepare_blob_proof(
            &replay_store,
            &mut replay_services,
            &replay_prepared,
            replay_plaintext,
            1,
        );
        let (first_outcome, first_operation, first_intent) = commit_blob_proof(
            &replay_store,
            &replay_services,
            &replay_first,
            b"replay-cap-first",
        );
        assert!(first_outcome.inserted());
        let full_replay_stats = replay_store.blob_stats().expect("full replay stats");
        let first_request = BlobOperationRequest::new(&first_operation, &first_intent);
        assert!(matches!(
            replay_store
                .commit_reserved_blob_once_with_policy(
                    &replay_first.policy,
                    &first_request,
                    &replay_first.reservation,
                    &replay_first.blob,
                    &replay_first.sealed,
                    &replay_first.completion,
                )
                .expect("matching replay remains usable at capacity"),
            BlobOnceOutcome::Existing { .. }
        ));
        let replay_second = prepare_blob_proof(
            &replay_store,
            &mut replay_services,
            &replay_prepared,
            replay_plaintext,
            1,
        );
        let second_operation =
            BlobOperationKey::new(b"replay-cap-second".to_vec()).expect("second operation");
        let second_intent = BlobPublicationIntent::new(
            replay_services.publisher.identity(),
            blob_topic(),
            blob_scope(),
            Priority::Immediate,
            replay_prepared.id(),
        )
        .expect("second replay intent");
        let second_request = BlobOperationRequest::new(&second_operation, &second_intent);
        assert!(matches!(
            replay_store.commit_reserved_blob_once_with_policy(
                &replay_second.policy,
                &second_request,
                &replay_second.reservation,
                &replay_second.blob,
                &replay_second.sealed,
                &replay_second.completion,
            ),
            Err(StoreError::Blob(BlobStoreError::ReplayFenceCapacity { .. }))
        ));
        assert_eq!(
            replay_store
                .blob_stats()
                .expect("replay capacity is non-mutating"),
            full_replay_stats
        );
        assert!(
            replay_store
                .blob_for_operation(&second_operation)
                .expect("second operation lookup")
                .is_none()
        );

        let publication_root = BlobTestRoot::new("lifecycle-publication-cap");
        let mut publication_services = blob_services(0xd5);
        let publication_limits = BlobLifecycleLimits::new(4, 4 * 97, 4, 4 * 185, 1)
            .expect("publication lifecycle limits");
        let publication_store = Store::open_with_all_limits_for_mission(
            &publication_root.database,
            StoreLimits::default(),
            BlobDepotLimits::default(),
            EventOperationLimits::DEFAULT,
            publication_limits,
            publication_services.authority,
        )
        .expect("publication store");
        let publication_plaintext = b"shared variant at publication capacity";
        let publication_prepared = prepared_blob(publication_plaintext);
        let publication_first = prepare_blob_proof(
            &publication_store,
            &mut publication_services,
            &publication_prepared,
            publication_plaintext,
            1,
        );
        let (publication_outcome, _, _) = commit_blob_proof(
            &publication_store,
            &publication_services,
            &publication_first,
            b"publication-cap-first",
        );
        assert!(publication_outcome.inserted());
        let full_publication_stats = publication_store
            .blob_stats()
            .expect("full publication stats");
        let publication_second = prepare_blob_proof(
            &publication_store,
            &mut publication_services,
            &publication_prepared,
            publication_plaintext,
            1,
        );
        let publication_operation = BlobOperationKey::new(b"publication-cap-second".to_vec())
            .expect("publication operation");
        let publication_intent = BlobPublicationIntent::new(
            publication_services.publisher.identity(),
            blob_topic(),
            blob_scope(),
            Priority::Immediate,
            publication_prepared.id(),
        )
        .expect("publication intent");
        let publication_request =
            BlobOperationRequest::new(&publication_operation, &publication_intent);
        assert!(matches!(
            publication_store.commit_reserved_blob_once_with_policy(
                &publication_second.policy,
                &publication_request,
                &publication_second.reservation,
                &publication_second.blob,
                &publication_second.sealed,
                &publication_second.completion,
            ),
            Err(StoreError::Blob(
                BlobStoreError::PublicationLifecycleCapacity { .. }
            ))
        ));
        assert_eq!(
            publication_store
                .blob_stats()
                .expect("publication capacity is non-mutating"),
            full_publication_stats
        );
        assert!(
            publication_store
                .blob_for_operation(&publication_operation)
                .expect("publication operation lookup")
                .is_none()
        );
    }

    fn depot_file_snapshot(root: &Path) -> BTreeMap<PathBuf, Vec<u8>> {
        fn visit(base: &Path, current: &Path, output: &mut BTreeMap<PathBuf, Vec<u8>>) {
            for entry in std::fs::read_dir(current).expect("read depot snapshot") {
                let entry = entry.expect("depot snapshot entry");
                let path = entry.path();
                if entry.file_type().expect("depot snapshot type").is_dir() {
                    visit(base, &path, output);
                } else {
                    output.insert(
                        path.strip_prefix(base)
                            .expect("depot snapshot relative path")
                            .to_path_buf(),
                        std::fs::read(path).expect("depot snapshot bytes"),
                    );
                }
            }
        }

        let mut output = BTreeMap::new();
        if root.exists() {
            visit(root, root, &mut output);
        }
        output
    }

    #[test]
    fn publication_reopen_exact_retry_duplicate_no_growth_and_epoch_partition() {
        let root = BlobTestRoot::new("reopen-dedup-rekey");
        let mut services = blob_services(0x61);
        let plaintext = vec![0x5a; SELECTED_BLOB_CHUNK_SIZE as usize + 17];
        let prepared = prepared_blob(&plaintext);
        let store = Store::open_for_mission(&root.database, services.authority).expect("store");
        let (stored, operation, intent) = publish_blob(
            &store,
            &mut services,
            &prepared,
            &plaintext,
            1,
            b"publish-one",
        );
        let first = store.blob_stats().expect("first Blob stats");
        assert_eq!(first.publications, 1);
        assert_eq!(first.operations, 1);
        assert_eq!(first.variants, 1);
        assert_eq!(first.finalized_variants, 1);
        assert_eq!(first.committed_chunks, 2);

        let policy = store.control_policy_snapshot().expect("retry policy");
        let request = BlobOperationRequest::new(&operation, &intent);
        assert_eq!(
            store
                .blob_for_operation_with_policy(&policy, &request)
                .expect("exact retry preflight"),
            Some(stored.clone())
        );
        let changed_intent = BlobPublicationIntent::new(
            services.publisher.identity(),
            blob_topic(),
            blob_scope(),
            Priority::Routine,
            prepared.id(),
        )
        .expect("changed intent");
        assert!(matches!(
            store.blob_for_operation_with_policy(
                &policy,
                &BlobOperationRequest::new(&operation, &changed_intent),
            ),
            Err(StoreError::Blob(BlobStoreError::OperationConflict))
        ));
        assert_eq!(store.blob_stats().expect("retry stats"), first);

        let same = finish_variant(&store, &services.publisher, &prepared, &plaintext, 1)
            .expect("repeat same variant");
        assert_eq!(same.id(), stored.blob_id);
        assert_eq!(store.blob_stats().expect("same variant stats"), first);

        let epoch_two = finish_variant(&store, &services.publisher, &prepared, &plaintext, 2)
            .expect("separate epoch variant");
        assert_eq!(epoch_two.id(), stored.blob_id);
        let partitioned = store.blob_stats().expect("partitioned stats");
        assert_eq!(partitioned.variants, 2);
        assert_eq!(partitioned.finalized_variants, 2);
        assert_eq!(partitioned.committed_chunks, 4);
        assert_ne!(
            blob_variant_id(stored.blob_id, &[0; 32], 1),
            blob_variant_id(stored.blob_id, &[0; 32], 2)
        );
        drop(store);

        let reopened = Store::open_for_mission(&root.database, services.authority).expect("reopen");
        assert_eq!(reopened.blob_stats().expect("reopened stats"), partitioned);
        let current = reopened.control_policy_snapshot().expect("reopened policy");
        assert_eq!(
            reopened
                .blob_for_operation_with_policy(
                    &current,
                    &BlobOperationRequest::new(&operation, &intent),
                )
                .expect("reopened exact retry"),
            Some(stored)
        );
        drop(reopened);
        assert_eq!(
            Store::inspect_existing(&root.database)
                .expect("strict Blob inspection")
                .blob_stats,
            partitioned
        );
    }

    #[test]
    fn operation_preflight_rejects_orphan_without_depot_work() {
        let root = BlobTestRoot::new("orphan-operation-preflight");
        let mut services = blob_services(0x60);
        let plaintext = vec![0x60; 2_049];
        let prepared = prepared_blob(&plaintext);
        let store = Store::open_for_mission(&root.database, services.authority)
            .expect("orphan-operation store");
        let (_, operation, intent) = publish_blob(
            &store,
            &mut services,
            &prepared,
            &plaintext,
            1,
            b"orphan-operation",
        );
        let policy = store
            .control_policy_snapshot()
            .expect("orphan operation policy");
        let before_io = depot::test_depot_io_counts(&store);
        let write = store
            .database
            .begin_write()
            .expect("truncated operation mutation write");
        write
            .open_table(BLOB_OPERATIONS)
            .expect("truncated operation table")
            .insert(operation.as_bytes(), [0u8].as_slice())
            .expect("truncate operation row");
        write.commit().expect("commit truncated operation row");
        let truncated = store
            .blob_for_operation_with_policy(
                &policy,
                &BlobOperationRequest::new(&operation, &intent),
            )
            .expect_err("truncated operation cannot become an ordinary error");
        assert!(matches!(
            truncated,
            StoreError::Blob(BlobStoreError::SchemaInvariant(_))
        ));

        let encoded = encode_blob_operation_record(BlobOperationRecord {
            transfer_id: BlobTransferId::new([0xf7; 32]),
            intent_digest: intent.digest(),
        });
        let write = store
            .database
            .begin_write()
            .expect("orphan operation mutation write");
        write
            .open_table(BLOB_OPERATIONS)
            .expect("orphan operation table")
            .insert(operation.as_bytes(), encoded.as_slice())
            .expect("orphan operation mutation");
        write.commit().expect("commit orphan operation");
        let orphan = store
            .blob_for_operation_with_policy(
                &policy,
                &BlobOperationRequest::new(&operation, &intent),
            )
            .expect_err("present operation cannot resolve as ordinary absence");
        assert!(matches!(
            orphan,
            StoreError::Blob(BlobStoreError::SchemaInvariant(_))
        ));
        assert_eq!(
            depot::test_depot_io_counts(&store),
            before_io,
            "operation preflight cannot open or mutate the depot"
        );
    }

    #[test]
    fn read_plan_preflight_rejects_orphan_content_index_without_depot_work() {
        let root = BlobTestRoot::new("orphan-content-preflight");
        let mut services = blob_services(0x5f);
        let plaintext = vec![0x5f; 2_049];
        let prepared = prepared_blob(&plaintext);
        let store = Store::open_for_mission(&root.database, services.authority)
            .expect("orphan-content store");
        let (stored, _, _) = publish_blob(
            &store,
            &mut services,
            &prepared,
            &plaintext,
            1,
            b"orphan-content",
        );
        let key = blob_content_key(
            &stored.header.topic,
            &stored.header.scope,
            stored.blob_id,
            stored.semantic_id,
        )
        .expect("orphan content-index key");
        let policy = store
            .control_policy_snapshot()
            .expect("orphan content policy");
        let before_io = depot::test_depot_io_counts(&store);
        let write = store
            .database
            .begin_write()
            .expect("truncated content-index mutation write");
        write
            .open_table(BLOB_CONTENT_INDEX)
            .expect("truncated content-index table")
            .insert(key.as_slice(), [0xf6].as_slice())
            .expect("truncate content-index value");
        write.commit().expect("commit truncated content index");
        let truncated_index = store
            .prepare_blob_read_with_policy(
                &policy,
                &stored.header.topic,
                &stored.header.scope,
                stored.blob_id,
            )
            .expect_err("truncated content index cannot produce a read plan");
        assert!(matches!(
            truncated_index,
            StoreError::Blob(BlobStoreError::SchemaInvariant(_))
        ));

        let write = store
            .database
            .begin_write()
            .expect("orphan content-index mutation write");
        write
            .open_table(BLOB_CONTENT_INDEX)
            .expect("orphan content-index table")
            .insert(key.as_slice(), [0xf6; 32].as_slice())
            .expect("orphan content-index mutation");
        write.commit().expect("commit orphan content index");
        let orphan_index = store
            .prepare_blob_read_with_policy(
                &policy,
                &stored.header.topic,
                &stored.header.scope,
                stored.blob_id,
            )
            .expect_err("orphan content index cannot produce an empty or partial plan");
        assert!(matches!(
            orphan_index,
            StoreError::Blob(BlobStoreError::SchemaInvariant(_))
        ));

        let write = store
            .database
            .begin_write()
            .expect("truncated publication mutation write");
        write
            .open_table(BLOB_CONTENT_INDEX)
            .expect("restore content-index table")
            .insert(key.as_slice(), stored.transfer_id.as_bytes().as_slice())
            .expect("restore content-index transfer");
        write
            .open_table(BLOB_PUBLICATIONS)
            .expect("truncated publication table")
            .insert(stored.transfer_id.as_bytes().as_slice(), [0u8].as_slice())
            .expect("truncate publication metadata");
        write.commit().expect("commit truncated publication row");
        let truncated_publication = store
            .prepare_blob_read_with_policy(
                &policy,
                &stored.header.topic,
                &stored.header.scope,
                stored.blob_id,
            )
            .expect_err("truncated publication cannot produce a read plan");
        assert!(matches!(
            truncated_publication,
            StoreError::Blob(BlobStoreError::SchemaInvariant(_))
        ));
        assert_eq!(
            depot::test_depot_io_counts(&store),
            before_io,
            "read-plan preflight cannot open or mutate the depot"
        );
    }

    #[test]
    fn projection_read_plan_bounds_prefix_work_and_exact_loads_one_source() {
        let root = BlobTestRoot::new("projection-read-plan-work");
        let mut services = blob_services(0x5e);
        let plaintext = vec![0x5e; 2_049];
        let prepared = prepared_blob(&plaintext);
        let store = Store::open_for_mission(&root.database, services.authority)
            .expect("projection read-plan store");
        let (stored, _, _) = publish_blob(
            &store,
            &mut services,
            &prepared,
            &plaintext,
            1,
            b"projection-read-plan",
        );
        let base_metadata = {
            let read = store.database.begin_read().expect("read base metadata");
            let table = read
                .open_table(BLOB_PUBLICATIONS)
                .expect("base publication table");
            let value = table
                .get(stored.transfer_id.as_bytes().as_slice())
                .expect("base publication lookup")
                .expect("base publication");
            decode_blob_metadata(value.value()).expect("decode base publication")
        };

        let write = store
            .database
            .begin_write()
            .expect("projection fixture write");
        {
            let mut publications = write
                .open_table(BLOB_PUBLICATIONS)
                .expect("projection publication table");
            let mut bytes = write
                .open_table(BLOB_BYTES)
                .expect("projection bytes table");
            let mut markers = write
                .open_table(BLOB_ACCEPTANCE_MARKERS)
                .expect("projection marker table");
            let mut content = write
                .open_table(BLOB_CONTENT_INDEX)
                .expect("projection content table");
            for index in 0..(MAX_BLOB_PUBLICATIONS_PER_CONTENT - 1) {
                let mut transfer_digest = Sha256::new();
                transfer_digest.update(b"aster/test/projection-transfer");
                transfer_digest.update((index as u64).to_be_bytes());
                let transfer = BlobTransferId::new(transfer_digest.finalize().into());
                let mut semantic_digest = Sha256::new();
                semantic_digest.update(b"aster/test/projection-semantic");
                semantic_digest.update((index as u64).to_be_bytes());
                let semantic = BlobSemanticId::new(semantic_digest.finalize().into());
                let mut metadata = base_metadata.clone();
                metadata.transfer_id = transfer;
                metadata.semantic_id = semantic;
                metadata.header.stamp.dot.counter = u64::try_from(index)
                    .expect("fixture index")
                    .checked_add(10_000)
                    .expect("fixture counter");
                let encoded = encode_blob_metadata(metadata).expect("encode projection fixture");
                publications
                    .insert(transfer.as_bytes().as_slice(), encoded.as_slice())
                    .expect("insert projection publication");
                bytes
                    .insert(transfer.as_bytes().as_slice(), [0x5e].as_slice())
                    .expect("insert projection bytes");
                markers
                    .insert(
                        transfer.as_bytes().as_slice(),
                        u64::try_from(index)
                            .expect("fixture marker index")
                            .checked_add(2)
                            .expect("fixture marker"),
                    )
                    .expect("insert projection marker");
                let key = blob_content_key(
                    &stored.header.topic,
                    &stored.header.scope,
                    stored.blob_id,
                    semantic,
                )
                .expect("projection content key");
                content
                    .insert(key.as_slice(), transfer.as_bytes().as_slice())
                    .expect("insert projection content row");
            }
            let unrelated_blob = BlobId::from_bytes([0xfe; 32]);
            for index in 0..4_096u64 {
                let mut semantic_bytes = [0u8; 32];
                semantic_bytes[24..].copy_from_slice(&index.to_be_bytes());
                let key = blob_content_key(
                    &stored.header.topic,
                    &stored.header.scope,
                    unrelated_blob,
                    BlobSemanticId::new(semantic_bytes),
                )
                .expect("unrelated content key");
                content
                    .insert(key.as_slice(), [0xa5; 32].as_slice())
                    .expect("insert unrelated content row");
            }
        }
        {
            let unrelated_topic = Topic::new("unrelated-blob-domain").expect("unrelated topic");
            let unrelated_scope =
                Scope::new("mission/unrelated-blob-domain").expect("unrelated scope");
            let mut key = event_domain_prefix(&unrelated_topic, &unrelated_scope)
                .expect("unrelated frontier prefix");
            key.extend_from_slice(&[0xdd; 32]);
            write
                .open_table(CAUSAL_FRONTIER)
                .expect("unrelated frontier table")
                .insert(key.as_slice(), 1)
                .expect("insert unrelated frontier row");
        }
        write.commit().expect("commit projection fixture");

        let policy = store
            .control_policy_snapshot()
            .expect("projection read policy");
        let frontier_before = test_blob_frontier_rows_visited();
        store
            .reserve_blob_with_policy(
                &policy,
                services.publisher.identity(),
                &stored.header.topic,
                &stored.header.scope,
            )
            .expect("bounded target-domain frontier reserve");
        assert_eq!(
            test_blob_frontier_rows_visited() - frontier_before,
            1,
            "unrelated causal-frontier domains were visited"
        );
        let before = test_blob_read_work_counts();
        let plan = store
            .prepare_blob_read_with_policy(
                &policy,
                &stored.header.topic,
                &stored.header.scope,
                stored.blob_id,
            )
            .expect("projection-only read plan");
        let after_plan = test_blob_read_work_counts();
        assert_eq!(plan.candidates().len(), MAX_BLOB_PUBLICATIONS_PER_CONTENT);
        assert_eq!(
            after_plan.0 - before.0,
            MAX_BLOB_PUBLICATIONS_PER_CONTENT as u64
        );
        assert_eq!(after_plan.1, before.1, "plan cloned source bytes");

        store
            .require_blob_read_plan_with_policy(&policy, &plan)
            .expect("projection-only plan recheck");
        let after_recheck = test_blob_read_work_counts();
        assert_eq!(
            after_recheck.0 - after_plan.0,
            MAX_BLOB_PUBLICATIONS_PER_CONTENT as u64
        );
        assert_eq!(after_recheck.1, before.1, "recheck cloned source bytes");

        store
            .load_blob_read_candidate_with_policy(
                &policy,
                plan.current().expect("selected projection"),
            )
            .expect("exact-load selected source");
        let after_selected = test_blob_read_work_counts();
        assert_eq!(after_selected.1 - before.1, 1);

        let capacity_before = test_blob_capacity_content_rows_visited();
        let read = store
            .database
            .begin_read()
            .expect("capacity preflight read");
        let capacity = require_blob_apply_capacity_read(&read, store.limits, &base_metadata, 1)
            .expect_err("content publication cap");
        assert!(matches!(
            capacity,
            StoreError::Blob(BlobStoreError::PublicationLimitExceeded { .. })
        ));
        assert_eq!(
            test_blob_capacity_content_rows_visited() - capacity_before,
            MAX_BLOB_PUBLICATIONS_PER_CONTENT as u64,
            "unrelated content-index rows were visited by capacity preflight"
        );
    }

    #[test]
    fn unmarked_crash_boundary_artifacts_are_reclaimed_before_exact_retry() {
        for (label, point) in [
            ("after-temp-sync", depot::DepotFaultPoint::TempSynced),
            ("after-rename", depot::DepotFaultPoint::Renamed),
            (
                "after-directory-sync",
                depot::DepotFaultPoint::DirectorySynced,
            ),
        ] {
            let root = BlobTestRoot::new(label);
            let services = blob_services(0x62);
            let plaintext = vec![0x33; 4_097];
            let prepared = prepared_blob(&plaintext);
            let store =
                Store::open_for_mission(&root.database, services.authority).expect("fault store");
            depot::inject_test_fault(&root.path, point);
            assert!(
                finish_variant(&store, &services.publisher, &prepared, &plaintext, 1).is_err(),
                "{point:?} must interrupt before the redb marker"
            );
            let variant = {
                let read = store.database.begin_read().expect("fault import read");
                let imports = read.open_table(BLOB_IMPORTS).expect("imports");
                let row = imports
                    .iter()
                    .expect("iterate imports")
                    .next()
                    .expect("import")
                    .expect("import row");
                BlobVariantId::from_bytes(row.0.value().try_into().expect("variant id"))
            };
            let variant_path = root.depot().join(test_hex32(variant.as_bytes()));
            assert!(directory_entry_count(&variant_path) > 0);
            let interrupted = store.blob_stats().expect("interrupted stats");
            assert_eq!(interrupted.variants, 1);
            assert_eq!(interrupted.committed_chunks, 0);
            drop(store);

            let reopened =
                Store::open_for_mission(&root.database, services.authority).expect("reclaim open");
            assert_eq!(directory_entry_count(&variant_path), 0);
            let finished = finish_variant(&reopened, &services.publisher, &prepared, &plaintext, 1)
                .expect("retry interrupted variant");
            assert_eq!(finished.id(), prepared.id());
            let recovered = reopened.blob_stats().expect("recovered stats");
            assert_eq!(recovered.variants, 1);
            assert_eq!(recovered.finalized_variants, 1);
            assert_eq!(recovered.committed_chunks, 1);
        }
    }

    #[test]
    fn marked_missing_truncated_and_hash_mismatched_chunks_fail_without_repair() {
        for (index, mode) in ["missing", "truncated", "hash-mismatch"]
            .into_iter()
            .enumerate()
        {
            let root = BlobTestRoot::new(mode);
            let mut services = blob_services(0x70 + u8::try_from(index).expect("seed"));
            let plaintext = vec![0x90 + u8::try_from(index).expect("byte"); 8_191];
            let prepared = prepared_blob(&plaintext);
            let store = Store::open_for_mission(&root.database, services.authority)
                .expect("corruption store");
            let (stored, _, _) = publish_blob(
                &store,
                &mut services,
                &prepared,
                &plaintext,
                1,
                mode.as_bytes(),
            );
            let chunk = root.chunk_path(stored.variant_id, 0);
            let original = std::fs::read(&chunk).expect("marked chunk");
            drop(store);

            let expected = match mode {
                "missing" => {
                    std::fs::remove_file(&chunk).expect("remove marked chunk");
                    None
                }
                "truncated" => {
                    let file = std::fs::OpenOptions::new()
                        .write(true)
                        .open(&chunk)
                        .expect("open marked chunk");
                    file.set_len(u64::try_from(original.len() - 1).expect("truncated length"))
                        .expect("truncate marked chunk");
                    Some(std::fs::read(&chunk).expect("truncated bytes"))
                }
                "hash-mismatch" => {
                    let mut corrupt = original.clone();
                    *corrupt.last_mut().expect("ciphertext byte") ^= 1;
                    std::fs::write(&chunk, &corrupt).expect("corrupt marked chunk");
                    Some(corrupt)
                }
                _ => unreachable!(),
            };

            let inspect_error = Store::inspect_existing(&root.database)
                .expect_err("strict inspection must reject marked corruption");
            assert_depot_integrity(&inspect_error);
            let reopen_error = match Store::open_for_mission(&root.database, services.authority) {
                Ok(_) => panic!("writable reopen must reject marked corruption"),
                Err(error) => error,
            };
            assert_depot_integrity(&reopen_error);
            match expected {
                None => assert!(!chunk.exists(), "missing marker target must stay missing"),
                Some(bytes) => assert_eq!(
                    std::fs::read(&chunk).expect("corrupt chunk remains"),
                    bytes,
                    "marked corruption must never be repaired silently"
                ),
            }
        }
    }

    #[test]
    fn blob_lifecycle_migration_empty_predecessor_is_atomic_and_idempotent() {
        let root = BlobTestRoot::new("lifecycle-empty-predecessor");
        let services = blob_services(0xd0);
        with_blob_lifecycle_predecessor_setup(|| {
            drop(
                Store::open_for_mission(&root.database, services.authority)
                    .expect("create empty lifecycle predecessor"),
            );
        });
        strip_blob_lifecycle_schema_for_test(&root.database);
        assert!(blob_lifecycle_tables_present(&root.database).is_empty());

        let predecessor_digest = blob_database_digest(&root.database);
        assert_eq!(
            Store::inspect_existing(&root.database)
                .expect("inspect complete empty predecessor")
                .blob_stats,
            BlobStoreStats::default()
        );
        assert!(blob_lifecycle_tables_present(&root.database).is_empty());
        assert_eq!(blob_database_digest(&root.database), predecessor_digest);

        drop(
            Store::open_for_mission(&root.database, services.authority)
                .expect("migrate empty lifecycle predecessor"),
        );
        assert_blob_lifecycle_current_shape(&root.database, 0, 0, 0, 0, 0);
        let migrated_digest = blob_lifecycle_digest(&root.database);
        drop(
            Store::open_for_mission(&root.database, services.authority)
                .expect("idempotent empty lifecycle reopen"),
        );
        assert_blob_lifecycle_current_shape(&root.database, 0, 0, 0, 0, 0);
        assert_eq!(blob_lifecycle_digest(&root.database), migrated_digest);
    }

    #[test]
    fn blob_lifecycle_migration_reconstructs_shared_pending_staging_and_operations() {
        let root = BlobTestRoot::new("lifecycle-populated-predecessor");
        let source_root = BlobTestRoot::new("lifecycle-pending-source");
        let mut services = blob_services(0xd1);
        let shared_plaintext = b"two publications share one exact retained variant".to_vec();
        let shared = prepared_blob(&shared_plaintext);
        let pending_plaintext = b"one pending authenticated source remains a live root".to_vec();
        let pending_prepared = prepared_blob(&pending_plaintext);
        let staging_plaintext = b"one unpublished import staging row has no semantic root".to_vec();
        let staging_prepared = prepared_blob(&staging_plaintext);

        let (first, first_operation, first_intent, second, pending_transfer) =
            with_blob_lifecycle_predecessor_setup(|| {
                let target = Store::open_for_mission(&root.database, services.authority)
                    .expect("populated predecessor target");
                let source = Store::open_for_mission(&source_root.database, services.authority)
                    .expect("pending predecessor source");
                let (first, first_operation, first_intent) = publish_blob(
                    &target,
                    &mut services,
                    &shared,
                    &shared_plaintext,
                    1,
                    b"lifecycle-first-operation",
                );
                let (second, _, _) = publish_blob(
                    &target,
                    &mut services,
                    &shared,
                    &shared_plaintext,
                    1,
                    b"lifecycle-second-operation",
                );
                assert_eq!(first.variant_id, second.variant_id);

                let pending = prepare_blob_proof(
                    &source,
                    &mut services,
                    &pending_prepared,
                    &pending_plaintext,
                    1,
                );
                let pending_plan = pending
                    .blob
                    .transfer_plan(&pending.manifest_bytes)
                    .expect("pending lifecycle plan");
                let policy = target
                    .control_policy_snapshot()
                    .expect("pending lifecycle policy");
                assert_eq!(
                    target
                        .stage_verified_blob_source_with_policy(
                            &policy,
                            &pending.blob,
                            &pending.sealed,
                            &pending_plan,
                        )
                        .expect("stage pending lifecycle source"),
                    BlobSourceStageOutcome::Inserted
                );
                let pending_transfer = BlobTransferId::new(pending.blob.envelope_id());

                finish_variant(
                    &target,
                    &services.publisher,
                    &staging_prepared,
                    &staging_plaintext,
                    1,
                )
                .expect("finish unpublished lifecycle staging variant");
                drop(source);
                drop(target);
                (
                    first,
                    first_operation,
                    first_intent,
                    second,
                    pending_transfer,
                )
            });
        strip_blob_lifecycle_schema_for_test(&root.database);
        let predecessor = Store::inspect_existing(&root.database)
            .expect("strict inspection accepts complete populated predecessor")
            .blob_stats;
        assert_eq!(predecessor.publications, 2);
        assert_eq!(predecessor.operations, 2);
        assert_eq!(predecessor.variants, 3);
        assert_eq!(predecessor.pending_sources, 1);
        assert_eq!(predecessor.lineage_fences, 3);
        assert_eq!(predecessor.lineage_fence_bytes, 291);
        assert_eq!(predecessor.replay_fences, 2);
        assert_eq!(predecessor.replay_fence_bytes, 370);
        assert_eq!(predecessor.publication_lifecycle_rows, 2);
        assert_eq!(predecessor.variant_references, 3);
        assert!(blob_lifecycle_tables_present(&root.database).is_empty());

        let migrated = Store::open_for_mission(&root.database, services.authority)
            .expect("migrate populated lifecycle predecessor");
        assert_eq!(
            migrated.blob_stats().expect("migrated Blob stats"),
            predecessor
        );
        assert_eq!(
            migrated
                .get_blob(first.transfer_id)
                .expect("first migrated publication")
                .expect("first publication retained")
                .sealed,
            first.sealed
        );
        assert_eq!(
            migrated
                .get_blob(second.transfer_id)
                .expect("second migrated publication")
                .expect("second publication retained")
                .sealed,
            second.sealed
        );
        assert!(
            migrated
                .pending_blob_source(pending_transfer)
                .expect("migrated pending source")
                .is_some()
        );
        let policy = migrated
            .control_policy_snapshot()
            .expect("migrated operation policy");
        assert_eq!(
            migrated
                .blob_for_operation_with_policy(
                    &policy,
                    &BlobOperationRequest::new(&first_operation, &first_intent),
                )
                .expect("migrated operation mapping")
                .expect("operation target retained")
                .transfer_id,
            first.transfer_id
        );
        drop(migrated);

        assert_blob_lifecycle_current_shape(&root.database, 3, 2, 3, 2, 2);
        let migrated_digest = blob_lifecycle_digest(&root.database);
        drop(
            Store::open_for_mission(&root.database, services.authority)
                .expect("idempotent populated lifecycle reopen"),
        );
        assert_blob_lifecycle_current_shape(&root.database, 3, 2, 3, 2, 2);
        assert_eq!(blob_lifecycle_digest(&root.database), migrated_digest);
    }

    #[test]
    fn blob_lifecycle_migration_preflights_every_limit_without_mutation() {
        let root = BlobTestRoot::new("lifecycle-limit-rollback");
        let mut services = blob_services(0xd2);
        with_blob_lifecycle_predecessor_setup(|| {
            let store = Store::open_for_mission(&root.database, services.authority)
                .expect("limit predecessor store");
            for (index, plaintext) in [
                b"first independent migration variant".as_slice(),
                b"second independent migration variant".as_slice(),
            ]
            .into_iter()
            .enumerate()
            {
                let prepared = prepared_blob(plaintext);
                publish_blob(
                    &store,
                    &mut services,
                    &prepared,
                    plaintext,
                    1,
                    format!("migration-limit-operation-{index}").as_bytes(),
                );
            }
        });
        strip_blob_lifecycle_schema_for_test(&root.database);
        let before = blob_database_digest(&root.database);
        for (kind, limits) in [
            (
                "lineage rows",
                BlobLifecycleLimits::new(1, 1_000, 10, 10_000, 10).expect("lineage limit"),
            ),
            (
                "lineage bytes",
                BlobLifecycleLimits::new(10, 193, 10, 10_000, 10).expect("lineage byte limit"),
            ),
            (
                "replay rows",
                BlobLifecycleLimits::new(10, 10_000, 1, 1_000, 10).expect("replay limit"),
            ),
            (
                "replay bytes",
                BlobLifecycleLimits::new(10, 10_000, 10, 369, 10).expect("replay byte limit"),
            ),
            (
                "publication rows",
                BlobLifecycleLimits::new(10, 10_000, 10, 10_000, 1).expect("publication limit"),
            ),
        ] {
            let error = match Store::open_with_all_limits_for_mission(
                &root.database,
                StoreLimits::default(),
                BlobDepotLimits::default(),
                EventOperationLimits::DEFAULT,
                limits,
                services.authority,
            ) {
                Ok(_) => panic!("migration over a configured lifecycle cap must fail"),
                Err(error) => error,
            };
            match (kind, error) {
                (
                    "lineage rows",
                    StoreError::Blob(BlobStoreError::LineageFenceCapacity {
                        required_rows: 2,
                        required_bytes: 194,
                        max_rows: 1,
                        max_bytes: 1_000,
                    }),
                )
                | (
                    "lineage bytes",
                    StoreError::Blob(BlobStoreError::LineageFenceCapacity {
                        required_rows: 2,
                        required_bytes: 194,
                        max_rows: 10,
                        max_bytes: 193,
                    }),
                )
                | (
                    "replay rows",
                    StoreError::Blob(BlobStoreError::ReplayFenceCapacity {
                        required_rows: 2,
                        required_bytes: 370,
                        max_rows: 1,
                        max_bytes: 1_000,
                    }),
                )
                | (
                    "replay bytes",
                    StoreError::Blob(BlobStoreError::ReplayFenceCapacity {
                        required_rows: 2,
                        required_bytes: 370,
                        max_rows: 10,
                        max_bytes: 369,
                    }),
                )
                | (
                    "publication rows",
                    StoreError::Blob(BlobStoreError::PublicationLifecycleCapacity {
                        required_rows: 2,
                        max_rows: 1,
                    }),
                ) => {}
                (_, error) => panic!("unexpected lifecycle limit error: {error}"),
            }
            assert_eq!(blob_database_digest(&root.database), before);
            assert!(blob_lifecycle_tables_present(&root.database).is_empty());
            assert_eq!(
                Store::inspect_existing(&root.database)
                    .expect("failed capacity migration preserves predecessor")
                    .blob_stats
                    .publications,
                2
            );
        }
    }

    #[test]
    fn blob_lifecycle_migration_rejects_missing_or_conflicting_lineage() {
        let missing = BlobTestRoot::new("lifecycle-missing-lineage");
        let services = blob_services(0xd3);
        let plaintext = b"unpublished import must retain authenticated lineage".to_vec();
        let prepared = prepared_blob(&plaintext);
        with_blob_lifecycle_predecessor_setup(|| {
            let store = Store::open_for_mission(&missing.database, services.authority)
                .expect("missing-lineage predecessor");
            finish_variant(&store, &services.publisher, &prepared, &plaintext, 1)
                .expect("stage lineage-bound unpublished import");
        });
        strip_blob_lifecycle_schema_for_test(&missing.database);
        {
            let database = Database::open(&missing.database).expect("raw missing-lineage database");
            let write = database.begin_write().expect("missing-lineage write");
            let variant = {
                let imports = write
                    .open_table(BLOB_IMPORTS)
                    .expect("missing-lineage imports");
                let row = imports
                    .iter()
                    .expect("missing-lineage rows")
                    .next()
                    .expect("one missing-lineage row")
                    .expect("missing-lineage row");
                BlobVariantId::from_bytes(
                    row.0
                        .value()
                        .try_into()
                        .expect("missing-lineage variant key"),
                )
            };
            depot::remove_import_physical_lineage_for_test(&write, variant)
                .expect("remove import lineage");
            write.commit().expect("commit missing import lineage");
        }
        let missing_before = blob_database_digest(&missing.database);
        assert!(
            Store::open_for_mission(&missing.database, services.authority).is_err(),
            "migration must not invent missing physical lineage"
        );
        assert_eq!(blob_database_digest(&missing.database), missing_before);
        assert!(blob_lifecycle_tables_present(&missing.database).is_empty());

        let conflict = BlobTestRoot::new("lifecycle-conflicting-lineage");
        let mut services = blob_services(0xd4);
        let plaintext = b"publication and import lineage must agree".to_vec();
        let prepared = prepared_blob(&plaintext);
        let stored = with_blob_lifecycle_predecessor_setup(|| {
            let store = Store::open_for_mission(&conflict.database, services.authority)
                .expect("conflicting-lineage predecessor");
            publish_blob(
                &store,
                &mut services,
                &prepared,
                &plaintext,
                1,
                b"conflicting-lineage-operation",
            )
            .0
        });
        strip_blob_lifecycle_schema_for_test(&conflict.database);
        {
            let database = Database::open(&conflict.database).expect("raw conflicting database");
            let write = database.begin_write().expect("conflicting-lineage write");
            depot::corrupt_completion_import_for_test(
                &write,
                stored.variant_id,
                "physical_lineage",
            )
            .expect("corrupt import lineage");
            write.commit().expect("commit conflicting lineage");
        }
        let conflict_before = blob_database_digest(&conflict.database);
        assert!(Store::open_for_mission(&conflict.database, services.authority).is_err());
        assert_eq!(blob_database_digest(&conflict.database), conflict_before);
        assert!(blob_lifecycle_tables_present(&conflict.database).is_empty());
    }

    #[test]
    fn blob_lifecycle_migration_fault_rolls_back_tables_and_wrappers() {
        let root = BlobTestRoot::new("lifecycle-injected-rollback");
        let mut services = blob_services(0xd5);
        with_blob_lifecycle_predecessor_setup(|| {
            let store = Store::open_for_mission(&root.database, services.authority)
                .expect("fault predecessor");
            let plaintext = b"migration fault preserves complete predecessor".to_vec();
            let prepared = prepared_blob(&plaintext);
            publish_blob(
                &store,
                &mut services,
                &prepared,
                &plaintext,
                1,
                b"migration-fault-operation",
            );
        });
        strip_blob_lifecycle_schema_for_test(&root.database);
        let before = blob_database_digest(&root.database);
        lifecycle::TEST_BLOB_LIFECYCLE_MIGRATION_FAULT.set(true);
        let result = Store::open_for_mission(&root.database, services.authority);
        lifecycle::TEST_BLOB_LIFECYCLE_MIGRATION_FAULT.set(false);
        assert!(
            result.is_err(),
            "injected pre-commit migration fault must abort"
        );
        assert_eq!(blob_database_digest(&root.database), before);
        assert!(blob_lifecycle_tables_present(&root.database).is_empty());
        assert_eq!(
            Store::inspect_existing(&root.database)
                .expect("fault rollback preserves inspectable predecessor")
                .blob_stats
                .publications,
            1
        );
    }

    #[test]
    fn blob_lifecycle_migration_physical_audit_failure_preserves_exact_predecessor() {
        let root = BlobTestRoot::new("lifecycle-physical-audit-rollback");
        let mut services = blob_services(0xd9);
        let stored = with_blob_lifecycle_predecessor_setup(|| {
            let store = Store::open_for_mission(&root.database, services.authority)
                .expect("physical-audit predecessor");
            let plaintext = b"missing physical evidence must roll back lifecycle migration";
            let prepared = prepared_blob(plaintext);
            publish_blob(
                &store,
                &mut services,
                &prepared,
                plaintext,
                1,
                b"migration-physical-audit-operation",
            )
            .0
        });
        strip_blob_lifecycle_schema_for_test(&root.database);
        let chunk = root.chunk_path(stored.variant_id, 0);
        std::fs::remove_file(&chunk).expect("remove marked migration chunk");
        let predecessor = blob_database_digest(&root.database);
        assert!(blob_lifecycle_tables_present(&root.database).is_empty());

        let error = match Store::open_for_mission(&root.database, services.authority) {
            Ok(_) => panic!("physical audit must reject Blob-only lifecycle migration"),
            Err(error) => error,
        };
        assert_depot_integrity(&error);
        assert_eq!(blob_database_digest(&root.database), predecessor);
        assert!(blob_lifecycle_tables_present(&root.database).is_empty());
        assert!(!chunk.exists(), "missing physical evidence remains missing");
    }

    #[test]
    fn blob_lifecycle_migration_current_schema_corruption_is_never_repaired() {
        let services = blob_services(0xd6);

        let partial = BlobTestRoot::new("lifecycle-partial-current");
        drop(
            Store::open_for_mission(&partial.database, services.authority)
                .expect("create current lifecycle schema"),
        );
        {
            let database = Database::open(&partial.database).expect("partial lifecycle database");
            let write = database.begin_write().expect("partial lifecycle write");
            write
                .delete_table(lifecycle::BLOB_REPLAY_FENCES)
                .expect("delete one lifecycle table");
            write.commit().expect("commit partial lifecycle schema");
        }
        assert!(Store::inspect_existing(&partial.database).is_err());
        assert!(Store::open_for_mission(&partial.database, services.authority).is_err());
        assert!(
            !blob_lifecycle_tables_present(&partial.database)
                .contains(lifecycle::BLOB_REPLAY_FENCES.name())
        );

        let wrong_kind = BlobTestRoot::new("lifecycle-wrong-kind-current");
        drop(
            Store::open_for_mission(&wrong_kind.database, services.authority)
                .expect("create wrong-kind lifecycle base"),
        );
        {
            let database = Database::open(&wrong_kind.database).expect("wrong-kind lifecycle db");
            let write = database.begin_write().expect("wrong-kind lifecycle write");
            write
                .delete_table(lifecycle::BLOB_REPLAY_FENCES)
                .expect("delete normal replay table");
            write
                .open_multimap_table(redb::MultimapTableDefinition::<&[u8], &[u8]>::new(
                    lifecycle::BLOB_REPLAY_FENCES.name(),
                ))
                .expect("create wrong-kind replay table")
                .insert(b"dot".as_slice(), b"fence".as_slice())
                .expect("insert wrong-kind replay row");
            write.commit().expect("commit wrong-kind lifecycle schema");
        }
        assert!(Store::inspect_existing(&wrong_kind.database).is_err());
        assert!(Store::open_for_mission(&wrong_kind.database, services.authority).is_err());

        let counter = BlobTestRoot::new("lifecycle-counter-current");
        drop(
            Store::open_for_mission(&counter.database, services.authority)
                .expect("create counter lifecycle base"),
        );
        {
            let database = Database::open(&counter.database).expect("counter lifecycle database");
            let write = database.begin_write().expect("counter lifecycle write");
            write
                .open_table(lifecycle::BLOB_LIFECYCLE_METADATA)
                .expect("lifecycle metadata")
                .insert("lineage_rows", 1)
                .expect("corrupt lineage counter");
            write.commit().expect("commit lifecycle counter corruption");
        }
        assert!(Store::inspect_existing(&counter.database).is_err());
        assert!(Store::open_for_mission(&counter.database, services.authority).is_err());
        let database = redb::Builder::new()
            .open_read_only(&counter.database)
            .expect("read unrepaired lifecycle counter");
        assert_eq!(
            database
                .begin_read()
                .expect("counter read")
                .open_table(lifecycle::BLOB_LIFECYCLE_METADATA)
                .expect("counter metadata")
                .get("lineage_rows")
                .expect("counter value")
                .expect("counter retained")
                .value(),
            1
        );
    }

    #[test]
    fn blob_lifecycle_migration_malformed_or_mismatched_current_relations_fail_closed() {
        for (label, corrupt_reference) in [("malformed", false), ("relation", true)] {
            let root = BlobTestRoot::new(&format!("lifecycle-current-{label}"));
            let mut services = blob_services(if corrupt_reference { 0xd8 } else { 0xd7 });
            with_blob_lifecycle_predecessor_setup(|| {
                let store = Store::open_for_mission(&root.database, services.authority)
                    .expect("current-corruption predecessor");
                let plaintext = format!("current lifecycle {label} corruption").into_bytes();
                let prepared = prepared_blob(&plaintext);
                publish_blob(
                    &store,
                    &mut services,
                    &prepared,
                    &plaintext,
                    1,
                    format!("current-{label}-operation").as_bytes(),
                );
            });
            strip_blob_lifecycle_schema_for_test(&root.database);
            drop(
                Store::open_for_mission(&root.database, services.authority)
                    .expect("migrate current-corruption base"),
            );
            {
                let database = Database::open(&root.database).expect("raw current corruption db");
                let write = database.begin_write().expect("current corruption write");
                if corrupt_reference {
                    let mut references = write
                        .open_table(lifecycle::BLOB_VARIANT_REFERENCES)
                        .expect("current references");
                    let key = references
                        .iter()
                        .expect("reference rows")
                        .next()
                        .expect("one reference")
                        .expect("reference row")
                        .0
                        .value()
                        .to_vec();
                    references
                        .remove(key.as_slice())
                        .expect("remove current reference");
                } else {
                    let mut replay = write
                        .open_table(lifecycle::BLOB_REPLAY_FENCES)
                        .expect("current replay fences");
                    let (key, mut value) = {
                        let (key, value) = replay
                            .iter()
                            .expect("replay rows")
                            .next()
                            .expect("one replay fence")
                            .expect("replay row");
                        (key.value().to_vec(), value.value().to_vec())
                    };
                    value.pop();
                    replay
                        .insert(key.as_slice(), value.as_slice())
                        .expect("truncate replay fence");
                }
                write.commit().expect("commit current corruption");
            }
            let before = blob_lifecycle_digest(&root.database);
            assert!(Store::inspect_existing(&root.database).is_err());
            assert!(Store::open_for_mission(&root.database, services.authority).is_err());
            assert_eq!(blob_lifecycle_digest(&root.database), before);
        }
    }

    #[test]
    fn blob_schema_migrates_only_as_one_whole_absent_group() {
        let legacy = BlobTestRoot::new("whole-absent-schema");
        let services = blob_services(0x76);
        {
            let store =
                Store::open_for_mission(&legacy.database, services.authority).expect("schema base");
            drop(store);
            let database = Database::open(&legacy.database).expect("raw schema database");
            let write = database.begin_write().expect("raw schema write");
            write.delete_table(BLOB_PUBLICATIONS).expect("publications");
            write.delete_table(BLOB_BYTES).expect("bytes");
            write.delete_table(BLOB_SEMANTIC_ITEMS).expect("semantic");
            write.delete_table(BLOB_CONTENT_INDEX).expect("content");
            write
                .delete_table(BLOB_ACCEPTANCE_MARKERS)
                .expect("markers");
            write.delete_table(BLOB_OPERATIONS).expect("operations");
            write.delete_table(BLOB_IMPORTS).expect("imports");
            write.delete_table(BLOB_CHUNKS).expect("chunks");
            write
                .delete_table(BLOB_DEPOT_METADATA)
                .expect("depot metadata");
            write
                .delete_table(BLOB_PENDING_SOURCES)
                .expect("pending sources");
            write
                .delete_table(BLOB_CARRIER_PREFIXES)
                .expect("carrier prefixes");
            write
                .delete_table(BLOB_NETWORK_METADATA)
                .expect("network metadata");
            write
                .delete_table(BLOB_CARRIER_FETCH_CURSORS)
                .expect("carrier cursors");
            write
                .delete_table(BLOB_ACCEPTANCE_ORDER)
                .expect("acceptance order");
            write
                .delete_table(super::super::blob_subscription::BLOB_SUBSCRIPTIONS)
                .expect("subscriptions");
            write
                .delete_table(super::super::blob_subscription::BLOB_SUBSCRIPTION_PENDING)
                .expect("pending deliveries");
            write
                .delete_table(super::super::blob_subscription::BLOB_DELIVERY_ACKNOWLEDGEMENTS)
                .expect("acknowledgements");
            write
                .delete_table(super::super::blob_subscription::BLOB_DELIVERY_CURSORS)
                .expect("delivery cursors");
            {
                let mut metadata = write.open_table(METADATA).expect("metadata");
                for field in blob_global_metadata_fields() {
                    metadata.remove(field).expect("remove Blob counter");
                }
                for field in [
                    super::super::blob_subscription::BLOB_SUBSCRIPTION_COUNT,
                    super::super::blob_subscription::BLOB_PENDING_DELIVERY_COUNT,
                    super::super::blob_subscription::BLOB_ACKNOWLEDGEMENT_COUNT,
                    super::super::blob_subscription::BLOB_DELIVERY_CURSOR_COUNT,
                    super::super::blob_subscription::BLOB_SELECTOR_GENERATION,
                ] {
                    metadata
                        .remove(field)
                        .expect("remove Blob delivery counter");
                }
            }
            write.commit().expect("commit whole-absent schema");
        }
        for error in [
            Store::inspect_existing(&legacy.database)
                .expect_err("orphan lifecycle authority is not an absent Blob schema"),
            match Store::open_for_mission(&legacy.database, services.authority) {
                Ok(_) => panic!("writable open must not repair orphan lifecycle authority"),
                Err(error) => error,
            },
        ] {
            assert!(matches!(
                error,
                StoreError::Blob(BlobStoreError::SchemaInvariant(
                    "Blob lifecycle authority exists without its base schema"
                ))
            ));
        }
        {
            let database = Database::open(&legacy.database).expect("orphan lifecycle database");
            let write = database.begin_write().expect("orphan lifecycle cleanup");
            write
                .delete_table(lifecycle::BLOB_LIFECYCLE_METADATA)
                .expect("delete orphan lifecycle metadata");
            write
                .delete_table(lifecycle::BLOB_VARIANT_REFERENCES)
                .expect("delete orphan lifecycle references");
            write
                .delete_table(lifecycle::BLOB_LINEAGE_FENCES)
                .expect("delete orphan lineage fences");
            write
                .delete_table(lifecycle::BLOB_REPLAY_FENCES)
                .expect("delete orphan replay fences");
            write
                .delete_table(lifecycle::BLOB_MAINTENANCE_CURSORS)
                .expect("delete orphan maintenance cursors");
            write.commit().expect("commit absent lifecycle schema");
        }
        assert_eq!(
            Store::inspect_existing(&legacy.database)
                .expect("inspect whole-absent Blob group")
                .blob_stats,
            BlobStoreStats::default()
        );
        let migrated = Store::open_for_mission(&legacy.database, services.authority)
            .expect("migrate whole-absent Blob group");
        assert_eq!(
            migrated.blob_stats().expect("migrated Blob stats"),
            BlobStoreStats::default()
        );
        drop(migrated);

        let partial = BlobTestRoot::new("partial-schema");
        {
            let store = Store::open_for_mission(&partial.database, services.authority)
                .expect("partial base");
            drop(store);
            let database = Database::open(&partial.database).expect("partial database");
            let write = database.begin_write().expect("partial write");
            write.delete_table(BLOB_CHUNKS).expect("delete one table");
            write.commit().expect("commit partial schema");
        }
        let inspect_error = Store::inspect_existing(&partial.database)
            .expect_err("inspection rejects partial Blob schema");
        let reopen_error = match Store::open_for_mission(&partial.database, services.authority) {
            Ok(_) => panic!("reopen rejects partial Blob schema"),
            Err(error) => error,
        };
        for error in [inspect_error, reopen_error] {
            assert!(matches!(
                error,
                StoreError::Blob(BlobStoreError::SchemaInvariant(
                    "mission-scoped Blob schema group is incomplete"
                ))
            ));
        }

        let missing_counter = BlobTestRoot::new("missing-counter");
        {
            let store = Store::open_for_mission(&missing_counter.database, services.authority)
                .expect("counter base");
            drop(store);
            let database = Database::open(&missing_counter.database).expect("counter database");
            let write = database.begin_write().expect("counter write");
            write
                .open_table(METADATA)
                .expect("metadata")
                .remove(BLOB_OPERATION_COUNT)
                .expect("remove Blob counter");
            write.commit().expect("commit missing counter");
        }
        assert!(matches!(
            Store::inspect_existing(&missing_counter.database),
            Err(StoreError::Blob(BlobStoreError::SchemaInvariant(
                "mission-scoped Blob schema group is incomplete"
            )))
        ));
        assert!(matches!(
            Store::open_for_mission(&missing_counter.database, services.authority),
            Err(StoreError::Blob(BlobStoreError::SchemaInvariant(
                "mission-scoped Blob schema group is incomplete"
            )))
        ));
        let database = redb::Builder::new()
            .open_read_only(&missing_counter.database)
            .expect("read missing counter");
        assert!(
            database
                .begin_read()
                .expect("read transaction")
                .open_table(METADATA)
                .expect("metadata")
                .get(BLOB_OPERATION_COUNT)
                .expect("counter read")
                .is_none(),
            "failed writable reopen must not repair a partial Blob schema"
        );

        let wrong_kind = BlobTestRoot::new("wrong-kind");
        {
            let store = Store::open_for_mission(&wrong_kind.database, services.authority)
                .expect("wrong-kind base");
            drop(store);
            let database = Database::open(&wrong_kind.database).expect("wrong-kind database");
            let write = database.begin_write().expect("wrong-kind write");
            write
                .delete_table(BLOB_OPERATIONS)
                .expect("delete normal Blob operations");
            let definition =
                redb::MultimapTableDefinition::<&[u8], &[u8]>::new("aster.blob-operations.v1");
            write
                .open_multimap_table(definition)
                .expect("wrong-kind Blob operations")
                .insert(b"operation".as_slice(), b"row".as_slice())
                .expect("wrong-kind row");
            write.commit().expect("commit wrong-kind schema");
        }
        assert!(matches!(
            Store::inspect_existing(&wrong_kind.database),
            Err(StoreError::Blob(BlobStoreError::SchemaInvariant(
                "mission-scoped Blob schema has the wrong table kind"
            )))
        ));
        assert!(matches!(
            Store::open_for_mission(&wrong_kind.database, services.authority),
            Err(StoreError::Blob(BlobStoreError::SchemaInvariant(
                "mission-scoped Blob schema has the wrong table kind"
            )))
        ));
    }

    #[test]
    fn predecessor_nine_table_blob_schema_migrates_network_additively_with_owner_tokens() {
        let mut services = blob_services(0xc1);
        let remove_network_tables = |path: &Path| {
            let database = Database::open(path).expect("raw predecessor database");
            let write = database.begin_write().expect("predecessor schema write");
            write
                .delete_table(BLOB_PENDING_SOURCES)
                .expect("delete predecessor pending table");
            write
                .delete_table(BLOB_CARRIER_PREFIXES)
                .expect("delete predecessor carrier table");
            write
                .delete_table(BLOB_NETWORK_METADATA)
                .expect("delete predecessor network metadata");
            write
                .delete_table(BLOB_CARRIER_FETCH_CURSORS)
                .expect("delete predecessor cursor table");
            write.commit().expect("commit predecessor schema");
        };
        let table_names = |path: &Path| {
            let database = redb::Builder::new()
                .open_read_only(path)
                .expect("read predecessor database");
            database
                .begin_read()
                .expect("predecessor read")
                .list_tables()
                .expect("predecessor tables")
                .map(|table| table.name().to_owned())
                .collect::<BTreeSet<_>>()
        };

        let empty = BlobTestRoot::new("predecessor-empty-owner-token");
        drop(
            Store::open_for_mission(&empty.database, services.authority)
                .expect("empty predecessor base"),
        );
        remove_network_tables(&empty.database);
        assert_eq!(
            Store::inspect_existing(&empty.database)
                .expect("read-only predecessor inspection")
                .blob_stats,
            BlobStoreStats::default()
        );
        let inspected_names = table_names(&empty.database);
        assert!(
            network_blob_table_names()
                .iter()
                .all(|table| !inspected_names.contains(*table)),
            "read-only inspection must not migrate the additive network group"
        );
        drop(
            Store::open_for_mission(&empty.database, services.authority)
                .expect("writable predecessor migration"),
        );
        let migrated_names = table_names(&empty.database);
        assert!(
            network_blob_table_names()
                .iter()
                .all(|table| migrated_names.contains(*table)),
            "writable migration must install all four additive network tables"
        );

        let populated = BlobTestRoot::new("predecessor-populated-owner-token");
        let plaintext = b"populated nine-table predecessor remains attributable".to_vec();
        let prepared = prepared_blob(&plaintext);
        let populated_store = Store::open_for_mission(&populated.database, services.authority)
            .expect("populated predecessor base");
        publish_blob(
            &populated_store,
            &mut services,
            &prepared,
            &plaintext,
            1,
            b"predecessor-populated",
        );
        let populated_stats = populated_store
            .blob_stats()
            .expect("populated predecessor stats");
        drop(populated_store);
        remove_network_tables(&populated.database);
        assert_eq!(
            Store::inspect_existing(&populated.database)
                .expect("inspect populated predecessor")
                .blob_stats,
            populated_stats
        );
        let reopened = Store::open_for_mission(&populated.database, services.authority)
            .expect("migrate populated attributed predecessor");
        assert_eq!(
            reopened.blob_stats().expect("migrated populated stats"),
            populated_stats
        );
        drop(reopened);

        let pre_token = BlobTestRoot::new("predecessor-empty-pre-token");
        drop(
            Store::open_for_mission(&pre_token.database, services.authority)
                .expect("pre-token predecessor base"),
        );
        remove_network_tables(&pre_token.database);
        {
            let database = Database::open(&pre_token.database).expect("raw pre-token database");
            let write = database.begin_write().expect("pre-token removal write");
            let mut depot = write
                .open_table(BLOB_DEPOT_METADATA)
                .expect("pre-token depot metadata");
            for field in depot_owner_token_fields() {
                depot.remove(field).expect("remove predecessor token field");
            }
            for field in depot_owner_binding_fields() {
                depot
                    .remove(field)
                    .expect("remove predecessor binding field");
            }
            drop(depot);
            write.commit().expect("commit exact empty pre-token state");
        }
        assert!(
            Store::inspect_existing(&pre_token.database).is_err(),
            "read-only inspection cannot mint an absent owner token"
        );
        drop(
            Store::open_for_mission(&pre_token.database, services.authority)
                .expect("migrate exact empty pre-token predecessor"),
        );
        Store::inspect_existing(&pre_token.database)
            .expect("inspect migrated pre-token predecessor");

        let partial = BlobTestRoot::new("predecessor-partial-network");
        drop(
            Store::open_for_mission(&partial.database, services.authority)
                .expect("partial-network base"),
        );
        {
            let database = Database::open(&partial.database).expect("raw partial-network database");
            let write = database.begin_write().expect("partial-network write");
            write
                .delete_table(BLOB_CARRIER_FETCH_CURSORS)
                .expect("delete one network table");
            write.commit().expect("commit partial network schema");
        }
        let partial_names = table_names(&partial.database);
        assert!(Store::inspect_existing(&partial.database).is_err());
        assert!(Store::open_for_mission(&partial.database, services.authority).is_err());
        assert_eq!(
            table_names(&partial.database),
            partial_names,
            "failed writable reopen must not repair a partial network group"
        );
    }

    #[test]
    fn terminal_open_rejects_before_touching_unmarked_depot_artifacts() {
        let root = BlobTestRoot::new("terminal-gate");
        let services = blob_services(0x77);
        let mut store = Store::open_for_mission(&root.database, services.authority).expect("store");
        drop(store.blob_depot().expect("create fixed depot"));
        let orphan = root.depot().join(".aster-blob-tmp-terminal-proof");
        let orphan_bytes = b"unmarked ciphertext remains outside terminal reopen";
        std::fs::write(&orphan, orphan_bytes).expect("write orphan");
        let intent = ZeroizationIntent::new(
            b"mission bundle descriptor".to_vec(),
            b"carrier identity descriptor".to_vec(),
        )
        .expect("zeroization intent");
        store.begin_zeroization(&intent).expect("terminal marker");
        drop(store);

        assert!(matches!(
            Store::open_for_mission(&root.database, services.authority),
            Err(StoreError::StoreZeroized(
                StoreZeroizationState::CleanupPending
            ))
        ));
        assert_eq!(
            std::fs::read(&orphan).expect("terminal orphan preserved"),
            orphan_bytes,
            "terminal gate must run before depot scan or cleanup"
        );
    }

    #[test]
    fn terminal_entry_closes_new_and_already_held_blob_depot_io_before_mutation() {
        let public_root = BlobTestRoot::new("terminal-depot-public-gate");
        let public_services = blob_services(0xb4);
        let mut public_store =
            Store::open_for_mission(&public_root.database, public_services.authority)
                .expect("public terminal store");
        drop(public_store.blob_depot().expect("initial depot adapter"));
        let before_terminal = depot_file_snapshot(&public_root.depot());
        let intent = ZeroizationIntent::new(
            b"terminal depot mission descriptor".to_vec(),
            b"terminal depot identity descriptor".to_vec(),
        )
        .expect("terminal intent");
        public_store
            .begin_zeroization(&intent)
            .expect("terminal entry");
        assert!(matches!(
            public_store.blob_depot(),
            Err(StoreError::StoreZeroized(
                StoreZeroizationState::CleanupPending
            ))
        ));
        assert_eq!(depot_file_snapshot(&public_root.depot()), before_terminal);

        let held_root = BlobTestRoot::new("terminal-depot-held-gate");
        let held_services = blob_services(0xb5);
        let held_store = Store::open_for_mission(&held_root.database, held_services.authority)
            .expect("held adapter store");
        let prepared = prepared_blob(b"held adapter gate");
        let mut held = held_store.blob_depot().expect("held adapter");
        let before_files = depot_file_snapshot(&held_root.depot());
        let before_rows = {
            let read = held_store.database.begin_read().expect("held gate read");
            (
                read.open_table(BLOB_IMPORTS)
                    .expect("imports")
                    .len()
                    .expect("import rows"),
                read.open_table(BLOB_CHUNKS)
                    .expect("chunks")
                    .len()
                    .expect("chunk rows"),
            )
        };
        held_store.live.store(false, Ordering::SeqCst);
        assert!(matches!(
            CoreBlobStore::plaintext_digest(&mut held, prepared.id(), 0),
            Err(StoreError::StoreZeroized(
                StoreZeroizationState::CleanupPending
            ))
        ));
        assert!(matches!(
            CoreBlobStore::put_plaintext_digest(&mut held, prepared.id(), 0, [0x55; 32]),
            Err(StoreError::StoreZeroized(
                StoreZeroizationState::CleanupPending
            ))
        ));
        let after_rows = {
            let read = held_store.database.begin_read().expect("held gate reread");
            (
                read.open_table(BLOB_IMPORTS)
                    .expect("imports")
                    .len()
                    .expect("import rows"),
                read.open_table(BLOB_CHUNKS)
                    .expect("chunks")
                    .len()
                    .expect("chunk rows"),
            )
        };
        assert_eq!(after_rows, before_rows);
        assert_eq!(depot_file_snapshot(&held_root.depot()), before_files);
        held_store.live.store(true, Ordering::SeqCst);
        drop(held);
    }

    #[test]
    fn blob_and_event_share_causal_ledgers_and_strict_corruption_authority() {
        let root = BlobTestRoot::new("shared-causal");
        let mut services = blob_services(0x78);
        let plaintext = vec![0x78; 1_337];
        let prepared = prepared_blob(&plaintext);
        let store = Store::open_for_mission(&root.database, services.authority).expect("store");
        let (stored, _, _) = publish_blob(
            &store,
            &mut services,
            &prepared,
            &plaintext,
            1,
            b"causal-blob",
        );
        let policy = store.control_policy_snapshot().expect("policy");
        let (reservation, event, sealed) =
            reserved_event(&store, &mut services, &policy, b"observes Blob");
        assert_eq!(reservation.counter(), 2);
        assert_eq!(
            reservation
                .context()
                .counter(&services.publisher.identity()),
            1
        );
        store
            .commit_reserved_event_with_policy(&policy, &reservation, &event, &sealed)
            .expect("commit Event after Blob");
        assert_eq!(store.event_stats().expect("Event stats").events, 1);
        assert_eq!(store.blob_stats().expect("Blob stats").publications, 1);
        drop(store);
        let inspection = Store::inspect_existing(&root.database).expect("shared inspection");
        assert_eq!(inspection.event_stats.events, 1);
        assert_eq!(inspection.blob_stats.publications, 1);

        let database = Database::open(&root.database).expect("raw corruption database");
        let write = database.begin_write().expect("raw corruption write");
        write
            .open_table(ACCEPTED_DOTS)
            .expect("accepted dots")
            .remove(accepted_dot_key(stored.header.stamp.dot).as_slice())
            .expect("remove Blob dot");
        write.commit().expect("commit Blob dot corruption");
        drop(database);
        assert!(matches!(
            Store::inspect_existing(&root.database),
            Err(StoreError::Blob(BlobStoreError::SchemaInvariant(
                "Blob publication is missing its accepted-dot row"
            )))
        ));
        assert!(matches!(
            Store::open_for_mission(&root.database, services.authority),
            Err(StoreError::Blob(BlobStoreError::SchemaInvariant(
                "Blob publication is missing its accepted-dot row"
            )))
        ));
    }

    #[test]
    fn blob_usage_counts_toward_cross_class_aggregate_quota_after_reopen() {
        let root = BlobTestRoot::new("aggregate-quota");
        let mut services = blob_services(0x79);
        let limits = StoreLimits::new(
            MAX_CONTROL_ITEMS + CUSTODY_EMERGENCY_ITEM_RESERVE + 2,
            u64::MAX,
        )
        .expect("aggregate limits");
        let plaintext = vec![0x79; 2_049];
        let prepared = prepared_blob(&plaintext);
        let store = Store::open_with_limits_for_mission(&root.database, limits, services.authority)
            .expect("quota store");
        let (stored, _, _) = publish_blob(
            &store,
            &mut services,
            &prepared,
            &plaintext,
            1,
            b"quota-blob",
        );
        let policy = store.control_policy_snapshot().expect("quota policy");
        let (reservation, event, sealed) =
            reserved_event(&store, &mut services, &policy, b"must roll back");
        let rejected =
            store.commit_reserved_event_with_policy(&policy, &reservation, &event, &sealed);
        assert!(
            matches!(
                rejected,
                Err(StoreError::ItemLimitExceeded {
                    current: 2,
                    limit: 2,
                })
            ),
            "unexpected aggregate result: {rejected:?}"
        );
        assert_eq!(
            store.event_stats().expect("rolled-back Event stats").events,
            0
        );
        assert_eq!(
            store.blob_inventory().expect("Blob inventory"),
            vec![stored.transfer_id]
        );
        drop(store);

        let reopened =
            Store::open_with_limits_for_mission(&root.database, limits, services.authority)
                .expect("quota reopen");
        let reopened_rejected =
            reopened.commit_reserved_event_with_policy(&policy, &reservation, &event, &sealed);
        assert!(
            matches!(
                reopened_rejected,
                Err(StoreError::ItemLimitExceeded {
                    current: 2,
                    limit: 2,
                })
            ),
            "unexpected reopened aggregate result: {reopened_rejected:?}"
        );
        assert_eq!(
            reopened.event_stats().expect("reopened Event stats").events,
            0
        );
        assert_eq!(
            reopened
                .blob_stats()
                .expect("reopened Blob stats")
                .publications,
            1
        );
    }

    #[test]
    fn cross_class_transfer_collision_is_rejected_on_inspection_and_reopen() {
        let root = BlobTestRoot::new("cross-class-collision");
        let mut services = blob_services(0x7a);
        let plaintext = vec![0x7a; 777];
        let prepared = prepared_blob(&plaintext);
        let store = Store::open_for_mission(&root.database, services.authority).expect("store");
        let (stored, _, _) = publish_blob(
            &store,
            &mut services,
            &prepared,
            &plaintext,
            1,
            b"collision-blob",
        );
        drop(store);
        let database = Database::open(&root.database).expect("collision database");
        let write = database.begin_write().expect("collision write");
        write
            .open_table(EVENTS)
            .expect("Events")
            .insert(
                stored.transfer_id.as_bytes().as_slice(),
                b"opaque collision".as_slice(),
            )
            .expect("insert transfer collision");
        write.commit().expect("commit transfer collision");
        drop(database);
        assert!(matches!(
            Store::inspect_existing(&root.database),
            Err(StoreError::TransferNamespaceCollision { transfer_id })
                if transfer_id == *stored.transfer_id.as_bytes()
        ));
        assert!(matches!(
            Store::open_for_mission(&root.database, services.authority),
            Err(StoreError::TransferNamespaceCollision { transfer_id })
                if transfer_id == *stored.transfer_id.as_bytes()
        ));

        let database = Database::open(&root.database).expect("semantic collision database");
        let write = database.begin_write().expect("semantic collision write");
        write
            .open_table(EVENTS)
            .expect("Events")
            .remove(stored.transfer_id.as_bytes().as_slice())
            .expect("remove transfer collision");
        write
            .open_table(SEMANTIC_ITEMS)
            .expect("Event semantic items")
            .insert(
                stored.semantic_id.as_bytes().as_slice(),
                stored.transfer_id.as_bytes().as_slice(),
            )
            .expect("insert semantic collision");
        write.commit().expect("commit semantic collision");
        drop(database);
        assert!(matches!(
            Store::inspect_existing(&root.database),
            Err(StoreError::SemanticNamespaceCollision { semantic_id })
                if semantic_id == *stored.semantic_id.as_bytes()
        ));
        assert!(matches!(
            Store::open_for_mission(&root.database, services.authority),
            Err(StoreError::SemanticNamespaceCollision { semantic_id })
                if semantic_id == *stored.semantic_id.as_bytes()
        ));
    }

    #[test]
    fn completion_rejects_forged_final_digest_with_wrong_committed_records() {
        let genuine_root = BlobTestRoot::new("genuine-manifest");
        let forged_root = BlobTestRoot::new("forged-completion");
        let mut services = blob_services(0x7b);
        let plaintext = vec![0x7b; 4_321];
        let prepared = prepared_blob(&plaintext);
        let genuine = Store::open_for_mission(&genuine_root.database, services.authority)
            .expect("genuine depot");
        let (manifest, finished) = {
            let depot = genuine.blob_depot().expect("genuine adapter");
            let mut service = services
                .publisher
                .blob_service_with_store(&blob_scope(), &blob_topic(), 1, depot)
                .expect("genuine service");
            let manifest = service
                .install_prepared(&prepared)
                .expect("genuine manifest");
            let progress = service
                .encrypt_some(&mut Cursor::new(&plaintext), &manifest, u64::MAX)
                .expect("genuine encryption");
            assert!(progress.complete);
            let finished = service
                .finish_manifest(&manifest)
                .expect("genuine finalization");
            (manifest, finished)
        };

        let forged = Store::open_for_mission(&forged_root.database, services.authority)
            .expect("forged depot");
        let policy = forged.control_policy_snapshot().expect("forged policy");
        let reservation = forged
            .reserve_blob_with_policy(
                &policy,
                services.publisher.identity(),
                &blob_topic(),
                &blob_scope(),
            )
            .expect("forged reservation");
        let header = reservation
            .header(
                Priority::Immediate,
                finished.route_commitment(),
                u64::try_from(finished.manifest_bytes().len()).expect("manifest length"),
                1,
            )
            .expect("source header");
        let sealed = services
            .publisher
            .seal_blob_manifest(&header, finished.manifest_bytes())
            .expect("source seal");
        let route = services
            .reader
            .verify_blob(&sealed.bytes)
            .expect("source route");
        let (blob, manifest_bytes) = match services
            .reader
            .verify_blob_content(route, &sealed.bytes)
            .expect("source content")
        {
            BlobContentVerification::ContentVerified {
                blob,
                manifest_bytes,
            } => (blob, manifest_bytes),
            BlobContentVerification::RouteOnly(_) => panic!("member unexpectedly route-only"),
        };

        {
            let mut depot = forged.blob_depot().expect("forged adapter");
            CoreBlobStore::begin_blob_with_lineage(&mut depot, &manifest, blob.physical_lineage())
                .expect("begin forged import");
            let wrong_plaintext_digest = [0xa5; 32];
            let ciphertext = vec![0x5a; plaintext.len() + 16];
            let ciphertext_digest: [u8; 32] = Sha256::digest(&ciphertext).into();
            let record = aster_mesh::BlobChunkRecord::from_parts(
                wrong_plaintext_digest,
                ciphertext_digest,
                u32::try_from(plaintext.len()).expect("plaintext length"),
                u32::try_from(ciphertext.len()).expect("ciphertext length"),
            )
            .expect("forged internally consistent record");
            CoreBlobStore::put_plaintext_digest(
                &mut depot,
                manifest.id(),
                0,
                wrong_plaintext_digest,
            )
            .expect("stage forged digest");
            CoreBlobStore::commit_verified_chunk(&mut depot, manifest.id(), 0, record, &ciphertext)
                .expect("commit forged record");
            CoreBlobStore::finalize_blob(&mut depot, manifest.id(), *blob.manifest_digest())
                .expect("forge final digest through public storage mechanics");
        }

        let error = forged
            .blob_depot()
            .and_then(|mut depot| depot.completed_blob(&blob, &manifest_bytes))
            .expect_err("strong completion must reject wrong authenticated records");
        assert!(matches!(
            error,
            StoreError::Blob(BlobStoreError::CompletionMismatch)
        ));
        let stats = forged
            .blob_stats()
            .expect("forged depot remains inspectable");
        assert_eq!(stats.finalized_variants, 1);
        assert_eq!(stats.publications, 0);
    }

    #[test]
    fn completion_capability_is_bound_to_one_exact_store_instance() {
        let first_root = BlobTestRoot::new("completion-instance-first");
        let second_root = BlobTestRoot::new("completion-instance-second");
        let empty_root = BlobTestRoot::new("completion-instance-empty");
        let mut services = blob_services(0x7d);
        let plaintext = vec![0x7d; SELECTED_BLOB_CHUNK_SIZE as usize + 2_048];
        let prepared = prepared_blob(&plaintext);
        let first =
            Store::open_for_mission(&first_root.database, services.authority).expect("first store");
        let second = Store::open_for_mission(&second_root.database, services.authority)
            .expect("second store");
        let empty =
            Store::open_for_mission(&empty_root.database, services.authority).expect("empty store");
        let proof = prepare_blob_proof(&first, &mut services, &prepared, &plaintext, 1);
        let exact_metadata = BlobMetadata {
            transfer_id: BlobTransferId::new(proof.blob.envelope_id()),
            semantic_id: BlobSemanticId::new(proof.blob.item_id()),
            blob_id: proof.blob.blob_id(),
            variant_id: blob_variant_id(
                proof.blob.blob_id(),
                proof.blob.manifest().content_group(),
                proof.blob.manifest().content_epoch(),
            ),
            manifest_digest: *proof.blob.manifest_digest(),
            route_lineage: Some(*proof.blob.route_lineage().binding()),
            physical_lineage: Some(*proof.blob.physical_lineage().binding()),
            header: proof.blob.header().clone(),
        };
        let exact_projection = blob_source_projection(
            &exact_metadata,
            u64::try_from(proof.sealed.len()).expect("sealed length"),
            depot::BlobSourceShape {
                total_len: proof.blob.manifest().total_len(),
                chunk_size: proof.blob.manifest().chunk_size(),
                chunk_count: proof.blob.manifest().chunk_count(),
            },
        )
        .expect("exact authenticated projection");
        assert!(
            exact_projection
                .matches_verified(&proof.blob, &proof.sealed)
                .expect("match exact verified source")
        );
        let mut forged_metadata = exact_metadata;
        forged_metadata.header.stamp.dot.counter = forged_metadata
            .header
            .stamp
            .dot
            .counter
            .checked_add(1)
            .expect("forged counter");
        let forged_projection = blob_source_projection(
            &forged_metadata,
            u64::try_from(proof.sealed.len()).expect("sealed length"),
            depot::BlobSourceShape {
                total_len: proof.blob.manifest().total_len(),
                chunk_size: proof.blob.manifest().chunk_size(),
                chunk_count: proof.blob.manifest().chunk_count(),
            },
        )
        .expect("forged durable projection");
        assert!(
            !forged_projection
                .matches_verified(&proof.blob, &proof.sealed)
                .expect("reject forged durable header")
        );
        let second_finished =
            finish_variant(&second, &services.publisher, &prepared, &plaintext, 1)
                .expect("install identical second-store variant");
        assert_eq!(
            second_finished.manifest_digest(),
            proof.blob.manifest_digest(),
            "both stores contain the same exact finalized variant"
        );
        first
            .blob_depot()
            .and_then(|mut depot| depot.recheck_completion(&proof.completion))
            .expect("completion remains exact in its issuing store");
        let before_mutators = depot::test_depot_io_counts(&first);
        {
            let mut read_only = first
                .blob_depot_for_authenticated_read(&proof.completion)
                .expect("open mutation-incapable authenticated depot");
            let record = CoreBlobStore::chunk_record(&mut read_only, prepared.id(), 0)
                .expect("read exact chunk record")
                .expect("committed first chunk record");
            assert!(CoreBlobStore::begin_blob(&mut read_only, proof.blob.manifest()).is_err());
            assert!(
                CoreBlobStore::begin_blob_with_lineage(
                    &mut read_only,
                    proof.blob.manifest(),
                    proof.blob.physical_lineage(),
                )
                .is_err()
            );
            assert!(
                CoreBlobStore::put_plaintext_digest(&mut read_only, prepared.id(), 0, [0x55; 32],)
                    .is_err()
            );
            assert!(
                CoreBlobStore::put_expected_chunk_record(&mut read_only, prepared.id(), 0, record,)
                    .is_err()
            );
            assert!(
                CoreBlobStore::commit_verified_chunk(
                    &mut read_only,
                    prepared.id(),
                    0,
                    record,
                    &[],
                )
                .is_err()
            );
            assert!(
                CoreBlobStore::finalize_blob(
                    &mut read_only,
                    prepared.id(),
                    *proof.blob.manifest_digest(),
                )
                .is_err()
            );
        }
        let after_mutators = depot::test_depot_io_counts(&first);
        assert_eq!(
            after_mutators.full_open_audits,
            before_mutators.full_open_audits
        );
        assert_eq!(
            after_mutators.begin_write_transactions,
            before_mutators.begin_write_transactions
        );
        assert_eq!(
            after_mutators.root_creations,
            before_mutators.root_creations
        );
        assert_eq!(
            after_mutators.authenticated_read_opens,
            before_mutators.authenticated_read_opens + 1
        );
        let before_range = first.blob_stats().expect("stats before bounded range");
        let before_io = depot::test_depot_io_counts(&first);
        {
            let mut service = services
                .publisher
                .blob_service_with_store(
                    &blob_scope(),
                    &blob_topic(),
                    1,
                    first
                        .blob_depot_for_authenticated_read(&proof.completion)
                        .expect("fresh authenticated range depot"),
                )
                .expect("fresh range service");
            let mut tail = [0u8; 1];
            let tail_stats = service
                .read_range_for_verified(
                    &proof.blob,
                    u64::try_from(plaintext.len() - 1).expect("tail offset"),
                    &mut tail,
                )
                .expect("fresh redb tail range");
            assert_eq!(tail, [0x7d]);
            assert_eq!(tail_stats.plaintext_bytes, 1);
            assert_eq!(tail_stats.verified_chunks, 1);

            let mut crossing = [0u8; 16];
            let crossing_stats = service
                .read_range_for_verified(
                    &proof.blob,
                    u64::from(SELECTED_BLOB_CHUNK_SIZE) - 8,
                    &mut crossing,
                )
                .expect("fresh redb cross-chunk range");
            assert_eq!(crossing, [0x7d; 16]);
            assert_eq!(crossing_stats.plaintext_bytes, 16);
            assert_eq!(crossing_stats.verified_chunks, 2);
        }
        let after_io = depot::test_depot_io_counts(&first);
        assert_eq!(after_io.full_open_audits, before_io.full_open_audits);
        assert_eq!(
            after_io.begin_write_transactions,
            before_io.begin_write_transactions
        );
        assert_eq!(after_io.root_creations, before_io.root_creations);
        assert_eq!(
            after_io.authenticated_read_opens,
            before_io.authenticated_read_opens + 1
        );
        assert_eq!(
            first.blob_stats().expect("stats after bounded range"),
            before_range,
            "exact range selection cannot manufacture or mutate durable depot state"
        );

        let mut rebound_to_empty = proof.completion.clone();
        rebound_to_empty.authority = Arc::clone(&empty.blob_completion_authority);
        rebound_to_empty.backing_identity = empty.backing_identity;
        let empty_before = depot::test_depot_io_counts(&empty);
        assert!(!empty_root.depot().exists());
        empty
            .blob_depot_for_authenticated_read(&rebound_to_empty)
            .err()
            .expect("authenticated read cannot create an absent depot root");
        let empty_after = depot::test_depot_io_counts(&empty);
        assert_eq!(empty_after.root_creations, empty_before.root_creations);
        assert_eq!(
            empty_after.begin_write_transactions,
            empty_before.begin_write_transactions
        );
        assert!(!empty_root.depot().exists());

        let policy = second.control_policy_snapshot().expect("second policy");
        let reservation = second
            .reserve_blob_with_policy(
                &policy,
                services.publisher.identity(),
                &blob_topic(),
                &blob_scope(),
            )
            .expect("second reservation");
        let operation =
            BlobOperationKey::new(b"cross-store-completion".to_vec()).expect("operation key");
        let intent = BlobPublicationIntent::new(
            services.publisher.identity(),
            blob_topic(),
            blob_scope(),
            Priority::Immediate,
            prepared.id(),
        )
        .expect("publication intent");
        let request = BlobOperationRequest::new(&operation, &intent);

        // Equalize the portable file-identity defense so this exercises the
        // private Store-instance token on Unix and non-Unix platforms alike.
        let mut replayed = proof.completion.clone();
        replayed.backing_identity = second.backing_identity;
        let error = second
            .blob_depot_for_authenticated_read(&replayed)
            .err()
            .expect("another Store instance cannot open an authenticated read depot");
        assert!(matches!(
            error,
            StoreError::Blob(BlobStoreError::CompletionMismatch)
        ));
        let error = second
            .blob_depot()
            .and_then(|mut depot| depot.recheck_completion(&replayed))
            .expect_err("another Store instance cannot recheck a completion capability");
        assert!(matches!(
            error,
            StoreError::Blob(BlobStoreError::CompletionMismatch)
        ));
        let error = second
            .commit_reserved_blob_once_with_policy(
                &policy,
                &request,
                &reservation,
                &proof.blob,
                &proof.sealed,
                &replayed,
            )
            .expect_err("another Store instance cannot replay a completion capability");
        assert!(matches!(
            error,
            StoreError::Blob(BlobStoreError::CompletionMismatch)
        ));
        let stats = second.blob_stats().expect("second stats after rejection");
        assert_eq!(stats.publications, 0);
        assert_eq!(stats.operations, 0);

        let write = first
            .database
            .begin_write()
            .expect("missing-range-chunk mutation write");
        depot::remove_completion_chunk_state_for_test(&write, proof.completion.variant_id(), 1)
            .expect("remove one requested completion chunk");
        write
            .commit()
            .expect("commit missing requested completion chunk");
        let before_missing = depot::test_depot_io_counts(&first);
        let missing = first
            .blob_depot_for_authenticated_read(&proof.completion)
            .and_then(|mut depot| depot.recheck_completion_range(&proof.completion, 1, 1))
            .expect_err("missing requested chunk must invalidate bounded completion");
        assert!(matches!(
            missing,
            StoreError::Blob(BlobStoreError::CompletionMismatch)
        ));
        let after_missing = depot::test_depot_io_counts(&first);
        assert_eq!(
            after_missing.full_open_audits,
            before_missing.full_open_audits
        );
        assert_eq!(
            after_missing.begin_write_transactions,
            before_missing.begin_write_transactions
        );
        assert_eq!(after_missing.root_creations, before_missing.root_creations);
        assert_eq!(
            after_missing.authenticated_read_opens,
            before_missing.authenticated_read_opens + 1
        );
    }

    #[test]
    fn retained_completion_mints_are_linear_in_exact_variant_chunks() {
        let root = BlobTestRoot::new("retained-completion-linear");
        let mut services = blob_services(0x7e);
        let store = Store::open_for_mission(&root.database, services.authority)
            .expect("retained completion store");
        let mut retained = Vec::new();
        for variant in 0..8u8 {
            let plaintext =
                vec![variant; SELECTED_BLOB_CHUNK_SIZE as usize + usize::from(variant) + 1];
            let prepared = prepared_blob(&plaintext);
            let proof = prepare_blob_proof(&store, &mut services, &prepared, &plaintext, 1);
            let operation = BlobOperationKey::new(format!("retained-{variant}").into_bytes())
                .expect("retained operation");
            let intent = BlobPublicationIntent::new(
                services.publisher.identity(),
                blob_topic(),
                blob_scope(),
                Priority::Immediate,
                prepared.id(),
            )
            .expect("retained intent");
            let outcome = store
                .commit_reserved_blob_once_with_policy(
                    &proof.policy,
                    &BlobOperationRequest::new(&operation, &intent),
                    &proof.reservation,
                    &proof.blob,
                    &proof.sealed,
                    &proof.completion,
                )
                .expect("commit retained variant");
            let projection = store
                .blob_source_projection(outcome.blob().transfer_id)
                .expect("retained projection lookup")
                .expect("retained projection");
            retained.push((proof, projection));
        }

        let before = depot::test_depot_io_counts(&store);
        let mut expected_rows = 0u64;
        for (proof, projection) in &retained {
            let completion = store
                .completed_retained_blob(
                    &projection.source,
                    projection.retention,
                    &proof.blob,
                    &proof.manifest_bytes,
                    &proof.sealed,
                )
                .expect("mint retained completion");
            assert_eq!(completion.blob_id(), proof.blob.blob_id());
            expected_rows = expected_rows
                .checked_add(proof.blob.manifest().chunk_count())
                .expect("expected chunk rows");
        }
        let after = depot::test_depot_io_counts(&store);
        assert_eq!(after.full_open_audits, before.full_open_audits);
        assert_eq!(
            after.begin_write_transactions,
            before.begin_write_transactions
        );
        assert_eq!(after.root_creations, before.root_creations);
        assert_eq!(
            after.completion_chunk_rows_visited - before.completion_chunk_rows_visited,
            expected_rows,
            "unrelated variants leaked into exact completion proofs"
        );
    }

    #[test]
    fn completion_capability_rejects_every_exact_import_identity_mutation() {
        for (index, field) in [
            "whole_plaintext_sha256",
            "media_type",
            "schema_id",
            "total_len",
            "chunk_size",
            "physical_lineage",
            "finalized_manifest_digest",
            "chunk_count",
        ]
        .into_iter()
        .enumerate()
        {
            let root = BlobTestRoot::new(field);
            let mut services = blob_services(0xa0 + u8::try_from(index).expect("mutation index"));
            let plaintext = vec![0xa5; 2_048];
            let prepared = prepared_blob(&plaintext);
            let store =
                Store::open_for_mission(&root.database, services.authority).expect("case store");
            let proof = prepare_blob_proof(&store, &mut services, &prepared, &plaintext, 1);
            let write = store.database.begin_write().expect("import mutation write");
            depot::corrupt_completion_import_for_test(&write, proof.completion.variant_id(), field)
                .expect("mutate exact completion import");
            write.commit().expect("commit import mutation");

            let error = depot::verify_completion(&store, &proof.completion)
                .expect_err("old completion capability rejects changed import");
            assert!(
                matches!(error, StoreError::Blob(_)),
                "completion recheck must fail in the Blob domain for {field}: {error:?}"
            );
            assert!(
                store
                    .blob_depot_for_authenticated_read(&proof.completion)
                    .is_err(),
                "authenticated read open must reject mutated {field}"
            );
            assert!(
                store
                    .blob_depot()
                    .and_then(|mut depot| {
                        depot.completed_blob(&proof.blob, &proof.manifest_bytes)
                    })
                    .is_err(),
                "completion mint must reject mutated {field}"
            );
        }
    }

    #[test]
    fn accepted_publication_requires_its_exact_finalized_import_without_repair() {
        let root = BlobTestRoot::new("missing-publication-import");
        let mut services = blob_services(0x7c);
        let plaintext = vec![0x7c; 1_111];
        let prepared = prepared_blob(&plaintext);
        let store = Store::open_for_mission(&root.database, services.authority).expect("store");
        let (stored, _, _) = publish_blob(
            &store,
            &mut services,
            &prepared,
            &plaintext,
            1,
            b"missing-import",
        );
        let variant_path = root.depot().join(test_hex32(stored.variant_id.as_bytes()));
        drop(store);

        let database = Database::open(&root.database).expect("raw import database");
        let write = database.begin_write().expect("raw import write");
        write
            .open_table(BLOB_IMPORTS)
            .expect("imports")
            .remove(stored.variant_id.as_bytes().as_slice())
            .expect("remove import");
        let chunk_keys = write
            .open_table(BLOB_CHUNKS)
            .expect("chunks")
            .iter()
            .expect("iterate chunks")
            .map(|row| row.map(|(key, _)| key.value().to_vec()))
            .collect::<Result<Vec<_>, _>>()
            .expect("chunk keys");
        {
            let mut chunks = write.open_table(BLOB_CHUNKS).expect("chunks");
            for key in chunk_keys {
                chunks.remove(key.as_slice()).expect("remove chunk marker");
            }
        }
        {
            let mut depot = write
                .open_table(BLOB_DEPOT_METADATA)
                .expect("depot metadata");
            depot.insert(DEPOT_VARIANT_COUNT, 0).expect("variant count");
            depot
                .insert(DEPOT_COMMITTED_CHUNK_COUNT, 0)
                .expect("chunk count");
            depot
                .insert(DEPOT_COMMITTED_FILE_BYTES, 0)
                .expect("byte count");
            depot
                .insert(DEPOT_RESERVED_FILE_BYTES, 0)
                .expect("reserved byte count");
        }
        write.commit().expect("commit coherent depot deletion");
        drop(database);
        std::fs::remove_dir_all(&variant_path).expect("remove physical variant");

        for error in [
            Store::inspect_existing(&root.database)
                .expect_err("inspection rejects missing publication import"),
            match Store::open_for_mission(&root.database, services.authority) {
                Ok(_) => panic!("reopen rejects missing publication import"),
                Err(error) => error,
            },
        ] {
            assert!(matches!(
                error,
                StoreError::Blob(BlobStoreError::SchemaInvariant(
                    "accepted Blob publication is missing its depot import"
                ))
            ));
        }
        assert!(
            !variant_path.exists(),
            "failed reopen must not manufacture an accepted publication import"
        );
    }

    #[test]
    fn accepted_publication_rejects_mismatched_finalized_import_digest() {
        let root = BlobTestRoot::new("mismatched-import-digest");
        let mut services = blob_services(0x83);
        let plaintext = vec![0x83; 1_234];
        let prepared = prepared_blob(&plaintext);
        let store = Store::open_for_mission(&root.database, services.authority).expect("store");
        let (stored, _, _) = publish_blob(
            &store,
            &mut services,
            &prepared,
            &plaintext,
            1,
            b"digest-import",
        );
        drop(store);
        let database = Database::open(&root.database).expect("raw import database");
        let write = database.begin_write().expect("raw import write");
        let mut encoded = write
            .open_table(BLOB_IMPORTS)
            .expect("imports")
            .get(stored.variant_id.as_bytes().as_slice())
            .expect("import read")
            .expect("import row")
            .value()
            .to_vec();
        const FINALIZED_FLAG_OFFSET: usize = 157;
        const FINALIZED_DIGEST_OFFSET: usize = FINALIZED_FLAG_OFFSET + 1;
        assert_eq!(encoded[FINALIZED_FLAG_OFFSET], 1);
        encoded[FINALIZED_DIGEST_OFFSET] ^= 1;
        write
            .open_table(BLOB_IMPORTS)
            .expect("imports")
            .insert(stored.variant_id.as_bytes().as_slice(), encoded.as_slice())
            .expect("replace final digest");
        write.commit().expect("commit final digest mismatch");
        drop(database);

        for error in [
            Store::inspect_existing(&root.database)
                .expect_err("inspection rejects mismatched import digest"),
            match Store::open_for_mission(&root.database, services.authority) {
                Ok(_) => panic!("reopen rejects mismatched import digest"),
                Err(error) => error,
            },
        ] {
            assert!(matches!(
                error,
                StoreError::Blob(BlobStoreError::SchemaInvariant(
                    "accepted Blob publication differs from its finalized depot import"
                ))
            ));
        }
        let database = redb::Builder::new()
            .open_read_only(&root.database)
            .expect("read corrupt import");
        let read = database.begin_read().expect("read transaction");
        assert_eq!(
            read.open_table(BLOB_IMPORTS)
                .expect("imports")
                .get(stored.variant_id.as_bytes().as_slice())
                .expect("import read")
                .expect("import row")
                .value(),
            encoded.as_slice(),
            "failed reopen must not rewrite a mismatched final digest"
        );
    }

    #[test]
    fn own_dot_observing_blob_context_is_rejected_as_durable_corruption() {
        let root = BlobTestRoot::new("own-dot-context");
        let mut services = blob_services(0x7d);
        let plaintext = vec![0x7d; 999];
        let prepared = prepared_blob(&plaintext);
        let store = Store::open_for_mission(&root.database, services.authority).expect("store");
        let (stored, _, _) =
            publish_blob(&store, &mut services, &prepared, &plaintext, 1, b"own-dot");
        drop(store);

        let database = Database::open(&root.database).expect("raw metadata database");
        let write = database.begin_write().expect("raw metadata write");
        let mut encoded = write
            .open_table(BLOB_PUBLICATIONS)
            .expect("publications")
            .get(stored.transfer_id.as_bytes().as_slice())
            .expect("publication read")
            .expect("publication row")
            .value()
            .to_vec();
        assert_eq!(&encoded[encoded.len() - 4..], &[0, 0, 0, 0]);
        let context_offset = encoded.len() - 4;
        encoded[context_offset..].copy_from_slice(&1u32.to_be_bytes());
        encoded.extend_from_slice(&stored.header.stamp.dot.publisher);
        encoded.extend_from_slice(&stored.header.stamp.dot.counter.to_be_bytes());
        write
            .open_table(BLOB_PUBLICATIONS)
            .expect("publications")
            .insert(stored.transfer_id.as_bytes().as_slice(), encoded.as_slice())
            .expect("corrupt context");
        write.commit().expect("commit context corruption");
        drop(database);

        assert!(matches!(
            Store::inspect_existing(&root.database),
            Err(StoreError::Blob(BlobStoreError::SchemaInvariant(
                "decoded Blob metadata is internally inconsistent"
            )))
        ));
        assert!(matches!(
            Store::open_for_mission(&root.database, services.authority),
            Err(StoreError::Blob(BlobStoreError::SchemaInvariant(
                "decoded Blob metadata is internally inconsistent"
            )))
        ));
    }

    #[test]
    fn unbound_interrupted_import_cannot_be_rebound_or_physically_reclaimed() {
        let root = BlobTestRoot::new("unbound-interrupted");
        let services = blob_services(0x7e);
        let other = blob_services(0x7f);
        let plaintext = vec![0x7e; 3_333];
        let prepared = prepared_blob(&plaintext);
        let store = Store::open_for_mission(&root.database, services.authority).expect("store");
        depot::inject_test_fault(&root.path, depot::DepotFaultPoint::TempSynced);
        assert!(finish_variant(&store, &services.publisher, &prepared, &plaintext, 1).is_err());
        drop(store);
        let variant = std::fs::read_dir(root.depot())
            .expect("depot root")
            .map(|entry| entry.expect("depot entry"))
            .find(|entry| entry.file_type().expect("depot entry type").is_dir())
            .expect("variant directory");
        let artifact = std::fs::read_dir(variant.path())
            .expect("variant directory")
            .next()
            .expect("interrupted artifact")
            .expect("artifact entry")
            .path();
        let artifact_bytes = std::fs::read(&artifact).expect("artifact bytes");

        let database = Database::open(&root.database).expect("raw unbind database");
        let write = database.begin_write().expect("raw unbind write");
        write
            .open_table(SEMANTIC_DOMAIN)
            .expect("semantic domain")
            .remove(MISSION_AUTHORITY_ID)
            .expect("remove mission binding");
        write.commit().expect("commit unbound fixture");
        drop(database);

        assert!(matches!(
            Store::open_for_mission(&root.database, other.authority),
            Err(StoreError::SemanticInvariant(
                "unbound store contains mission-scoped Event, State, Record, Blob, or control state"
            ))
        ));
        assert_eq!(
            std::fs::read(&artifact).expect("unbound artifact remains"),
            artifact_bytes,
            "mission preflight must reject before depot cleanup"
        );
        assert_eq!(
            inspect_mission_binding_read_only(&root.database)
                .expect_err("unbound Blob rows remain unbindable")
                .to_string(),
            StoreError::SemanticInvariant(
                "unbound store contains mission-scoped Event, State, Record, Blob, or control state"
            )
            .to_string()
        );
    }

    #[test]
    fn operation_row_and_byte_caps_roll_back_atomically_and_survive_reopen() {
        for byte_cap in [false, true] {
            let root = BlobTestRoot::new(if byte_cap {
                "operation-bytes"
            } else {
                "operation-rows"
            });
            let mut services = blob_services(if byte_cap { 0x80 } else { 0x81 });
            let plaintext = vec![if byte_cap { 0x80 } else { 0x81 }; 512];
            let prepared = prepared_blob(&plaintext);
            let store = Store::open_for_mission(&root.database, services.authority).expect("store");
            let (stored, _, _) = publish_blob(
                &store,
                &mut services,
                &prepared,
                &plaintext,
                1,
                b"original-operation",
            );
            let write = store.database.begin_write().expect("seed operation ledger");
            {
                let mut operations = write.open_table(BLOB_OPERATIONS).expect("operations");
                if byte_cap {
                    let mut index = 0u32;
                    loop {
                        let mut key = vec![b'b'; 200];
                        key[..4].copy_from_slice(&index.to_be_bytes());
                        let encoded = encode_blob_operation_record(BlobOperationRecord {
                            transfer_id: stored.transfer_id,
                            intent_digest: [u8::try_from(index % 251).expect("intent byte"); 32],
                        });
                        let current_bytes = operations
                            .iter()
                            .expect("operation rows")
                            .map(|row| {
                                row.map(|(key, value)| key.value().len() + value.value().len())
                            })
                            .collect::<Result<Vec<_>, _>>()
                            .expect("operation row lengths")
                            .into_iter()
                            .sum::<usize>();
                        if u64::try_from(current_bytes + key.len() + encoded.len())
                            .expect("operation bytes")
                            > MAX_BLOB_OPERATION_BYTES - 64
                        {
                            break;
                        }
                        operations
                            .insert(key.as_slice(), encoded.as_slice())
                            .expect("seed byte-cap operation");
                        index = index.checked_add(1).expect("operation index");
                    }
                } else {
                    for index in 1..MAX_BLOB_OPERATIONS {
                        let key = format!("r{index:04}").into_bytes();
                        let encoded = encode_blob_operation_record(BlobOperationRecord {
                            transfer_id: stored.transfer_id,
                            intent_digest: [u8::try_from(index % 251).expect("intent byte"); 32],
                        });
                        operations
                            .insert(key.as_slice(), encoded.as_slice())
                            .expect("seed row-cap operation");
                    }
                }
            }
            let (count, bytes) = {
                let operations = write.open_table(BLOB_OPERATIONS).expect("operations");
                let count = operations.len().expect("operation count");
                let bytes = operations
                    .iter()
                    .expect("operation rows")
                    .map(|row| {
                        row.map(|(key, value)| {
                            u64::try_from(key.value().len() + value.value().len())
                                .expect("operation row bytes")
                        })
                    })
                    .collect::<Result<Vec<_>, _>>()
                    .expect("operation row lengths")
                    .into_iter()
                    .sum::<u64>();
                (count, bytes)
            };
            {
                let mut metadata = write.open_table(METADATA).expect("metadata");
                metadata
                    .insert(BLOB_OPERATION_COUNT, count)
                    .expect("operation count accounting");
                metadata
                    .insert(BLOB_OPERATION_TOTAL_BYTES, bytes)
                    .expect("operation byte accounting");
            }
            write.commit().expect("commit seeded operation ledger");
            drop(store);

            let reopened = Store::open_for_mission(&root.database, services.authority)
                .expect("reopen seeded operation ledger");
            let before = reopened
                .blob_stats()
                .expect("operation stats before rejection");
            assert_eq!(before.operations, count);
            assert_eq!(before.operation_bytes, bytes);
            let operation = BlobOperationKey::new(vec![b'z'; 256]).expect("new operation");
            let intent = BlobPublicationIntent::new(
                services.publisher.identity(),
                blob_topic(),
                blob_scope(),
                Priority::Immediate,
                stored.blob_id,
            )
            .expect("operation intent");
            let request = BlobOperationRequest::new(&operation, &intent);
            let write = reopened
                .database
                .begin_write()
                .expect("rejected operation write");
            let error =
                insert_blob_operation(&write, reopened.limits, &request, stored.transfer_id)
                    .expect_err("operation cap must reject");
            if byte_cap {
                assert!(matches!(
                    error,
                    StoreError::Blob(BlobStoreError::OperationByteLimitExceeded { .. })
                ));
            } else {
                assert!(matches!(
                    error,
                    StoreError::Blob(BlobStoreError::OperationLimitExceeded { .. })
                ));
            }
            drop(write);
            assert_eq!(reopened.blob_stats().expect("post-rejection stats"), before);
            drop(reopened);
            assert_eq!(
                Store::inspect_existing(&root.database)
                    .expect("strict operation inspection")
                    .blob_stats,
                before
            );
        }
    }

    #[test]
    fn depot_owner_staging_recovers_every_durable_first_install_boundary() {
        for (index, point) in [
            depot::DepotFaultPoint::OwnerStagingCreated,
            depot::DepotFaultPoint::OwnerTempCreated,
            depot::DepotFaultPoint::OwnerTempPartiallyWritten,
            depot::DepotFaultPoint::OwnerTempSynced,
            depot::DepotFaultPoint::OwnerMarkerRenamed,
            depot::DepotFaultPoint::OwnerMarkerDirectorySynced,
            depot::DepotFaultPoint::OwnerRootSynced,
            depot::DepotFaultPoint::OwnerRenamed,
            depot::DepotFaultPoint::OwnerDirectorySynced,
        ]
        .into_iter()
        .enumerate()
        {
            let root = BlobTestRoot::new(&format!("owner-crash-{index}"));
            let services = blob_services(0xa0 + u8::try_from(index).expect("fault index"));
            let store =
                Store::open_for_mission(&root.database, services.authority).expect("empty store");
            depot::inject_test_fault(&root.path, point);
            assert!(store.blob_depot().is_err(), "fault {point:?} must fire");
            drop(store);
            let reopened = Store::open_for_mission(&root.database, services.authority)
                .expect("reopen interrupted owner election");
            drop(reopened.blob_depot().expect("same-DB owner-election retry"));
            assert_eq!(
                reopened.blob_stats().expect("owner-election retry stats"),
                BlobStoreStats::default()
            );
            let marker = root.depot().join(".aster-store-owner-v1");
            assert_eq!(std::fs::metadata(&marker).expect("owner marker").len(), 72);
            assert!(
                std::fs::read_dir(&root.path)
                    .expect("state root")
                    .map(|entry| entry.expect("state entry").file_name())
                    .all(|name| !name
                        .to_string_lossy()
                        .starts_with(".aster-blob-depot-pending-v1-")),
                "successful retry must publish, not strand, its pending directory"
            );
        }
    }

    #[test]
    fn distinct_same_parent_stores_elect_one_depot_without_mutating_the_loser() {
        let root = BlobTestRoot::new("same-parent-election");
        let second_path = root.path.join("second.redb");
        let services = blob_services(0xb1);
        let first =
            Store::open_for_mission(&root.database, services.authority).expect("first store");
        let second =
            Store::open_for_mission(&second_path, services.authority).expect("second store");
        let first_database_before = file_digest(&root.database);
        let second_database_before = file_digest(&second_path);
        let barrier = std::sync::Barrier::new(3);
        let (first_result, second_result) = std::thread::scope(|scope| {
            let first_thread = scope.spawn(|| {
                barrier.wait();
                first.blob_depot().map(drop)
            });
            let second_thread = scope.spawn(|| {
                barrier.wait();
                second.blob_depot().map(drop)
            });
            barrier.wait();
            (
                first_thread.join().expect("first election thread"),
                second_thread.join().expect("second election thread"),
            )
        });
        assert_ne!(first_result.is_ok(), second_result.is_ok());
        let marker = root.depot().join(".aster-store-owner-v1");
        let marker_before = std::fs::read(&marker).expect("winner marker");
        let (winner, loser, loser_database, loser_before) = if first_result.is_ok() {
            (&first, &second, &second_path, second_database_before)
        } else {
            (&second, &first, &root.database, first_database_before)
        };
        drop(winner.blob_depot().expect("winner retry"));
        let loser_error = match loser.blob_depot() {
            Err(error) => error,
            Ok(_) => panic!("loser must fail closed"),
        };
        assert_depot_integrity(&loser_error);
        assert_eq!(
            std::fs::read(&marker).expect("unchanged winner marker"),
            marker_before
        );
        assert_eq!(file_digest(loser_database), loser_before);
        assert_eq!(
            winner.blob_stats().expect("winner empty stats"),
            BlobStoreStats::default()
        );
    }

    #[test]
    fn malformed_owner_marker_and_same_path_replacement_fail_without_repair() {
        let malformed = BlobTestRoot::new("owner-marker-malformed");
        let services = blob_services(0xb2);
        let store =
            Store::open_for_mission(&malformed.database, services.authority).expect("marker store");
        drop(store.blob_depot().expect("create marker"));
        drop(store);
        let marker = malformed.depot().join(".aster-store-owner-v1");
        std::fs::write(&marker, b"truncated-owner-marker").expect("truncate marker");
        let corrupted = depot_file_snapshot(&malformed.depot());
        assert_depot_integrity(
            &Store::inspect_existing(&malformed.database).expect_err("inspect malformed marker"),
        );
        let reopen_error = match Store::open_for_mission(&malformed.database, services.authority) {
            Err(error) => error,
            Ok(_) => panic!("reopen malformed marker must fail"),
        };
        assert_depot_integrity(&reopen_error);
        assert_eq!(depot_file_snapshot(&malformed.depot()), corrupted);

        #[cfg(unix)]
        {
            let replaced = BlobTestRoot::new("owner-same-path-replacement");
            let replacement_services = blob_services(0xb3);
            let live = Store::open_for_mission(&replaced.database, replacement_services.authority)
                .expect("live original");
            drop(live.blob_depot().expect("bind original depot"));
            let before = depot_file_snapshot(&replaced.depot());
            let parked = replaced.path.join("parked.redb");
            std::fs::rename(&replaced.database, &parked).expect("park original backing");
            assert!(
                Store::open_for_mission(&replaced.database, replacement_services.authority)
                    .is_err()
            );
            assert_eq!(depot_file_snapshot(&replaced.depot()), before);
            drop(live);
        }
    }

    #[test]
    fn owner_binding_migration_is_empty_only_and_partial_or_relocated_state_fails_closed() {
        let services = blob_services(0xb6);
        let empty = BlobTestRoot::new("owner-binding-empty-migration");
        drop(
            Store::open_for_mission(&empty.database, services.authority)
                .expect("empty binding store"),
        );
        {
            let database = Database::open(&empty.database).expect("raw empty binding database");
            let write = database.begin_write().expect("remove empty binding");
            let mut depot = write
                .open_table(BLOB_DEPOT_METADATA)
                .expect("depot metadata");
            for field in depot_owner_binding_fields() {
                depot.remove(field).expect("remove owner binding field");
            }
            drop(depot);
            write.commit().expect("commit absent owner binding");
        }
        assert!(Store::inspect_existing(&empty.database).is_err());
        drop(
            Store::open_for_mission(&empty.database, services.authority)
                .expect("canonical empty binding migration"),
        );
        Store::inspect_existing(&empty.database).expect("inspect migrated binding");

        let partial = BlobTestRoot::new("owner-binding-partial");
        drop(
            Store::open_for_mission(&partial.database, services.authority)
                .expect("partial binding base"),
        );
        {
            let database = Database::open(&partial.database).expect("raw partial database");
            let write = database.begin_write().expect("partial binding write");
            write
                .open_table(BLOB_DEPOT_METADATA)
                .expect("depot metadata")
                .remove(DEPOT_OWNER_BINDING_3)
                .expect("remove one binding field");
            write.commit().expect("commit partial binding");
        }
        assert!(Store::inspect_existing(&partial.database).is_err());
        assert!(Store::open_for_mission(&partial.database, services.authority).is_err());

        let copied = empty.path.join("copied.redb");
        std::fs::copy(&empty.database, &copied).expect("copy canonical empty database");
        assert!(Store::inspect_existing(&copied).is_err());
        assert!(Store::open_for_mission(&copied, services.authority).is_err());
        Store::inspect_existing(&empty.database).expect("original binding remains valid");

        let rooted = BlobTestRoot::new("owner-binding-empty-root-present");
        let rooted_store = Store::open_for_mission(&rooted.database, services.authority)
            .expect("empty rooted binding store");
        drop(
            rooted_store
                .blob_depot()
                .expect("bind empty physical depot"),
        );
        drop(rooted_store);
        {
            let database = Database::open(&rooted.database).expect("raw rooted database");
            let write = database.begin_write().expect("remove rooted binding");
            let mut depot = write
                .open_table(BLOB_DEPOT_METADATA)
                .expect("depot metadata");
            for field in depot_owner_binding_fields() {
                depot.remove(field).expect("remove rooted binding field");
            }
            drop(depot);
            write.commit().expect("commit rooted missing binding");
        }
        let database_before = blob_database_digest(&rooted.database);
        let depot_before = depot_file_snapshot(&rooted.depot());
        assert!(Store::inspect_existing(&rooted.database).is_err());
        assert!(Store::open_for_mission(&rooted.database, services.authority).is_err());
        assert_eq!(blob_database_digest(&rooted.database), database_before);
        assert_eq!(depot_file_snapshot(&rooted.depot()), depot_before);
    }

    #[test]
    fn depot_owner_token_migration_is_rootless_empty_and_all_or_nothing() {
        let services = blob_services(0xbb);
        let remove_all_owner_fields = |path: &Path| {
            let database = Database::open(path).expect("raw owner-token database");
            let write = database.begin_write().expect("owner-token removal write");
            let mut depot = write
                .open_table(BLOB_DEPOT_METADATA)
                .expect("depot metadata");
            for field in depot_owner_token_fields() {
                depot.remove(field).expect("remove owner-token field");
            }
            for field in depot_owner_binding_fields() {
                depot.remove(field).expect("remove owner-binding field");
            }
            drop(depot);
            write.commit().expect("commit owner-token removal");
        };

        let migratable = BlobTestRoot::new("owner-token-empty-migration");
        drop(
            Store::open_for_mission(&migratable.database, services.authority)
                .expect("owner-token migration base"),
        );
        remove_all_owner_fields(&migratable.database);
        assert!(Store::inspect_existing(&migratable.database).is_err());
        drop(
            Store::open_for_mission(&migratable.database, services.authority)
                .expect("migrate exact empty pre-token schema"),
        );
        Store::inspect_existing(&migratable.database).expect("inspect migrated owner token");
        {
            let database = redb::Builder::new()
                .open_read_only(&migratable.database)
                .expect("read migrated owner token");
            let read = database.begin_read().expect("owner-token read transaction");
            assert_ne!(
                depot::depot_owner_token_read(&read).expect("canonical migrated owner token"),
                [0; 32]
            );
            let depot = read
                .open_table(BLOB_DEPOT_METADATA)
                .expect("migrated depot metadata");
            for field in depot_owner_binding_fields() {
                assert!(
                    depot
                        .get(field)
                        .expect("migrated owner binding read")
                        .is_some()
                );
            }
        }

        let partial = BlobTestRoot::new("owner-token-partial");
        drop(
            Store::open_for_mission(&partial.database, services.authority)
                .expect("partial owner-token base"),
        );
        {
            let database = Database::open(&partial.database).expect("raw partial-token database");
            let write = database.begin_write().expect("partial-token removal write");
            write
                .open_table(BLOB_DEPOT_METADATA)
                .expect("depot metadata")
                .remove(DEPOT_OWNER_TOKEN_3)
                .expect("remove one owner-token field");
            write.commit().expect("commit partial owner token");
        }
        let partial_before = blob_database_digest(&partial.database);
        assert!(Store::inspect_existing(&partial.database).is_err());
        assert!(Store::open_for_mission(&partial.database, services.authority).is_err());
        assert_eq!(blob_database_digest(&partial.database), partial_before);
        assert!(!partial.depot().exists());

        for (name, table) in [
            ("publication", BLOB_PUBLICATIONS),
            ("import", BLOB_IMPORTS),
            ("chunk", BLOB_CHUNKS),
        ] {
            let populated = BlobTestRoot::new(&format!("owner-token-populated-{name}"));
            drop(
                Store::open_for_mission(&populated.database, services.authority)
                    .expect("populated owner-token base"),
            );
            remove_all_owner_fields(&populated.database);
            {
                let database = Database::open(&populated.database)
                    .expect("raw populated owner-token database");
                let write = database.begin_write().expect("populated owner-token write");
                write
                    .open_table(table)
                    .expect("Blob row table")
                    .insert(b"unattributed".as_slice(), b"row".as_slice())
                    .expect("insert unattributed Blob row");
                write.commit().expect("commit unattributed Blob row");
            }
            let before = blob_database_digest(&populated.database);
            assert!(Store::inspect_existing(&populated.database).is_err());
            assert!(Store::open_for_mission(&populated.database, services.authority).is_err());
            assert_eq!(blob_database_digest(&populated.database), before);
            assert!(!populated.depot().exists());
        }

        let counted = BlobTestRoot::new("owner-token-nonzero-counter");
        drop(
            Store::open_for_mission(&counted.database, services.authority)
                .expect("counter owner-token base"),
        );
        remove_all_owner_fields(&counted.database);
        {
            let database = Database::open(&counted.database).expect("raw counter database");
            let write = database.begin_write().expect("counter corruption write");
            write
                .open_table(METADATA)
                .expect("global metadata")
                .insert(BLOB_ITEM_COUNT, 1)
                .expect("insert nonzero Blob counter");
            write.commit().expect("commit nonzero Blob counter");
        }
        let counted_before = blob_database_digest(&counted.database);
        assert!(Store::inspect_existing(&counted.database).is_err());
        assert!(Store::open_for_mission(&counted.database, services.authority).is_err());
        assert_eq!(blob_database_digest(&counted.database), counted_before);
        assert!(!counted.depot().exists());

        let rooted = BlobTestRoot::new("owner-token-root-present");
        let rooted_store = Store::open_for_mission(&rooted.database, services.authority)
            .expect("rooted owner-token base");
        drop(
            rooted_store
                .blob_depot()
                .expect("create attributed depot root"),
        );
        drop(rooted_store);
        remove_all_owner_fields(&rooted.database);
        let rooted_database_before = blob_database_digest(&rooted.database);
        let rooted_depot_before = depot_file_snapshot(&rooted.depot());
        assert!(Store::inspect_existing(&rooted.database).is_err());
        assert!(Store::open_for_mission(&rooted.database, services.authority).is_err());
        assert_eq!(
            blob_database_digest(&rooted.database),
            rooted_database_before
        );
        assert_eq!(depot_file_snapshot(&rooted.depot()), rooted_depot_before);
    }

    #[test]
    fn populated_owner_marker_or_root_loss_never_recreates_or_repairs() {
        for remove_root in [false, true] {
            let root = BlobTestRoot::new(if remove_root {
                "populated-root-loss"
            } else {
                "populated-marker-loss"
            });
            let mut services = blob_services(if remove_root { 0xb7 } else { 0xb8 });
            let plaintext = b"owner loss must not repair".to_vec();
            let prepared = prepared_blob(&plaintext);
            let store =
                Store::open_for_mission(&root.database, services.authority).expect("owner store");
            publish_blob(
                &store,
                &mut services,
                &prepared,
                &plaintext,
                1,
                b"owner-loss-publication",
            );
            let stats = store.blob_stats().expect("owner loss stats");
            drop(store);
            if remove_root {
                std::fs::remove_dir_all(root.depot()).expect("remove populated depot root");
            } else {
                std::fs::remove_file(root.depot().join(".aster-store-owner-v1"))
                    .expect("remove populated owner marker");
            }
            let database_before = blob_database_digest(&root.database);
            let depot_before = depot_file_snapshot(&root.depot());
            assert!(Store::inspect_existing(&root.database).is_err());
            assert!(Store::open_for_mission(&root.database, services.authority).is_err());
            assert_eq!(blob_database_digest(&root.database), database_before);
            assert_eq!(depot_file_snapshot(&root.depot()), depot_before);
            assert_eq!(stats.publications, 1);
        }

        let populated = BlobTestRoot::new("populated-prebinding-rejected");
        let mut populated_services = blob_services(0xb9);
        let plaintext = b"populated binding removal".to_vec();
        let prepared = prepared_blob(&plaintext);
        let store = Store::open_for_mission(&populated.database, populated_services.authority)
            .expect("populated binding store");
        publish_blob(
            &store,
            &mut populated_services,
            &prepared,
            &plaintext,
            1,
            b"populated-binding-publication",
        );
        drop(store);
        {
            let database = Database::open(&populated.database).expect("raw populated binding");
            let write = database.begin_write().expect("remove populated binding");
            let mut depot = write
                .open_table(BLOB_DEPOT_METADATA)
                .expect("depot metadata");
            for field in depot_owner_binding_fields() {
                depot.remove(field).expect("remove populated binding field");
            }
            drop(depot);
            write.commit().expect("commit populated missing binding");
        }
        let files_before = depot_file_snapshot(&populated.depot());
        assert!(Store::inspect_existing(&populated.database).is_err());
        assert!(
            Store::open_for_mission(&populated.database, populated_services.authority).is_err()
        );
        assert_eq!(depot_file_snapshot(&populated.depot()), files_before);
    }

    #[test]
    fn structural_audit_rejects_content_publication_cap_plus_one_without_repair() {
        let root = BlobTestRoot::new("content-cap-corruption");
        let mut services = blob_services(0xba);
        let plaintext = b"one physical variant, too many synthetic publications".to_vec();
        let prepared = prepared_blob(&plaintext);
        let store =
            Store::open_for_mission(&root.database, services.authority).expect("content cap store");
        let (stored, _, _) = publish_blob(
            &store,
            &mut services,
            &prepared,
            &plaintext,
            1,
            b"content-cap-base",
        );
        let base_stats = store.blob_stats().expect("base content stats");
        drop(store);

        let database = Database::open(&root.database).expect("raw content-cap database");
        let write = database
            .begin_write()
            .expect("content-cap corruption write");
        let base = write
            .open_table(BLOB_PUBLICATIONS)
            .expect("publications")
            .get(stored.transfer_id.as_bytes().as_slice())
            .expect("base metadata read")
            .map(|value| decode_blob_metadata(value.value()))
            .transpose()
            .expect("decode base metadata")
            .expect("base metadata");
        let mut total_bytes = base_stats.total_sealed_bytes;
        for counter in
            2..=u64::try_from(MAX_BLOB_PUBLICATIONS_PER_CONTENT + 1).expect("content cap counter")
        {
            let sealed = format!("synthetic-over-cap-source-{counter}").into_bytes();
            let transfer_id = BlobTransferId::new(Sha256::digest(&sealed).into());
            let semantic_id = BlobSemanticId::new(
                Sha256::digest(format!("synthetic-over-cap-semantic-{counter}")).into(),
            );
            let mut metadata = base.clone();
            metadata.transfer_id = transfer_id;
            metadata.semantic_id = semantic_id;
            metadata.header.stamp.dot.counter = counter;
            metadata.header.stamp.context = VersionVector::default();
            let encoded = encode_blob_metadata(metadata).expect("encode synthetic metadata");
            write
                .open_table(BLOB_PUBLICATIONS)
                .expect("publications")
                .insert(transfer_id.as_bytes().as_slice(), encoded.as_slice())
                .expect("insert synthetic metadata");
            write
                .open_table(BLOB_BYTES)
                .expect("source bytes")
                .insert(transfer_id.as_bytes().as_slice(), sealed.as_slice())
                .expect("insert synthetic source");
            write
                .open_table(BLOB_ACCEPTANCE_MARKERS)
                .expect("markers")
                .insert(transfer_id.as_bytes().as_slice(), counter)
                .expect("insert synthetic marker");
            write
                .open_table(BLOB_SEMANTIC_ITEMS)
                .expect("semantic index")
                .insert(
                    semantic_id.as_bytes().as_slice(),
                    transfer_id.as_bytes().as_slice(),
                )
                .expect("insert synthetic semantic");
            let content_key = blob_content_key(
                &base.header.topic,
                &base.header.scope,
                base.blob_id,
                semantic_id,
            )
            .expect("synthetic content key");
            write
                .open_table(BLOB_CONTENT_INDEX)
                .expect("content index")
                .insert(content_key.as_slice(), transfer_id.as_bytes().as_slice())
                .expect("insert synthetic content");
            let dot_key = accepted_dot_key(Dot {
                publisher: base.header.stamp.dot.publisher,
                counter,
            });
            write
                .open_table(ACCEPTED_DOTS)
                .expect("accepted dots")
                .insert(dot_key.as_slice(), semantic_id.as_bytes().as_slice())
                .expect("insert synthetic dot");
            total_bytes = total_bytes
                .checked_add(u64::try_from(sealed.len()).expect("synthetic source length"))
                .expect("synthetic byte accounting");
        }
        let over_cap = u64::try_from(MAX_BLOB_PUBLICATIONS_PER_CONTENT + 1)
            .expect("over-cap publication count");
        write
            .open_table(PUBLISHER_HIGH_WATER)
            .expect("publisher high water")
            .insert(base.header.stamp.dot.publisher.as_slice(), over_cap)
            .expect("update publisher high water");
        let frontier_key = causal_frontier_key(
            &base.header.topic,
            &base.header.scope,
            base.header.stamp.dot.publisher,
        )
        .expect("frontier key");
        write
            .open_table(CAUSAL_FRONTIER)
            .expect("causal frontier")
            .insert(frontier_key.as_slice(), over_cap)
            .expect("update frontier");
        {
            let mut metadata = write.open_table(METADATA).expect("global metadata");
            metadata
                .insert(BLOB_ITEM_COUNT, over_cap)
                .expect("update Blob count");
            metadata
                .insert(BLOB_TOTAL_BYTES, total_bytes)
                .expect("update Blob bytes");
            metadata
                .insert(LAST_BLOB_ACCEPTANCE_MARKER, over_cap)
                .expect("update Blob marker");
        }
        write.commit().expect("commit over-cap corruption");
        drop(database);

        let database_before = blob_database_digest(&root.database);
        assert!(matches!(
            Store::inspect_existing(&root.database),
            Err(StoreError::Blob(BlobStoreError::SchemaInvariant(
                "Blob content publication count exceeds its durable safety cap"
            )))
        ));
        assert!(matches!(
            Store::open_for_mission(&root.database, services.authority),
            Err(StoreError::Blob(BlobStoreError::SchemaInvariant(
                "Blob content publication count exceeds its durable safety cap"
            )))
        ));
        assert_eq!(blob_database_digest(&root.database), database_before);
    }

    #[test]
    fn stale_future_epoch_and_revocation_reject_before_operation_replay() {
        let root = BlobTestRoot::new("policy-before-replay");
        let mut services = blob_services(0x82);
        let plaintext = vec![0x82; 1_024];
        let prepared = prepared_blob(&plaintext);
        let store = Store::open_for_mission(&root.database, services.authority).expect("store");
        let (_stored, operation, intent) = publish_blob(
            &store,
            &mut services,
            &prepared,
            &plaintext,
            1,
            b"policy-operation",
        );
        let stale = prepare_blob_proof(&store, &mut services, &prepared, &plaintext, 1);
        let current = prepare_blob_proof(&store, &mut services, &prepared, &plaintext, 2);
        let future = prepare_blob_proof(&store, &mut services, &prepared, &plaintext, 3);
        for proof in [&stale, &current, &future] {
            proof
                .blob
                .verify_exact_manifest(&proof.manifest_bytes)
                .expect("proof retains exact manifest bytes");
        }
        let request = BlobOperationRequest::new(&operation, &intent);

        let effect_id = ControlTransferId::new([0x82; 32]);
        {
            let write = store.database.begin_write().expect("epoch write");
            let encoded = encode_scope_epoch_index(2, effect_id);
            write
                .open_table(CONTROL_SCOPE_EPOCHS)
                .expect("scope epochs")
                .insert(blob_scope().as_str(), encoded.as_slice())
                .expect("activate epoch two");
            write.commit().expect("commit epoch two");
        }
        assert!(matches!(
            store.commit_reserved_blob_once_with_policy(
                &stale.policy,
                &request,
                &stale.reservation,
                &stale.blob,
                &stale.sealed,
                &stale.completion,
            ),
            Err(StoreError::Blob(BlobStoreError::KeyEpochStale {
                current: 2,
                received: 1,
            }))
        ));
        assert!(matches!(
            store.commit_reserved_blob_once_with_policy(
                &future.policy,
                &request,
                &future.reservation,
                &future.blob,
                &future.sealed,
                &future.completion,
            ),
            Err(StoreError::Blob(BlobStoreError::KeyEpochNotActive {
                current: 2,
                received: 3,
            }))
        ));

        {
            let write = store.database.begin_write().expect("revocation write");
            let encoded = encode_revocation_index(services.authority, 1, effect_id);
            write
                .open_table(CONTROL_REVOCATIONS)
                .expect("revocations")
                .insert(services.publisher.identity().as_slice(), encoded.as_slice())
                .expect("revoke publisher");
            write.commit().expect("commit revocation");
        }
        assert!(matches!(
            store.commit_reserved_blob_once_with_policy(
                &current.policy,
                &request,
                &current.reservation,
                &current.blob,
                &current.sealed,
                &current.completion,
            ),
            Err(StoreError::Blob(BlobStoreError::PublisherRevoked(publisher)))
                if publisher == services.publisher.identity()
        ));
        assert_eq!(
            store
                .blob_stats()
                .expect("policy rejection stats")
                .publications,
            1
        );
    }

    #[test]
    fn import_profile_corruption_fails_read_and_write_audit_without_repair() {
        let cases = [
            ("oversized-media", Some(256), None, None),
            ("oversized-schema", None, Some(1_025), None),
            ("noncanonical-count", None, None, Some(2)),
        ];
        for (index, (label, media_len, schema_len, chunk_count)) in cases.into_iter().enumerate() {
            let root = BlobTestRoot::new(label);
            let mut services = blob_services(0x90 + u8::try_from(index).expect("case index"));
            let plaintext = vec![0x90; 777];
            let prepared = prepared_blob(&plaintext);
            let store =
                Store::open_for_mission(&root.database, services.authority).expect("case store");
            let (stored, _, _) = publish_blob(
                &store,
                &mut services,
                &prepared,
                &plaintext,
                1,
                label.as_bytes(),
            );
            let chunk_path = root.chunk_path(stored.variant_id, 0);
            let chunk_before = std::fs::read(&chunk_path).expect("marked chunk before corruption");
            drop(store);

            let database = Database::open(&root.database).expect("corruption database");
            let write = database.begin_write().expect("corruption write");
            depot::corrupt_import_profile_for_test(
                &write,
                stored.variant_id,
                media_len,
                schema_len,
                chunk_count,
            )
            .expect("corrupt import profile");
            write.commit().expect("commit import corruption");
            drop(database);

            let error = Store::inspect_existing(&root.database)
                .expect_err("read-only audit rejects corrupt import profile");
            assert_blob_schema_invariant(&error);
            match Store::open_for_mission(&root.database, services.authority) {
                Err(error) => assert_blob_schema_invariant(&error),
                Ok(_) => panic!("writable reopen rejects corrupt import profile"),
            }
            assert_eq!(
                std::fs::read(&chunk_path).expect("marked chunk after rejected opens"),
                chunk_before,
                "profile rejection must not repair or rewrite the marked artifact"
            );
        }
    }

    #[test]
    fn incomplete_finalize_and_wrong_last_record_length_are_rejected_without_repair() {
        let root = BlobTestRoot::new("incomplete-finalize-last-length");
        let services = blob_services(0x94);
        let plaintext = vec![0x94; SELECTED_BLOB_CHUNK_SIZE as usize + 37];
        let prepared = prepared_blob(&plaintext);
        let store = Store::open_for_mission(&root.database, services.authority).expect("store");
        let (manifest, physical_lineage) = {
            let depot = store.blob_depot().expect("depot");
            let mut service = services
                .publisher
                .blob_service_with_store(&blob_scope(), &blob_topic(), 1, depot)
                .expect("Blob service");
            let physical_lineage = service.physical_lineage();
            let manifest = service
                .install_prepared(&prepared)
                .expect("install prepared Blob");
            (manifest, physical_lineage)
        };
        let variant = BlobVariantId::for_content(
            manifest.id(),
            manifest.content_group(),
            manifest.content_epoch(),
        );
        {
            let mut depot = store.blob_depot().expect("active depot");
            CoreBlobStore::begin_blob_with_lineage(&mut depot, &manifest, physical_lineage)
                .expect("resume import");
            let finalize_error =
                CoreBlobStore::finalize_blob(&mut depot, manifest.id(), [0x94; 32])
                    .expect_err("incomplete import cannot finalize");
            assert_depot_integrity(&finalize_error);
            assert_eq!(
                CoreBlobStore::finalized_manifest_digest(&mut depot, manifest.id())
                    .expect("read finalization state"),
                None,
                "rejected finalization must not write its arbitrary digest"
            );

            let last = manifest.chunk_count() - 1;
            let plaintext_digest = CoreBlobStore::plaintext_digest(&mut depot, manifest.id(), last)
                .expect("read staged digest")
                .expect("last digest is staged");
            let expected =
                aster_mesh::BlobChunkRecord::from_parts(plaintext_digest, [0x49; 32], 37, 53)
                    .expect("correct last-record lengths");
            CoreBlobStore::put_expected_chunk_record(&mut depot, manifest.id(), last, expected)
                .expect("stage correct last record");
        }
        drop(store);

        let database = Database::open(&root.database).expect("corruption database");
        let write = database.begin_write().expect("corruption write");
        depot::corrupt_expected_chunk_lengths_for_test(
            &write,
            variant,
            manifest.chunk_count() - 1,
            SELECTED_BLOB_CHUNK_SIZE,
            SELECTED_BLOB_CHUNK_SIZE + 16,
        )
        .expect("corrupt last-record lengths");
        write.commit().expect("commit chunk-record corruption");
        let read = database.begin_read().expect("corrupt row read");
        let key = depot::test_chunk_key(variant, manifest.chunk_count() - 1);
        let row_before = read
            .open_table(BLOB_CHUNKS)
            .expect("Blob chunks")
            .get(key.as_slice())
            .expect("read corrupt chunk")
            .expect("corrupt chunk exists")
            .value()
            .to_vec();
        drop(read);
        drop(database);

        let error = Store::inspect_existing(&root.database)
            .expect_err("read-only audit rejects wrong last-record length");
        assert_blob_schema_invariant(&error);
        match Store::open_for_mission(&root.database, services.authority) {
            Err(error) => assert_blob_schema_invariant(&error),
            Ok(_) => panic!("writable reopen rejects wrong last-record length"),
        }
        let database = Database::open(&root.database).expect("post-rejection database");
        let read = database.begin_read().expect("post-rejection read");
        let row_after = read
            .open_table(BLOB_CHUNKS)
            .expect("Blob chunks")
            .get(key.as_slice())
            .expect("read corrupt chunk after rejection")
            .expect("corrupt chunk remains")
            .value()
            .to_vec();
        assert_eq!(
            row_after, row_before,
            "audit rejection must not repair metadata"
        );
    }

    #[test]
    fn depot_read_round_trips_with_one_core_bounded_chunk_buffer() {
        let root = BlobTestRoot::new("bounded-depot-read");
        let mut services = blob_services(0x95);
        let plaintext = vec![0x95; SELECTED_BLOB_CHUNK_SIZE as usize + 37];
        let prepared = prepared_blob(&plaintext);
        let store = Store::open_for_mission(&root.database, services.authority).expect("store");
        let proof = prepare_blob_proof(&store, &mut services, &prepared, &plaintext, 1);
        let depot = store.blob_depot().expect("read depot");
        let mut service = services
            .reader
            .blob_service_with_store(&blob_scope(), &blob_topic(), 1, depot)
            .expect("reader service");
        service
            .install_verified_manifest(&proof.blob, &proof.manifest_bytes)
            .expect("install exact verified manifest");
        let mut reader = service
            .reader_for_verified(&proof.blob)
            .expect("verified reader");
        let mut output = Vec::new();
        let stats = reader.stream_into(&mut output).expect("stream Blob");
        assert_eq!(output, plaintext);
        assert_eq!(stats.plaintext_bytes, plaintext.len() as u64);
        assert_eq!(stats.verified_chunks, 2);
        assert!(
            stats.peak_working_buffer_bytes <= SELECTED_BLOB_CHUNK_SIZE as usize + 16,
            "depot adapter must read its fixed header on the stack and ciphertext directly into the core-owned chunk buffer"
        );
    }

    #[test]
    fn physical_depot_byte_chunk_and_variant_caps_are_durable_and_atomic() {
        let byte_root = BlobTestRoot::new("depot-byte-cap");
        let byte_services = blob_services(0x84);
        let byte_plaintext = vec![0x84; 512];
        let byte_prepared = prepared_blob(&byte_plaintext);
        let byte_store = Store::open_with_limits_and_blob_depot_limits_for_mission(
            &byte_root.database,
            StoreLimits::default(),
            BlobDepotLimits::new(1, 10, 10).expect("byte limits"),
            byte_services.authority,
        )
        .expect("byte-cap store");
        assert!(
            finish_variant(
                &byte_store,
                &byte_services.publisher,
                &byte_prepared,
                &byte_plaintext,
                1,
            )
            .is_err()
        );
        let byte_stats = byte_store.blob_stats().expect("byte-cap stats");
        assert_eq!(byte_stats.variants, 1);
        assert_eq!(byte_stats.committed_chunks, 0);
        assert_eq!(byte_stats.committed_file_bytes, 0);
        drop(byte_store);
        let byte_reopen = Store::open_with_limits_and_blob_depot_limits_for_mission(
            &byte_root.database,
            StoreLimits::default(),
            BlobDepotLimits::new(1, 10, 10).expect("byte limits"),
            byte_services.authority,
        )
        .expect("byte-cap reopen");
        assert_eq!(
            byte_reopen.blob_stats().expect("reopened byte stats"),
            byte_stats
        );

        let chunk_root = BlobTestRoot::new("depot-chunk-cap");
        let chunk_services = blob_services(0x85);
        let chunk_plaintext = vec![0x85; SELECTED_BLOB_CHUNK_SIZE as usize + 1];
        let chunk_prepared = prepared_blob(&chunk_plaintext);
        let chunk_store = Store::open_with_limits_and_blob_depot_limits_for_mission(
            &chunk_root.database,
            StoreLimits::default(),
            BlobDepotLimits::new(u64::MAX, 1, 10).expect("chunk limits"),
            chunk_services.authority,
        )
        .expect("chunk-cap store");
        assert!(
            finish_variant(
                &chunk_store,
                &chunk_services.publisher,
                &chunk_prepared,
                &chunk_plaintext,
                1,
            )
            .is_err()
        );
        let chunk_stats = chunk_store.blob_stats().expect("chunk-cap stats");
        assert_eq!(chunk_stats.variants, 1);
        assert_eq!(chunk_stats.committed_chunks, 0);
        assert_eq!(chunk_stats.committed_file_bytes, 0);
        drop(chunk_store);
        let chunk_reopen = Store::open_with_limits_and_blob_depot_limits_for_mission(
            &chunk_root.database,
            StoreLimits::default(),
            BlobDepotLimits::new(u64::MAX, 1, 10).expect("chunk limits"),
            chunk_services.authority,
        )
        .expect("chunk-cap reopen");
        assert_eq!(
            chunk_reopen.blob_stats().expect("reopened chunk stats"),
            chunk_stats
        );

        let variant_root = BlobTestRoot::new("depot-variant-cap");
        let variant_services = blob_services(0x86);
        let variant_plaintext = vec![0x86; 1_024];
        let variant_prepared = prepared_blob(&variant_plaintext);
        let variant_store = Store::open_with_limits_and_blob_depot_limits_for_mission(
            &variant_root.database,
            StoreLimits::default(),
            BlobDepotLimits::new(u64::MAX, 10, 1).expect("variant limits"),
            variant_services.authority,
        )
        .expect("variant-cap store");
        finish_variant(
            &variant_store,
            &variant_services.publisher,
            &variant_prepared,
            &variant_plaintext,
            1,
        )
        .expect("first variant");
        let before_second = variant_store.blob_stats().expect("first variant stats");
        assert!(
            finish_variant(
                &variant_store,
                &variant_services.publisher,
                &variant_prepared,
                &variant_plaintext,
                2,
            )
            .is_err()
        );
        assert_eq!(
            variant_store.blob_stats().expect("variant-cap stats"),
            before_second
        );
    }

    fn all_blob_subscription_candidates_deliverable(
        plan: &BlobSubscriptionPollPlan,
    ) -> BlobSubscriptionPollSelection {
        BlobSubscriptionPollSelection {
            deliverable: plan
                .candidates()
                .iter()
                .map(|candidate| candidate.projection().semantic_id)
                .collect(),
            inactive: Vec::new(),
        }
    }

    #[test]
    fn blob_subscription_retries_acks_reopens_and_fences_selector_aba() {
        let root = BlobTestRoot::new("subscription-ledger");
        let mut services = blob_services(0xd1);
        let plaintext = vec![0xd1; 1_024];
        let prepared = prepared_blob(&plaintext);
        let store = Store::open_for_mission(&root.database, services.authority)
            .expect("subscription store");
        let first = publish_blob(
            &store,
            &mut services,
            &prepared,
            &plaintext,
            1,
            b"blob-subscription-first",
        )
        .0;
        let second = publish_blob(
            &store,
            &mut services,
            &prepared,
            &plaintext,
            1,
            b"blob-subscription-second",
        )
        .0;
        assert_eq!(first.blob_id, second.blob_id);
        assert_ne!(first.semantic_id, second.semantic_id);

        let policy = store
            .control_policy_snapshot()
            .expect("subscription policy");
        let key = BlobSubscriptionKey::new(b"blob-subscription".to_vec()).expect("key");
        let spec = BlobSubscriptionSpec {
            topic: blob_topic(),
            scope: blob_scope(),
            include_descendant_scopes: false,
        };
        let created = store
            .create_blob_subscription_with_policy(&policy, &key, spec.clone())
            .expect("create subscription");
        assert!(created.inserted);
        assert_eq!(
            store
                .create_blob_subscription_with_policy(&policy, &key, spec.clone())
                .expect("idempotent create"),
            BlobSubscriptionCreateOutcome {
                id: created.id,
                inserted: false,
            }
        );
        let plan = store
            .prepare_blob_subscription_poll_with_policy(&policy, created.id, 1, 8)
            .expect("first plan");
        assert_eq!(plan.candidates().len(), 2);
        assert_eq!(
            plan.candidates()
                .iter()
                .map(|candidate| candidate.projection().blob_id)
                .collect::<Vec<_>>(),
            vec![first.blob_id, first.blob_id]
        );
        let first_page = store
            .commit_blob_subscription_poll_with_policy(
                &policy,
                &plan,
                &all_blob_subscription_candidates_deliverable(&plan),
            )
            .expect("first commit");
        assert_eq!(first_page.deliveries.len(), 1);
        assert!(first_page.has_more);
        assert_eq!(first_page.deliveries[0].attempt, 1);
        let first_delivery = first_page.deliveries[0].clone();

        let retry_plan = store
            .prepare_blob_subscription_poll_with_policy(&policy, created.id, 1, 8)
            .expect("retry plan");
        let retry_page = store
            .commit_blob_subscription_poll_with_policy(
                &policy,
                &retry_plan,
                &all_blob_subscription_candidates_deliverable(&retry_plan),
            )
            .expect("retry commit");
        assert_eq!(retry_page.deliveries.len(), 1);
        assert_eq!(
            retry_page.deliveries[0].semantic_id,
            first_delivery.semantic_id
        );
        assert_eq!(retry_page.deliveries[0].attempt, 2);
        assert_eq!(
            store
                .acknowledge_blob_delivery_with_policy(
                    &policy,
                    created.id,
                    first_delivery.semantic_id,
                    first_delivery.token,
                )
                .expect("acknowledge earlier attempt token"),
            BlobDeliveryAck::Acknowledged
        );
        assert_eq!(
            store
                .acknowledge_blob_delivery_with_policy(
                    &policy,
                    created.id,
                    first_delivery.semantic_id,
                    retry_page.deliveries[0].token,
                )
                .expect("reacknowledge retried token"),
            BlobDeliveryAck::AlreadyAcknowledged
        );

        let other_key = BlobSubscriptionKey::new(b"other-subscription".to_vec()).expect("key");
        let other = store
            .create_blob_subscription_with_policy(&policy, &other_key, spec.clone())
            .expect("other subscription");
        assert!(matches!(
            store.acknowledge_blob_delivery_with_policy(
                &policy,
                other.id,
                first_delivery.semantic_id,
                first_delivery.token,
            ),
            Err(StoreError::BlobDeliveryTokenBindingMismatch)
        ));
        assert!(matches!(
            store.acknowledge_blob_delivery_with_policy(
                &policy,
                created.id,
                second.semantic_id,
                first_delivery.token,
            ),
            Err(StoreError::BlobDeliveryTokenBindingMismatch)
        ));
        let mut malformed = *first_delivery.token.as_bytes();
        malformed[0] = 0xff;
        assert!(matches!(
            BlobDeliveryToken::from_bytes(malformed),
            Err(StoreError::InvalidBlobDeliveryToken)
        ));

        let next_plan = store
            .prepare_blob_subscription_poll_with_policy(&policy, created.id, 2, 8)
            .expect("next plan");
        let next_page = store
            .commit_blob_subscription_poll_with_policy(
                &policy,
                &next_plan,
                &BlobSubscriptionPollSelection {
                    deliverable: vec![second.semantic_id],
                    inactive: vec![first_delivery.semantic_id],
                },
            )
            .expect("next commit");
        assert_eq!(next_page.deliveries.len(), 1);
        assert_ne!(
            next_page.deliveries[0].semantic_id,
            first_delivery.semantic_id
        );
        assert_eq!(
            store
                .acknowledge_blob_delivery_with_policy(
                    &policy,
                    created.id,
                    next_page.deliveries[0].semantic_id,
                    next_page.deliveries[0].token,
                )
                .expect("acknowledge second publication"),
            BlobDeliveryAck::Acknowledged
        );
        assert!(matches!(
            store.acknowledge_blob_delivery_with_policy(
                &policy,
                created.id,
                first_delivery.semantic_id,
                first_delivery.token,
            ),
            Err(StoreError::BlobDeliveryNotFound)
        ));
        let reactivation_plan = store
            .prepare_blob_subscription_poll_with_policy(&policy, created.id, 2, 8)
            .expect("reactivation plan");
        let reactivation_page = store
            .commit_blob_subscription_poll_with_policy(
                &policy,
                &reactivation_plan,
                &all_blob_subscription_candidates_deliverable(&reactivation_plan),
            )
            .expect("reactivation commit");
        assert_eq!(reactivation_page.deliveries.len(), 1);
        assert_eq!(
            reactivation_page.deliveries[0].semantic_id,
            first_delivery.semantic_id
        );
        assert_eq!(reactivation_page.deliveries[0].attempt, 1);
        assert_ne!(reactivation_page.deliveries[0].token, first_delivery.token);
        assert!(matches!(
            store.acknowledge_blob_delivery_with_policy(
                &policy,
                created.id,
                first_delivery.semantic_id,
                first_delivery.token,
            ),
            Err(StoreError::BlobDeliveryTenureChanged { .. })
        ));
        assert_eq!(
            store
                .acknowledge_blob_delivery_with_policy(
                    &policy,
                    created.id,
                    first_delivery.semantic_id,
                    reactivation_page.deliveries[0].token,
                )
                .expect("acknowledge reactivated publication"),
            BlobDeliveryAck::Acknowledged
        );
        let stats = store.blob_subscription_stats().expect("ledger stats");
        assert_eq!(stats.subscriptions, 2);
        assert_eq!(stats.pending_deliveries, 0);
        assert_eq!(stats.acknowledged_deliveries, 2);
        assert_eq!(stats.delivery_cursors, 2);
        drop(store);

        let reopened = Store::open_for_mission(&root.database, services.authority)
            .expect("subscription reopen");
        assert_eq!(
            reopened.blob_subscription_stats().expect("reopen stats"),
            stats
        );
        let reopened_policy = reopened.control_policy_snapshot().expect("reopen policy");
        let quiet = reopened
            .prepare_blob_subscription_poll_with_policy(&reopened_policy, created.id, 2, 8)
            .expect("quiet plan");
        assert!(
            reopened
                .commit_blob_subscription_poll_with_policy(
                    &reopened_policy,
                    &quiet,
                    &all_blob_subscription_candidates_deliverable(&quiet),
                )
                .expect("quiet commit")
                .deliveries
                .is_empty()
        );
        assert!(
            reopened
                .remove_blob_subscription_with_policy(&reopened_policy, created.id)
                .expect("remove selector")
                .removed
        );
        let recreated = reopened
            .create_blob_subscription_with_policy(
                &reopened_policy,
                &key,
                BlobSubscriptionSpec {
                    include_descendant_scopes: true,
                    ..spec
                },
            )
            .expect("recreate selector");
        assert_eq!(recreated.id, created.id);
        assert!(matches!(
            reopened.acknowledge_blob_delivery_with_policy(
                &reopened_policy,
                recreated.id,
                first_delivery.semantic_id,
                first_delivery.token,
            ),
            Err(StoreError::BlobSubscriptionIncarnationChanged { .. })
        ));
        assert_eq!(
            reopened.blob_subscription_stats().expect("recreated stats"),
            BlobSubscriptionStats {
                subscriptions: 2,
                selector_generation: stats.selector_generation + 2,
                ..BlobSubscriptionStats::default()
            }
        );
    }

    #[test]
    fn blob_subscription_rejects_nonexhaustive_selection_and_full_projection_change() {
        let root = BlobTestRoot::new("subscription-plan-change");
        let mut services = blob_services(0xd4);
        let plaintext = vec![0xd4; 768];
        let prepared = prepared_blob(&plaintext);
        let store =
            Store::open_for_mission(&root.database, services.authority).expect("plan-change store");
        let published = publish_blob(
            &store,
            &mut services,
            &prepared,
            &plaintext,
            1,
            b"blob-subscription-plan-change",
        )
        .0;
        let policy = store.control_policy_snapshot().expect("plan-change policy");
        let created = store
            .create_blob_subscription_with_policy(
                &policy,
                &BlobSubscriptionKey::new(b"plan-change-selector".to_vec()).expect("key"),
                BlobSubscriptionSpec {
                    topic: blob_topic(),
                    scope: blob_scope(),
                    include_descendant_scopes: false,
                },
            )
            .expect("plan-change selector");
        let plan = store
            .prepare_blob_subscription_poll_with_policy(&policy, created.id, 1, 8)
            .expect("plan-change poll");
        assert_eq!(plan.candidates().len(), 1);
        for selection in [
            BlobSubscriptionPollSelection::default(),
            BlobSubscriptionPollSelection {
                deliverable: vec![published.semantic_id, published.semantic_id],
                inactive: Vec::new(),
            },
            BlobSubscriptionPollSelection {
                deliverable: vec![published.semantic_id],
                inactive: vec![published.semantic_id],
            },
        ] {
            assert!(matches!(
                store.commit_blob_subscription_poll_with_policy(&policy, &plan, &selection),
                Err(StoreError::BlobSubscriptionPlanChanged)
            ));
        }

        let original_sealed = {
            let read = store.database.begin_read().expect("source bytes read");
            read.open_table(BLOB_BYTES)
                .expect("source bytes")
                .get(published.transfer_id.as_bytes().as_slice())
                .expect("source lookup")
                .expect("source row")
                .value()
                .to_vec()
        };
        {
            let write = store.database.begin_write().expect("source mutation write");
            let mut corrupted = original_sealed.clone();
            corrupted[0] ^= 0x01;
            write
                .open_table(BLOB_BYTES)
                .expect("source bytes")
                .insert(
                    published.transfer_id.as_bytes().as_slice(),
                    corrupted.as_slice(),
                )
                .expect("replace same-length source bytes");
            write.commit().expect("commit source mutation");
        }
        assert!(matches!(
            store.commit_blob_subscription_poll_with_policy(
                &policy,
                &plan,
                &all_blob_subscription_candidates_deliverable(&plan),
            ),
            Err(StoreError::BlobSubscriptionPlanChanged)
        ));

        {
            let write = store.database.begin_write().expect("source restore write");
            write
                .open_table(BLOB_BYTES)
                .expect("source bytes")
                .insert(
                    published.transfer_id.as_bytes().as_slice(),
                    original_sealed.as_slice(),
                )
                .expect("restore exact source bytes");
            write.commit().expect("commit source restore");
        }
        {
            let write = store
                .database
                .begin_write()
                .expect("metadata mutation write");
            let encoded = write
                .open_table(BLOB_PUBLICATIONS)
                .expect("publications")
                .get(published.transfer_id.as_bytes().as_slice())
                .expect("publication lookup")
                .expect("publication row")
                .value()
                .to_vec();
            let mut metadata = decode_blob_metadata(&encoded).expect("decode publication");
            metadata.header.stamp.dot.counter += 1;
            let encoded = encode_blob_metadata(metadata).expect("encode changed publication");
            write
                .open_table(BLOB_PUBLICATIONS)
                .expect("publications")
                .insert(
                    published.transfer_id.as_bytes().as_slice(),
                    encoded.as_slice(),
                )
                .expect("replace publication");
            write.commit().expect("commit metadata mutation");
        }
        assert!(matches!(
            store.commit_blob_subscription_poll_with_policy(
                &policy,
                &plan,
                &all_blob_subscription_candidates_deliverable(&plan),
            ),
            Err(StoreError::BlobSubscriptionPlanChanged)
        ));
    }

    #[test]
    fn blob_subscription_schema_backfills_predecessor_publications_and_rejects_partial_current_group()
     {
        let root = BlobTestRoot::new("subscription-migration");
        let mut services = blob_services(0xd2);
        let plaintext = vec![0xd2; 512];
        let prepared = prepared_blob(&plaintext);
        let store = Store::open_for_mission(&root.database, services.authority)
            .expect("migration source store");
        let published = publish_blob(
            &store,
            &mut services,
            &prepared,
            &plaintext,
            1,
            b"blob-subscription-migration",
        )
        .0;
        drop(store);

        {
            let database = Database::open(&root.database).expect("raw predecessor database");
            let write = database.begin_write().expect("predecessor write");
            write
                .delete_table(BLOB_ACCEPTANCE_ORDER)
                .expect("delete acceptance order");
            write
                .delete_table(super::super::blob_subscription::BLOB_SUBSCRIPTIONS)
                .expect("delete subscriptions");
            write
                .delete_table(super::super::blob_subscription::BLOB_SUBSCRIPTION_PENDING)
                .expect("delete pending");
            write
                .delete_table(super::super::blob_subscription::BLOB_DELIVERY_ACKNOWLEDGEMENTS)
                .expect("delete acknowledgements");
            write
                .delete_table(super::super::blob_subscription::BLOB_DELIVERY_CURSORS)
                .expect("delete cursors");
            {
                let mut metadata = write.open_table(METADATA).expect("metadata");
                for field in [
                    super::super::blob_subscription::BLOB_SUBSCRIPTION_COUNT,
                    super::super::blob_subscription::BLOB_PENDING_DELIVERY_COUNT,
                    super::super::blob_subscription::BLOB_ACKNOWLEDGEMENT_COUNT,
                    super::super::blob_subscription::BLOB_DELIVERY_CURSOR_COUNT,
                    super::super::blob_subscription::BLOB_SELECTOR_GENERATION,
                ] {
                    metadata.remove(field).expect("remove extension metadata");
                }
            }
            write.commit().expect("commit predecessor shape");
        }

        let old_inspection = Store::inspect_existing(&root.database).expect("inspect predecessor");
        assert_eq!(old_inspection.blob_stats.publications, 1);
        assert_eq!(
            old_inspection.blob_subscription_stats,
            BlobSubscriptionStats::default()
        );
        let migrated = Store::open_for_mission(&root.database, services.authority)
            .expect("migrate predecessor");
        assert_eq!(
            migrated.blob_subscription_stats().expect("migrated stats"),
            BlobSubscriptionStats::default()
        );
        {
            let read = migrated.database.begin_read().expect("order read");
            let order = read
                .open_table(BLOB_ACCEPTANCE_ORDER)
                .expect("acceptance order");
            assert_eq!(
                order
                    .get(published.acceptance_marker)
                    .expect("order lookup")
                    .expect("backfilled row")
                    .value(),
                published.transfer_id.as_bytes().as_slice()
            );
        }

        let policy = migrated
            .control_policy_snapshot()
            .expect("migration policy");
        let created = migrated
            .create_blob_subscription_with_policy(
                &policy,
                &BlobSubscriptionKey::new(b"migration-selector".to_vec()).expect("key"),
                BlobSubscriptionSpec {
                    topic: blob_topic(),
                    scope: blob_scope(),
                    include_descendant_scopes: false,
                },
            )
            .expect("create migrated selector");
        assert_eq!(
            migrated
                .prepare_blob_subscription_poll_with_policy(&policy, created.id, 1, 8)
                .expect("migrated plan")
                .candidates()
                .len(),
            1
        );
        drop(migrated);

        {
            let database = Database::open(&root.database).expect("raw partial database");
            let write = database.begin_write().expect("partial write");
            write
                .delete_table(BLOB_ACCEPTANCE_ORDER)
                .expect("delete current order");
            write.commit().expect("commit partial group");
        }
        assert!(Store::inspect_existing(&root.database).is_err());
        assert!(Store::open_for_mission(&root.database, services.authority).is_err());
    }

    #[test]
    fn blob_subscription_count_and_poll_limits_are_enforced() {
        let root = BlobTestRoot::new("subscription-caps");
        let services = blob_services(0xd3);
        let store = Store::open_for_mission(&root.database, services.authority)
            .expect("subscription cap store");
        let policy = store.control_policy_snapshot().expect("cap policy");
        let spec = BlobSubscriptionSpec {
            topic: blob_topic(),
            scope: blob_scope(),
            include_descendant_scopes: false,
        };
        let mut first = None;
        for index in 0..MAX_BLOB_SUBSCRIPTIONS {
            let id = store
                .create_blob_subscription_with_policy(
                    &policy,
                    &BlobSubscriptionKey::new(format!("blob-cap-{index}").into_bytes())
                        .expect("bounded key"),
                    spec.clone(),
                )
                .expect("bounded subscription")
                .id;
            first.get_or_insert(id);
        }
        let first = first.expect("first subscription");
        assert!(matches!(
            store.create_blob_subscription_with_policy(
                &policy,
                &BlobSubscriptionKey::new(b"blob-cap-overflow".to_vec()).expect("overflow key"),
                spec,
            ),
            Err(StoreError::BlobSubscriptionLimitExceeded {
                current: MAX_BLOB_SUBSCRIPTIONS,
                limit: MAX_BLOB_SUBSCRIPTIONS,
            })
        ));
        assert!(matches!(
            store.prepare_blob_subscription_poll_with_policy(&policy, first, 0, 1),
            Err(StoreError::BlobSubscriptionPollLimitExceeded { .. })
        ));
        assert!(matches!(
            store.prepare_blob_subscription_poll_with_policy(
                &policy,
                first,
                1,
                MAX_BLOB_SUBSCRIPTION_SCAN + 1,
            ),
            Err(StoreError::BlobSubscriptionPollLimitExceeded { .. })
        ));
        assert_eq!(
            store
                .blob_subscription_stats()
                .expect("bounded subscription stats")
                .subscriptions,
            MAX_BLOB_SUBSCRIPTIONS
        );
    }

    fn install_unreferenced_variant(
        store: &Store,
        services: &BlobServices,
        plaintext: &[u8],
        epoch: u64,
        finalized: bool,
    ) -> BlobVariantId {
        let prepared = prepared_blob(plaintext);
        let depot = store.blob_depot().expect("maintenance test depot");
        let mut service = services
            .publisher
            .blob_service_with_store(&blob_scope(), &blob_topic(), epoch, depot)
            .expect("maintenance test Blob service");
        let manifest = service
            .install_prepared(&prepared)
            .expect("install maintenance test import");
        let variant = BlobVariantId::for_content(
            manifest.id(),
            manifest.content_group(),
            manifest.content_epoch(),
        );
        if finalized {
            let progress = service
                .encrypt_some(&mut Cursor::new(plaintext), &manifest, u64::MAX)
                .expect("encrypt maintenance test import");
            assert!(progress.complete);
            service
                .finish_manifest(&manifest)
                .expect("finalize maintenance test import");
        }
        variant
    }

    fn stage_pending_source_for_maintenance(
        source: &Store,
        target: &Store,
        services: &mut BlobServices,
        plaintext: &[u8],
        epoch: u64,
        with_prefix: bool,
    ) -> BlobTransferId {
        let prepared = prepared_blob(plaintext);
        let proof = prepare_blob_proof(source, services, &prepared, plaintext, epoch);
        let plan = proof
            .blob
            .transfer_plan(&proof.manifest_bytes)
            .expect("maintenance pending plan");
        let transfer = BlobTransferId::new(proof.blob.envelope_id());
        let policy = target
            .control_policy_snapshot()
            .expect("maintenance target policy");
        assert_eq!(
            target
                .stage_verified_blob_source_with_policy(&policy, &proof.blob, &proof.sealed, &plan,)
                .expect("stage maintenance pending source"),
            BlobSourceStageOutcome::Inserted
        );
        if with_prefix {
            let mut source_depot = source.blob_depot().expect("maintenance source depot");
            CoreBlobStore::begin_blob_with_lineage(
                &mut source_depot,
                plan.manifest(),
                plan.physical_lineage(),
            )
            .expect("activate maintenance source plan");
            let carrier = plan
                .build_carrier(&mut source_depot, 0)
                .expect("build maintenance carrier");
            let object = BlobCarrierObjectId::new(carrier.object_id().wire_bytes())
                .expect("typed maintenance carrier");
            let total_len = u64::try_from(carrier.bytes().len()).expect("carrier length");
            let first = carrier
                .bytes()
                .chunks(MAX_BLOB_NETWORK_RANGE_BYTES)
                .next()
                .expect("nonempty carrier");
            target
                .append_blob_carrier_prefix_with_policy(
                    &policy, transfer, object, total_len, 0, first,
                )
                .expect("append maintenance carrier prefix");
        }
        transfer
    }

    fn maintenance_budget(rows: u64) -> lifecycle::BlobMaintenanceBudget {
        lifecycle::BlobMaintenanceBudget::new(rows, 1, 2 * 1024 * 1024)
            .expect("nonzero maintenance budget")
    }

    fn maintenance_cursor_value(position: Option<&[u8]>) -> Vec<u8> {
        let mut value = vec![1, u8::from(position.is_some())];
        if let Some(position) = position {
            value.extend_from_slice(position);
        }
        value
    }

    fn set_maintenance_next_class(store: &Store, class: lifecycle::BlobMaintenanceClass) {
        let write = store
            .database
            .begin_write()
            .expect("maintenance next-class transaction");
        write
            .open_table(lifecycle::BLOB_MAINTENANCE_CURSORS)
            .expect("maintenance cursors")
            .insert(0, [1, class.cursor_key()].as_slice())
            .expect("set maintenance next class");
        write.commit().expect("commit maintenance next class");
    }

    fn set_maintenance_cursor(
        store: &Store,
        class: lifecycle::BlobMaintenanceClass,
        position: Option<&[u8]>,
    ) {
        let write = store
            .database
            .begin_write()
            .expect("maintenance cursor transaction");
        let mut cursors = write
            .open_table(lifecycle::BLOB_MAINTENANCE_CURSORS)
            .expect("maintenance cursors");
        cursors
            .insert(0, [1, class.cursor_key()].as_slice())
            .expect("set maintenance next class");
        cursors
            .insert(
                class.cursor_key(),
                maintenance_cursor_value(position).as_slice(),
            )
            .expect("set maintenance class cursor");
        drop(cursors);
        write.commit().expect("commit maintenance cursor");
    }

    #[derive(Clone, Copy, Debug)]
    enum MaintenancePublicationCorruption {
        LineageOwnerBinding,
        ReplaySourceLength,
        ReplaySourceDigest,
        ConflictingAcceptedDot,
        LaggingPublisherHighWater,
        MissingCausalFrontier,
    }

    fn corrupt_maintenance_publication(
        store: &Store,
        publication: &StoredBlob,
        corruption: MaintenancePublicationCorruption,
    ) {
        match corruption {
            MaintenancePublicationCorruption::ConflictingAcceptedDot => {
                corrupt_blob_causal_point(
                    store,
                    publication,
                    BlobCausalPointCorruption::ConflictingAcceptedDot,
                );
                return;
            }
            MaintenancePublicationCorruption::LaggingPublisherHighWater => {
                corrupt_blob_causal_point(
                    store,
                    publication,
                    BlobCausalPointCorruption::LaggingPublisherHighWater,
                );
                return;
            }
            MaintenancePublicationCorruption::MissingCausalFrontier => {
                corrupt_blob_causal_point(
                    store,
                    publication,
                    BlobCausalPointCorruption::MissingFrontier,
                );
                return;
            }
            _ => {}
        }

        let write = store
            .database
            .begin_write()
            .expect("maintenance evidence corruption transaction");
        match corruption {
            MaintenancePublicationCorruption::LineageOwnerBinding => {
                let key = publication.variant_id.as_bytes().as_slice();
                let mut encoded = write
                    .open_table(lifecycle::BLOB_LINEAGE_FENCES)
                    .expect("lineage fences")
                    .get(key)
                    .expect("lineage lookup")
                    .expect("lineage fence")
                    .value()
                    .to_vec();
                assert_eq!(encoded.len(), 65);
                encoded[33] ^= 1;
                write
                    .open_table(lifecycle::BLOB_LINEAGE_FENCES)
                    .expect("lineage fences")
                    .insert(key, encoded.as_slice())
                    .expect("corrupt lineage owner binding");
            }
            MaintenancePublicationCorruption::ReplaySourceLength
            | MaintenancePublicationCorruption::ReplaySourceDigest => {
                let key = accepted_dot_key(publication.header.stamp.dot);
                let mut encoded = write
                    .open_table(lifecycle::BLOB_REPLAY_FENCES)
                    .expect("replay fences")
                    .get(key.as_slice())
                    .expect("replay lookup")
                    .expect("replay fence")
                    .value()
                    .to_vec();
                assert_eq!(encoded.len(), 145);
                let offset = match corruption {
                    MaintenancePublicationCorruption::ReplaySourceLength => 112,
                    MaintenancePublicationCorruption::ReplaySourceDigest => 113,
                    _ => unreachable!(),
                };
                encoded[offset] ^= 1;
                write
                    .open_table(lifecycle::BLOB_REPLAY_FENCES)
                    .expect("replay fences")
                    .insert(key.as_slice(), encoded.as_slice())
                    .expect("corrupt replay evidence");
            }
            MaintenancePublicationCorruption::ConflictingAcceptedDot
            | MaintenancePublicationCorruption::LaggingPublisherHighWater
            | MaintenancePublicationCorruption::MissingCausalFrontier => unreachable!(),
        }
        write
            .commit()
            .expect("commit maintenance evidence corruption");
    }

    #[test]
    fn blob_maintenance_publication_requires_complete_lineage_replay_and_causal_evidence() {
        let mut missed = Vec::new();
        for (index, corruption) in [
            MaintenancePublicationCorruption::LineageOwnerBinding,
            MaintenancePublicationCorruption::ReplaySourceLength,
            MaintenancePublicationCorruption::ReplaySourceDigest,
            MaintenancePublicationCorruption::ConflictingAcceptedDot,
            MaintenancePublicationCorruption::LaggingPublisherHighWater,
            MaintenancePublicationCorruption::MissingCausalFrontier,
        ]
        .into_iter()
        .enumerate()
        {
            let root = BlobTestRoot::new(&format!("maintenance-evidence-{index}"));
            let mut services = blob_services(0x80 + u8::try_from(index).expect("case index"));
            let store = Store::open_for_mission(&root.database, services.authority)
                .expect("maintenance evidence store");
            let plaintext = format!("maintenance exact evidence {index}").into_bytes();
            let prepared = prepared_blob(&plaintext);
            let (publication, _, _) = publish_blob(
                &store,
                &mut services,
                &prepared,
                &plaintext,
                1,
                format!("maintenance-evidence-operation-{index}").as_bytes(),
            );
            corrupt_maintenance_publication(&store, &publication, corruption);
            set_maintenance_next_class(
                &store,
                lifecycle::BlobMaintenanceClass::ExpiredPublicationsAndPendingSources,
            );
            let before = blob_current_admission_digest(&store);
            match store.run_blob_maintenance_turn(maintenance_budget(64)) {
                Err(error) => {
                    assert_blob_schema_invariant(&error);
                    assert_eq!(
                        blob_current_admission_digest(&store),
                        before,
                        "{corruption:?} advanced a cursor before rejecting corruption"
                    );
                }
                Ok(_) => missed.push(format!("{corruption:?}")),
            }
        }
        assert!(
            missed.is_empty(),
            "maintenance accepted incomplete authority: {missed:?}"
        );
    }

    #[test]
    fn blob_maintenance_budgets_and_round_robin_are_bounded_and_fair() {
        // Break caught: a nonempty early class, or an empty later class, must
        // not reset the durable scheduler and starve another class.
        let root = BlobTestRoot::new("maintenance-bounds-fairness");
        let source_root = BlobTestRoot::new("maintenance-bounds-source");
        let mut services = blob_services(0x41);
        let store = Store::open_for_mission(&root.database, services.authority)
            .expect("maintenance fairness store");
        let source = Store::open_for_mission(&source_root.database, services.authority)
            .expect("maintenance fairness source");
        for index in 0..8u8 {
            let plaintext = vec![0x40 | index; 192 + usize::from(index)];
            let prepared = prepared_blob(&plaintext);
            publish_blob(
                &store,
                &mut services,
                &prepared,
                &plaintext,
                1,
                format!("maintenance-fairness-{index}").as_bytes(),
            );
            publish_blob(
                &source,
                &mut services,
                &prepared,
                &plaintext,
                1,
                format!("maintenance-fairness-source-{index}").as_bytes(),
            );
        }
        for index in 0..2u8 {
            stage_pending_source_for_maintenance(
                &source,
                &store,
                &mut services,
                &vec![0x70 | index; 320 + usize::from(index)],
                1,
                false,
            );
        }
        for index in 0..2u8 {
            install_unreferenced_variant(
                &store,
                &services,
                &vec![0x20 | index; 256 + usize::from(index)],
                1,
                index == 1,
            );
        }

        let budget = maintenance_budget(1);
        let mut selected = Vec::new();
        let mut first_class_more = 0;
        for _ in 0..12 {
            let progress = store
                .run_blob_maintenance_turn(budget)
                .expect("bounded maintenance turn");
            assert!(progress.rows_examined <= budget.rows);
            assert!(progress.files_examined <= budget.files);
            assert!(progress.bytes_examined <= budget.bytes);
            if progress.class
                == lifecycle::BlobMaintenanceClass::ExpiredPublicationsAndPendingSources
            {
                first_class_more += usize::from(progress.class_has_more_work);
            }
            selected.push(progress.class);
        }
        assert_eq!(
            selected,
            lifecycle::BlobMaintenanceClass::ALL
                .into_iter()
                .cycle()
                .take(12)
                .collect::<Vec<_>>()
        );
        assert_eq!(
            first_class_more, 2,
            "continuous first-class rows must not prevent later-class turns"
        );
    }

    #[test]
    fn blob_maintenance_restart_preserves_the_exact_next_class() {
        // Break caught: startup must not reconstruct scheduling at the first
        // precedence class after a clean restart.
        let budget = maintenance_budget(2);
        for stop_after in 0..lifecycle::BlobMaintenanceClass::ALL.len() {
            let actual_root = BlobTestRoot::new(&format!("maintenance-restart-{stop_after}"));
            let uninterrupted_root =
                BlobTestRoot::new(&format!("maintenance-uninterrupted-{stop_after}"));
            let services = blob_services(0x50 + u8::try_from(stop_after).expect("small class"));
            let actual = Store::open_for_mission(&actual_root.database, services.authority)
                .expect("restart actual store");
            let uninterrupted =
                Store::open_for_mission(&uninterrupted_root.database, services.authority)
                    .expect("restart uninterrupted store");
            for _ in 0..stop_after {
                actual
                    .run_blob_maintenance_turn(budget)
                    .expect("advance restart store");
                uninterrupted
                    .run_blob_maintenance_turn(budget)
                    .expect("advance uninterrupted store");
            }
            drop(actual);
            let reopened = Store::open_for_mission(&actual_root.database, services.authority)
                .expect("reopen maintenance store");
            assert_eq!(
                reopened
                    .run_blob_maintenance_turn(budget)
                    .expect("restarted next turn")
                    .class,
                uninterrupted
                    .run_blob_maintenance_turn(budget)
                    .expect("uninterrupted next turn")
                    .class,
                "restart after class {stop_after} changed the next class"
            );
        }
    }

    #[test]
    fn blob_maintenance_removed_cursor_row_resumes_exclusively_and_wraps() {
        // Break caught: a cursor key names a lexicographic position, not a
        // foreign-key requirement on the row that happened to occupy it.
        let root = BlobTestRoot::new("maintenance-removed-cursor-row");
        let mut services = blob_services(0x5a);
        let store = Store::open_for_mission(&root.database, services.authority)
            .expect("removed-cursor store");
        for key in [b"cursor-a".as_slice(), b"cursor-b", b"cursor-c"] {
            let plaintext = key.to_vec();
            let prepared = prepared_blob(&plaintext);
            publish_blob(&store, &mut services, &prepared, &plaintext, 1, key);
        }
        {
            let write = store
                .database
                .begin_write()
                .expect("remove cursor operation");
            let removed = write
                .open_table(BLOB_OPERATIONS)
                .expect("Blob operations")
                .remove(b"cursor-b".as_slice())
                .expect("remove cursor operation row")
                .expect("cursor operation exists")
                .value()
                .to_vec();
            let mut metadata = write.open_table(METADATA).expect("store metadata");
            metadata
                .insert(BLOB_OPERATION_COUNT, 2)
                .expect("decrement operation rows");
            let bytes = metadata
                .get(BLOB_OPERATION_TOTAL_BYTES)
                .expect("operation bytes")
                .expect("operation bytes exist")
                .value();
            metadata
                .insert(
                    BLOB_OPERATION_TOTAL_BYTES,
                    bytes
                        - u64::try_from(b"cursor-b".len() + removed.len())
                            .expect("removed operation size"),
                )
                .expect("decrement operation bytes");
            drop(metadata);
            let mut cursors = write
                .open_table(lifecycle::BLOB_MAINTENANCE_CURSORS)
                .expect("maintenance cursors");
            cursors
                .insert(0, [1, 5].as_slice())
                .expect("select operation class");
            cursors
                .insert(5, maintenance_cursor_value(Some(b"cursor-b")).as_slice())
                .expect("position removed-row cursor");
            drop(cursors);
            write.commit().expect("commit removed cursor row");
        }

        let progress = store
            .run_blob_maintenance_turn(maintenance_budget(2))
            .expect("resume strictly after removed row");
        assert_eq!(
            progress.class,
            lifecycle::BlobMaintenanceClass::ExpiredRetirementRecords
        );
        assert!(progress.class_has_more_work);
        let read = store.database.begin_read().expect("read advanced cursor");
        assert_eq!(
            read.open_table(lifecycle::BLOB_MAINTENANCE_CURSORS)
                .expect("maintenance cursors")
                .get(5)
                .expect("operation cursor")
                .expect("operation cursor exists")
                .value(),
            maintenance_cursor_value(Some(b"cursor-c"))
        );
        drop(read);

        for _ in 0..5 {
            store
                .run_blob_maintenance_turn(maintenance_budget(2))
                .expect("rotate to operation class");
        }
        let wrapped = store
            .run_blob_maintenance_turn(maintenance_budget(2))
            .expect("wrap operation cursor");
        assert_eq!(
            wrapped.class,
            lifecycle::BlobMaintenanceClass::ExpiredRetirementRecords
        );
        let read = store.database.begin_read().expect("read wrapped cursor");
        assert_eq!(
            read.open_table(lifecycle::BLOB_MAINTENANCE_CURSORS)
                .expect("maintenance cursors")
                .get(5)
                .expect("operation cursor")
                .expect("operation cursor exists")
                .value(),
            maintenance_cursor_value(Some(b"cursor-a"))
        );
    }

    #[test]
    fn blob_maintenance_carrier_evidence_is_charged_before_cursor_advance() {
        // Break caught: selecting a carrier prefix must not clone and decode
        // its pending-source evidence outside the reported row/byte budget.
        let root = BlobTestRoot::new("maintenance-carrier-evidence-budget");
        let source_root = BlobTestRoot::new("maintenance-carrier-evidence-source");
        let mut services = blob_services(0x5c);
        let store = Store::open_for_mission(&root.database, services.authority)
            .expect("carrier evidence target");
        let source = Store::open_for_mission(&source_root.database, services.authority)
            .expect("carrier evidence source");
        let transfer = stage_pending_source_for_maintenance(
            &source,
            &store,
            &mut services,
            &vec![0x5d; SELECTED_BLOB_CHUNK_SIZE as usize + 29],
            1,
            true,
        );
        let (carrier_key, carrier_bytes, supporting_bytes) = {
            let read = store.database.begin_read().expect("carrier evidence read");
            let carriers = read
                .open_table(BLOB_CARRIER_PREFIXES)
                .expect("carrier prefixes");
            let (key, value) = carriers
                .iter()
                .expect("carrier rows")
                .next()
                .expect("carrier row exists")
                .expect("carrier row");
            let carrier_key = key.value().to_vec();
            let carrier_bytes =
                maintenance_entry_bytes(key.value(), value.value()).expect("carrier encoded bytes");
            let pending = read
                .open_table(BLOB_PENDING_SOURCES)
                .expect("pending sources");
            let pending = pending
                .get(transfer.as_bytes().as_slice())
                .expect("pending lookup")
                .expect("pending evidence exists");
            let pending_bytes = maintenance_entry_bytes(transfer.as_bytes(), pending.value())
                .expect("pending encoded bytes");
            let pending_record =
                decode_pending_blob_source(pending.value()).expect("pending evidence record");
            let variant = pending_record.metadata.variant_id;
            let imports = read.open_table(BLOB_IMPORTS).expect("depot imports");
            let import = imports
                .get(variant.as_bytes().as_slice())
                .expect("import lookup")
                .expect("import evidence exists");
            let import_bytes = maintenance_entry_bytes(variant.as_bytes(), import.value())
                .expect("import encoded bytes");
            let lineages = read
                .open_table(lifecycle::BLOB_LINEAGE_FENCES)
                .expect("lineage fences");
            let lineage = lineages
                .get(variant.as_bytes().as_slice())
                .expect("lineage lookup")
                .expect("lineage evidence exists");
            let lineage_bytes = maintenance_entry_bytes(variant.as_bytes(), lineage.value())
                .expect("lineage encoded bytes");
            let mut reference_key = Vec::with_capacity(65);
            reference_key.extend_from_slice(variant.as_bytes());
            reference_key
                .extend_from_slice(&lifecycle::VariantReferenceOwner::PendingSource.encode());
            reference_key.extend_from_slice(transfer.as_bytes());
            let references = read
                .open_table(lifecycle::BLOB_VARIANT_REFERENCES)
                .expect("variant references");
            let reference = references
                .get(reference_key.as_slice())
                .expect("reference lookup")
                .expect("reference evidence exists");
            let reference_bytes = maintenance_entry_bytes(&reference_key, reference.value())
                .expect("reference encoded bytes");
            (
                carrier_key,
                carrier_bytes,
                pending_bytes + import_bytes + lineage_bytes + reference_bytes,
            )
        };
        let mut after_pending = vec![MAINTENANCE_PRIMARY_SOURCE_TAG];
        after_pending.extend_from_slice(transfer.as_bytes());
        let encoded_after_pending = maintenance_cursor_value(Some(&after_pending));

        for budget in [
            BlobMaintenanceBudget::new(4, 1, u64::MAX).expect("row-limited budget"),
            BlobMaintenanceBudget::new(5, 1, carrier_bytes + supporting_bytes - 1)
                .expect("byte-limited budget"),
        ] {
            set_maintenance_cursor(
                &store,
                lifecycle::BlobMaintenanceClass::InvalidPendingWork,
                Some(&after_pending),
            );
            let progress = store
                .run_blob_maintenance_turn(budget)
                .expect("insufficient carrier evidence budget is ordinary progress");
            assert_eq!(
                progress.class,
                lifecycle::BlobMaintenanceClass::InvalidPendingWork
            );
            assert!(progress.rows_examined <= budget.rows());
            assert!(progress.bytes_examined <= budget.bytes());
            assert!(progress.class_has_more_work);
            let read = store.database.begin_read().expect("read retained cursor");
            assert_eq!(
                read.open_table(lifecycle::BLOB_MAINTENANCE_CURSORS)
                    .expect("maintenance cursors")
                    .get(2)
                    .expect("invalid-pending cursor")
                    .expect("invalid-pending cursor exists")
                    .value(),
                encoded_after_pending,
                "insufficient supporting evidence must not advance the page"
            );
        }

        set_maintenance_cursor(
            &store,
            lifecycle::BlobMaintenanceClass::InvalidPendingWork,
            Some(&after_pending),
        );
        let admitted = store
            .run_blob_maintenance_turn(
                BlobMaintenanceBudget::new(5, 1, carrier_bytes + supporting_bytes)
                    .expect("exact carrier evidence budget"),
            )
            .expect("exact carrier evidence budget admits the row");
        assert_eq!(admitted.rows_examined, 5);
        assert_eq!(
            admitted.bytes_examined,
            carrier_bytes + supporting_bytes,
            "progress charges the carrier, pending row, and decoded authority evidence"
        );
        let mut expected_position = vec![MAINTENANCE_SECONDARY_SOURCE_TAG];
        expected_position.extend_from_slice(&carrier_key);
        let read = store.database.begin_read().expect("read advanced cursor");
        assert_eq!(
            read.open_table(lifecycle::BLOB_MAINTENANCE_CURSORS)
                .expect("maintenance cursors")
                .get(2)
                .expect("invalid-pending cursor")
                .expect("invalid-pending cursor exists")
                .value(),
            maintenance_cursor_value(Some(&expected_position))
        );
    }

    #[test]
    fn blob_maintenance_publication_evidence_obeys_exact_row_and_byte_budgets() {
        // One selected publication needs eleven independent support rows. A
        // turn may report a partial evidence scan, but cannot validate or move
        // the publication cursor until the complete set fits.
        let root = BlobTestRoot::new("maintenance-publication-evidence-budget");
        let mut services = blob_services(0x68);
        let store = Store::open_for_mission(&root.database, services.authority)
            .expect("publication evidence store");
        let plaintext = vec![0x69; SELECTED_BLOB_CHUNK_SIZE as usize + 41];
        let prepared = prepared_blob(&plaintext);
        let (publication, _, _) = publish_blob(
            &store,
            &mut services,
            &prepared,
            &plaintext,
            1,
            b"maintenance-publication-evidence-budget",
        );

        let exact_bytes = {
            let read = store
                .database
                .begin_read()
                .expect("publication evidence read");
            macro_rules! bytes_entry {
                ($definition:expr, $key:expr) => {{
                    let key: &[u8] = $key;
                    let table = read.open_table($definition).expect("evidence table");
                    let value = table
                        .get(key)
                        .expect("evidence lookup")
                        .expect("evidence row");
                    maintenance_entry_bytes(key, value.value()).expect("evidence bytes")
                }};
            }
            macro_rules! u64_entry {
                ($definition:expr, $key:expr) => {{
                    let key: &[u8] = $key;
                    read.open_table($definition)
                        .expect("u64 evidence table")
                        .get(key)
                        .expect("u64 evidence lookup")
                        .expect("u64 evidence row");
                    u64::try_from(key.len() + std::mem::size_of::<u64>())
                        .expect("u64 evidence bytes")
                }};
            }
            let transfer = publication.transfer_id.as_bytes().as_slice();
            let variant = publication.variant_id.as_bytes().as_slice();
            let dot_key = accepted_dot_key(publication.header.stamp.dot);
            let frontier_key = causal_frontier_key(
                &publication.header.topic,
                &publication.header.scope,
                publication.header.stamp.dot.publisher,
            )
            .expect("frontier key");
            let content_key = blob_content_key(
                &publication.header.topic,
                &publication.header.scope,
                publication.blob_id,
                publication.semantic_id,
            )
            .expect("content key");
            let mut reference_key = Vec::with_capacity(65);
            reference_key.extend_from_slice(variant);
            reference_key
                .extend_from_slice(&lifecycle::VariantReferenceOwner::Publication.encode());
            reference_key.extend_from_slice(transfer);
            bytes_entry!(BLOB_PUBLICATIONS, transfer)
                + bytes_entry!(BLOB_IMPORTS, variant)
                + bytes_entry!(lifecycle::BLOB_LINEAGE_FENCES, variant)
                + bytes_entry!(lifecycle::BLOB_VARIANT_REFERENCES, &reference_key)
                + bytes_entry!(BLOB_BYTES, transfer)
                + u64_entry!(BLOB_ACCEPTANCE_MARKERS, transfer)
                + bytes_entry!(BLOB_SEMANTIC_ITEMS, publication.semantic_id.as_bytes())
                + bytes_entry!(BLOB_CONTENT_INDEX, &content_key)
                + bytes_entry!(lifecycle::BLOB_REPLAY_FENCES, &dot_key)
                + bytes_entry!(ACCEPTED_DOTS, &dot_key)
                + u64_entry!(
                    PUBLISHER_HIGH_WATER,
                    &publication.header.stamp.dot.publisher
                )
                + u64_entry!(CAUSAL_FRONTIER, &frontier_key)
        };
        let unset_cursor = maintenance_cursor_value(None);
        for budget in [
            BlobMaintenanceBudget::new(11, 1, exact_bytes).expect("one-row-short budget"),
            BlobMaintenanceBudget::new(12, 1, exact_bytes - 1).expect("one-byte-short budget"),
        ] {
            set_maintenance_cursor(
                &store,
                lifecycle::BlobMaintenanceClass::ExpiredPublicationsAndPendingSources,
                None,
            );
            let progress = store
                .run_blob_maintenance_turn(budget)
                .expect("partial publication evidence is ordinary progress");
            assert!(progress.rows_examined <= budget.rows());
            assert!(progress.bytes_examined <= budget.bytes());
            assert!(progress.class_has_more_work);
            let read = store
                .database
                .begin_read()
                .expect("retained publication cursor");
            assert_eq!(
                read.open_table(lifecycle::BLOB_MAINTENANCE_CURSORS)
                    .expect("maintenance cursors")
                    .get(1)
                    .expect("publication cursor lookup")
                    .expect("publication cursor")
                    .value(),
                unset_cursor,
                "incomplete publication evidence advanced the row cursor"
            );
        }

        set_maintenance_cursor(
            &store,
            lifecycle::BlobMaintenanceClass::ExpiredPublicationsAndPendingSources,
            None,
        );
        let admitted = store
            .run_blob_maintenance_turn(
                BlobMaintenanceBudget::new(12, 1, exact_bytes)
                    .expect("exact publication evidence budget"),
            )
            .expect("exact publication evidence budget admits the row");
        assert_eq!(admitted.rows_examined, 12);
        assert_eq!(admitted.bytes_examined, exact_bytes);
        let mut expected_position = vec![MAINTENANCE_PRIMARY_SOURCE_TAG];
        expected_position.extend_from_slice(publication.transfer_id.as_bytes());
        let read = store
            .database
            .begin_read()
            .expect("advanced publication cursor");
        assert_eq!(
            read.open_table(lifecycle::BLOB_MAINTENANCE_CURSORS)
                .expect("maintenance cursors")
                .get(1)
                .expect("publication cursor lookup")
                .expect("publication cursor")
                .value(),
            maintenance_cursor_value(Some(&expected_position))
        );
    }

    #[test]
    fn blob_maintenance_pending_evidence_obeys_budgets_in_both_classes() {
        let root = BlobTestRoot::new("maintenance-pending-evidence-budget");
        let source_root = BlobTestRoot::new("maintenance-pending-evidence-source");
        let mut services = blob_services(0x6b);
        let store = Store::open_for_mission(&root.database, services.authority)
            .expect("pending evidence target");
        let source = Store::open_for_mission(&source_root.database, services.authority)
            .expect("pending evidence source");
        let transfer = stage_pending_source_for_maintenance(
            &source,
            &store,
            &mut services,
            b"pending evidence uses four durable rows",
            1,
            false,
        );
        let exact_bytes = {
            let read = store.database.begin_read().expect("pending evidence read");
            let pending = read
                .open_table(BLOB_PENDING_SOURCES)
                .expect("pending table")
                .get(transfer.as_bytes().as_slice())
                .expect("pending lookup")
                .expect("pending row");
            let pending_bytes = maintenance_entry_bytes(transfer.as_bytes(), pending.value())
                .expect("pending bytes");
            let pending_record =
                decode_pending_blob_source(pending.value()).expect("pending record");
            let variant = pending_record.metadata.variant_id;
            let import = read
                .open_table(BLOB_IMPORTS)
                .expect("imports")
                .get(variant.as_bytes().as_slice())
                .expect("import lookup")
                .expect("import row");
            let lineage = read
                .open_table(lifecycle::BLOB_LINEAGE_FENCES)
                .expect("lineages")
                .get(variant.as_bytes().as_slice())
                .expect("lineage lookup")
                .expect("lineage row");
            let reference_key = variant_reference_key(
                variant,
                lifecycle::VariantReferenceOwner::PendingSource,
                transfer,
            );
            let reference = read
                .open_table(lifecycle::BLOB_VARIANT_REFERENCES)
                .expect("references")
                .get(reference_key.as_slice())
                .expect("reference lookup")
                .expect("reference row");
            pending_bytes
                + maintenance_entry_bytes(variant.as_bytes(), import.value()).expect("import bytes")
                + maintenance_entry_bytes(variant.as_bytes(), lineage.value())
                    .expect("lineage bytes")
                + maintenance_entry_bytes(&reference_key, reference.value())
                    .expect("reference bytes")
        };

        for (class, tag) in [
            (
                lifecycle::BlobMaintenanceClass::ExpiredPublicationsAndPendingSources,
                MAINTENANCE_SECONDARY_SOURCE_TAG,
            ),
            (
                lifecycle::BlobMaintenanceClass::InvalidPendingWork,
                MAINTENANCE_PRIMARY_SOURCE_TAG,
            ),
        ] {
            for budget in [
                BlobMaintenanceBudget::new(3, 1, exact_bytes).expect("one-row-short pending"),
                BlobMaintenanceBudget::new(4, 1, exact_bytes - 1).expect("one-byte-short pending"),
            ] {
                set_maintenance_cursor(&store, class, None);
                let progress = store
                    .run_blob_maintenance_turn(budget)
                    .expect("partial pending evidence progress");
                assert!(progress.rows_examined <= budget.rows());
                assert!(progress.bytes_examined <= budget.bytes());
                assert_eq!(progress.files_examined, 0);
                assert!(progress.class_has_more_work);
                let read = store.database.begin_read().expect("pending cursor read");
                assert_eq!(
                    read.open_table(lifecycle::BLOB_MAINTENANCE_CURSORS)
                        .expect("maintenance cursors")
                        .get(class.cursor_key())
                        .expect("pending cursor lookup")
                        .expect("pending cursor")
                        .value(),
                    maintenance_cursor_value(None)
                );
            }

            set_maintenance_cursor(&store, class, None);
            let progress = store
                .run_blob_maintenance_turn(
                    BlobMaintenanceBudget::new(4, 1, exact_bytes).expect("exact pending evidence"),
                )
                .expect("exact pending evidence progress");
            assert_eq!(progress.rows_examined, 4);
            assert_eq!(progress.bytes_examined, exact_bytes);
            assert_eq!(progress.files_examined, 0);
            let mut expected_position = vec![tag];
            expected_position.extend_from_slice(transfer.as_bytes());
            let read = store
                .database
                .begin_read()
                .expect("advanced pending cursor");
            assert_eq!(
                read.open_table(lifecycle::BLOB_MAINTENANCE_CURSORS)
                    .expect("maintenance cursors")
                    .get(class.cursor_key())
                    .expect("pending cursor lookup")
                    .expect("pending cursor")
                    .value(),
                maintenance_cursor_value(Some(&expected_position))
            );
        }
    }

    #[test]
    fn blob_maintenance_import_evidence_obeys_budgets_with_and_without_references() {
        for (index, class, referenced, finalized) in [
            (
                0u8,
                lifecycle::BlobMaintenanceClass::UnreferencedLocalImportStaging,
                false,
                false,
            ),
            (
                1,
                lifecycle::BlobMaintenanceClass::UnreferencedCompletedVariants,
                false,
                true,
            ),
            (
                2,
                lifecycle::BlobMaintenanceClass::UnreferencedLocalImportStaging,
                true,
                true,
            ),
            (
                3,
                lifecycle::BlobMaintenanceClass::UnreferencedCompletedVariants,
                true,
                true,
            ),
        ] {
            let root = BlobTestRoot::new(&format!("maintenance-import-evidence-{index}"));
            let mut services = blob_services(0x90 + index);
            let store = Store::open_for_mission(&root.database, services.authority)
                .expect("import evidence store");
            let plaintext = format!("import evidence {index}").into_bytes();
            let (variant, transfer) = if referenced {
                let prepared = prepared_blob(&plaintext);
                let (publication, _, _) = publish_blob(
                    &store,
                    &mut services,
                    &prepared,
                    &plaintext,
                    1,
                    format!("import-evidence-operation-{index}").as_bytes(),
                );
                (publication.variant_id, Some(publication.transfer_id))
            } else {
                (
                    install_unreferenced_variant(&store, &services, &plaintext, 1, finalized),
                    None,
                )
            };
            let (exact_rows, exact_bytes) = {
                let read = store.database.begin_read().expect("import evidence read");
                let import = read
                    .open_table(BLOB_IMPORTS)
                    .expect("imports")
                    .get(variant.as_bytes().as_slice())
                    .expect("import lookup")
                    .expect("import row");
                let lineage = read
                    .open_table(lifecycle::BLOB_LINEAGE_FENCES)
                    .expect("lineages")
                    .get(variant.as_bytes().as_slice())
                    .expect("lineage lookup")
                    .expect("lineage row");
                let mut bytes = maintenance_entry_bytes(variant.as_bytes(), import.value())
                    .expect("import bytes")
                    + maintenance_entry_bytes(variant.as_bytes(), lineage.value())
                        .expect("lineage bytes");
                let rows = if let Some(transfer) = transfer {
                    let key = variant_reference_key(
                        variant,
                        lifecycle::VariantReferenceOwner::Publication,
                        transfer,
                    );
                    let reference = read
                        .open_table(lifecycle::BLOB_VARIANT_REFERENCES)
                        .expect("references")
                        .get(key.as_slice())
                        .expect("reference lookup")
                        .expect("reference row");
                    bytes +=
                        maintenance_entry_bytes(&key, reference.value()).expect("reference bytes");
                    3
                } else {
                    2
                };
                (rows, bytes)
            };

            for budget in [
                BlobMaintenanceBudget::new(exact_rows - 1, 1, exact_bytes)
                    .expect("one-row-short import"),
                BlobMaintenanceBudget::new(exact_rows, 1, exact_bytes - 1)
                    .expect("one-byte-short import"),
            ] {
                set_maintenance_cursor(&store, class, None);
                let progress = store
                    .run_blob_maintenance_turn(budget)
                    .expect("partial import evidence progress");
                assert!(progress.rows_examined <= budget.rows());
                assert!(progress.bytes_examined <= budget.bytes());
                assert_eq!(progress.files_examined, 0);
                assert!(progress.candidates.is_empty());
                let read = store.database.begin_read().expect("import cursor read");
                assert_eq!(
                    read.open_table(lifecycle::BLOB_MAINTENANCE_CURSORS)
                        .expect("maintenance cursors")
                        .get(class.cursor_key())
                        .expect("import cursor lookup")
                        .expect("import cursor")
                        .value(),
                    maintenance_cursor_value(None)
                );
            }

            set_maintenance_cursor(&store, class, None);
            let progress = store
                .run_blob_maintenance_turn(
                    BlobMaintenanceBudget::new(exact_rows, 1, exact_bytes)
                        .expect("exact import evidence"),
                )
                .expect("exact import evidence progress");
            assert_eq!(progress.rows_examined, exact_rows);
            assert_eq!(progress.bytes_examined, exact_bytes);
            assert_eq!(progress.files_examined, 0);
            let read = store
                .database
                .begin_read()
                .expect("exact import cursor read");
            let cursor = read
                .open_table(lifecycle::BLOB_MAINTENANCE_CURSORS)
                .expect("maintenance cursors")
                .get(class.cursor_key())
                .expect("import cursor lookup")
                .expect("import cursor");
            if referenced {
                assert!(progress.candidates.is_empty());
                assert_eq!(
                    cursor.value(),
                    maintenance_cursor_value(Some(variant.as_bytes()))
                );
            } else {
                assert_eq!(progress.candidates.len(), 1);
                assert!(progress.awaiting_later_handler);
                assert_eq!(cursor.value(), maintenance_cursor_value(None));
            }
        }
    }

    #[test]
    fn blob_maintenance_operation_evidence_obeys_exact_row_and_byte_budgets() {
        let root = BlobTestRoot::new("maintenance-operation-evidence-budget");
        let mut services = blob_services(0x95);
        let store = Store::open_for_mission(&root.database, services.authority)
            .expect("operation evidence store");
        let plaintext = b"operation evidence publication".to_vec();
        let prepared = prepared_blob(&plaintext);
        let (publication, operation, _) = publish_blob(
            &store,
            &mut services,
            &prepared,
            &plaintext,
            1,
            b"maintenance-operation-evidence",
        );
        let exact_bytes = {
            let read = store
                .database
                .begin_read()
                .expect("operation evidence read");
            let operation_value = read
                .open_table(BLOB_OPERATIONS)
                .expect("operations")
                .get(operation.as_bytes())
                .expect("operation lookup")
                .expect("operation row");
            let publication_value = read
                .open_table(BLOB_PUBLICATIONS)
                .expect("publications")
                .get(publication.transfer_id.as_bytes().as_slice())
                .expect("publication lookup")
                .expect("publication row");
            maintenance_entry_bytes(operation.as_bytes(), operation_value.value())
                .expect("operation bytes")
                + maintenance_entry_bytes(
                    publication.transfer_id.as_bytes(),
                    publication_value.value(),
                )
                .expect("publication bytes")
        };
        let class = lifecycle::BlobMaintenanceClass::ExpiredRetirementRecords;
        for budget in [
            BlobMaintenanceBudget::new(1, 1, exact_bytes).expect("one-row-short operation"),
            BlobMaintenanceBudget::new(2, 1, exact_bytes - 1).expect("one-byte-short operation"),
        ] {
            set_maintenance_cursor(&store, class, None);
            let progress = store
                .run_blob_maintenance_turn(budget)
                .expect("partial operation evidence progress");
            assert!(progress.rows_examined <= budget.rows());
            assert!(progress.bytes_examined <= budget.bytes());
            assert_eq!(progress.files_examined, 0);
            assert!(progress.class_has_more_work);
            let read = store.database.begin_read().expect("operation cursor read");
            assert_eq!(
                read.open_table(lifecycle::BLOB_MAINTENANCE_CURSORS)
                    .expect("maintenance cursors")
                    .get(class.cursor_key())
                    .expect("operation cursor lookup")
                    .expect("operation cursor")
                    .value(),
                maintenance_cursor_value(None)
            );
        }

        set_maintenance_cursor(&store, class, None);
        let progress = store
            .run_blob_maintenance_turn(
                BlobMaintenanceBudget::new(2, 1, exact_bytes).expect("exact operation evidence"),
            )
            .expect("exact operation evidence progress");
        assert_eq!(progress.rows_examined, 2);
        assert_eq!(progress.bytes_examined, exact_bytes);
        assert_eq!(progress.files_examined, 0);
        let read = store
            .database
            .begin_read()
            .expect("advanced operation cursor");
        assert_eq!(
            read.open_table(lifecycle::BLOB_MAINTENANCE_CURSORS)
                .expect("maintenance cursors")
                .get(class.cursor_key())
                .expect("operation cursor lookup")
                .expect("operation cursor")
                .value(),
            maintenance_cursor_value(Some(operation.as_bytes()))
        );
    }

    #[test]
    fn blob_maintenance_wrong_kind_carrier_cursor_fails_turn_and_restart() {
        // Break caught: a composite cursor is typed durable state, not merely
        // a tag plus a byte string of the right length.
        for mode in ["turn", "restart"] {
            let root = BlobTestRoot::new(&format!("maintenance-wrong-kind-cursor-{mode}"));
            let services = blob_services(if mode == "turn" { 0x5e } else { 0x5f });
            let store = Store::open_for_mission(&root.database, services.authority)
                .expect("wrong-kind cursor store");
            let mut position = vec![MAINTENANCE_SECONDARY_SOURCE_TAG];
            position.extend_from_slice(&[0x77; 32]);
            position.extend_from_slice(&[0x01; BLOB_CARRIER_OBJECT_ID_BYTES]);
            set_maintenance_cursor(
                &store,
                lifecycle::BlobMaintenanceClass::InvalidPendingWork,
                Some(&position),
            );
            let before = blob_current_admission_digest(&store);
            if mode == "turn" {
                assert_blob_schema_invariant(
                    &store
                        .run_blob_maintenance_turn(maintenance_budget(1))
                        .expect_err("wrong-kind cursor fails the turn"),
                );
                assert_eq!(blob_current_admission_digest(&store), before);
            } else {
                drop(store);
                match Store::open_for_mission(&root.database, services.authority) {
                    Ok(_) => panic!("wrong-kind cursor passed startup audit"),
                    Err(error) => assert_blob_schema_invariant(&error),
                }
            }
        }
    }

    #[test]
    fn blob_maintenance_malformed_cursors_and_impossible_accounting_fail_closed() {
        // Break caught: damaged durable progress or impossible lifecycle
        // counters must not silently restart scheduling at class one.
        for (label, corrupt) in [("class", 0u8), ("key", 1u8), ("accounting", 2u8)] {
            let root = BlobTestRoot::new(&format!("maintenance-corrupt-{label}"));
            let services = blob_services(0x60 + corrupt);
            let store = Store::open_for_mission(&root.database, services.authority)
                .expect("maintenance corruption store");
            let write = store
                .database
                .begin_write()
                .expect("maintenance corruption transaction");
            match corrupt {
                0 => {
                    write
                        .open_table(lifecycle::BLOB_MAINTENANCE_CURSORS)
                        .expect("maintenance cursors")
                        .insert(0, [1, 7].as_slice())
                        .expect("corrupt next class");
                }
                1 => {
                    let mut cursors = write
                        .open_table(lifecycle::BLOB_MAINTENANCE_CURSORS)
                        .expect("maintenance cursors");
                    cursors
                        .insert(0, [1, 3].as_slice())
                        .expect("select staging class");
                    cursors
                        .insert(3, [1, 1, 0].as_slice())
                        .expect("corrupt staging cursor key");
                }
                2 => {
                    write
                        .open_table(lifecycle::BLOB_LIFECYCLE_METADATA)
                        .expect("lifecycle metadata")
                        .insert("publication_rows", 1)
                        .expect("corrupt publication accounting");
                }
                _ => unreachable!(),
            }
            write.commit().expect("commit maintenance corruption");
            let before = blob_current_admission_digest(&store);
            assert_blob_schema_invariant(
                &store
                    .run_blob_maintenance_turn(maintenance_budget(1))
                    .expect_err("maintenance corruption fails closed"),
            );
            assert_eq!(blob_current_admission_digest(&store), before);
        }
    }

    #[test]
    fn blob_maintenance_destructive_candidates_remain_revisitable_without_mutation() {
        // Break caught: discovery must not acknowledge or remove destructive
        // work before the later retention/deletion handlers exist.
        let root = BlobTestRoot::new("maintenance-nondestructive");
        let source_root = BlobTestRoot::new("maintenance-nondestructive-source");
        let mut services = blob_services(0x6a);
        let store = Store::open_for_mission(&root.database, services.authority)
            .expect("non-destructive maintenance store");
        let source = Store::open_for_mission(&source_root.database, services.authority)
            .expect("non-destructive maintenance source");
        let published_plaintext = vec![0x31; SELECTED_BLOB_CHUNK_SIZE as usize + 17];
        let prepared = prepared_blob(&published_plaintext);
        publish_blob(
            &store,
            &mut services,
            &prepared,
            &published_plaintext,
            1,
            b"maintenance-nondestructive-operation",
        );
        publish_blob(
            &source,
            &mut services,
            &prepared,
            &published_plaintext,
            1,
            b"maintenance-nondestructive-source-operation",
        );
        stage_pending_source_for_maintenance(
            &source,
            &store,
            &mut services,
            &vec![0x42; SELECTED_BLOB_CHUNK_SIZE as usize + 23],
            1,
            true,
        );
        let staging_variant = install_unreferenced_variant(
            &store,
            &services,
            b"unreferenced local staging",
            1,
            false,
        );
        let completed_variant = install_unreferenced_variant(
            &store,
            &services,
            b"unreferenced completed variant",
            1,
            true,
        );
        let before_rows = {
            let read = store
                .database
                .begin_read()
                .expect("maintenance before image");
            blob_database_digest_read(&read)
        };
        let before_files = depot_file_snapshot(&root.depot());
        let budget = maintenance_budget(64);
        let mut staging_candidates = Vec::new();
        let mut completed_candidates = Vec::new();
        for _ in 0..12 {
            let progress = store
                .run_blob_maintenance_turn(budget)
                .expect("non-destructive maintenance turn");
            assert_eq!(progress.files_examined, 0);
            if progress.class == lifecycle::BlobMaintenanceClass::UnreferencedLocalImportStaging {
                assert!(progress.awaiting_later_handler);
                staging_candidates.push(progress.candidates.clone());
            }
            if progress.class == lifecycle::BlobMaintenanceClass::UnreferencedCompletedVariants {
                assert!(progress.awaiting_later_handler);
                completed_candidates.push(progress.candidates.clone());
            }
        }
        assert_eq!(staging_candidates.len(), 2);
        assert_eq!(staging_candidates[0], staging_candidates[1]);
        assert!(staging_candidates[0].contains(
            &lifecycle::BlobMaintenanceCandidate::UnreferencedLocalImport { staging_variant }
        ));
        assert_eq!(completed_candidates.len(), 2);
        assert_eq!(completed_candidates[0], completed_candidates[1]);
        assert!(completed_candidates[0].contains(
            &lifecycle::BlobMaintenanceCandidate::UnreferencedCompletedVariant {
                variant: completed_variant,
            }
        ));
        let after_rows = {
            let read = store
                .database
                .begin_read()
                .expect("maintenance after image");
            blob_database_digest_read(&read)
        };
        assert_eq!(after_rows, before_rows);
        assert_eq!(depot_file_snapshot(&root.depot()), before_files);
    }

    #[test]
    fn blob_maintenance_structural_contradiction_fails_before_cursor_advance() {
        // Break caught: maintenance must preserve contradictory evidence and
        // leave both class and per-class progress at the failing position.
        let root = BlobTestRoot::new("maintenance-structural-contradiction");
        let mut services = blob_services(0x72);
        let store = Store::open_for_mission(&root.database, services.authority)
            .expect("maintenance contradiction store");
        let plaintext = b"maintenance contradiction publication".to_vec();
        let prepared = prepared_blob(&plaintext);
        let (stored, _, _) = publish_blob(
            &store,
            &mut services,
            &prepared,
            &plaintext,
            1,
            b"maintenance-contradiction-operation",
        );
        {
            let write = store
                .database
                .begin_write()
                .expect("contradict maintenance authority");
            let mut key = Vec::with_capacity(65);
            key.extend_from_slice(stored.variant_id.as_bytes());
            key.push(1);
            key.extend_from_slice(stored.transfer_id.as_bytes());
            write
                .open_table(lifecycle::BLOB_VARIANT_REFERENCES)
                .expect("variant references")
                .remove(key.as_slice())
                .expect("remove publication reference")
                .expect("publication reference exists");
            write
                .open_table(lifecycle::BLOB_LIFECYCLE_METADATA)
                .expect("lifecycle metadata")
                .insert("reference_rows", 0)
                .expect("adjust reference accounting");
            write.commit().expect("commit maintenance contradiction");
        }
        set_maintenance_next_class(
            &store,
            lifecycle::BlobMaintenanceClass::ExpiredPublicationsAndPendingSources,
        );
        let before = blob_current_admission_digest(&store);
        assert_blob_schema_invariant(
            &store
                .run_blob_maintenance_turn(maintenance_budget(4))
                .expect_err("structural contradiction fails maintenance"),
        );
        assert_eq!(blob_current_admission_digest(&store), before);
    }
}
