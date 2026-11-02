use std::cmp::Ordering;
use std::collections::{BTreeMap, BTreeSet};

use aster_mesh::{BlobId, Priority, Scope, Topic};
use redb::{
    Key, MultimapTableHandle, ReadableTable, ReadableTableMetadata, TableDefinition, TableHandle,
    TypeName, Value,
};
use sha2::{Digest, Sha256};

use super::{
    BlobSemanticId, BlobStoreError, BlobTransferId, BlobVariantId, StoreError, blob_error,
};

const PRESSURE_RECORD_VERSION: u8 = 2;
const PRESSURE_CANDIDATE_COMPLETED: u8 = 1;
const PRESSURE_EXPIRY_EXPIRED_FINITE: u8 = 0;
const PRESSURE_EXPIRY_FINITE: u8 = 1;
const PRESSURE_EXPIRY_DURABLE: u8 = 2;
// Current writable stores use v5 expiry aggregates and durable-only indexes;
// v2-v4 remain byte-exact read-only/migration inputs.
const ACTIVE_PRESSURE_SCHEMA_VERSION: u64 = 5;
const PRESSURE_V4_SCHEMA_VERSION: u64 = 4;
const PRESSURE_SCHEMA_VERSION: u64 = 5;
pub(crate) const PREVIOUS_PRESSURE_SCHEMA_VERSION: u64 = 3;
pub(crate) const PRESSURE_SCHEMA_VERSION_FIELD: &str = "schema_version";
pub(super) const NEXT_PENDING_ACCEPTANCE_ORDER: &str = "next_pending_acceptance_order";
const REANCHOR_TARGET_GENERATION: &str = "reanchor_target_generation";
const REANCHOR_DIRTY: &str = "reanchor_dirty";
const REANCHOR_NEXT_PHASE: &str = "reanchor_next_phase";
const PRESSURE_CONTENT_DOMAIN: &[u8] = b"aster/blob-pressure-content/v1";

const fn pressure_v5_metadata_fields() -> [&'static str; 5] {
    [
        PRESSURE_SCHEMA_VERSION_FIELD,
        NEXT_PENDING_ACCEPTANCE_ORDER,
        REANCHOR_TARGET_GENERATION,
        REANCHOR_DIRTY,
        REANCHOR_NEXT_PHASE,
    ]
}

/// Fixed-width canonical identity for one per-content pressure partition.
///
/// The digest is an ordered lookup accelerator only. Candidate selection must
/// also compare the padded canonical topic/scope/Blob identity retained here.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct PressureContentIdentity {
    digest: [u8; 32],
    topic_len: u8,
    topic: [u8; aster_profile::MAX_TOPIC_BYTES],
    scope_len: u8,
    scope: [u8; aster_profile::MAX_SCOPE_BYTES],
    blob_id: [u8; 32],
}

impl PressureContentIdentity {
    pub fn new(topic: &Topic, scope: &Scope, blob_id: BlobId) -> Result<Self, StoreError> {
        let topic_bytes = topic.as_str().as_bytes();
        let scope_bytes = scope.as_str().as_bytes();
        let topic_len = u8::try_from(topic_bytes.len())
            .map_err(|_| pressure_corruption("Blob pressure topic length overflows"))?;
        let scope_len = u8::try_from(scope_bytes.len())
            .map_err(|_| pressure_corruption("Blob pressure scope length overflows"))?;
        let mut topic_fixed = [0; aster_profile::MAX_TOPIC_BYTES];
        topic_fixed[..topic_bytes.len()].copy_from_slice(topic_bytes);
        let mut scope_fixed = [0; aster_profile::MAX_SCOPE_BYTES];
        scope_fixed[..scope_bytes.len()].copy_from_slice(scope_bytes);
        let canonical = pressure_content_identity(topic, scope, blob_id)?;
        let mut digest = Sha256::new();
        digest.update(PRESSURE_CONTENT_DOMAIN);
        digest.update(&canonical);
        Ok(Self {
            digest: digest.finalize().into(),
            topic_len,
            topic: topic_fixed,
            scope_len,
            scope: scope_fixed,
            blob_id: *blob_id.as_bytes(),
        })
    }

    pub const fn digest(self) -> [u8; 32] {
        self.digest
    }

    pub fn matches(&self, topic: &Topic, scope: &Scope, blob_id: BlobId) -> bool {
        let topic_bytes = topic.as_str().as_bytes();
        let scope_bytes = scope.as_str().as_bytes();
        usize::from(self.topic_len) == topic_bytes.len()
            && self.topic[..topic_bytes.len()] == *topic_bytes
            && usize::from(self.scope_len) == scope_bytes.len()
            && self.scope[..scope_bytes.len()] == *scope_bytes
            && self.blob_id == *blob_id.as_bytes()
    }

    fn index_prefix(self) -> Result<Vec<u8>, StoreError> {
        let topic_len = usize::from(self.topic_len);
        let scope_len = usize::from(self.scope_len);
        if topic_len == 0
            || scope_len == 0
            || topic_len > self.topic.len()
            || scope_len > self.scope.len()
            || self.topic[topic_len..].iter().any(|byte| *byte != 0)
            || self.scope[scope_len..].iter().any(|byte| *byte != 0)
        {
            return Err(pressure_corruption(
                "Blob pressure content lookup identity is not canonical",
            ));
        }
        let mut canonical = Vec::with_capacity(4 + topic_len + scope_len + 32);
        canonical.extend_from_slice(
            &u16::try_from(topic_len)
                .map_err(|_| pressure_corruption("Blob pressure topic length overflows"))?
                .to_be_bytes(),
        );
        canonical.extend_from_slice(&self.topic[..topic_len]);
        canonical.extend_from_slice(
            &u16::try_from(scope_len)
                .map_err(|_| pressure_corruption("Blob pressure scope length overflows"))?
                .to_be_bytes(),
        );
        canonical.extend_from_slice(&self.scope[..scope_len]);
        canonical.extend_from_slice(&self.blob_id);
        let mut digest = Sha256::new();
        digest.update(PRESSURE_CONTENT_DOMAIN);
        digest.update(&canonical);
        if <[u8; 32]>::from(digest.finalize()) != self.digest {
            return Err(pressure_corruption(
                "Blob pressure content lookup digest is contradictory",
            ));
        }
        let mut prefix = Vec::with_capacity(1 + 32 + canonical.len());
        prefix.push(PRESSURE_RECORD_VERSION);
        prefix.extend_from_slice(&self.digest);
        prefix.extend_from_slice(&canonical);
        Ok(prefix)
    }
}

/// Exact durable resource partition rejected by one Blob admission attempt.
#[expect(
    clippy::large_enum_variant,
    reason = "bounded recovery demand intentionally remains fixed-size and Copy"
)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum BlobCapacityPartition {
    AggregateItems,
    AggregateBytes,
    ContentPublications(PressureContentIdentity),
    NetworkStagingRows,
    NetworkStagingBytes,
    DepotBytes,
    DepotChunks,
    DepotVariants,
    Operation,
    PublicationLifecycle,
}

/// Fixed-size store-owned pressure input derived from the first typed capacity
/// rejection. A zero deficit is never a capacity rejection.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct BlobCapacityRecoveryDemand {
    partition: BlobCapacityPartition,
    incoming_priority: Priority,
    deficit: u64,
}

impl BlobCapacityRecoveryDemand {
    pub const fn new(
        partition: BlobCapacityPartition,
        incoming_priority: Priority,
        deficit: u64,
    ) -> Result<Self, BlobStoreError> {
        if deficit == 0 {
            return Err(BlobStoreError::InvalidMaintenanceBudget);
        }
        Ok(Self {
            partition,
            incoming_priority,
            deficit,
        })
    }

    pub const fn partition(self) -> BlobCapacityPartition {
        self.partition
    }

    pub const fn incoming_priority(self) -> Priority {
        self.incoming_priority
    }

    pub const fn deficit(self) -> u64 {
        self.deficit
    }
}

/// Fixed-size verified admission context needed where an existing public
/// capacity error deliberately omits request-specific physical unit counts.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct BlobCapacityRecoveryContext {
    incoming_priority: Priority,
    content: Option<PressureContentIdentity>,
    depot_chunks: u64,
    depot_variants: u64,
}

/// Independent bounds for one pressure-selection and atomic-retirement
/// attempt. The root/operation/manifest dimensions prevent a small row from
/// hiding an unbounded semantic work unit.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct BlobPressureRecoveryBudget {
    pub(crate) rows: u64,
    pub(crate) bytes: u64,
    pub(crate) roots: u64,
    pub(crate) operations: u64,
    pub(crate) deletion_manifests: u64,
}

impl BlobPressureRecoveryBudget {
    pub const fn new(
        rows: u64,
        bytes: u64,
        roots: u64,
        operations: u64,
        deletion_manifests: u64,
    ) -> Result<Self, BlobStoreError> {
        if rows == 0 || bytes == 0 {
            return Err(BlobStoreError::InvalidMaintenanceBudget);
        }
        Ok(Self {
            rows,
            bytes,
            roots,
            operations,
            deletion_manifests,
        })
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum PressureCandidate {
    Publication(BlobTransferId),
    PendingSource(BlobTransferId),
    Variant(BlobVariantId),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum PressureSelectionEligibility {
    AllVisible,
    DurableOnly,
}

impl PressureSelectionEligibility {
    const fn admits(self, expiry: PressureExpiry) -> bool {
        matches!(self, Self::AllVisible) || matches!(expiry, PressureExpiry::Durable)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct PressureSelection {
    candidate: Option<PressureCandidate>,
    rows_examined: u64,
    bytes_examined: u64,
    proven: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct BlobPressurePhysicalCandidate {
    variant: BlobVariantId,
    partition: BlobCapacityPartition,
    deficit: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct BlobPressurePhysicalRecoveryReceipt {
    variant: BlobVariantId,
    partition: BlobCapacityPartition,
    baseline: u64,
    deficit: u64,
    budget_rows: u64,
    budget_files: u64,
    budget_bytes: u64,
    consumed_rows: u64,
    consumed_bytes: u64,
}

impl BlobPressurePhysicalRecoveryReceipt {
    pub(crate) const fn variant(self) -> BlobVariantId {
        self.variant
    }

    pub(crate) const fn partition(self) -> BlobCapacityPartition {
        self.partition
    }

    pub(crate) const fn baseline(self) -> u64 {
        self.baseline
    }

    pub(crate) const fn deficit(self) -> u64 {
        self.deficit
    }

    pub(crate) const fn remaining_rows(self) -> u64 {
        self.budget_rows - self.consumed_rows
    }

    pub(crate) const fn remaining_files(self) -> u64 {
        self.budget_files
    }

    pub(crate) const fn remaining_bytes(self) -> u64 {
        self.budget_bytes - self.consumed_bytes
    }
}

/// Bounded store-owned outcome of one pressure attempt.
#[derive(Clone, Debug, Eq, PartialEq)]
#[doc(hidden)]
pub struct BlobCapacityRecoveryResult {
    evicted_transfer_ids: Vec<BlobTransferId>,
    recovered_units: u64,
    deficit_met: bool,
    rows_examined: u64,
    bytes_examined: u64,
    physical_candidate: Option<BlobPressurePhysicalCandidate>,
    physical_receipt: Option<BlobPressurePhysicalRecoveryReceipt>,
}

impl BlobCapacityRecoveryResult {
    pub(crate) const fn empty(rows_examined: u64, bytes_examined: u64) -> Self {
        Self {
            evicted_transfer_ids: Vec::new(),
            recovered_units: 0,
            deficit_met: false,
            rows_examined,
            bytes_examined,
            physical_candidate: None,
            physical_receipt: None,
        }
    }

    pub(crate) fn recovered(
        evicted_transfer_ids: Vec<BlobTransferId>,
        recovered_units: u64,
        deficit: u64,
        rows_examined: u64,
        bytes_examined: u64,
    ) -> Self {
        Self {
            evicted_transfer_ids,
            recovered_units,
            deficit_met: recovered_units >= deficit,
            rows_examined,
            bytes_examined,
            physical_candidate: None,
            physical_receipt: None,
        }
    }

    pub(crate) fn recovered_with_physical_candidate(
        evicted_transfer_ids: Vec<BlobTransferId>,
        recovered_units: u64,
        demand: BlobCapacityRecoveryDemand,
        rows_examined: u64,
        bytes_examined: u64,
        variant: BlobVariantId,
    ) -> Self {
        let mut result = Self::recovered(
            evicted_transfer_ids,
            recovered_units,
            demand.deficit(),
            rows_examined,
            bytes_examined,
        );
        if !result.deficit_met {
            result.physical_candidate = Some(BlobPressurePhysicalCandidate {
                variant,
                partition: demand.partition(),
                deficit: demand.deficit(),
            });
        }
        result
    }

    pub fn evicted_transfer_ids(&self) -> &[BlobTransferId] {
        &self.evicted_transfer_ids
    }

    pub(crate) const fn recovered_units(&self) -> u64 {
        self.recovered_units
    }

    pub const fn deficit_met(&self) -> bool {
        self.deficit_met
    }

    pub(crate) const fn rows_examined(&self) -> u64 {
        self.rows_examined
    }

    pub(crate) const fn bytes_examined(&self) -> u64 {
        self.bytes_examined
    }

    pub(crate) fn bind_physical_recovery(
        mut self,
        baseline: u64,
        budget: super::BlobMaintenanceBudget,
    ) -> Self {
        let Some(candidate) = self.physical_candidate.take() else {
            return self;
        };
        if self.rows_examined >= budget.rows() || self.bytes_examined >= budget.bytes() {
            return self;
        }
        self.physical_receipt = Some(BlobPressurePhysicalRecoveryReceipt {
            variant: candidate.variant,
            partition: candidate.partition,
            baseline,
            deficit: candidate.deficit,
            budget_rows: budget.rows(),
            budget_files: budget.files(),
            budget_bytes: budget.bytes(),
            consumed_rows: self.rows_examined,
            consumed_bytes: self.bytes_examined,
        });
        self
    }

    pub(crate) fn take_physical_recovery_receipt(
        &mut self,
    ) -> Option<BlobPressurePhysicalRecoveryReceipt> {
        self.physical_receipt.take()
    }

    pub(crate) fn with_physical_recovery(
        self,
        recovered_units: u64,
        deficit: u64,
        progress: super::BlobCapacityGcProgress,
    ) -> Result<Self, StoreError> {
        let deficit_met = recovered_units >= deficit;
        Ok(Self {
            evicted_transfer_ids: self.evicted_transfer_ids,
            recovered_units,
            deficit_met,
            rows_examined: self
                .rows_examined
                .checked_add(progress.rows_examined)
                .ok_or(StoreError::ItemCountAccountingOverflow)?,
            bytes_examined: self
                .bytes_examined
                .checked_add(progress.bytes_examined)
                .ok_or(StoreError::PayloadByteAccountingOverflow)?,
            physical_candidate: if deficit_met {
                None
            } else {
                self.physical_candidate
            },
            physical_receipt: None,
        })
    }
}

impl PressureSelection {
    pub(crate) const fn candidate(self) -> Option<PressureCandidate> {
        self.candidate
    }

    pub(crate) const fn rows_examined(self) -> u64 {
        self.rows_examined
    }

    pub(crate) const fn bytes_examined(self) -> u64 {
        self.bytes_examined
    }

    pub(crate) const fn proven(self) -> bool {
        self.proven
    }
}

struct PressureSelectionCharge {
    budget: BlobPressureRecoveryBudget,
    rows: u64,
    bytes: u64,
    roots: u64,
}

impl PressureSelectionCharge {
    const fn new(budget: BlobPressureRecoveryBudget) -> Self {
        Self {
            budget,
            rows: 0,
            bytes: 0,
            roots: 0,
        }
    }

    fn charge(&mut self, key_len: usize, value_len: usize, root: bool) -> Result<bool, StoreError> {
        let row_bytes = key_len
            .checked_add(value_len)
            .and_then(|value| u64::try_from(value).ok())
            .ok_or(StoreError::PayloadByteAccountingOverflow)?;
        let rows = self
            .rows
            .checked_add(1)
            .ok_or(StoreError::ItemCountAccountingOverflow)?;
        let bytes = self
            .bytes
            .checked_add(row_bytes)
            .ok_or(StoreError::PayloadByteAccountingOverflow)?;
        let roots = self
            .roots
            .checked_add(u64::from(root))
            .ok_or(StoreError::ItemCountAccountingOverflow)?;
        if rows > self.budget.rows || bytes > self.budget.bytes || roots > self.budget.roots {
            return Ok(false);
        }
        self.rows = rows;
        self.bytes = bytes;
        self.roots = roots;
        Ok(true)
    }

    const fn finish(self, candidate: Option<PressureCandidate>, proven: bool) -> PressureSelection {
        PressureSelection {
            candidate,
            rows_examined: self.rows,
            bytes_examined: self.bytes,
            proven,
        }
    }
}

impl BlobCapacityRecoveryContext {
    pub const fn new(incoming_priority: Priority) -> Self {
        Self {
            incoming_priority,
            content: None,
            depot_chunks: 1,
            depot_variants: 1,
        }
    }

    pub const fn with_content(mut self, content: PressureContentIdentity) -> Self {
        self.content = Some(content);
        self
    }

    pub const fn with_depot_units(mut self, chunks: u64, variants: u64) -> Self {
        self.depot_chunks = chunks;
        self.depot_variants = variants;
        self
    }
}

fn exact_deficit(current: u64, incoming: u64, limit: u64) -> Result<u64, StoreError> {
    let required = current
        .checked_add(incoming)
        .ok_or(StoreError::PayloadByteAccountingOverflow)?;
    required
        .checked_sub(limit)
        .filter(|deficit| *deficit != 0)
        .ok_or_else(|| {
            pressure_corruption("Blob capacity error does not describe an exceeded partition")
        })
}

/// Maps only the first typed Blob admission rejection to its exact pressure
/// partition. Security and causal limits deliberately return `None`.
pub(crate) fn capacity_recovery_demand(
    error: &StoreError,
    context: BlobCapacityRecoveryContext,
) -> Result<Option<BlobCapacityRecoveryDemand>, StoreError> {
    let (partition, deficit) = match error {
        StoreError::ItemLimitExceeded { current, limit } => (
            BlobCapacityPartition::AggregateItems,
            exact_deficit(*current, 1, *limit)?,
        ),
        StoreError::PayloadByteLimitExceeded {
            current,
            incoming,
            limit,
        } => (
            BlobCapacityPartition::AggregateBytes,
            exact_deficit(*current, *incoming, *limit)?,
        ),
        StoreError::Blob(BlobStoreError::PublicationLimitExceeded { current, limit }) => {
            let identity = context.content.ok_or_else(|| {
                pressure_corruption("Blob per-content capacity failure lacks exact identity")
            })?;
            (
                BlobCapacityPartition::ContentPublications(identity),
                exact_deficit(
                    u64::try_from(*current).map_err(|_| StoreError::ItemCountAccountingOverflow)?,
                    1,
                    u64::try_from(*limit).map_err(|_| StoreError::ItemCountAccountingOverflow)?,
                )?,
            )
        }
        StoreError::Blob(BlobStoreError::NetworkStagingRowLimitExceeded {
            current,
            incoming,
            limit,
        }) => (
            BlobCapacityPartition::NetworkStagingRows,
            exact_deficit(*current, *incoming, *limit)?,
        ),
        StoreError::Blob(BlobStoreError::NetworkStagingByteLimitExceeded {
            current,
            incoming,
            limit,
        }) => (
            BlobCapacityPartition::NetworkStagingBytes,
            exact_deficit(*current, *incoming, *limit)?,
        ),
        StoreError::Blob(BlobStoreError::DepotByteLimitExceeded {
            current,
            incoming,
            limit,
        }) => (
            BlobCapacityPartition::DepotBytes,
            exact_deficit(*current, *incoming, *limit)?,
        ),
        StoreError::Blob(BlobStoreError::DepotChunkLimitExceeded { current, limit }) => (
            BlobCapacityPartition::DepotChunks,
            exact_deficit(*current, context.depot_chunks, *limit)?,
        ),
        StoreError::Blob(BlobStoreError::DepotVariantLimitExceeded { current, limit }) => (
            BlobCapacityPartition::DepotVariants,
            exact_deficit(*current, context.depot_variants, *limit)?,
        ),
        StoreError::Blob(BlobStoreError::OperationLimitExceeded { current, limit }) => (
            BlobCapacityPartition::Operation,
            exact_deficit(*current, 1, *limit)?,
        ),
        StoreError::Blob(BlobStoreError::OperationByteLimitExceeded {
            current,
            incoming,
            limit,
        }) => (
            BlobCapacityPartition::Operation,
            exact_deficit(*current, *incoming, *limit)?,
        ),
        StoreError::Blob(BlobStoreError::PublicationLifecycleCapacity {
            required_rows,
            max_rows,
        }) => (
            BlobCapacityPartition::PublicationLifecycle,
            required_rows
                .checked_sub(*max_rows)
                .filter(|deficit| *deficit != 0)
                .ok_or_else(|| {
                    pressure_corruption("Blob lifecycle capacity error is not over limit")
                })?,
        ),
        StoreError::Blob(
            BlobStoreError::CausalFrontierLimitExceeded { .. }
            | BlobStoreError::LineageFenceCapacity { .. }
            | BlobStoreError::ReplayFenceCapacity { .. }
            | BlobStoreError::LeaseCapacity,
        ) => return Ok(None),
        _ => return Ok(None),
    };
    BlobCapacityRecoveryDemand::new(partition, context.incoming_priority, deficit)
        .map(Some)
        .map_err(blob_error)
}

pub(crate) const BLOB_PRESSURE_METADATA: TableDefinition<&str, u64> =
    TableDefinition::new("aster.blob-pressure-metadata.v1");
pub(crate) const BLOB_PRESSURE_PUBLICATION_ROOTS: TableDefinition<&[u8], &[u8]> =
    TableDefinition::new("aster.blob-pressure-publication-roots.v1");
pub(crate) const BLOB_PRESSURE_PENDING_ROOTS: TableDefinition<&[u8], &[u8]> =
    TableDefinition::new("aster.blob-pressure-pending-roots.v1");
pub(crate) const BLOB_PRESSURE_VARIANT_SUMMARIES: TableDefinition<&[u8], &[u8]> =
    TableDefinition::new("aster.blob-pressure-variant-summaries.v1");
pub(crate) const BLOB_PRESSURE_PUBLICATIONS: TableDefinition<&[u8], &[u8]> =
    TableDefinition::new("aster.blob-pressure-publications.v1");
pub(crate) const BLOB_PRESSURE_CONTENT_PUBLICATIONS: TableDefinition<&[u8], &[u8]> =
    TableDefinition::new("aster.blob-pressure-content-publications.v1");
pub(crate) const BLOB_PRESSURE_PENDING_SOURCES: TableDefinition<PressurePendingIndexKey, &[u8]> =
    TableDefinition::new("aster.blob-pressure-pending-sources.v1");
pub(crate) const BLOB_PRESSURE_VARIANTS: TableDefinition<PressureVariantIndexKey, &[u8]> =
    TableDefinition::new("aster.blob-pressure-variants.v1");
pub(crate) const BLOB_PRESSURE_DURABLE_PUBLICATIONS: TableDefinition<&[u8], &[u8]> =
    TableDefinition::new("aster.blob-pressure-durable-publications.v1");
pub(crate) const BLOB_PRESSURE_DURABLE_CONTENT_PUBLICATIONS: TableDefinition<&[u8], &[u8]> =
    TableDefinition::new("aster.blob-pressure-durable-content-publications.v1");
pub(crate) const BLOB_PRESSURE_DURABLE_PENDING_SOURCES: TableDefinition<
    PressurePendingIndexKey,
    &[u8],
> = TableDefinition::new("aster.blob-pressure-durable-pending-sources.v1");
pub(crate) const BLOB_PRESSURE_DURABLE_VARIANTS: TableDefinition<PressureVariantIndexKey, &[u8]> =
    TableDefinition::new("aster.blob-pressure-durable-variants.v1");
pub(crate) const BLOB_PRESSURE_REANCHOR_CURSORS: TableDefinition<u8, &[u8]> =
    TableDefinition::new("aster.blob-pressure-reanchor-cursors.v1");

const PRESSURE_REANCHOR_CURSOR_VERSION: u8 = 1;
const PRESSURE_REANCHOR_EMPTY_COMPLETE_TAG: u8 = 0;
const PRESSURE_REANCHOR_ACTIVE_TAG: u8 = 1;
const PRESSURE_REANCHOR_COMPLETE_TAG: u8 = 2;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum PressureReanchorCursor {
    EmptyComplete,
    Active {
        end_transfer: BlobTransferId,
        position: Option<BlobTransferId>,
    },
    Complete {
        end_transfer: BlobTransferId,
    },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum PressureReanchorRoot {
    Publication,
    Pending,
}

impl PressureReanchorRoot {
    const fn phase(self) -> u64 {
        match self {
            Self::Publication => 1,
            Self::Pending => 2,
        }
    }

    const fn cursor_key(self) -> u8 {
        self.phase() as u8
    }

    const fn next_phase(self) -> u64 {
        match self {
            Self::Publication => 2,
            Self::Pending => 1,
        }
    }

    fn decode(phase: u64) -> Result<Self, StoreError> {
        match phase {
            1 => Ok(Self::Publication),
            2 => Ok(Self::Pending),
            _ => Err(pressure_corruption(
                "Blob pressure reanchor phase is invalid",
            )),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct PressureReanchorTurn {
    pub(crate) root: PressureReanchorRoot,
    pub(crate) transfer: Option<BlobTransferId>,
    next_cursor: PressureReanchorCursor,
}

fn encode_reanchor_cursor(cursor: PressureReanchorCursor) -> Vec<u8> {
    let mut encoded = Vec::with_capacity(67);
    encoded.push(PRESSURE_REANCHOR_CURSOR_VERSION);
    match cursor {
        PressureReanchorCursor::EmptyComplete => {
            encoded.push(PRESSURE_REANCHOR_EMPTY_COMPLETE_TAG);
        }
        PressureReanchorCursor::Active {
            end_transfer,
            position,
        } => {
            encoded.push(PRESSURE_REANCHOR_ACTIVE_TAG);
            encoded.extend_from_slice(end_transfer.as_bytes());
            if let Some(position) = position {
                encoded.push(1);
                encoded.extend_from_slice(position.as_bytes());
            } else {
                encoded.push(0);
            }
        }
        PressureReanchorCursor::Complete { end_transfer } => {
            encoded.push(PRESSURE_REANCHOR_COMPLETE_TAG);
            encoded.extend_from_slice(end_transfer.as_bytes());
        }
    }
    encoded
}

fn decode_reanchor_cursor(bytes: &[u8]) -> Result<PressureReanchorCursor, StoreError> {
    if bytes.first().copied() != Some(PRESSURE_REANCHOR_CURSOR_VERSION) {
        return Err(pressure_corruption(
            "Blob pressure reanchor cursor has an unknown version",
        ));
    }
    match bytes {
        [
            PRESSURE_REANCHOR_CURSOR_VERSION,
            PRESSURE_REANCHOR_EMPTY_COMPLETE_TAG,
        ] => Ok(PressureReanchorCursor::EmptyComplete),
        [
            PRESSURE_REANCHOR_CURSOR_VERSION,
            PRESSURE_REANCHOR_ACTIVE_TAG,
            end @ ..,
        ] if end.len() == 33 && end[32] == 0 => Ok(PressureReanchorCursor::Active {
            end_transfer: BlobTransferId::new(end[..32].try_into().expect("fixed transfer")),
            position: None,
        }),
        [
            PRESSURE_REANCHOR_CURSOR_VERSION,
            PRESSURE_REANCHOR_ACTIVE_TAG,
            body @ ..,
        ] if body.len() == 65 && body[32] == 1 => {
            let end_transfer = BlobTransferId::new(body[..32].try_into().expect("fixed transfer"));
            let position = BlobTransferId::new(body[33..].try_into().expect("fixed transfer"));
            if position.as_bytes() > end_transfer.as_bytes() {
                return Err(pressure_corruption(
                    "Blob pressure reanchor cursor exceeds its captured end fence",
                ));
            }
            Ok(PressureReanchorCursor::Active {
                end_transfer,
                position: Some(position),
            })
        }
        [
            PRESSURE_REANCHOR_CURSOR_VERSION,
            PRESSURE_REANCHOR_COMPLETE_TAG,
            end @ ..,
        ] if end.len() == 32 => Ok(PressureReanchorCursor::Complete {
            end_transfer: BlobTransferId::new(end.try_into().expect("fixed transfer")),
        }),
        _ => Err(pressure_corruption(
            "Blob pressure reanchor cursor is not canonical",
        )),
    }
}

fn reanchor_fence_write(
    write: &redb::WriteTransaction,
    root: PressureReanchorRoot,
) -> Result<PressureReanchorCursor, StoreError> {
    let last = match root {
        PressureReanchorRoot::Publication => write
            .open_table(BLOB_PRESSURE_PUBLICATION_ROOTS)?
            .iter()?
            .next_back()
            .transpose()?
            .map(|(key, _)| key.value().to_vec()),
        PressureReanchorRoot::Pending => write
            .open_table(BLOB_PRESSURE_PENDING_ROOTS)?
            .iter()?
            .next_back()
            .transpose()?
            .map(|(key, _)| key.value().to_vec()),
    };
    last.map_or(Ok(PressureReanchorCursor::EmptyComplete), |key| {
        let transfer = BlobTransferId::new(key.as_slice().try_into().map_err(|_| {
            pressure_corruption("Blob pressure root key is not a transfer identifier")
        })?);
        Ok(PressureReanchorCursor::Active {
            end_transfer: transfer,
            position: None,
        })
    })
}

/// Restarts the persisted fenced reanchor pass whenever custody continuity
/// advances to a new generation. Roots admitted after these fences are
/// required to be target-normalized by their ordinary mutation transaction.
pub(crate) fn synchronize_reanchor_state_write(
    write: &redb::WriteTransaction,
) -> Result<(), StoreError> {
    let metadata = write.open_table(BLOB_PRESSURE_METADATA)?;
    let version = metadata
        .get(PRESSURE_SCHEMA_VERSION_FIELD)?
        .map(|value| value.value())
        .ok_or_else(|| pressure_corruption("Blob pressure schema version is missing"))?;
    if version != PRESSURE_SCHEMA_VERSION {
        return Ok(());
    }
    let target = metadata
        .get(REANCHOR_TARGET_GENERATION)?
        .map(|value| value.value())
        .ok_or_else(|| pressure_corruption("Blob pressure reanchor target is missing"))?;
    drop(metadata);
    let current = crate::custody::lower_bound_continuity_write(write)?
        .map_or(0, |continuity| continuity.generation);
    if target == current {
        return Ok(());
    }

    let live = reanchor_fence_write(write, PressureReanchorRoot::Publication)?;
    let pending = reanchor_fence_write(write, PressureReanchorRoot::Pending)?;
    let dirty = !matches!(live, PressureReanchorCursor::EmptyComplete)
        || !matches!(pending, PressureReanchorCursor::EmptyComplete);
    {
        let mut metadata = write.open_table(BLOB_PRESSURE_METADATA)?;
        metadata.insert(REANCHOR_TARGET_GENERATION, current)?;
        metadata.insert(REANCHOR_DIRTY, u64::from(dirty))?;
        metadata.insert(REANCHOR_NEXT_PHASE, 1)?;
    }
    let mut cursors = write.open_table(BLOB_PRESSURE_REANCHOR_CURSORS)?;
    cursors.insert(1, encode_reanchor_cursor(live).as_slice())?;
    cursors.insert(2, encode_reanchor_cursor(pending).as_slice())?;
    Ok(())
}

pub(crate) fn reanchor_state_needs_sync_write(
    write: &redb::WriteTransaction,
) -> Result<bool, StoreError> {
    let metadata = write.open_table(BLOB_PRESSURE_METADATA)?;
    if metadata
        .get(PRESSURE_SCHEMA_VERSION_FIELD)?
        .map(|value| value.value())
        != Some(PRESSURE_SCHEMA_VERSION)
    {
        return Ok(false);
    }
    let target = metadata
        .get(REANCHOR_TARGET_GENERATION)?
        .map(|value| value.value())
        .ok_or_else(|| pressure_corruption("Blob pressure reanchor target is missing"))?;
    drop(metadata);
    let current = crate::custody::lower_bound_continuity_write(write)?
        .map_or(0, |continuity| continuity.generation);
    Ok(target != current)
}

pub(crate) fn charge_reanchor_sync_state_write(
    write: &redb::WriteTransaction,
    charge: &mut super::MaintenanceCharge,
) -> Result<bool, StoreError> {
    let metadata = write.open_table(BLOB_PRESSURE_METADATA)?;
    for field in [
        PRESSURE_SCHEMA_VERSION_FIELD,
        REANCHOR_TARGET_GENERATION,
        REANCHOR_DIRTY,
        REANCHOR_NEXT_PHASE,
    ] {
        let value = metadata.get(field)?.ok_or_else(|| {
            pressure_corruption("Blob pressure synchronization metadata is missing")
        })?;
        if !charge.charge_row(
            super::MaintenanceRowIdentity::new("aster.blob-pressure-metadata.v1", field.as_bytes()),
            std::mem::size_of_val(&value.value()),
        )? {
            return Ok(false);
        }
    }
    drop(metadata);
    let cursors = write.open_table(BLOB_PRESSURE_REANCHOR_CURSORS)?;
    for key in [1u8, 2u8] {
        let value = cursors.get(key)?.ok_or_else(|| {
            pressure_corruption("Blob pressure synchronization cursor is missing")
        })?;
        if !charge.charge_row(
            super::MaintenanceRowIdentity::new("aster.blob-pressure-reanchor-cursors.v1", [key]),
            value.value().len(),
        )? {
            return Ok(false);
        }
    }
    drop(cursors);
    for (root, table_name) in [
        (
            PressureReanchorRoot::Publication,
            "aster.blob-pressure-publication-roots.v1",
        ),
        (
            PressureReanchorRoot::Pending,
            "aster.blob-pressure-pending-roots.v1",
        ),
    ] {
        let last = match root {
            PressureReanchorRoot::Publication => write
                .open_table(BLOB_PRESSURE_PUBLICATION_ROOTS)?
                .iter()?
                .next_back()
                .transpose()?
                .map(|(key, value)| (key.value().to_vec(), value.value().len())),
            PressureReanchorRoot::Pending => write
                .open_table(BLOB_PRESSURE_PENDING_ROOTS)?
                .iter()?
                .next_back()
                .transpose()?
                .map(|(key, value)| (key.value().to_vec(), value.value().len())),
        };
        if let Some((key, value_len)) = last
            && !charge.charge_row(
                super::MaintenanceRowIdentity::new(table_name, key),
                value_len,
            )?
        {
            return Ok(false);
        }
    }
    Ok(true)
}

fn next_reanchor_transfer_write(
    write: &redb::WriteTransaction,
    root: PressureReanchorRoot,
    cursor: PressureReanchorCursor,
) -> Result<Option<BlobTransferId>, StoreError> {
    use std::ops::Bound::{Excluded, Included, Unbounded};

    let PressureReanchorCursor::Active {
        end_transfer,
        position,
    } = cursor
    else {
        return Ok(None);
    };
    let lower = position.as_ref().map_or(Unbounded, |position| {
        Excluded(position.as_bytes().as_slice())
    });
    let upper = Included(end_transfer.as_bytes().as_slice());
    let key = match root {
        PressureReanchorRoot::Publication => write
            .open_table(BLOB_PRESSURE_PUBLICATION_ROOTS)?
            .range::<&[u8]>((lower, upper))?
            .next()
            .transpose()?
            .map(|(key, _)| key.value().to_vec()),
        PressureReanchorRoot::Pending => write
            .open_table(BLOB_PRESSURE_PENDING_ROOTS)?
            .range::<&[u8]>((lower, upper))?
            .next()
            .transpose()?
            .map(|(key, _)| key.value().to_vec()),
    };
    key.map(|key| {
        Ok(BlobTransferId::new(key.as_slice().try_into().map_err(
            |_| pressure_corruption("Blob pressure root key is not a transfer identifier"),
        )?))
    })
    .transpose()
}

fn reanchor_cursor_write(
    write: &redb::WriteTransaction,
    root: PressureReanchorRoot,
) -> Result<PressureReanchorCursor, StoreError> {
    let cursors = write.open_table(BLOB_PRESSURE_REANCHOR_CURSORS)?;
    decode_reanchor_cursor(
        cursors
            .get(root.cursor_key())?
            .ok_or_else(|| pressure_corruption("Blob pressure reanchor cursor is missing"))?
            .value(),
    )
}

fn store_reanchor_progress_write(
    write: &redb::WriteTransaction,
    root: PressureReanchorRoot,
    cursor: PressureReanchorCursor,
) -> Result<(), StoreError> {
    write
        .open_table(BLOB_PRESSURE_REANCHOR_CURSORS)?
        .insert(root.cursor_key(), encode_reanchor_cursor(cursor).as_slice())?;
    let other = match root {
        PressureReanchorRoot::Publication => PressureReanchorRoot::Pending,
        PressureReanchorRoot::Pending => PressureReanchorRoot::Publication,
    };
    let other_cursor = reanchor_cursor_write(write, other)?;
    let complete = |cursor| {
        matches!(
            cursor,
            PressureReanchorCursor::EmptyComplete | PressureReanchorCursor::Complete { .. }
        )
    };
    let mut metadata = write.open_table(BLOB_PRESSURE_METADATA)?;
    if complete(cursor) && complete(other_cursor) {
        metadata.insert(REANCHOR_DIRTY, 0)?;
        metadata.insert(REANCHOR_NEXT_PHASE, 1)?;
        drop(metadata);
        let empty = encode_reanchor_cursor(PressureReanchorCursor::EmptyComplete);
        let mut cursors = write.open_table(BLOB_PRESSURE_REANCHOR_CURSORS)?;
        cursors.insert(1, empty.as_slice())?;
        cursors.insert(2, empty.as_slice())?;
    } else {
        metadata.insert(REANCHOR_NEXT_PHASE, root.next_phase())?;
    }
    Ok(())
}

pub(crate) fn plan_reanchor_turn_write(
    write: &redb::WriteTransaction,
) -> Result<Option<PressureReanchorTurn>, StoreError> {
    let metadata = write.open_table(BLOB_PRESSURE_METADATA)?;
    if metadata
        .get(PRESSURE_SCHEMA_VERSION_FIELD)?
        .map(|value| value.value())
        != Some(PRESSURE_SCHEMA_VERSION)
        || metadata.get(REANCHOR_DIRTY)?.map(|value| value.value()) != Some(1)
    {
        return Ok(None);
    }
    let root = PressureReanchorRoot::decode(
        metadata
            .get(REANCHOR_NEXT_PHASE)?
            .map(|value| value.value())
            .ok_or_else(|| pressure_corruption("Blob pressure reanchor phase is missing"))?,
    )?;
    drop(metadata);
    let cursor = reanchor_cursor_write(write, root)?;
    let Some(transfer) = next_reanchor_transfer_write(write, root, cursor)? else {
        let completed = match cursor {
            PressureReanchorCursor::Active { end_transfer, .. } => {
                PressureReanchorCursor::Complete { end_transfer }
            }
            complete => complete,
        };
        return Ok(Some(PressureReanchorTurn {
            root,
            transfer: None,
            next_cursor: completed,
        }));
    };
    let PressureReanchorCursor::Active { end_transfer, .. } = cursor else {
        return Err(pressure_corruption(
            "Blob pressure reanchor selected from a completed cursor",
        ));
    };
    let next_cursor = if transfer == end_transfer {
        PressureReanchorCursor::Complete { end_transfer }
    } else {
        PressureReanchorCursor::Active {
            end_transfer,
            position: Some(transfer),
        }
    };
    Ok(Some(PressureReanchorTurn {
        root,
        transfer: Some(transfer),
        next_cursor,
    }))
}

pub(crate) fn finish_reanchor_turn_write(
    write: &redb::WriteTransaction,
    turn: PressureReanchorTurn,
) -> Result<(), StoreError> {
    let metadata = write.open_table(BLOB_PRESSURE_METADATA)?;
    if metadata.get(REANCHOR_DIRTY)?.map(|value| value.value()) != Some(1)
        || metadata
            .get(REANCHOR_NEXT_PHASE)?
            .map(|value| value.value())
            != Some(turn.root.phase())
    {
        return Err(pressure_corruption(
            "Blob pressure reanchor state changed before its unit committed",
        ));
    }
    drop(metadata);
    store_reanchor_progress_write(write, turn.root, turn.next_cursor)
}

/// Preflights the persisted progress rows changed when a reanchor unit commits.
pub(crate) fn charge_reanchor_turn_write(
    write: &redb::WriteTransaction,
    turn: PressureReanchorTurn,
    charge: &mut super::MaintenanceCharge,
) -> Result<bool, StoreError> {
    let cursors = write.open_table(BLOB_PRESSURE_REANCHOR_CURSORS)?;
    let other = match turn.root {
        PressureReanchorRoot::Publication => PressureReanchorRoot::Pending,
        PressureReanchorRoot::Pending => PressureReanchorRoot::Publication,
    };
    for key in [turn.root.cursor_key(), other.cursor_key()] {
        let value = cursors
            .get(key)?
            .ok_or_else(|| pressure_corruption("Blob pressure reanchor cursor is missing"))?;
        if !charge.charge_row(
            super::MaintenanceRowIdentity::new("aster.blob-pressure-reanchor-cursors.v1", [key]),
            value.value().len(),
        )? {
            return Ok(false);
        }
    }
    drop(cursors);
    for field in [
        PRESSURE_SCHEMA_VERSION_FIELD,
        REANCHOR_DIRTY,
        REANCHOR_NEXT_PHASE,
    ] {
        if !charge.charge_row(
            super::MaintenanceRowIdentity::new("aster.blob-pressure-metadata.v1", field.as_bytes()),
            std::mem::size_of::<u64>(),
        )? {
            return Ok(false);
        }
    }
    if let Some(transfer) = turn.transfer {
        let encoded = match turn.root {
            PressureReanchorRoot::Publication => write
                .open_table(BLOB_PRESSURE_PUBLICATION_ROOTS)?
                .get(transfer.as_bytes().as_slice())?
                .map(|value| value.value().to_vec()),
            PressureReanchorRoot::Pending => write
                .open_table(BLOB_PRESSURE_PENDING_ROOTS)?
                .get(transfer.as_bytes().as_slice())?
                .map(|value| value.value().to_vec()),
        }
        .ok_or_else(|| pressure_corruption("Blob pressure reanchor root disappeared"))?;
        let table = match turn.root {
            PressureReanchorRoot::Publication => "aster.blob-pressure-publication-roots.v1",
            PressureReanchorRoot::Pending => "aster.blob-pressure-pending-roots.v1",
        };
        if !charge.charge_row(
            super::MaintenanceRowIdentity::new(table, transfer.as_bytes()),
            encoded.len(),
        )? {
            return Ok(false);
        }
    }
    Ok(true)
}

const PRESSURE_PENDING_INDEX_LEN: usize = 68;
const PRESSURE_VARIANT_INDEX_LEN: usize = 84;
const PRESSURE_VARIANT_HAS_FINITE_ROOT_MASK: u64 = 1 << 63;

#[derive(Debug)]
pub(crate) struct PressurePendingIndexKey;

#[derive(Debug)]
pub(crate) struct PressureVariantIndexKey;

macro_rules! pressure_index_value {
    ($key:ty, $len:expr, $name:literal) => {
        impl Value for $key {
            type SelfType<'a> = [u8; $len];
            type AsBytes<'a> = [u8; $len];

            fn fixed_width() -> Option<usize> {
                Some($len)
            }

            fn from_bytes<'a>(data: &'a [u8]) -> Self::SelfType<'a>
            where
                Self: 'a,
            {
                data.try_into()
                    .expect("redb enforces fixed pressure key width")
            }

            fn as_bytes<'a, 'b: 'a>(value: &'a Self::SelfType<'b>) -> Self::AsBytes<'a>
            where
                Self: 'b,
            {
                *value
            }

            fn type_name() -> TypeName {
                TypeName::new($name)
            }
        }
    };
}

pressure_index_value!(
    PressurePendingIndexKey,
    PRESSURE_PENDING_INDEX_LEN,
    "aster::blob::PressurePendingIndexKeyV1"
);
pressure_index_value!(
    PressureVariantIndexKey,
    PRESSURE_VARIANT_INDEX_LEN,
    "aster::blob::PressureVariantIndexKeyV1"
);

fn pressure_corruption(message: &'static str) -> StoreError {
    blob_error(BlobStoreError::SchemaInvariant(message))
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum PressureExpiry {
    ExpiredFinite,
    Finite(u64),
    Durable,
}

impl PressureExpiry {
    fn encode(self, output: &mut Vec<u8>) {
        match self {
            Self::ExpiredFinite => {
                output.push(PRESSURE_EXPIRY_EXPIRED_FINITE);
                output.extend_from_slice(&0u64.to_be_bytes());
            }
            Self::Finite(deadline) => {
                output.push(PRESSURE_EXPIRY_FINITE);
                output.extend_from_slice(&deadline.to_be_bytes());
            }
            Self::Durable => {
                output.push(PRESSURE_EXPIRY_DURABLE);
                output.extend_from_slice(&0u64.to_be_bytes());
            }
        }
    }

    fn decode(cursor: &mut PressureCursor<'_>) -> Result<Self, StoreError> {
        let tag = cursor.u8()?;
        let deadline = cursor.u64()?;
        match tag {
            PRESSURE_EXPIRY_EXPIRED_FINITE if deadline == 0 => Ok(Self::ExpiredFinite),
            PRESSURE_EXPIRY_EXPIRED_FINITE => Err(pressure_corruption(
                "Blob pressure expired finite record has a deadline",
            )),
            PRESSURE_EXPIRY_FINITE if deadline != 0 => Ok(Self::Finite(deadline)),
            PRESSURE_EXPIRY_FINITE => Err(pressure_corruption(
                "Blob pressure live finite record has a zero deadline",
            )),
            PRESSURE_EXPIRY_DURABLE if deadline == 0 => Ok(Self::Durable),
            PRESSURE_EXPIRY_DURABLE => Err(pressure_corruption(
                "Blob pressure durable record expiry has a deadline",
            )),
            _ => Err(pressure_corruption(
                "Blob pressure record has an unknown expiry tag",
            )),
        }
    }
}

fn lifetime_expiry(lifetime: super::BlobLifetime) -> Result<PressureExpiry, StoreError> {
    match lifetime {
        super::BlobLifetime::Durable => Ok(PressureExpiry::Durable),
        super::BlobLifetime::Finite { ttl_ms, age, .. } => {
            super::validate_blob_lifetime(lifetime)?;
            if age.cumulative_age_ms >= ttl_ms {
                return Ok(PressureExpiry::ExpiredFinite);
            }
            let remaining = ttl_ms - age.cumulative_age_ms;
            match age.checkpoint {
                Some(checkpoint) => Ok(PressureExpiry::Finite(
                    checkpoint.tick_ms.saturating_add(remaining),
                )),
                None => Ok(PressureExpiry::Finite(u64::MAX)),
            }
        }
    }
}

fn latest_expiry(left: PressureExpiry, right: PressureExpiry) -> PressureExpiry {
    match (left, right) {
        (PressureExpiry::Durable, _) | (_, PressureExpiry::Durable) => PressureExpiry::Durable,
        (PressureExpiry::Finite(left), PressureExpiry::Finite(right)) => {
            PressureExpiry::Finite(left.max(right))
        }
        (PressureExpiry::Finite(value), PressureExpiry::ExpiredFinite)
        | (PressureExpiry::ExpiredFinite, PressureExpiry::Finite(value)) => {
            PressureExpiry::Finite(value)
        }
        (PressureExpiry::ExpiredFinite, PressureExpiry::ExpiredFinite) => {
            PressureExpiry::ExpiredFinite
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct PressureFraction {
    numerator: u64,
    denominator: u64,
}

impl PressureFraction {
    pub(crate) const ONE: Self = Self {
        numerator: 1,
        denominator: 1,
    };

    pub(crate) fn new(numerator: u64, denominator: u64) -> Result<Self, StoreError> {
        if denominator == 0 {
            return Err(pressure_corruption(
                "Blob pressure progress has a zero authenticated denominator",
            ));
        }
        if numerator > denominator {
            return Err(pressure_corruption(
                "Blob pressure progress exceeds its authenticated total",
            ));
        }
        Ok(Self {
            numerator,
            denominator,
        })
    }

    pub(crate) const fn numerator(self) -> u64 {
        self.numerator
    }

    pub(crate) const fn denominator(self) -> u64 {
        self.denominator
    }
}

fn authenticated_progress_fraction(
    numerator: u64,
    denominator: u64,
) -> Result<PressureFraction, StoreError> {
    if numerator == 0 && denominator == 0 {
        Ok(PressureFraction::ONE)
    } else {
        PressureFraction::new(numerator, denominator)
    }
}

/// Exact progress ordering shared by pending-source and whole-variant selection.
///
/// Both products are widened before multiplication; a product of two `u64`
/// values is always exactly representable in `u128`.
pub(crate) fn compare_pressure_fraction(
    left: PressureFraction,
    right: PressureFraction,
) -> Ordering {
    u128::from(left.numerator)
        .checked_mul(u128::from(right.denominator))
        .expect("u64 cross product fits u128")
        .cmp(
            &u128::from(right.numerator)
                .checked_mul(u128::from(left.denominator))
                .expect("u64 cross product fits u128"),
        )
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct PressurePublicationKey {
    pub(crate) priority: Priority,
    pub(crate) expiry: PressureExpiry,
    pub(crate) acceptance_order: u64,
    pub(crate) transfer_id: BlobTransferId,
}

pub(crate) fn encode_publication_key(key: PressurePublicationKey) -> Vec<u8> {
    encode_publication_key_for_generation(key, false)
}

fn expiry_indexes_active_write(write: &redb::WriteTransaction) -> Result<bool, StoreError> {
    let version = write
        .open_table(BLOB_PRESSURE_METADATA)?
        .get(PRESSURE_SCHEMA_VERSION_FIELD)?
        .map(|value| value.value())
        .ok_or_else(|| pressure_corruption("Blob pressure schema version is missing"))?;
    match version {
        PRESSURE_SCHEMA_VERSION => Ok(true),
        2 | PREVIOUS_PRESSURE_SCHEMA_VERSION | PRESSURE_V4_SCHEMA_VERSION => Ok(false),
        _ => Err(pressure_corruption(
            "Blob pressure schema version is unknown",
        )),
    }
}

fn expiry_indexes_active_read(read: &redb::ReadTransaction) -> Result<bool, StoreError> {
    let version = read
        .open_table(BLOB_PRESSURE_METADATA)?
        .get(PRESSURE_SCHEMA_VERSION_FIELD)?
        .map(|value| value.value())
        .ok_or_else(|| pressure_corruption("Blob pressure schema version is missing"))?;
    match version {
        PRESSURE_SCHEMA_VERSION => Ok(true),
        2 | PREVIOUS_PRESSURE_SCHEMA_VERSION | PRESSURE_V4_SCHEMA_VERSION => Ok(false),
        _ => Err(pressure_corruption(
            "Blob pressure schema version is unknown",
        )),
    }
}

fn finite_aggregate_active_write(write: &redb::WriteTransaction) -> Result<bool, StoreError> {
    Ok(matches!(
        pressure_schema_state(write)?,
        PressureSchemaState::Current
    ))
}

fn finite_aggregate_active_read(read: &redb::ReadTransaction) -> Result<bool, StoreError> {
    Ok(matches!(
        pressure_schema_state(read)?,
        PressureSchemaState::Current
    ))
}

fn publication_index_key_write(
    write: &redb::WriteTransaction,
    key: PressurePublicationKey,
) -> Result<Vec<u8>, StoreError> {
    Ok(encode_publication_key_for_generation(
        key,
        expiry_indexes_active_write(write)?,
    ))
}

fn publication_index_key_read(
    read: &redb::ReadTransaction,
    key: PressurePublicationKey,
) -> Result<Vec<u8>, StoreError> {
    Ok(encode_publication_key_for_generation(
        key,
        expiry_indexes_active_read(read)?,
    ))
}

fn encode_publication_key_for_generation(
    key: PressurePublicationKey,
    activate_expiry: bool,
) -> Vec<u8> {
    let mut output = Vec::with_capacity(52);
    output.push(PRESSURE_RECORD_VERSION);
    output.push(key.priority as u8);
    output.push(PRESSURE_CANDIDATE_COMPLETED);
    if activate_expiry {
        key.expiry
    } else {
        PressureExpiry::Durable
    }
    .encode(&mut output);
    output.extend_from_slice(&key.acceptance_order.to_be_bytes());
    output.extend_from_slice(key.transfer_id.as_bytes());
    output
}

pub(crate) fn decode_publication_key(bytes: &[u8]) -> Result<PressurePublicationKey, StoreError> {
    let mut cursor = PressureCursor::new(bytes);
    cursor.version()?;
    let priority = decode_priority(cursor.u8()?)?;
    if cursor.u8()? != PRESSURE_CANDIDATE_COMPLETED {
        return Err(pressure_corruption(
            "Blob pressure publication key has an invalid completion tag",
        ));
    }
    let expiry = PressureExpiry::decode(&mut cursor)?;
    let acceptance_order = cursor.u64()?;
    if acceptance_order == 0 {
        return Err(pressure_corruption(
            "Blob pressure publication key has a zero acceptance order",
        ));
    }
    let transfer_id = BlobTransferId::new(cursor.array()?);
    cursor.finish()?;
    Ok(PressurePublicationKey {
        priority,
        expiry,
        acceptance_order,
        transfer_id,
    })
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct PressurePublicationRoot {
    pub(crate) variant_id: BlobVariantId,
    pub(crate) semantic_id: BlobSemanticId,
    pub(crate) priority: Priority,
    pub(crate) acceptance_order: u64,
    pub(crate) expiry: PressureExpiry,
    pub(crate) topic: Topic,
    pub(crate) scope: Scope,
    pub(crate) blob_id: BlobId,
}

pub(crate) fn encode_publication_root(
    root: &PressurePublicationRoot,
) -> Result<Vec<u8>, StoreError> {
    if root.acceptance_order == 0 {
        return Err(pressure_corruption(
            "Blob pressure publication root has a zero acceptance order",
        ));
    }
    let topic = root.topic.as_str().as_bytes();
    let scope = root.scope.as_str().as_bytes();
    let topic_len = u16::try_from(topic.len())
        .map_err(|_| pressure_corruption("Blob pressure topic length overflows"))?;
    let scope_len = u16::try_from(scope.len())
        .map_err(|_| pressure_corruption("Blob pressure scope length overflows"))?;
    let mut output = Vec::with_capacity(120 + topic.len() + scope.len());
    output.push(PRESSURE_RECORD_VERSION);
    output.extend_from_slice(root.variant_id.as_bytes());
    output.extend_from_slice(root.semantic_id.as_bytes());
    output.push(root.priority as u8);
    output.extend_from_slice(&root.acceptance_order.to_be_bytes());
    root.expiry.encode(&mut output);
    output.extend_from_slice(&topic_len.to_be_bytes());
    output.extend_from_slice(topic);
    output.extend_from_slice(&scope_len.to_be_bytes());
    output.extend_from_slice(scope);
    output.extend_from_slice(root.blob_id.as_bytes());
    Ok(output)
}

pub(crate) fn decode_publication_root(bytes: &[u8]) -> Result<PressurePublicationRoot, StoreError> {
    let mut cursor = PressureCursor::new(bytes);
    cursor.version()?;
    let variant_id = BlobVariantId::from_bytes(cursor.array()?);
    let semantic_id = BlobSemanticId::new(cursor.array()?);
    let priority = decode_priority(cursor.u8()?)?;
    let acceptance_order = cursor.u64()?;
    if acceptance_order == 0 {
        return Err(pressure_corruption(
            "Blob pressure publication root has a zero acceptance order",
        ));
    }
    let expiry = PressureExpiry::decode(&mut cursor)?;
    let topic = Topic::new(cursor.short_string()?)
        .map_err(|_| pressure_corruption("Blob pressure root has an invalid topic"))?;
    let scope = Scope::new(cursor.short_string()?)
        .map_err(|_| pressure_corruption("Blob pressure root has an invalid scope"))?;
    let blob_id = BlobId::from_bytes(cursor.array()?);
    cursor.finish()?;
    Ok(PressurePublicationRoot {
        variant_id,
        semantic_id,
        priority,
        acceptance_order,
        expiry,
        topic,
        scope,
        blob_id,
    })
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct PressurePendingRoot {
    pub(crate) variant_id: BlobVariantId,
    pub(crate) authenticated_source_binding: [u8; 32],
    pub(crate) priority: Priority,
    pub(crate) acceptance_order: u64,
    pub(crate) completion: PressureFraction,
    pub(crate) expiry: PressureExpiry,
    pub(crate) topic: Topic,
    pub(crate) scope: Scope,
    pub(crate) blob_id: BlobId,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum PressurePendingRootEncodingGeneration {
    PressureV3,
    PressureV4,
}

pub(super) fn encode_pending_root(root: &PressurePendingRoot) -> Result<Vec<u8>, StoreError> {
    encode_pending_root_for_generation(root, PressurePendingRootEncodingGeneration::PressureV4)
}

pub(super) fn encode_pending_root_for_generation(
    root: &PressurePendingRoot,
    generation: PressurePendingRootEncodingGeneration,
) -> Result<Vec<u8>, StoreError> {
    if root.acceptance_order == 0 {
        return Err(pressure_corruption(
            "Blob pressure pending root has a zero acceptance order",
        ));
    }
    let topic = root.topic.as_str().as_bytes();
    let scope = root.scope.as_str().as_bytes();
    let topic_len = u16::try_from(topic.len())
        .map_err(|_| pressure_corruption("Blob pressure topic length overflows"))?;
    let scope_len = u16::try_from(scope.len())
        .map_err(|_| pressure_corruption("Blob pressure scope length overflows"))?;
    let binding_len = match generation {
        PressurePendingRootEncodingGeneration::PressureV3 => 0,
        PressurePendingRootEncodingGeneration::PressureV4 => 32,
    };
    let mut output = Vec::with_capacity(110 + binding_len + topic.len() + scope.len());
    output.push(PRESSURE_RECORD_VERSION);
    output.extend_from_slice(root.variant_id.as_bytes());
    if generation == PressurePendingRootEncodingGeneration::PressureV4 {
        output.extend_from_slice(&root.authenticated_source_binding);
    }
    output.push(root.priority as u8);
    output.extend_from_slice(&root.acceptance_order.to_be_bytes());
    output.extend_from_slice(&root.completion.numerator.to_be_bytes());
    output.extend_from_slice(&root.completion.denominator.to_be_bytes());
    root.expiry.encode(&mut output);
    output.extend_from_slice(&topic_len.to_be_bytes());
    output.extend_from_slice(topic);
    output.extend_from_slice(&scope_len.to_be_bytes());
    output.extend_from_slice(scope);
    output.extend_from_slice(root.blob_id.as_bytes());
    Ok(output)
}

pub(super) fn decode_pending_root(bytes: &[u8]) -> Result<PressurePendingRoot, StoreError> {
    decode_pending_root_for_generation(bytes, PressurePendingRootEncodingGeneration::PressureV4)
}

pub(super) fn decode_pending_root_for_generation(
    bytes: &[u8],
    generation: PressurePendingRootEncodingGeneration,
) -> Result<PressurePendingRoot, StoreError> {
    let mut cursor = PressureCursor::new(bytes);
    cursor.version()?;
    let variant_id = BlobVariantId::from_bytes(cursor.array()?);
    let authenticated_source_binding = match generation {
        PressurePendingRootEncodingGeneration::PressureV3 => [0; 32],
        PressurePendingRootEncodingGeneration::PressureV4 => cursor.array()?,
    };
    let priority = decode_priority(cursor.u8()?)?;
    let acceptance_order = cursor.u64()?;
    if acceptance_order == 0 {
        return Err(pressure_corruption(
            "Blob pressure pending root has a zero acceptance order",
        ));
    }
    let completion = PressureFraction::new(cursor.u64()?, cursor.u64()?)?;
    let expiry = PressureExpiry::decode(&mut cursor)?;
    let topic = Topic::new(cursor.short_string()?)
        .map_err(|_| pressure_corruption("Blob pressure pending root has an invalid topic"))?;
    let scope = Scope::new(cursor.short_string()?)
        .map_err(|_| pressure_corruption("Blob pressure pending root has an invalid scope"))?;
    let blob_id = BlobId::from_bytes(cursor.array()?);
    cursor.finish()?;
    Ok(PressurePendingRoot {
        variant_id,
        authenticated_source_binding,
        priority,
        acceptance_order,
        completion,
        expiry,
        topic,
        scope,
        blob_id,
    })
}

pub(crate) fn encode_pending_index_key(
    root: PressurePendingRoot,
    transfer_id: BlobTransferId,
) -> [u8; PRESSURE_PENDING_INDEX_LEN] {
    encode_pending_index_key_for_generation(root, transfer_id, false)
}

fn pending_index_key_write(
    write: &redb::WriteTransaction,
    root: PressurePendingRoot,
    transfer_id: BlobTransferId,
) -> Result<[u8; PRESSURE_PENDING_INDEX_LEN], StoreError> {
    Ok(encode_pending_index_key_for_generation(
        root,
        transfer_id,
        expiry_indexes_active_write(write)?,
    ))
}

fn pending_index_key_read(
    read: &redb::ReadTransaction,
    root: PressurePendingRoot,
    transfer_id: BlobTransferId,
) -> Result<[u8; PRESSURE_PENDING_INDEX_LEN], StoreError> {
    Ok(encode_pending_index_key_for_generation(
        root,
        transfer_id,
        expiry_indexes_active_read(read)?,
    ))
}

fn encode_pending_index_key_for_generation(
    root: PressurePendingRoot,
    transfer_id: BlobTransferId,
    activate_expiry: bool,
) -> [u8; PRESSURE_PENDING_INDEX_LEN] {
    let mut output = [0u8; PRESSURE_PENDING_INDEX_LEN];
    output[0] = PRESSURE_RECORD_VERSION;
    output[1] = root.priority as u8;
    output[2] = 0; // incomplete
    encode_fixed_expiry(
        if activate_expiry {
            root.expiry
        } else {
            PressureExpiry::Durable
        },
        &mut output[3..12],
    );
    output[12..20].copy_from_slice(&root.completion.numerator.to_be_bytes());
    output[20..28].copy_from_slice(&root.completion.denominator.to_be_bytes());
    output[28..36].copy_from_slice(&root.acceptance_order.to_be_bytes());
    output[36..68].copy_from_slice(transfer_id.as_bytes());
    output
}

pub(crate) fn encode_variant_index_key(
    summary: PressureVariantSummary,
    variant_id: BlobVariantId,
) -> [u8; PRESSURE_VARIANT_INDEX_LEN] {
    encode_variant_index_key_for_generation(summary, variant_id, false, false)
}

fn variant_index_key_write(
    write: &redb::WriteTransaction,
    summary: PressureVariantSummary,
    variant_id: BlobVariantId,
) -> Result<[u8; PRESSURE_VARIANT_INDEX_LEN], StoreError> {
    Ok(encode_variant_index_key_for_generation(
        summary,
        variant_id,
        expiry_indexes_active_write(write)?,
        finite_aggregate_active_write(write)?,
    ))
}

fn variant_index_key_read(
    read: &redb::ReadTransaction,
    summary: PressureVariantSummary,
    variant_id: BlobVariantId,
) -> Result<[u8; PRESSURE_VARIANT_INDEX_LEN], StoreError> {
    Ok(encode_variant_index_key_for_generation(
        summary,
        variant_id,
        expiry_indexes_active_read(read)?,
        finite_aggregate_active_read(read)?,
    ))
}

fn insert_durable_publication_indexes_write(
    write: &redb::WriteTransaction,
    root: &PressurePublicationRoot,
    transfer: BlobTransferId,
) -> Result<(), StoreError> {
    if !expiry_indexes_active_write(write)? || root.expiry != PressureExpiry::Durable {
        return Ok(());
    }
    let global = publication_index_key_write(
        write,
        PressurePublicationKey {
            priority: root.priority,
            expiry: root.expiry,
            acceptance_order: root.acceptance_order,
            transfer_id: transfer,
        },
    )?;
    let content = content_publication_index_key_write(write, root, transfer)?;
    if write
        .open_table(BLOB_PRESSURE_DURABLE_PUBLICATIONS)?
        .insert(global.as_slice(), &[] as &[u8])?
        .is_some()
        || write
            .open_table(BLOB_PRESSURE_DURABLE_CONTENT_PUBLICATIONS)?
            .insert(content.as_slice(), &[] as &[u8])?
            .is_some()
    {
        return Err(pressure_corruption(
            "durable publication pressure index is duplicated",
        ));
    }
    Ok(())
}

fn remove_durable_publication_indexes_write(
    write: &redb::WriteTransaction,
    root: &PressurePublicationRoot,
    transfer: BlobTransferId,
) -> Result<(), StoreError> {
    if !expiry_indexes_active_write(write)? || root.expiry != PressureExpiry::Durable {
        return Ok(());
    }
    let global = publication_index_key_write(
        write,
        PressurePublicationKey {
            priority: root.priority,
            expiry: root.expiry,
            acceptance_order: root.acceptance_order,
            transfer_id: transfer,
        },
    )?;
    if write
        .open_table(BLOB_PRESSURE_DURABLE_PUBLICATIONS)?
        .remove(global.as_slice())?
        .is_none()
        || write
            .open_table(BLOB_PRESSURE_DURABLE_CONTENT_PUBLICATIONS)?
            .remove(content_publication_index_key_write(write, root, transfer)?.as_slice())?
            .is_none()
    {
        return Err(pressure_corruption(
            "durable publication pressure root lacks its exact index",
        ));
    }
    Ok(())
}

fn insert_durable_pending_index_write(
    write: &redb::WriteTransaction,
    root: PressurePendingRoot,
    transfer: BlobTransferId,
) -> Result<(), StoreError> {
    if expiry_indexes_active_write(write)? && root.expiry == PressureExpiry::Durable {
        let key = pending_index_key_write(write, root, transfer)?;
        if write
            .open_table(BLOB_PRESSURE_DURABLE_PENDING_SOURCES)?
            .insert(&key, &[] as &[u8])?
            .is_some()
        {
            return Err(pressure_corruption(
                "durable pending pressure index is duplicated",
            ));
        }
    }
    Ok(())
}

fn remove_durable_pending_index_write(
    write: &redb::WriteTransaction,
    root: PressurePendingRoot,
    transfer: BlobTransferId,
) -> Result<(), StoreError> {
    if expiry_indexes_active_write(write)? && root.expiry == PressureExpiry::Durable {
        let key = pending_index_key_write(write, root, transfer)?;
        if write
            .open_table(BLOB_PRESSURE_DURABLE_PENDING_SOURCES)?
            .remove(&key)?
            .is_none()
        {
            return Err(pressure_corruption(
                "durable pending pressure root lacks its exact index",
            ));
        }
    }
    Ok(())
}

fn insert_durable_variant_index_write(
    write: &redb::WriteTransaction,
    summary: PressureVariantSummary,
    variant: BlobVariantId,
) -> Result<(), StoreError> {
    if expiry_indexes_active_write(write)? && !summary.has_finite_roots {
        let key = variant_index_key_write(write, summary, variant)?;
        if write
            .open_table(BLOB_PRESSURE_DURABLE_VARIANTS)?
            .insert(&key, &[] as &[u8])?
            .is_some()
        {
            return Err(pressure_corruption(
                "durable variant pressure index is duplicated",
            ));
        }
    }
    Ok(())
}

fn remove_durable_variant_index_write(
    write: &redb::WriteTransaction,
    summary: PressureVariantSummary,
    variant: BlobVariantId,
) -> Result<(), StoreError> {
    if expiry_indexes_active_write(write)? && !summary.has_finite_roots {
        let key = variant_index_key_write(write, summary, variant)?;
        if write
            .open_table(BLOB_PRESSURE_DURABLE_VARIANTS)?
            .remove(&key)?
            .is_none()
        {
            return Err(pressure_corruption(
                "durable variant pressure summary lacks its exact index",
            ));
        }
    }
    Ok(())
}

fn encode_variant_index_key_for_generation(
    summary: PressureVariantSummary,
    variant_id: BlobVariantId,
    activate_expiry: bool,
    activate_finite_aggregate: bool,
) -> [u8; PRESSURE_VARIANT_INDEX_LEN] {
    let mut output = [0u8; PRESSURE_VARIANT_INDEX_LEN];
    output[0] = PRESSURE_RECORD_VERSION;
    output[1] = summary.effective_priority as u8;
    output[2] = u8::from(summary.finalized);
    encode_fixed_expiry(
        if activate_expiry {
            summary.final_reference_expiry
        } else {
            PressureExpiry::Durable
        },
        &mut output[3..12],
    );
    output[12..20].copy_from_slice(&summary.committed_progress.numerator.to_be_bytes());
    output[20..28].copy_from_slice(&summary.committed_progress.denominator.to_be_bytes());
    output[28..36].copy_from_slice(&summary.minimum_root_acceptance_order.to_be_bytes());
    output[36..68].copy_from_slice(variant_id.as_bytes());
    debug_assert!(summary.publication_roots < PRESSURE_VARIANT_HAS_FINITE_ROOT_MASK);
    let encoded_publication_roots = summary.publication_roots
        | if activate_finite_aggregate && summary.has_finite_roots {
            PRESSURE_VARIANT_HAS_FINITE_ROOT_MASK
        } else {
            0
        };
    output[68..76].copy_from_slice(&encoded_publication_roots.to_be_bytes());
    output[76..84].copy_from_slice(&summary.pending_roots.to_be_bytes());
    output
}

fn encode_fixed_expiry(expiry: PressureExpiry, output: &mut [u8]) {
    debug_assert_eq!(output.len(), 9);
    match expiry {
        PressureExpiry::ExpiredFinite => {
            output[0] = PRESSURE_EXPIRY_EXPIRED_FINITE;
            output[1..].fill(0);
        }
        PressureExpiry::Finite(deadline) => {
            output[0] = PRESSURE_EXPIRY_FINITE;
            output[1..].copy_from_slice(&deadline.to_be_bytes());
        }
        PressureExpiry::Durable => {
            output[0] = PRESSURE_EXPIRY_DURABLE;
            output[1..].fill(0);
        }
    }
}

fn decode_fixed_expiry(bytes: &[u8]) -> Result<PressureExpiry, StoreError> {
    let deadline = u64::from_be_bytes(
        bytes[1..9]
            .try_into()
            .map_err(|_| pressure_corruption("Blob pressure index expiry is malformed"))?,
    );
    match bytes.first().copied() {
        Some(PRESSURE_EXPIRY_EXPIRED_FINITE) if deadline == 0 => Ok(PressureExpiry::ExpiredFinite),
        Some(PRESSURE_EXPIRY_EXPIRED_FINITE) => Err(pressure_corruption(
            "Blob pressure expired finite index has a deadline",
        )),
        Some(PRESSURE_EXPIRY_FINITE) if deadline != 0 => Ok(PressureExpiry::Finite(deadline)),
        Some(PRESSURE_EXPIRY_FINITE) => Err(pressure_corruption(
            "Blob pressure live finite index has a zero deadline",
        )),
        Some(PRESSURE_EXPIRY_DURABLE) if deadline == 0 => Ok(PressureExpiry::Durable),
        Some(PRESSURE_EXPIRY_DURABLE) => Err(pressure_corruption(
            "Blob pressure durable index expiry has a deadline",
        )),
        _ => Err(pressure_corruption(
            "Blob pressure index has an unknown expiry tag",
        )),
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct PressurePendingIndexEntry {
    pub(crate) priority: Priority,
    pub(crate) acceptance_order: u64,
    pub(crate) completion: PressureFraction,
    pub(crate) expiry: PressureExpiry,
    pub(crate) transfer_id: BlobTransferId,
}

pub(crate) fn decode_pending_index_key(
    bytes: &[u8],
) -> Result<PressurePendingIndexEntry, StoreError> {
    if bytes.len() != PRESSURE_PENDING_INDEX_LEN || bytes[0] != PRESSURE_RECORD_VERSION {
        return Err(pressure_corruption(
            "Blob pressure pending index key is malformed",
        ));
    }
    if bytes[2] != 0 {
        return Err(pressure_corruption(
            "Blob pressure pending index has an invalid completion tag",
        ));
    }
    let entry = PressurePendingIndexEntry {
        priority: decode_priority(bytes[1])?,
        acceptance_order: u64::from_be_bytes(bytes[28..36].try_into().unwrap()),
        completion: PressureFraction::new(
            u64::from_be_bytes(bytes[12..20].try_into().unwrap()),
            u64::from_be_bytes(bytes[20..28].try_into().unwrap()),
        )?,
        expiry: decode_fixed_expiry(&bytes[3..12])?,
        transfer_id: BlobTransferId::new(bytes[36..68].try_into().unwrap()),
    };
    if entry.acceptance_order == 0 {
        return Err(pressure_corruption(
            "Blob pressure pending index has a zero acceptance order",
        ));
    }
    Ok(entry)
}

pub(crate) fn decode_variant_index_key(
    bytes: &[u8],
) -> Result<(PressureVariantSummary, BlobVariantId), StoreError> {
    if bytes.len() != PRESSURE_VARIANT_INDEX_LEN || bytes[0] != PRESSURE_RECORD_VERSION {
        return Err(pressure_corruption(
            "Blob pressure variant index key is malformed",
        ));
    }
    let finalized = match bytes[2] {
        0 => false,
        1 => true,
        _ => {
            return Err(pressure_corruption(
                "Blob pressure variant index finalization is malformed",
            ));
        }
    };
    let encoded_publication_roots = u64::from_be_bytes(bytes[68..76].try_into().unwrap());
    let summary = PressureVariantSummary {
        effective_priority: decode_priority(bytes[1])?,
        minimum_root_acceptance_order: u64::from_be_bytes(bytes[28..36].try_into().unwrap()),
        committed_progress: PressureFraction::new(
            u64::from_be_bytes(bytes[12..20].try_into().unwrap()),
            u64::from_be_bytes(bytes[20..28].try_into().unwrap()),
        )?,
        finalized,
        publication_roots: encoded_publication_roots & !PRESSURE_VARIANT_HAS_FINITE_ROOT_MASK,
        pending_roots: u64::from_be_bytes(bytes[76..84].try_into().unwrap()),
        final_reference_expiry: decode_fixed_expiry(&bytes[3..12])?,
        has_finite_roots: encoded_publication_roots & PRESSURE_VARIANT_HAS_FINITE_ROOT_MASK != 0,
    };
    if summary.minimum_root_acceptance_order == 0
        || (summary.publication_roots == 0 && summary.pending_roots == 0)
    {
        return Err(pressure_corruption(
            "Blob pressure variant index key is contradictory",
        ));
    }
    Ok((
        summary,
        BlobVariantId::from_bytes(bytes[36..68].try_into().unwrap()),
    ))
}

fn pressure_prefix_upper_bound(prefix: &[u8]) -> Result<Vec<u8>, StoreError> {
    let mut upper = prefix.to_vec();
    let index = upper
        .iter()
        .rposition(|byte| *byte != u8::MAX)
        .ok_or_else(|| pressure_corruption("Blob pressure prefix has no finite successor"))?;
    upper[index] += 1;
    upper.truncate(index + 1);
    Ok(upper)
}

fn select_publication_from_row(
    read: &redb::ReadTransaction,
    key: &[u8],
    value: &[u8],
    content: Option<PressureContentIdentity>,
    incoming_priority: Priority,
    charge: &mut PressureSelectionCharge,
) -> Result<Option<Option<PressureCandidate>>, StoreError> {
    if !value.is_empty() {
        return Err(pressure_corruption(
            "Blob pressure publication index value is not empty",
        ));
    }
    let publication = match content {
        Some(identity) => {
            let decoded = decode_content_publication_key(key)?;
            if !identity.matches(&decoded.topic, &decoded.scope, decoded.blob_id) {
                return Err(pressure_corruption(
                    "Blob pressure content candidate escaped its exact partition",
                ));
            }
            decoded.publication
        }
        None => decode_publication_key(key)?,
    };
    if publication.priority >= incoming_priority {
        return Ok(Some(None));
    }
    let roots = read.open_table(BLOB_PRESSURE_PUBLICATION_ROOTS)?;
    let encoded = roots
        .get(publication.transfer_id.as_bytes().as_slice())?
        .ok_or_else(|| pressure_corruption("pressure publication index lacks its root"))?;
    if !charge.charge(32, encoded.value().len(), true)? {
        return Ok(None);
    }
    let root = decode_publication_root(encoded.value())?;
    let expected = match content {
        Some(identity) => {
            if !identity.matches(&root.topic, &root.scope, root.blob_id) {
                return Err(pressure_corruption(
                    "Blob pressure publication root escaped its exact content partition",
                ));
            }
            content_publication_index_key_read(read, &root, publication.transfer_id)?
        }
        None => publication_index_key_read(
            read,
            PressurePublicationKey {
                priority: root.priority,
                expiry: root.expiry,
                acceptance_order: root.acceptance_order,
                transfer_id: publication.transfer_id,
            },
        )?,
    };
    if root.priority != publication.priority || expected != key {
        return Err(pressure_corruption(
            "Blob pressure publication index contradicts its root",
        ));
    }
    Ok(Some(Some(PressureCandidate::Publication(
        publication.transfer_id,
    ))))
}

fn select_global_publication_read(
    read: &redb::ReadTransaction,
    incoming_priority: Priority,
    charge: &mut PressureSelectionCharge,
    eligibility: PressureSelectionEligibility,
) -> Result<(Option<PressureCandidate>, bool), StoreError> {
    let table = read.open_table(match eligibility {
        PressureSelectionEligibility::AllVisible => BLOB_PRESSURE_PUBLICATIONS,
        PressureSelectionEligibility::DurableOnly => BLOB_PRESSURE_DURABLE_PUBLICATIONS,
    })?;
    for row in table.iter()? {
        let (key, value) = row?;
        if !charge.charge(key.value().len(), value.value().len(), false)? {
            return Ok((None, false));
        }
        if !value.value().is_empty() {
            return Err(pressure_corruption(
                "Blob pressure publication index value is not empty",
            ));
        }
        let publication = decode_publication_key(key.value())?;
        if !eligibility.admits(publication.expiry) {
            if eligibility == PressureSelectionEligibility::DurableOnly {
                return Err(pressure_corruption(
                    "durable publication index contains a finite candidate",
                ));
            }
            continue;
        }
        return match select_publication_from_row(
            read,
            key.value(),
            value.value(),
            None,
            incoming_priority,
            charge,
        )? {
            Some(candidate) => Ok((candidate, true)),
            None => Ok((None, false)),
        };
    }
    Ok((None, true))
}

fn select_content_publication_read(
    read: &redb::ReadTransaction,
    identity: PressureContentIdentity,
    incoming_priority: Priority,
    charge: &mut PressureSelectionCharge,
    eligibility: PressureSelectionEligibility,
) -> Result<(Option<PressureCandidate>, bool), StoreError> {
    let prefix = identity.index_prefix()?;
    let upper = pressure_prefix_upper_bound(&prefix)?;
    let table = read.open_table(match eligibility {
        PressureSelectionEligibility::AllVisible => BLOB_PRESSURE_CONTENT_PUBLICATIONS,
        PressureSelectionEligibility::DurableOnly => BLOB_PRESSURE_DURABLE_CONTENT_PUBLICATIONS,
    })?;
    for row in table.range::<&[u8]>((
        std::ops::Bound::Included(prefix.as_slice()),
        std::ops::Bound::Excluded(upper.as_slice()),
    ))? {
        let (key, value) = row?;
        if !charge.charge(key.value().len(), value.value().len(), false)? {
            return Ok((None, false));
        }
        if !value.value().is_empty() {
            return Err(pressure_corruption(
                "Blob pressure publication index value is not empty",
            ));
        }
        let publication = decode_content_publication_key(key.value())?.publication;
        if !eligibility.admits(publication.expiry) {
            if eligibility == PressureSelectionEligibility::DurableOnly {
                return Err(pressure_corruption(
                    "durable content publication index contains a finite candidate",
                ));
            }
            continue;
        }
        return match select_publication_from_row(
            read,
            key.value(),
            value.value(),
            Some(identity),
            incoming_priority,
            charge,
        )? {
            Some(candidate) => Ok((candidate, true)),
            None => Ok((None, false)),
        };
    }
    Ok((None, true))
}

fn select_pending_source_read(
    read: &redb::ReadTransaction,
    incoming_priority: Priority,
    charge: &mut PressureSelectionCharge,
    eligibility: PressureSelectionEligibility,
) -> Result<(Option<PressureCandidate>, bool), StoreError> {
    let table = read.open_table(match eligibility {
        PressureSelectionEligibility::AllVisible => BLOB_PRESSURE_PENDING_SOURCES,
        PressureSelectionEligibility::DurableOnly => BLOB_PRESSURE_DURABLE_PENDING_SOURCES,
    })?;
    for row in table.iter()? {
        let (key, value) = row?;
        let key_bytes = key.value();
        if !charge.charge(key_bytes.len(), value.value().len(), false)? {
            return Ok((None, false));
        }
        if !value.value().is_empty() {
            return Err(pressure_corruption(
                "Blob pressure pending index value is not empty",
            ));
        }
        let entry = decode_pending_index_key(&key_bytes)?;
        if !eligibility.admits(entry.expiry) {
            if eligibility == PressureSelectionEligibility::DurableOnly {
                return Err(pressure_corruption(
                    "durable pending index contains a finite candidate",
                ));
            }
            continue;
        }
        if entry.priority >= incoming_priority {
            return Ok((None, true));
        }
        let roots = read.open_table(BLOB_PRESSURE_PENDING_ROOTS)?;
        let encoded = roots
            .get(entry.transfer_id.as_bytes().as_slice())?
            .ok_or_else(|| pressure_corruption("pressure pending index lacks its root"))?;
        if !charge.charge(32, encoded.value().len(), true)? {
            return Ok((None, false));
        }
        let root = decode_pending_root(encoded.value())?;
        if pending_index_key_read(read, root, entry.transfer_id)? != key_bytes {
            return Err(pressure_corruption(
                "Blob pressure pending index contradicts its root",
            ));
        }
        return Ok((
            Some(PressureCandidate::PendingSource(entry.transfer_id)),
            true,
        ));
    }
    Ok((None, true))
}

fn select_variant_read(
    read: &redb::ReadTransaction,
    incoming_priority: Priority,
    charge: &mut PressureSelectionCharge,
    eligibility: PressureSelectionEligibility,
) -> Result<(Option<PressureCandidate>, bool), StoreError> {
    let table = read.open_table(match eligibility {
        PressureSelectionEligibility::AllVisible => BLOB_PRESSURE_VARIANTS,
        PressureSelectionEligibility::DurableOnly => BLOB_PRESSURE_DURABLE_VARIANTS,
    })?;
    if let Some(row) = table.iter()?.next().transpose()? {
        let (key, value) = row;
        let key_bytes = key.value();
        if !charge.charge(key_bytes.len(), value.value().len(), false)? {
            return Ok((None, false));
        }
        if !value.value().is_empty() {
            return Err(pressure_corruption(
                "Blob pressure variant index value is not empty",
            ));
        }
        let (indexed, variant) = decode_variant_index_key(&key_bytes)?;
        if eligibility == PressureSelectionEligibility::DurableOnly && indexed.has_finite_roots {
            return Err(pressure_corruption(
                "durable variant index contains a finite-root candidate",
            ));
        }
        if indexed.effective_priority >= incoming_priority {
            return Ok((None, true));
        }
        if indexed
            .publication_roots
            .checked_add(indexed.pending_roots)
            .ok_or(StoreError::ItemCountAccountingOverflow)?
            > charge.budget.roots
        {
            return Ok((None, false));
        }
        let summaries = read.open_table(BLOB_PRESSURE_VARIANT_SUMMARIES)?;
        let encoded = summaries
            .get(variant.as_bytes().as_slice())?
            .ok_or_else(|| pressure_corruption("pressure variant index lacks its summary"))?;
        if !charge.charge(32, encoded.value().len(), false)? {
            return Ok((None, false));
        }
        let actual = decode_variant_summary(encoded.value())?;
        if actual != indexed || variant_index_key_read(read, actual, variant)? != key_bytes {
            return Err(pressure_corruption(
                "Blob pressure variant index contradicts its summary",
            ));
        }
        return Ok((Some(PressureCandidate::Variant(variant)), true));
    }
    Ok((None, true))
}

/// Selects only from the rejected partition using the canonical ordered index.
/// `proven == false` means the first candidate could not be established inside
/// the supplied bounds and therefore no mutation is permitted.
pub(crate) fn select_pressure_candidate_read(
    read: &redb::ReadTransaction,
    demand: BlobCapacityRecoveryDemand,
    budget: BlobPressureRecoveryBudget,
) -> Result<PressureSelection, StoreError> {
    select_pressure_candidate_read_with_eligibility(
        read,
        demand,
        budget,
        PressureSelectionEligibility::AllVisible,
    )
}

pub(crate) fn select_durable_pressure_candidate_read(
    read: &redb::ReadTransaction,
    demand: BlobCapacityRecoveryDemand,
    budget: BlobPressureRecoveryBudget,
) -> Result<PressureSelection, StoreError> {
    select_pressure_candidate_read_with_eligibility(
        read,
        demand,
        budget,
        PressureSelectionEligibility::DurableOnly,
    )
}

fn select_pressure_candidate_read_with_eligibility(
    read: &redb::ReadTransaction,
    demand: BlobCapacityRecoveryDemand,
    budget: BlobPressureRecoveryBudget,
    eligibility: PressureSelectionEligibility,
) -> Result<PressureSelection, StoreError> {
    let mut charge = PressureSelectionCharge::new(budget);
    if !pressure_ready_read(read)? {
        return Ok(charge.finish(None, true));
    }
    let (candidate, proven) = match demand.partition {
        BlobCapacityPartition::AggregateItems | BlobCapacityPartition::AggregateBytes => {
            select_global_publication_read(
                read,
                demand.incoming_priority,
                &mut charge,
                eligibility,
            )?
        }
        BlobCapacityPartition::ContentPublications(identity) => select_content_publication_read(
            read,
            identity,
            demand.incoming_priority,
            &mut charge,
            eligibility,
        )?,
        BlobCapacityPartition::NetworkStagingRows | BlobCapacityPartition::NetworkStagingBytes => {
            select_pending_source_read(read, demand.incoming_priority, &mut charge, eligibility)?
        }
        BlobCapacityPartition::DepotBytes
        | BlobCapacityPartition::DepotChunks
        | BlobCapacityPartition::DepotVariants => {
            select_variant_read(read, demand.incoming_priority, &mut charge, eligibility)?
        }
        BlobCapacityPartition::Operation | BlobCapacityPartition::PublicationLifecycle => {
            (None, true)
        }
    };
    Ok(charge.finish(candidate, proven))
}

fn pressure_ready_read(read: &redb::ReadTransaction) -> Result<bool, StoreError> {
    let metadata = read.open_table(BLOB_PRESSURE_METADATA)?;
    let version = metadata
        .get(PRESSURE_SCHEMA_VERSION_FIELD)?
        .map(|value| value.value())
        .ok_or_else(|| pressure_corruption("Blob pressure schema version is missing"))?;
    if version != PRESSURE_SCHEMA_VERSION {
        return match version {
            2 | PREVIOUS_PRESSURE_SCHEMA_VERSION | PRESSURE_V4_SCHEMA_VERSION => Ok(true),
            _ => Err(pressure_corruption(
                "Blob pressure schema version is unknown",
            )),
        };
    }
    let dirty = metadata
        .get(REANCHOR_DIRTY)?
        .map(|value| value.value())
        .ok_or_else(|| pressure_corruption("Blob pressure reanchor dirty flag is missing"))?;
    if dirty == 1 {
        return Ok(false);
    }
    if dirty != 0 {
        return Err(pressure_corruption(
            "Blob pressure reanchor dirty flag is invalid",
        ));
    }
    let target = metadata
        .get(REANCHOR_TARGET_GENERATION)?
        .map(|value| value.value())
        .ok_or_else(|| pressure_corruption("Blob pressure reanchor target is missing"))?;
    let current = crate::custody::lower_bound_continuity_read(read)?
        .map_or(0, |continuity| continuity.generation);
    if target != current {
        // A continuity observation can commit independently of the next Blob
        // write.  Read-side pressure must therefore fail closed until that
        // write establishes the fenced dirty pass; it is not store corruption.
        return Ok(false);
    }
    Ok(true)
}

pub(crate) fn pressure_ready_write(write: &redb::WriteTransaction) -> Result<bool, StoreError> {
    let metadata = write.open_table(BLOB_PRESSURE_METADATA)?;
    let version = metadata
        .get(PRESSURE_SCHEMA_VERSION_FIELD)?
        .map(|value| value.value())
        .ok_or_else(|| pressure_corruption("Blob pressure schema version is missing"))?;
    if version != PRESSURE_SCHEMA_VERSION {
        return match version {
            2 | PREVIOUS_PRESSURE_SCHEMA_VERSION | PRESSURE_V4_SCHEMA_VERSION => Ok(true),
            _ => Err(pressure_corruption(
                "Blob pressure schema version is unknown",
            )),
        };
    }
    let dirty = metadata
        .get(REANCHOR_DIRTY)?
        .map(|value| value.value())
        .ok_or_else(|| pressure_corruption("Blob pressure reanchor dirty flag is missing"))?;
    if dirty == 1 {
        return Ok(false);
    }
    if dirty != 0 {
        return Err(pressure_corruption(
            "Blob pressure reanchor dirty flag is invalid",
        ));
    }
    let target = metadata
        .get(REANCHOR_TARGET_GENERATION)?
        .map(|value| value.value())
        .ok_or_else(|| pressure_corruption("Blob pressure reanchor target is missing"))?;
    let current = crate::custody::lower_bound_continuity_write(write)?
        .map_or(0, |continuity| continuity.generation);
    if target != current {
        return Ok(false);
    }
    Ok(true)
}

fn compare_index_prefix(left: &[u8], right: &[u8]) -> Ordering {
    left[..12].cmp(&right[..12])
}

fn compare_index_key(left: &[u8], right: &[u8], identity_end: usize) -> Ordering {
    compare_index_prefix(left, right)
        .then_with(|| {
            let left_fraction = PressureFraction {
                numerator: u64::from_be_bytes(left[12..20].try_into().unwrap()),
                denominator: u64::from_be_bytes(left[20..28].try_into().unwrap()),
            };
            let right_fraction = PressureFraction {
                numerator: u64::from_be_bytes(right[12..20].try_into().unwrap()),
                denominator: u64::from_be_bytes(right[20..28].try_into().unwrap()),
            };
            if left_fraction.denominator == 0 || right_fraction.denominator == 0 {
                left[12..28].cmp(&right[12..28])
            } else {
                compare_pressure_fraction(left_fraction, right_fraction)
            }
        })
        .then_with(|| left[28..36].cmp(&right[28..36]))
        .then_with(|| left[36..identity_end].cmp(&right[36..identity_end]))
        .then_with(|| left[identity_end..].cmp(&right[identity_end..]))
        .then_with(|| left[12..28].cmp(&right[12..28]))
}

impl Key for PressurePendingIndexKey {
    fn compare(left: &[u8], right: &[u8]) -> Ordering {
        compare_index_key(left, right, PRESSURE_PENDING_INDEX_LEN)
    }
}

impl Key for PressureVariantIndexKey {
    fn compare(left: &[u8], right: &[u8]) -> Ordering {
        compare_index_key(left, right, 68)
    }
}

fn pressure_content_identity(
    topic: &Topic,
    scope: &Scope,
    blob_id: BlobId,
) -> Result<Vec<u8>, StoreError> {
    let topic = topic.as_str().as_bytes();
    let scope = scope.as_str().as_bytes();
    let topic_len = u16::try_from(topic.len())
        .map_err(|_| pressure_corruption("Blob pressure topic length overflows"))?;
    let scope_len = u16::try_from(scope.len())
        .map_err(|_| pressure_corruption("Blob pressure scope length overflows"))?;
    let mut canonical = Vec::with_capacity(4 + topic.len() + scope.len() + 32);
    canonical.extend_from_slice(&topic_len.to_be_bytes());
    canonical.extend_from_slice(topic);
    canonical.extend_from_slice(&scope_len.to_be_bytes());
    canonical.extend_from_slice(scope);
    canonical.extend_from_slice(blob_id.as_bytes());
    Ok(canonical)
}

pub(crate) fn encode_content_publication_key(
    root: &PressurePublicationRoot,
    transfer_id: BlobTransferId,
) -> Result<Vec<u8>, StoreError> {
    encode_content_publication_key_for_generation(root, transfer_id, false)
}

fn content_publication_index_key_write(
    write: &redb::WriteTransaction,
    root: &PressurePublicationRoot,
    transfer_id: BlobTransferId,
) -> Result<Vec<u8>, StoreError> {
    encode_content_publication_key_for_generation(
        root,
        transfer_id,
        expiry_indexes_active_write(write)?,
    )
}

fn content_publication_index_key_read(
    read: &redb::ReadTransaction,
    root: &PressurePublicationRoot,
    transfer_id: BlobTransferId,
) -> Result<Vec<u8>, StoreError> {
    encode_content_publication_key_for_generation(
        root,
        transfer_id,
        expiry_indexes_active_read(read)?,
    )
}

fn encode_content_publication_key_for_generation(
    root: &PressurePublicationRoot,
    transfer_id: BlobTransferId,
    activate_expiry: bool,
) -> Result<Vec<u8>, StoreError> {
    let identity = pressure_content_identity(&root.topic, &root.scope, root.blob_id)?;
    let mut digest = Sha256::new();
    digest.update(PRESSURE_CONTENT_DOMAIN);
    digest.update(&identity);
    let global = encode_publication_key_for_generation(
        PressurePublicationKey {
            priority: root.priority,
            expiry: root.expiry,
            acceptance_order: root.acceptance_order,
            transfer_id,
        },
        activate_expiry,
    );
    let mut output = Vec::with_capacity(1 + 32 + identity.len() + global.len() - 1);
    output.push(PRESSURE_RECORD_VERSION);
    output.extend_from_slice(&digest.finalize());
    output.extend_from_slice(&identity);
    output.extend_from_slice(&global[1..]);
    Ok(output)
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct PressureContentPublicationKey {
    pub(crate) topic: Topic,
    pub(crate) scope: Scope,
    pub(crate) blob_id: BlobId,
    pub(crate) publication: PressurePublicationKey,
}

pub(crate) fn decode_content_publication_key(
    bytes: &[u8],
) -> Result<PressureContentPublicationKey, StoreError> {
    let mut cursor = PressureCursor::new(bytes);
    cursor.version()?;
    let stored_digest: [u8; 32] = cursor.array()?;
    let topic = Topic::new(cursor.short_string()?)
        .map_err(|_| pressure_corruption("Blob pressure content index has an invalid topic"))?;
    let scope = Scope::new(cursor.short_string()?)
        .map_err(|_| pressure_corruption("Blob pressure content index has an invalid scope"))?;
    let blob_id = BlobId::from_bytes(cursor.array()?);
    let mut global = Vec::with_capacity(1 + bytes.len().saturating_sub(cursor.offset));
    global.push(PRESSURE_RECORD_VERSION);
    global.extend_from_slice(cursor.take(bytes.len().saturating_sub(cursor.offset))?);
    cursor.finish()?;
    let publication = decode_publication_key(&global)?;
    let identity = pressure_content_identity(&topic, &scope, blob_id)?;
    let mut digest = Sha256::new();
    digest.update(PRESSURE_CONTENT_DOMAIN);
    digest.update(identity);
    if digest.finalize().as_slice() != stored_digest {
        return Err(pressure_corruption(
            "Blob pressure content index identity digest is contradictory",
        ));
    }
    Ok(PressureContentPublicationKey {
        topic,
        scope,
        blob_id,
        publication,
    })
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct PressureVariantSummary {
    pub(crate) effective_priority: Priority,
    pub(crate) minimum_root_acceptance_order: u64,
    pub(crate) committed_progress: PressureFraction,
    pub(crate) finalized: bool,
    pub(crate) publication_roots: u64,
    pub(crate) pending_roots: u64,
    pub(crate) final_reference_expiry: PressureExpiry,
    pub(crate) has_finite_roots: bool,
}

pub(crate) fn encode_variant_summary(summary: PressureVariantSummary) -> Vec<u8> {
    encode_variant_summary_for_generation(summary, false)
}

fn encode_variant_summary_for_generation(
    summary: PressureVariantSummary,
    activate_finite_aggregate: bool,
) -> Vec<u8> {
    let mut output = Vec::with_capacity(53);
    output.push(PRESSURE_RECORD_VERSION);
    output.push(summary.effective_priority as u8);
    output.extend_from_slice(&summary.minimum_root_acceptance_order.to_be_bytes());
    output.extend_from_slice(&summary.committed_progress.numerator.to_be_bytes());
    output.extend_from_slice(&summary.committed_progress.denominator.to_be_bytes());
    output.push(u8::from(summary.finalized));
    debug_assert!(summary.publication_roots < PRESSURE_VARIANT_HAS_FINITE_ROOT_MASK);
    let encoded_publication_roots = summary.publication_roots
        | if activate_finite_aggregate && summary.has_finite_roots {
            PRESSURE_VARIANT_HAS_FINITE_ROOT_MASK
        } else {
            0
        };
    output.extend_from_slice(&encoded_publication_roots.to_be_bytes());
    output.extend_from_slice(&summary.pending_roots.to_be_bytes());
    summary.final_reference_expiry.encode(&mut output);
    output
}

fn encode_variant_summary_write(
    write: &redb::WriteTransaction,
    summary: PressureVariantSummary,
) -> Result<Vec<u8>, StoreError> {
    Ok(encode_variant_summary_for_generation(
        summary,
        finite_aggregate_active_write(write)?,
    ))
}

pub(crate) fn decode_variant_summary(bytes: &[u8]) -> Result<PressureVariantSummary, StoreError> {
    let mut cursor = PressureCursor::new(bytes);
    cursor.version()?;
    let effective_priority = decode_priority(cursor.u8()?)?;
    let minimum_root_acceptance_order = cursor.u64()?;
    if minimum_root_acceptance_order == 0 {
        return Err(pressure_corruption(
            "Blob pressure variant has a zero minimum acceptance order",
        ));
    }
    let committed_progress = PressureFraction::new(cursor.u64()?, cursor.u64()?)?;
    let finalized = match cursor.u8()? {
        0 => false,
        1 => true,
        _ => {
            return Err(pressure_corruption(
                "Blob pressure variant has an invalid finalization tag",
            ));
        }
    };
    let encoded_publication_roots = cursor.u64()?;
    let publication_roots = encoded_publication_roots & !PRESSURE_VARIANT_HAS_FINITE_ROOT_MASK;
    let has_finite_roots = encoded_publication_roots & PRESSURE_VARIANT_HAS_FINITE_ROOT_MASK != 0;
    let pending_roots = cursor.u64()?;
    if publication_roots == 0 && pending_roots == 0 {
        return Err(pressure_corruption(
            "Blob pressure variant has no authoritative roots",
        ));
    }
    let final_reference_expiry = PressureExpiry::decode(&mut cursor)?;
    cursor.finish()?;
    Ok(PressureVariantSummary {
        effective_priority,
        minimum_root_acceptance_order,
        committed_progress,
        finalized,
        publication_roots,
        pending_roots,
        final_reference_expiry,
        has_finite_roots,
    })
}

fn decode_priority(value: u8) -> Result<Priority, StoreError> {
    Priority::from_wire(value)
        .ok_or_else(|| pressure_corruption("Blob pressure record has an unknown priority"))
}

struct PressureCursor<'a> {
    bytes: &'a [u8],
    offset: usize,
}

impl<'a> PressureCursor<'a> {
    const fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, offset: 0 }
    }

    fn take(&mut self, length: usize) -> Result<&'a [u8], StoreError> {
        let end = self
            .offset
            .checked_add(length)
            .ok_or_else(|| pressure_corruption("Blob pressure record length overflows"))?;
        let value = self
            .bytes
            .get(self.offset..end)
            .ok_or_else(|| pressure_corruption("Blob pressure record is truncated"))?;
        self.offset = end;
        Ok(value)
    }

    fn u8(&mut self) -> Result<u8, StoreError> {
        Ok(self.take(1)?[0])
    }

    fn u16(&mut self) -> Result<u16, StoreError> {
        Ok(u16::from_be_bytes(self.take(2)?.try_into().map_err(
            |_| pressure_corruption("Blob pressure short length is malformed"),
        )?))
    }

    fn u64(&mut self) -> Result<u64, StoreError> {
        Ok(u64::from_be_bytes(self.take(8)?.try_into().map_err(
            |_| pressure_corruption("Blob pressure integer is malformed"),
        )?))
    }

    fn array<const N: usize>(&mut self) -> Result<[u8; N], StoreError> {
        self.take(N)?
            .try_into()
            .map_err(|_| pressure_corruption("Blob pressure fixed identity is malformed"))
    }

    fn short_string(&mut self) -> Result<String, StoreError> {
        let length = usize::from(self.u16()?);
        let bytes = self.take(length)?;
        std::str::from_utf8(bytes)
            .map(str::to_owned)
            .map_err(|_| pressure_corruption("Blob pressure string is not UTF-8"))
    }

    fn version(&mut self) -> Result<(), StoreError> {
        if self.u8()? != PRESSURE_RECORD_VERSION {
            return Err(pressure_corruption(
                "Blob pressure record has an unknown version",
            ));
        }
        Ok(())
    }

    fn finish(self) -> Result<(), StoreError> {
        if self.offset != self.bytes.len() {
            return Err(pressure_corruption(
                "Blob pressure record has trailing bytes",
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum PressureSchemaState {
    Predecessor,
    V4,
    OldV5,
    Current,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum PressureImageEncodingGeneration {
    LegacyV4,
    PreTask5V5,
    CurrentV5,
}

impl PressureImageEncodingGeneration {
    const fn expiry_indexes_active(self) -> bool {
        !matches!(self, Self::LegacyV4)
    }

    const fn finite_aggregate_active(self) -> bool {
        matches!(self, Self::CurrentV5)
    }

    const fn durable_indexes_active(self) -> bool {
        matches!(self, Self::CurrentV5)
    }
}

#[derive(Default)]
struct PressureImage {
    publication_roots: BTreeMap<Vec<u8>, Vec<u8>>,
    pending_roots: BTreeMap<Vec<u8>, Vec<u8>>,
    variant_summaries: BTreeMap<Vec<u8>, Vec<u8>>,
    publications: BTreeMap<Vec<u8>, Vec<u8>>,
    content_publications: BTreeMap<Vec<u8>, Vec<u8>>,
    pending_sources: BTreeMap<[u8; PRESSURE_PENDING_INDEX_LEN], Vec<u8>>,
    variants: BTreeMap<[u8; PRESSURE_VARIANT_INDEX_LEN], Vec<u8>>,
    durable_publications: BTreeMap<Vec<u8>, Vec<u8>>,
    durable_content_publications: BTreeMap<Vec<u8>, Vec<u8>>,
    durable_pending_sources: BTreeMap<[u8; PRESSURE_PENDING_INDEX_LEN], Vec<u8>>,
    durable_variants: BTreeMap<[u8; PRESSURE_VARIANT_INDEX_LEN], Vec<u8>>,
    finite_publication_generations: BTreeMap<Vec<u8>, u64>,
    finite_pending_generations: BTreeMap<Vec<u8>, u64>,
    next_pending_acceptance_order: u64,
    reanchor_target_generation: u64,
    reanchor_dirty: bool,
    reanchor_next_phase: u8,
    reanchor_live_cursor: Vec<u8>,
    reanchor_pending_cursor: Vec<u8>,
}

fn prepare_reanchor_image(
    write: &redb::WriteTransaction,
    image: &mut PressureImage,
) -> Result<(), StoreError> {
    let continuity = crate::custody::lower_bound_continuity_write(write)?;
    prepare_reanchor_image_from_continuity(image, continuity)
}

fn prepare_reanchor_image_from_continuity(
    image: &mut PressureImage,
    continuity: Option<crate::custody::LowerBoundContinuity>,
) -> Result<(), StoreError> {
    image.reanchor_target_generation = continuity.map_or(0, |value| value.generation);
    image.reanchor_next_phase = 1;
    let has_finite = image
        .publication_roots
        .values()
        .try_fold(false, |finite, value| {
            Ok::<_, StoreError>(
                finite || decode_publication_root(value)?.expiry != PressureExpiry::Durable,
            )
        })?
        || image
            .pending_roots
            .values()
            .try_fold(false, |finite, value| {
                Ok::<_, StoreError>(
                    finite || decode_pending_root(value)?.expiry != PressureExpiry::Durable,
                )
            })?;
    image.reanchor_dirty = has_finite && continuity.is_none();
    let cursor = |rows: &BTreeMap<Vec<u8>, Vec<u8>>| {
        rows.last_key_value()
            .map_or(PressureReanchorCursor::EmptyComplete, |(key, _)| {
                PressureReanchorCursor::Active {
                    end_transfer: BlobTransferId::new(
                        key.as_slice()
                            .try_into()
                            .expect("pressure root transfer key"),
                    ),
                    position: None,
                }
            })
    };
    image.reanchor_live_cursor = encode_reanchor_cursor(if image.reanchor_dirty {
        cursor(&image.publication_roots)
    } else {
        PressureReanchorCursor::EmptyComplete
    });
    image.reanchor_pending_cursor = encode_reanchor_cursor(if image.reanchor_dirty {
        cursor(&image.pending_roots)
    } else {
        PressureReanchorCursor::EmptyComplete
    });
    Ok(())
}

#[cfg(test)]
mod reanchor_codec_tests {
    use super::*;

    #[test]
    fn pressure_v5_reanchor_cursors_are_fenced_independent_and_canonical() {
        let end = BlobTransferId::new([0x70; 32]);
        let position = BlobTransferId::new([0x60; 32]);
        let active = PressureReanchorCursor::Active {
            end_transfer: end,
            position: Some(position),
        };
        let complete = PressureReanchorCursor::Complete { end_transfer: end };

        assert_eq!(
            decode_reanchor_cursor(&encode_reanchor_cursor(active)).unwrap(),
            active
        );
        assert_eq!(
            decode_reanchor_cursor(&encode_reanchor_cursor(complete)).unwrap(),
            complete
        );
        assert!(decode_reanchor_cursor(&[1, 1]).is_err());
        assert!(
            decode_reanchor_cursor(&encode_reanchor_cursor(PressureReanchorCursor::Active {
                end_transfer: position,
                position: Some(end),
            }))
            .is_err()
        );

        assert_eq!(PRESSURE_V4_SCHEMA_VERSION, 4);
        assert_eq!(PRESSURE_SCHEMA_VERSION, 5);
        assert_eq!(pressure_v5_metadata_fields().len(), 5);
        assert!(pressure_v5_metadata_fields().contains(&REANCHOR_TARGET_GENERATION));
        assert!(pressure_v5_metadata_fields().contains(&REANCHOR_DIRTY));
        assert!(pressure_v5_metadata_fields().contains(&REANCHOR_NEXT_PHASE));
    }

    #[test]
    fn pressure_v5_image_is_clean_with_valid_continuity_and_canonical_dirty_without_it() {
        // Mutations caught: marking every finite migration dirty unnecessarily
        // gates a fully projected image, while missing continuity must retain a
        // fenced dirty pass instead of pretending the image is clean.
        let transfer = BlobTransferId::new([0x81; 32]);
        let root = PressurePublicationRoot {
            variant_id: BlobVariantId::from_bytes([0x82; 32]),
            semantic_id: BlobSemanticId::new([0x83; 32]),
            priority: Priority::Routine,
            acceptance_order: 1,
            expiry: PressureExpiry::Finite(900),
            topic: Topic::new("ttl-reanchor").expect("topic"),
            scope: Scope::new("mission/ttl-reanchor").expect("scope"),
            blob_id: BlobId::from_bytes([0x84; 32]),
        };
        let mut image = PressureImage::default();
        image.publication_roots.insert(
            transfer.as_bytes().to_vec(),
            encode_publication_root(&root).expect("publication root"),
        );
        let continuity = crate::custody::LowerBoundContinuity {
            generation: 7,
            sample: aster_mesh::CustodySample {
                clock_id: [0x85; 16],
                tick_ms: 100,
            },
        };

        prepare_reanchor_image_from_continuity(&mut image, Some(continuity))
            .expect("valid-continuity image");
        assert_eq!(image.reanchor_target_generation, continuity.generation);
        assert!(!image.reanchor_dirty);
        assert_eq!(
            decode_reanchor_cursor(&image.reanchor_live_cursor).unwrap(),
            PressureReanchorCursor::EmptyComplete
        );
        assert_eq!(
            decode_reanchor_cursor(&image.reanchor_pending_cursor).unwrap(),
            PressureReanchorCursor::EmptyComplete
        );

        prepare_reanchor_image_from_continuity(&mut image, None).expect("missing-continuity image");
        assert_eq!(image.reanchor_target_generation, 0);
        assert!(image.reanchor_dirty);
        assert!(matches!(
            decode_reanchor_cursor(&image.reanchor_live_cursor).unwrap(),
            PressureReanchorCursor::Active { end_transfer, position: None }
                if end_transfer == transfer
        ));
        assert_eq!(
            decode_reanchor_cursor(&image.reanchor_pending_cursor).unwrap(),
            PressureReanchorCursor::EmptyComplete
        );
    }

    #[test]
    fn pressure_v5_dirty_audit_rejects_generation_mismatch_and_completed_pass() {
        // Mutations caught: dirty previously bypassed all target/cursor
        // invariants, allowing a mismatched generation or a fully completed
        // pass to remain pressure-eligible forever.
        let path = std::env::temp_dir().join(format!(
            "aster-pressure-v5-dirty-audit-{}.redb",
            std::process::id()
        ));
        let _ = std::fs::remove_file(&path);
        let database = redb::Database::create(&path).expect("dirty audit database");
        let write = database.begin_write().expect("dirty audit writer");
        {
            let mut metadata = write
                .open_table(BLOB_PRESSURE_METADATA)
                .expect("pressure metadata");
            for (field, value) in [
                (PRESSURE_SCHEMA_VERSION_FIELD, PRESSURE_SCHEMA_VERSION),
                (NEXT_PENDING_ACCEPTANCE_ORDER, 1),
                (REANCHOR_TARGET_GENERATION, 9),
                (REANCHOR_DIRTY, 1),
                (REANCHOR_NEXT_PHASE, 1),
            ] {
                metadata.insert(field, value).expect("metadata row");
            }
        }
        let empty = encode_reanchor_cursor(PressureReanchorCursor::EmptyComplete);
        {
            let mut cursors = write
                .open_table(BLOB_PRESSURE_REANCHOR_CURSORS)
                .expect("reanchor cursors");
            cursors.insert(1, empty.as_slice()).expect("live cursor");
            cursors.insert(2, empty.as_slice()).expect("pending cursor");
        }
        let continuity = crate::custody::LowerBoundContinuity {
            generation: 7,
            sample: aster_mesh::CustodySample {
                clock_id: [0x86; 16],
                tick_ms: 100,
            },
        };
        assert!(
            audit_reanchor_state(
                &write.open_table(BLOB_PRESSURE_METADATA).unwrap(),
                &write.open_table(BLOB_PRESSURE_REANCHOR_CURSORS).unwrap(),
                Some(continuity),
                false,
                &BTreeMap::new(),
                &BTreeMap::new(),
            )
            .is_err(),
            "dirty target must equal current continuity generation"
        );
        write
            .open_table(BLOB_PRESSURE_METADATA)
            .unwrap()
            .insert(REANCHOR_TARGET_GENERATION, continuity.generation)
            .unwrap();
        assert!(
            audit_reanchor_state(
                &write.open_table(BLOB_PRESSURE_METADATA).unwrap(),
                &write.open_table(BLOB_PRESSURE_REANCHOR_CURSORS).unwrap(),
                Some(continuity),
                false,
                &BTreeMap::new(),
                &BTreeMap::new(),
            )
            .is_err(),
            "a completed dirty pass must clear atomically"
        );
        drop(write);
        drop(database);
        std::fs::remove_file(path).expect("remove dirty audit database");
    }

    #[test]
    fn pressure_v5_reanchor_audit_rejects_clean_or_cursor_skipped_stale_finite_roots() {
        let path = std::env::temp_dir().join(format!(
            "aster-pressure-v5-root-generation-audit-{}.redb",
            std::process::id()
        ));
        let _ = std::fs::remove_file(&path);
        let database = redb::Database::create(&path).unwrap();
        let write = database.begin_write().unwrap();
        {
            let mut metadata = write.open_table(BLOB_PRESSURE_METADATA).unwrap();
            for (field, value) in [
                (PRESSURE_SCHEMA_VERSION_FIELD, PRESSURE_SCHEMA_VERSION),
                (NEXT_PENDING_ACCEPTANCE_ORDER, 1),
                (REANCHOR_TARGET_GENERATION, 7),
                (REANCHOR_DIRTY, 0),
                (REANCHOR_NEXT_PHASE, 1),
            ] {
                metadata.insert(field, value).unwrap();
            }
        }
        let empty = encode_reanchor_cursor(PressureReanchorCursor::EmptyComplete);
        {
            let mut cursors = write.open_table(BLOB_PRESSURE_REANCHOR_CURSORS).unwrap();
            cursors.insert(1, empty.as_slice()).unwrap();
            cursors.insert(2, empty.as_slice()).unwrap();
        }
        let continuity = crate::custody::LowerBoundContinuity {
            generation: 8,
            sample: aster_mesh::CustodySample {
                clock_id: [0x96; 16],
                tick_ms: 100,
            },
        };
        let mut finite_live = BTreeMap::from([(vec![0x30; 32], 6)]);
        let finite_pending = BTreeMap::new();
        assert!(
            audit_reanchor_state(
                &write.open_table(BLOB_PRESSURE_METADATA).unwrap(),
                &write.open_table(BLOB_PRESSURE_REANCHOR_CURSORS).unwrap(),
                Some(continuity),
                true,
                &finite_live,
                &finite_pending,
            )
            .is_err()
        );
        finite_live.insert(vec![0x30; 32], 7);
        audit_reanchor_state(
            &write.open_table(BLOB_PRESSURE_METADATA).unwrap(),
            &write.open_table(BLOB_PRESSURE_REANCHOR_CURSORS).unwrap(),
            Some(continuity),
            true,
            &finite_live,
            &finite_pending,
        )
        .expect("clean lag is valid only when every finite root matches target");

        write
            .open_table(BLOB_PRESSURE_METADATA)
            .unwrap()
            .insert(REANCHOR_DIRTY, 1)
            .unwrap();
        let live = encode_reanchor_cursor(PressureReanchorCursor::Active {
            end_transfer: BlobTransferId::new([0x80; 32]),
            position: Some(BlobTransferId::new([0x40; 32])),
        });
        write
            .open_table(BLOB_PRESSURE_REANCHOR_CURSORS)
            .unwrap()
            .insert(1, live.as_slice())
            .unwrap();
        for (key, valid) in [
            (vec![0x30; 32], false),
            (vec![0x50; 32], true),
            (vec![0x90; 32], false),
        ] {
            finite_live = BTreeMap::from([(key, 6)]);
            assert_eq!(
                audit_reanchor_state(
                    &write.open_table(BLOB_PRESSURE_METADATA).unwrap(),
                    &write.open_table(BLOB_PRESSURE_REANCHOR_CURSORS).unwrap(),
                    Some(continuity),
                    true,
                    &finite_live,
                    &finite_pending,
                )
                .is_ok(),
                valid,
            );
        }
        drop(write);
        drop(database);
        std::fs::remove_file(path).unwrap();
    }
}

#[cfg(test)]
thread_local! {
    pub(crate) static TEST_PRESSURE_MIGRATION_FAULT: std::cell::Cell<bool> = const {
        std::cell::Cell::new(false)
    };
    static TEST_PRESSURE_FULL_SCAN_ROWS: std::cell::Cell<u64> = const {
        std::cell::Cell::new(0)
    };
}

#[cfg(test)]
pub(crate) fn reset_transition_full_scan_rows_for_test() {
    TEST_PRESSURE_FULL_SCAN_ROWS.set(0);
}

#[cfg(test)]
pub(crate) fn transition_full_scan_rows_for_test() -> u64 {
    TEST_PRESSURE_FULL_SCAN_ROWS.get()
}

fn note_full_scan_row() {
    #[cfg(test)]
    TEST_PRESSURE_FULL_SCAN_ROWS.set(
        TEST_PRESSURE_FULL_SCAN_ROWS
            .get()
            .checked_add(1)
            .expect("test pressure scan counter"),
    );
}

fn pressure_v4_table_names() -> [&'static str; 8] {
    [
        BLOB_PRESSURE_METADATA.name(),
        BLOB_PRESSURE_PUBLICATION_ROOTS.name(),
        BLOB_PRESSURE_PENDING_ROOTS.name(),
        BLOB_PRESSURE_VARIANT_SUMMARIES.name(),
        BLOB_PRESSURE_PUBLICATIONS.name(),
        BLOB_PRESSURE_CONTENT_PUBLICATIONS.name(),
        BLOB_PRESSURE_PENDING_SOURCES.name(),
        BLOB_PRESSURE_VARIANTS.name(),
    ]
}

fn pressure_old_v5_table_names() -> [&'static str; 9] {
    [
        BLOB_PRESSURE_METADATA.name(),
        BLOB_PRESSURE_PUBLICATION_ROOTS.name(),
        BLOB_PRESSURE_PENDING_ROOTS.name(),
        BLOB_PRESSURE_VARIANT_SUMMARIES.name(),
        BLOB_PRESSURE_PUBLICATIONS.name(),
        BLOB_PRESSURE_CONTENT_PUBLICATIONS.name(),
        BLOB_PRESSURE_PENDING_SOURCES.name(),
        BLOB_PRESSURE_VARIANTS.name(),
        BLOB_PRESSURE_REANCHOR_CURSORS.name(),
    ]
}

fn pressure_table_names() -> [&'static str; 13] {
    [
        BLOB_PRESSURE_METADATA.name(),
        BLOB_PRESSURE_PUBLICATION_ROOTS.name(),
        BLOB_PRESSURE_PENDING_ROOTS.name(),
        BLOB_PRESSURE_VARIANT_SUMMARIES.name(),
        BLOB_PRESSURE_PUBLICATIONS.name(),
        BLOB_PRESSURE_CONTENT_PUBLICATIONS.name(),
        BLOB_PRESSURE_PENDING_SOURCES.name(),
        BLOB_PRESSURE_VARIANTS.name(),
        BLOB_PRESSURE_REANCHOR_CURSORS.name(),
        BLOB_PRESSURE_DURABLE_PUBLICATIONS.name(),
        BLOB_PRESSURE_DURABLE_CONTENT_PUBLICATIONS.name(),
        BLOB_PRESSURE_DURABLE_PENDING_SOURCES.name(),
        BLOB_PRESSURE_DURABLE_VARIANTS.name(),
    ]
}

#[cfg(test)]
pub(crate) fn pressure_table_names_for_test() -> [&'static str; 13] {
    pressure_table_names()
}

fn pressure_schema_state<T>(transaction: &T) -> Result<PressureSchemaState, StoreError>
where
    T: PressureTableCatalog,
{
    let names = pressure_table_names();
    let normal = transaction.normal_table_names()?;
    if transaction
        .multimap_table_names()?
        .iter()
        .any(|name| names.contains(&name.as_str()))
    {
        return Err(pressure_corruption(
            "Blob pressure schema has a table with the wrong kind",
        ));
    }
    let present = names.iter().filter(|name| normal.contains(**name)).count();
    match present {
        0 => Ok(PressureSchemaState::Predecessor),
        count
            if count == pressure_v4_table_names().len()
                && pressure_v4_table_names()
                    .iter()
                    .all(|name| normal.contains(*name)) =>
        {
            Ok(PressureSchemaState::V4)
        }
        count
            if count == pressure_old_v5_table_names().len()
                && pressure_old_v5_table_names()
                    .iter()
                    .all(|name| normal.contains(*name)) =>
        {
            Ok(PressureSchemaState::OldV5)
        }
        count if count == names.len() => Ok(PressureSchemaState::Current),
        _ => Err(pressure_corruption(
            "Blob pressure schema is partial and cannot be repaired",
        )),
    }
}

trait PressureTableCatalog {
    fn normal_table_names(&self) -> Result<BTreeSet<String>, StoreError>;
    fn multimap_table_names(&self) -> Result<BTreeSet<String>, StoreError>;
}

impl PressureTableCatalog for redb::WriteTransaction {
    fn normal_table_names(&self) -> Result<BTreeSet<String>, StoreError> {
        Ok(self
            .list_tables()?
            .map(|table| table.name().to_owned())
            .collect())
    }

    fn multimap_table_names(&self) -> Result<BTreeSet<String>, StoreError> {
        Ok(self
            .list_multimap_tables()?
            .map(|table| table.name().to_owned())
            .collect())
    }
}

impl PressureTableCatalog for redb::ReadTransaction {
    fn normal_table_names(&self) -> Result<BTreeSet<String>, StoreError> {
        Ok(self
            .list_tables()?
            .map(|table| table.name().to_owned())
            .collect())
    }

    fn multimap_table_names(&self) -> Result<BTreeSet<String>, StoreError> {
        Ok(self
            .list_multimap_tables()?
            .map(|table| table.name().to_owned())
            .collect())
    }
}

fn migrate_pending_acceptance_orders(
    write: &redb::WriteTransaction,
    generation: super::PendingBlobEncodingGeneration,
) -> Result<u64, StoreError> {
    let pending = write.open_table(super::BLOB_PENDING_SOURCES)?;
    let mut records = Vec::new();
    let mut saw_legacy = false;
    let mut saw_current = false;
    let mut unique = BTreeSet::new();
    let mut maximum = 0u64;
    for row in pending.iter()? {
        let (key, value) = row?;
        if key.value().len() != 32 {
            return Err(pressure_corruption(
                "pending Blob pressure migration found an invalid transfer identity",
            ));
        }
        let record = super::decode_pending_blob_source_for_encoding(value.value(), generation)?;
        if record.pending_acceptance_order == 0 {
            saw_legacy = true;
        } else {
            saw_current = true;
            maximum = maximum.max(record.pending_acceptance_order);
            if !unique.insert(record.pending_acceptance_order) {
                return Err(pressure_corruption(
                    "pending Blob acceptance order is duplicated",
                ));
            }
        }
        records.push((key.value().to_vec(), record));
    }
    drop(pending);
    if saw_legacy && saw_current {
        return Err(pressure_corruption(
            "pending Blob sources mix legacy and current acceptance orders",
        ));
    }
    if saw_legacy {
        let mut next = 1u64;
        for (_, record) in &mut records {
            record.pending_acceptance_order = next;
            next = next.checked_add(1).ok_or_else(|| {
                pressure_corruption("pending Blob acceptance order overflows during migration")
            })?;
        }
        let added_bytes = u64::try_from(records.len())
            .map_err(|_| StoreError::PayloadByteAccountingOverflow)?
            .checked_mul(8)
            .ok_or(StoreError::PayloadByteAccountingOverflow)?;
        let metadata = write.open_table(super::BLOB_NETWORK_METADATA)?;
        let current = metadata
            .get(super::BLOB_NETWORK_STAGING_BYTES)?
            .map(|value| value.value())
            .ok_or_else(|| {
                pressure_corruption("Blob network staging byte counter is missing during migration")
            })?;
        let migrated = current
            .checked_add(added_bytes)
            .ok_or(StoreError::PayloadByteAccountingOverflow)?;
        if migrated > super::MAX_BLOB_NETWORK_STAGING_BYTES {
            return Err(blob_error(
                BlobStoreError::NetworkStagingByteLimitExceeded {
                    current,
                    incoming: added_bytes,
                    limit: super::MAX_BLOB_NETWORK_STAGING_BYTES,
                },
            ));
        }
        drop(metadata);
        let mut pending = write.open_table(super::BLOB_PENDING_SOURCES)?;
        for (key, record) in records {
            let encoded = super::encode_pending_blob_source(&record)?;
            pending.insert(key.as_slice(), encoded.as_slice())?;
        }
        drop(pending);
        let mut metadata = write.open_table(super::BLOB_NETWORK_METADATA)?;
        metadata.insert(super::BLOB_NETWORK_STAGING_BYTES, migrated)?;
        Ok(next)
    } else {
        maximum.checked_add(1).ok_or_else(|| {
            pressure_corruption("pending Blob acceptance order overflows during migration")
        })
    }
}

fn pending_progress(
    source: BlobTransferId,
    record: &super::PendingBlobSourceRecord,
    carrier_prefixes: &impl ReadableTable<&'static [u8], &'static [u8]>,
    imports: &impl ReadableTable<&'static [u8], &'static [u8]>,
    chunks: &impl ReadableTable<&'static [u8], &'static [u8]>,
) -> Result<PressureFraction, StoreError> {
    let total = record.carriers.iter().try_fold(0u64, |total, carrier| {
        total
            .checked_add(carrier.total_len)
            .ok_or(StoreError::PayloadByteAccountingOverflow)
    })?;
    let import = imports
        .get(record.metadata.variant_id.as_bytes().as_slice())?
        .map(|value| value.value().to_vec())
        .ok_or_else(|| pressure_corruption("pending Blob pressure root lacks its depot import"))?;
    let mut durable = 0u64;
    for carrier in &record.carriers {
        let mut key = [0u8; 40];
        key[..32].copy_from_slice(record.metadata.variant_id.as_bytes());
        key[32..].copy_from_slice(&carrier.index.to_be_bytes());
        let state = chunks
            .get(key.as_slice())?
            .map(|value| value.value().to_vec());
        if let Some(state) = state
            && super::depot::deletion_chunk_projection(&import, carrier.index, &state)?
                .record
                .is_some()
        {
            durable = durable
                .checked_add(carrier.total_len)
                .ok_or(StoreError::PayloadByteAccountingOverflow)?;
            continue;
        }
        let prefix_key = super::blob_carrier_prefix_key(source, carrier.object);
        let prefix = carrier_prefixes
            .get(prefix_key.as_slice())?
            .map(|value| super::decode_blob_carrier_prefix(value.value()))
            .transpose()?
            .map(|prefix| {
                if prefix.source != source || prefix.total_len != carrier.total_len {
                    return Err(pressure_corruption(
                        "Blob pressure carrier prefix contradicts its pending source",
                    ));
                }
                u64::try_from(prefix.prefix.len())
                    .map_err(|_| StoreError::PayloadByteAccountingOverflow)
            })
            .transpose()?
            .unwrap_or(0);
        durable = durable
            .checked_add(prefix)
            .ok_or(StoreError::PayloadByteAccountingOverflow)?;
    }
    authenticated_progress_fraction(durable, total)
}

#[allow(clippy::too_many_arguments)]
fn build_pressure_image(
    publications: &impl ReadableTable<&'static [u8], &'static [u8]>,
    markers: &impl ReadableTable<&'static [u8], u64>,
    pending: &impl ReadableTable<&'static [u8], &'static [u8]>,
    carrier_prefixes: &impl ReadableTable<&'static [u8], &'static [u8]>,
    imports: &impl ReadableTable<&'static [u8], &'static [u8]>,
    packs: &impl ReadableTable<&'static [u8], &'static [u8]>,
    chunks: &impl ReadableTable<&'static [u8], &'static [u8]>,
    next_pending_acceptance_order: u64,
    publication_encoding: super::lifecycle::PublicationEncodingGeneration,
    pending_root_encoding: PressurePendingRootEncodingGeneration,
    index_encoding: PressureImageEncodingGeneration,
) -> Result<PressureImage, StoreError> {
    if next_pending_acceptance_order == 0 {
        return Err(pressure_corruption(
            "next pending Blob acceptance order is zero",
        ));
    }
    let mut image = PressureImage {
        next_pending_acceptance_order,
        ..PressureImage::default()
    };
    let activate_expiry_indexes = index_encoding.expiry_indexes_active();
    let activate_finite_aggregate = index_encoding.finite_aggregate_active();
    let activate_durable_indexes = index_encoding.durable_indexes_active();
    let mut variant_roots =
        BTreeMap::<BlobVariantId, Vec<(Priority, u64, bool, PressureExpiry)>>::new();
    for row in publications.iter()? {
        note_full_scan_row();
        let (key, value) = row?;
        if super::lifecycle::publication_record_is_retired(value.value()).map_err(blob_error)? {
            continue;
        }
        let transfer = BlobTransferId::new(key.value().try_into().map_err(|_| {
            pressure_corruption("Blob pressure publication has an invalid transfer key")
        })?);
        let payload =
            super::lifecycle::publication_payload_for_encoding(value.value(), publication_encoding)
                .map_err(blob_error)?;
        let metadata = super::decode_blob_metadata(payload)?;
        if metadata.transfer_id != transfer {
            return Err(pressure_corruption(
                "Blob pressure publication key differs from its metadata",
            ));
        }
        if let super::BlobLifetime::Finite { age, .. } = metadata.lifetime {
            image
                .finite_publication_generations
                .insert(key.value().to_vec(), age.continuity_generation);
        }
        let acceptance_order = markers
            .get(key.value())?
            .map(|value| value.value())
            .ok_or_else(|| pressure_corruption("Blob pressure publication lacks its marker"))?;
        let root = PressurePublicationRoot {
            variant_id: metadata.variant_id,
            semantic_id: metadata.semantic_id,
            priority: metadata.header.priority,
            acceptance_order,
            expiry: lifetime_expiry(metadata.lifetime)?,
            topic: metadata.header.topic.clone(),
            scope: metadata.header.scope.clone(),
            blob_id: metadata.blob_id,
        };
        let root_value = encode_publication_root(&root)?;
        let global_key = encode_publication_key_for_generation(
            PressurePublicationKey {
                priority: root.priority,
                expiry: root.expiry,
                acceptance_order,
                transfer_id: transfer,
            },
            activate_expiry_indexes,
        );
        let content_key = encode_content_publication_key_for_generation(
            &root,
            transfer,
            activate_expiry_indexes,
        )?;
        image
            .publication_roots
            .insert(key.value().to_vec(), root_value);
        image.publications.insert(global_key.clone(), Vec::new());
        image
            .content_publications
            .insert(content_key.clone(), Vec::new());
        if activate_durable_indexes && root.expiry == PressureExpiry::Durable {
            image.durable_publications.insert(global_key, Vec::new());
            image
                .durable_content_publications
                .insert(content_key, Vec::new());
        }
        variant_roots.entry(root.variant_id).or_default().push((
            root.priority,
            acceptance_order,
            false,
            root.expiry,
        ));
    }

    let mut pending_orders = BTreeSet::new();
    let mut maximum_pending_order = 0u64;
    for row in pending.iter()? {
        note_full_scan_row();
        let (key, value) = row?;
        let source = BlobTransferId::new(key.value().try_into().map_err(|_| {
            pressure_corruption("Blob pressure pending source has an invalid transfer key")
        })?);
        let record = super::decode_pending_blob_source_for_encoding(
            value.value(),
            super::pending_blob_encoding_for_publication_encoding(publication_encoding),
        )?;
        let acceptance_order = record.pending_acceptance_order;
        if acceptance_order == 0 || !pending_orders.insert(acceptance_order) {
            return Err(pressure_corruption(
                "Blob pressure pending source has a missing or duplicate acceptance order",
            ));
        }
        maximum_pending_order = maximum_pending_order.max(acceptance_order);
        let root = PressurePendingRoot {
            variant_id: record.metadata.variant_id,
            authenticated_source_binding: record.authenticated_source_binding,
            priority: record.metadata.header.priority,
            acceptance_order,
            completion: pending_progress(source, &record, carrier_prefixes, imports, chunks)?,
            expiry: lifetime_expiry(record.metadata.lifetime)?,
            topic: record.metadata.header.topic.clone(),
            scope: record.metadata.header.scope.clone(),
            blob_id: record.metadata.blob_id,
        };
        if let super::BlobLifetime::Finite { age, .. } = record.metadata.lifetime {
            image
                .finite_pending_generations
                .insert(key.value().to_vec(), age.continuity_generation);
        }
        image.pending_roots.insert(
            key.value().to_vec(),
            encode_pending_root_for_generation(&root, pending_root_encoding)?,
        );
        let pending_key =
            encode_pending_index_key_for_generation(root.clone(), source, activate_expiry_indexes);
        image.pending_sources.insert(pending_key, Vec::new());
        if activate_durable_indexes && root.expiry == PressureExpiry::Durable {
            image
                .durable_pending_sources
                .insert(pending_key, Vec::new());
        }
        variant_roots.entry(root.variant_id).or_default().push((
            root.priority,
            acceptance_order,
            true,
            root.expiry,
        ));
    }
    if next_pending_acceptance_order <= maximum_pending_order {
        return Err(pressure_corruption(
            "next pending Blob acceptance order does not exceed assigned orders",
        ));
    }

    let mut import_values = BTreeMap::<BlobVariantId, Vec<u8>>::new();
    let mut import_facts = BTreeMap::new();
    for row in imports.iter()? {
        note_full_scan_row();
        let (key, value) = row?;
        let fact = super::depot::deletion_import_projection(key.value(), value.value())?;
        import_values.insert(fact.variant_id, value.value().to_vec());
        import_facts.insert(fact.variant_id, fact);
    }
    let mut pack_facts = BTreeMap::<BlobVariantId, u64>::new();
    for row in packs.iter()? {
        note_full_scan_row();
        let (key, value) = row?;
        if let Some((variant, total_len)) =
            super::pack_lifecycle::pressure_projection(value.value())?
            && (key.value() != variant.as_bytes()
                || import_facts.contains_key(&variant)
                || pack_facts.insert(variant, total_len).is_some())
        {
            return Err(pressure_corruption(
                "Blob pressure Profile-5 pack identity is contradictory",
            ));
        }
    }
    let mut committed = BTreeMap::<BlobVariantId, u64>::new();
    for row in chunks.iter()? {
        note_full_scan_row();
        let (key, value) = row?;
        if key.value().len() != 40 {
            return Err(pressure_corruption(
                "Blob pressure chunk key has an invalid length",
            ));
        }
        let variant = BlobVariantId::from_bytes(
            key.value()[..32]
                .try_into()
                .map_err(|_| pressure_corruption("Blob pressure chunk variant is invalid"))?,
        );
        let index = u64::from_be_bytes(
            key.value()[32..]
                .try_into()
                .map_err(|_| pressure_corruption("Blob pressure chunk index is invalid"))?,
        );
        let import_value = import_values.get(&variant).ok_or_else(|| {
            pressure_corruption("Blob pressure chunk is orphaned from its variant")
        })?;
        let projection =
            super::depot::deletion_chunk_projection(import_value, index, value.value())?;
        if let Some(record) = projection.record {
            let current = committed.entry(variant).or_default();
            *current = current
                .checked_add(u64::from(record.plaintext_len()))
                .ok_or(StoreError::PayloadByteAccountingOverflow)?;
        }
    }
    for (variant, roots) in variant_roots {
        let legacy_fact = import_facts.get(&variant);
        let pack_total = pack_facts.get(&variant).copied();
        if legacy_fact.is_none() == pack_total.is_none() {
            return Err(pressure_corruption(
                "Blob pressure rooted variant lacks one exact physical representation",
            ));
        }
        let effective_priority = roots
            .iter()
            .map(|(priority, _, _, _)| *priority)
            .max()
            .ok_or_else(|| pressure_corruption("Blob pressure variant has no roots"))?;
        let minimum_root_acceptance_order = roots
            .iter()
            .map(|(_, order, _, _)| *order)
            .min()
            .ok_or_else(|| pressure_corruption("Blob pressure variant has no roots"))?;
        let publication_roots =
            u64::try_from(roots.iter().filter(|(_, _, pending, _)| !*pending).count())
                .map_err(|_| StoreError::ItemCountAccountingOverflow)?;
        let pending_roots =
            u64::try_from(roots.iter().filter(|(_, _, pending, _)| *pending).count())
                .map_err(|_| StoreError::ItemCountAccountingOverflow)?;
        let (numerator, denominator, finalized) = if let Some(fact) = legacy_fact {
            (
                if fact.finalized_root.is_some() {
                    fact.total_len
                } else {
                    committed.get(&variant).copied().unwrap_or(0)
                },
                fact.total_len,
                fact.finalized_root.is_some(),
            )
        } else {
            let total = pack_total.expect("checked exact physical representation");
            (total, total, true)
        };
        let summary = PressureVariantSummary {
            effective_priority,
            minimum_root_acceptance_order,
            committed_progress: authenticated_progress_fraction(numerator, denominator)?,
            finalized,
            publication_roots,
            pending_roots,
            final_reference_expiry: roots
                .iter()
                .map(|(_, _, _, expiry)| *expiry)
                .reduce(latest_expiry)
                .ok_or_else(|| pressure_corruption("Blob pressure variant has no expiries"))?,
            has_finite_roots: roots
                .iter()
                .any(|(_, _, _, expiry)| *expiry != PressureExpiry::Durable),
        };
        image.variant_summaries.insert(
            variant.as_bytes().to_vec(),
            encode_variant_summary_for_generation(summary, activate_finite_aggregate),
        );
        let variant_key = encode_variant_index_key_for_generation(
            summary,
            variant,
            activate_expiry_indexes,
            activate_finite_aggregate,
        );
        image.variants.insert(variant_key, Vec::new());
        if activate_durable_indexes && !summary.has_finite_roots {
            image.durable_variants.insert(variant_key, Vec::new());
        }
    }
    Ok(image)
}

fn table_map(
    table: &impl ReadableTable<&'static [u8], &'static [u8]>,
) -> Result<BTreeMap<Vec<u8>, Vec<u8>>, StoreError> {
    table
        .iter()?
        .map(|row| {
            let (key, value) = row?;
            Ok((key.value().to_vec(), value.value().to_vec()))
        })
        .collect::<Result<_, redb::StorageError>>()
        .map_err(StoreError::from)
}

fn pending_index_map(
    table: &impl ReadableTable<PressurePendingIndexKey, &'static [u8]>,
) -> Result<BTreeMap<[u8; PRESSURE_PENDING_INDEX_LEN], Vec<u8>>, StoreError> {
    table
        .iter()?
        .map(|row| {
            let (key, value) = row?;
            Ok((key.value(), value.value().to_vec()))
        })
        .collect::<Result<_, redb::StorageError>>()
        .map_err(StoreError::from)
}

fn variant_index_map(
    table: &impl ReadableTable<PressureVariantIndexKey, &'static [u8]>,
) -> Result<BTreeMap<[u8; PRESSURE_VARIANT_INDEX_LEN], Vec<u8>>, StoreError> {
    table
        .iter()?
        .map(|row| {
            let (key, value) = row?;
            Ok((key.value(), value.value().to_vec()))
        })
        .collect::<Result<_, redb::StorageError>>()
        .map_err(StoreError::from)
}

fn audit_image_write(
    write: &redb::WriteTransaction,
    image: &PressureImage,
) -> Result<(), StoreError> {
    audit_image(
        &write.open_table(BLOB_PRESSURE_PUBLICATION_ROOTS)?,
        &write.open_table(BLOB_PRESSURE_PENDING_ROOTS)?,
        &write.open_table(BLOB_PRESSURE_VARIANT_SUMMARIES)?,
        &write.open_table(BLOB_PRESSURE_PUBLICATIONS)?,
        &write.open_table(BLOB_PRESSURE_CONTENT_PUBLICATIONS)?,
        &write.open_table(BLOB_PRESSURE_PENDING_SOURCES)?,
        &write.open_table(BLOB_PRESSURE_VARIANTS)?,
        image,
    )
}

fn audit_durable_image_write(
    write: &redb::WriteTransaction,
    image: &PressureImage,
) -> Result<(), StoreError> {
    audit_durable_image(
        &write.open_table(BLOB_PRESSURE_DURABLE_PUBLICATIONS)?,
        &write.open_table(BLOB_PRESSURE_DURABLE_CONTENT_PUBLICATIONS)?,
        &write.open_table(BLOB_PRESSURE_DURABLE_PENDING_SOURCES)?,
        &write.open_table(BLOB_PRESSURE_DURABLE_VARIANTS)?,
        image,
    )
}

fn audit_image_read(read: &redb::ReadTransaction, image: &PressureImage) -> Result<(), StoreError> {
    audit_image(
        &read.open_table(BLOB_PRESSURE_PUBLICATION_ROOTS)?,
        &read.open_table(BLOB_PRESSURE_PENDING_ROOTS)?,
        &read.open_table(BLOB_PRESSURE_VARIANT_SUMMARIES)?,
        &read.open_table(BLOB_PRESSURE_PUBLICATIONS)?,
        &read.open_table(BLOB_PRESSURE_CONTENT_PUBLICATIONS)?,
        &read.open_table(BLOB_PRESSURE_PENDING_SOURCES)?,
        &read.open_table(BLOB_PRESSURE_VARIANTS)?,
        image,
    )
}

fn audit_durable_image_read(
    read: &redb::ReadTransaction,
    image: &PressureImage,
) -> Result<(), StoreError> {
    audit_durable_image(
        &read.open_table(BLOB_PRESSURE_DURABLE_PUBLICATIONS)?,
        &read.open_table(BLOB_PRESSURE_DURABLE_CONTENT_PUBLICATIONS)?,
        &read.open_table(BLOB_PRESSURE_DURABLE_PENDING_SOURCES)?,
        &read.open_table(BLOB_PRESSURE_DURABLE_VARIANTS)?,
        image,
    )
}

fn audit_durable_image(
    publications: &impl ReadableTable<&'static [u8], &'static [u8]>,
    content_publications: &impl ReadableTable<&'static [u8], &'static [u8]>,
    pending_sources: &impl ReadableTable<PressurePendingIndexKey, &'static [u8]>,
    variants: &impl ReadableTable<PressureVariantIndexKey, &'static [u8]>,
    image: &PressureImage,
) -> Result<(), StoreError> {
    if table_map(publications)? != image.durable_publications
        || table_map(content_publications)? != image.durable_content_publications
        || pending_index_map(pending_sources)? != image.durable_pending_sources
        || variant_index_map(variants)? != image.durable_variants
    {
        return Err(pressure_corruption(
            "Blob pressure durable indexes contradict authoritative state",
        ));
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn audit_image(
    publication_roots: &impl ReadableTable<&'static [u8], &'static [u8]>,
    pending_roots: &impl ReadableTable<&'static [u8], &'static [u8]>,
    variant_summaries: &impl ReadableTable<&'static [u8], &'static [u8]>,
    publications: &impl ReadableTable<&'static [u8], &'static [u8]>,
    content_publications: &impl ReadableTable<&'static [u8], &'static [u8]>,
    pending_sources: &impl ReadableTable<PressurePendingIndexKey, &'static [u8]>,
    variants: &impl ReadableTable<PressureVariantIndexKey, &'static [u8]>,
    image: &PressureImage,
) -> Result<(), StoreError> {
    let actual_pending_roots = table_map(pending_roots)?;
    if actual_pending_roots != image.pending_roots {
        if actual_pending_roots.keys().collect::<Vec<_>>()
            != image.pending_roots.keys().collect::<Vec<_>>()
        {
            return Err(pressure_corruption(
                "Blob pressure pending root identities are contradictory",
            ));
        }
        for (key, actual) in &actual_pending_roots {
            let expected = image.pending_roots.get(key).expect("matching keys");
            if actual.len() != expected.len() {
                return Err(pressure_corruption(
                    "Blob pressure pending root generations are contradictory",
                ));
            }
            let actual = decode_pending_root(actual)?;
            let expected = decode_pending_root(expected)?;
            if actual.authenticated_source_binding != expected.authenticated_source_binding {
                return Err(pressure_corruption(
                    "Blob pressure pending root source binding is contradictory",
                ));
            }
            if actual.expiry != expected.expiry {
                return Err(pressure_corruption(
                    "Blob pressure pending root expiry is contradictory",
                ));
            }
        }
        return Err(pressure_corruption(
            "Blob pressure pending roots are contradictory",
        ));
    }
    for (matches, label) in [
        (
            table_map(publication_roots)? == image.publication_roots,
            "publication roots",
        ),
        (
            table_map(variant_summaries)? == image.variant_summaries,
            "variant summaries",
        ),
        (
            table_map(publications)? == image.publications,
            "publication index",
        ),
        (
            table_map(content_publications)? == image.content_publications,
            "content publication index",
        ),
        (
            pending_index_map(pending_sources)? == image.pending_sources,
            "pending index",
        ),
        (
            variant_index_map(variants)? == image.variants,
            "variant index",
        ),
    ] {
        if !matches {
            return Err(pressure_corruption(match label {
                "publication roots" => "Blob pressure publication roots are contradictory",
                "variant summaries" => "Blob pressure variant summaries are contradictory",
                "publication index" => "Blob pressure publication index is contradictory",
                "content publication index" => {
                    "Blob pressure content publication index is contradictory"
                }
                "pending index" => "Blob pressure pending index is contradictory",
                _ => "Blob pressure variant index is contradictory",
            }));
        }
    }
    Ok(())
}

fn audit_reanchor_state(
    metadata: &impl ReadableTable<&'static str, u64>,
    cursors: &impl ReadableTable<u8, &'static [u8]>,
    continuity: Option<crate::custody::LowerBoundContinuity>,
    allow_target_lag: bool,
    finite_publication_generations: &BTreeMap<Vec<u8>, u64>,
    finite_pending_generations: &BTreeMap<Vec<u8>, u64>,
) -> Result<(), StoreError> {
    if metadata.len()? != pressure_v5_metadata_fields().len() as u64 || cursors.len()? != 2 {
        return Err(pressure_corruption(
            "Blob pressure-v5 reanchor metadata is incomplete or contains unknown rows",
        ));
    }
    if metadata
        .get(PRESSURE_SCHEMA_VERSION_FIELD)?
        .map(|value| value.value())
        != Some(PRESSURE_SCHEMA_VERSION)
    {
        return Err(pressure_corruption(
            "Blob pressure schema version is not current",
        ));
    }
    let target = metadata
        .get(REANCHOR_TARGET_GENERATION)?
        .map(|value| value.value())
        .ok_or_else(|| pressure_corruption("Blob pressure reanchor target is missing"))?;
    let dirty = match metadata.get(REANCHOR_DIRTY)?.map(|value| value.value()) {
        Some(0) => false,
        Some(1) => true,
        _ => {
            return Err(pressure_corruption(
                "Blob pressure reanchor dirty flag is invalid",
            ));
        }
    };
    let next_phase = match metadata
        .get(REANCHOR_NEXT_PHASE)?
        .map(|value| value.value())
    {
        Some(phase @ (1 | 2)) => phase,
        _ => {
            return Err(pressure_corruption(
                "Blob pressure reanchor phase is invalid",
            ));
        }
    };
    let live = decode_reanchor_cursor(
        cursors
            .get(1)?
            .ok_or_else(|| pressure_corruption("Blob pressure live reanchor cursor is missing"))?
            .value(),
    )?;
    let pending = decode_reanchor_cursor(
        cursors
            .get(2)?
            .ok_or_else(|| pressure_corruption("Blob pressure pending reanchor cursor is missing"))?
            .value(),
    )?;
    let current_generation = continuity.map_or(0, |value| value.generation);
    if target > current_generation || (target < current_generation && !allow_target_lag) {
        return Err(pressure_corruption(
            "Blob pressure reanchor target contradicts durable continuity",
        ));
    }
    let cursor_complete = |cursor| {
        matches!(
            cursor,
            PressureReanchorCursor::EmptyComplete | PressureReanchorCursor::Complete { .. }
        )
    };
    if !dirty {
        if next_phase != 1
            || live != PressureReanchorCursor::EmptyComplete
            || pending != PressureReanchorCursor::EmptyComplete
        {
            return Err(pressure_corruption(
                "clean Blob pressure reanchor state contradicts continuity or cursors",
            ));
        }
        if finite_publication_generations
            .values()
            .chain(finite_pending_generations.values())
            .any(|generation| *generation != target)
        {
            return Err(pressure_corruption(
                "clean Blob pressure reanchor state contains an unnormalized finite root",
            ));
        }
    } else if cursor_complete(live) && cursor_complete(pending) {
        return Err(pressure_corruption(
            "dirty Blob pressure reanchor pass is already complete",
        ));
    } else {
        let stale_is_unprocessed = |key: &[u8], generation: u64, cursor| {
            if generation == target {
                return true;
            }
            if generation > target || key.len() != 32 {
                return false;
            }
            let transfer = BlobTransferId::new(
                key.try_into()
                    .expect("finite pressure identity length checked"),
            );
            match cursor {
                PressureReanchorCursor::Active {
                    end_transfer,
                    position,
                } => {
                    transfer <= end_transfer && position.is_none_or(|position| transfer > position)
                }
                PressureReanchorCursor::EmptyComplete | PressureReanchorCursor::Complete { .. } => {
                    false
                }
            }
        };
        if finite_publication_generations
            .iter()
            .any(|(key, generation)| !stale_is_unprocessed(key, *generation, live))
            || finite_pending_generations
                .iter()
                .any(|(key, generation)| !stale_is_unprocessed(key, *generation, pending))
        {
            return Err(pressure_corruption(
                "dirty Blob pressure reanchor cursor skips an unnormalized finite root",
            ));
        }
    }
    Ok(())
}

fn apply_image(write: &redb::WriteTransaction, image: &PressureImage) -> Result<(), StoreError> {
    let mut metadata = write.open_table(BLOB_PRESSURE_METADATA)?;
    metadata.insert(PRESSURE_SCHEMA_VERSION_FIELD, PRESSURE_SCHEMA_VERSION)?;
    metadata.insert(
        NEXT_PENDING_ACCEPTANCE_ORDER,
        image.next_pending_acceptance_order,
    )?;
    metadata.insert(REANCHOR_TARGET_GENERATION, image.reanchor_target_generation)?;
    metadata.insert(REANCHOR_DIRTY, u64::from(image.reanchor_dirty))?;
    metadata.insert(REANCHOR_NEXT_PHASE, u64::from(image.reanchor_next_phase))?;
    drop(metadata);
    #[cfg(test)]
    if TEST_PRESSURE_MIGRATION_FAULT.get() {
        return Err(pressure_corruption(
            "injected Blob pressure migration interruption",
        ));
    }
    apply_current_index_maps(write, image)?;
    let mut cursors = write.open_table(BLOB_PRESSURE_REANCHOR_CURSORS)?;
    cursors.insert(1, image.reanchor_live_cursor.as_slice())?;
    cursors.insert(2, image.reanchor_pending_cursor.as_slice())?;
    Ok(())
}

fn apply_v4_image(write: &redb::WriteTransaction, image: &PressureImage) -> Result<(), StoreError> {
    let mut metadata = write.open_table(BLOB_PRESSURE_METADATA)?;
    metadata.insert(PRESSURE_SCHEMA_VERSION_FIELD, PRESSURE_V4_SCHEMA_VERSION)?;
    metadata.insert(
        NEXT_PENDING_ACCEPTANCE_ORDER,
        image.next_pending_acceptance_order,
    )?;
    drop(metadata);
    #[cfg(test)]
    if TEST_PRESSURE_MIGRATION_FAULT.get() {
        return Err(pressure_corruption(
            "injected Blob pressure migration interruption",
        ));
    }
    apply_index_maps(write, image)
}

fn apply_index_maps(
    write: &redb::WriteTransaction,
    image: &PressureImage,
) -> Result<(), StoreError> {
    macro_rules! insert_map {
        ($definition:expr, $rows:expr) => {{
            let mut table = write.open_table($definition)?;
            for (key, value) in $rows {
                table.insert(key.as_slice(), value.as_slice())?;
            }
        }};
    }
    insert_map!(BLOB_PRESSURE_PUBLICATION_ROOTS, &image.publication_roots);
    insert_map!(BLOB_PRESSURE_PENDING_ROOTS, &image.pending_roots);
    insert_map!(BLOB_PRESSURE_VARIANT_SUMMARIES, &image.variant_summaries);
    insert_map!(BLOB_PRESSURE_PUBLICATIONS, &image.publications);
    insert_map!(
        BLOB_PRESSURE_CONTENT_PUBLICATIONS,
        &image.content_publications
    );
    {
        let mut table = write.open_table(BLOB_PRESSURE_PENDING_SOURCES)?;
        for (key, value) in &image.pending_sources {
            table.insert(key, value.as_slice())?;
        }
    }
    {
        let mut table = write.open_table(BLOB_PRESSURE_VARIANTS)?;
        for (key, value) in &image.variants {
            table.insert(key, value.as_slice())?;
        }
    }
    Ok(())
}

fn apply_current_index_maps(
    write: &redb::WriteTransaction,
    image: &PressureImage,
) -> Result<(), StoreError> {
    apply_index_maps(write, image)?;
    apply_durable_index_maps(write, image)
}

fn replace_current_index_maps(
    write: &redb::WriteTransaction,
    image: &PressureImage,
) -> Result<(), StoreError> {
    write.delete_table(BLOB_PRESSURE_PUBLICATION_ROOTS)?;
    write.delete_table(BLOB_PRESSURE_PENDING_ROOTS)?;
    write.delete_table(BLOB_PRESSURE_VARIANT_SUMMARIES)?;
    write.delete_table(BLOB_PRESSURE_PUBLICATIONS)?;
    write.delete_table(BLOB_PRESSURE_CONTENT_PUBLICATIONS)?;
    write.delete_table(BLOB_PRESSURE_PENDING_SOURCES)?;
    write.delete_table(BLOB_PRESSURE_VARIANTS)?;
    write.delete_table(BLOB_PRESSURE_DURABLE_PUBLICATIONS)?;
    write.delete_table(BLOB_PRESSURE_DURABLE_CONTENT_PUBLICATIONS)?;
    write.delete_table(BLOB_PRESSURE_DURABLE_PENDING_SOURCES)?;
    write.delete_table(BLOB_PRESSURE_DURABLE_VARIANTS)?;
    #[cfg(test)]
    if TEST_PRESSURE_MIGRATION_FAULT.get() {
        return Err(pressure_corruption(
            "injected Blob pressure migration interruption",
        ));
    }
    apply_current_index_maps(write, image)
}

fn apply_durable_index_maps(
    write: &redb::WriteTransaction,
    image: &PressureImage,
) -> Result<(), StoreError> {
    macro_rules! insert_map {
        ($definition:expr, $rows:expr) => {{
            let mut table = write.open_table($definition)?;
            for (key, value) in $rows {
                table.insert(key.as_slice(), value.as_slice())?;
            }
        }};
    }
    insert_map!(
        BLOB_PRESSURE_DURABLE_PUBLICATIONS,
        &image.durable_publications
    );
    insert_map!(
        BLOB_PRESSURE_DURABLE_CONTENT_PUBLICATIONS,
        &image.durable_content_publications
    );
    {
        let mut table = write.open_table(BLOB_PRESSURE_DURABLE_PENDING_SOURCES)?;
        for (key, value) in &image.durable_pending_sources {
            table.insert(key, value.as_slice())?;
        }
    }
    {
        let mut table = write.open_table(BLOB_PRESSURE_DURABLE_VARIANTS)?;
        for (key, value) in &image.durable_variants {
            table.insert(key, value.as_slice())?;
        }
    }
    Ok(())
}

fn replace_image(write: &redb::WriteTransaction, image: &PressureImage) -> Result<(), StoreError> {
    let has_reanchor_cursors = matches!(
        pressure_schema_state(write)?,
        PressureSchemaState::OldV5 | PressureSchemaState::Current
    );
    write.delete_table(BLOB_PRESSURE_PUBLICATION_ROOTS)?;
    write.delete_table(BLOB_PRESSURE_PENDING_ROOTS)?;
    write.delete_table(BLOB_PRESSURE_VARIANT_SUMMARIES)?;
    write.delete_table(BLOB_PRESSURE_PUBLICATIONS)?;
    write.delete_table(BLOB_PRESSURE_CONTENT_PUBLICATIONS)?;
    write.delete_table(BLOB_PRESSURE_PENDING_SOURCES)?;
    write.delete_table(BLOB_PRESSURE_VARIANTS)?;
    if has_reanchor_cursors {
        write.delete_table(BLOB_PRESSURE_REANCHOR_CURSORS)?;
        write.delete_table(BLOB_PRESSURE_DURABLE_PUBLICATIONS)?;
        write.delete_table(BLOB_PRESSURE_DURABLE_CONTENT_PUBLICATIONS)?;
        write.delete_table(BLOB_PRESSURE_DURABLE_PENDING_SOURCES)?;
        write.delete_table(BLOB_PRESSURE_DURABLE_VARIANTS)?;
    }
    apply_image(write, image)
}

fn replace_with_v4_image(
    write: &redb::WriteTransaction,
    image: &PressureImage,
) -> Result<(), StoreError> {
    let has_reanchor_cursors = matches!(
        pressure_schema_state(write)?,
        PressureSchemaState::OldV5 | PressureSchemaState::Current
    );
    write.delete_table(BLOB_PRESSURE_PUBLICATION_ROOTS)?;
    write.delete_table(BLOB_PRESSURE_PENDING_ROOTS)?;
    write.delete_table(BLOB_PRESSURE_VARIANT_SUMMARIES)?;
    write.delete_table(BLOB_PRESSURE_PUBLICATIONS)?;
    write.delete_table(BLOB_PRESSURE_CONTENT_PUBLICATIONS)?;
    write.delete_table(BLOB_PRESSURE_PENDING_SOURCES)?;
    write.delete_table(BLOB_PRESSURE_VARIANTS)?;
    if has_reanchor_cursors {
        write.delete_table(BLOB_PRESSURE_REANCHOR_CURSORS)?;
        write.delete_table(BLOB_PRESSURE_DURABLE_PUBLICATIONS)?;
        write.delete_table(BLOB_PRESSURE_DURABLE_CONTENT_PUBLICATIONS)?;
        write.delete_table(BLOB_PRESSURE_DURABLE_PENDING_SOURCES)?;
        write.delete_table(BLOB_PRESSURE_DURABLE_VARIANTS)?;
    }
    apply_v4_image(write, image)
}

#[cfg(test)]
pub(crate) fn downgrade_pressure_v5_to_v4_for_test(
    write: &redb::WriteTransaction,
) -> Result<(), StoreError> {
    let next = write
        .open_table(BLOB_PRESSURE_METADATA)?
        .get(NEXT_PENDING_ACCEPTANCE_ORDER)?
        .map(|value| value.value())
        .ok_or_else(|| pressure_corruption("next pending Blob acceptance order is missing"))?;
    let image = build_pressure_image(
        &write.open_table(super::BLOB_PUBLICATIONS)?,
        &write.open_table(super::BLOB_ACCEPTANCE_MARKERS)?,
        &write.open_table(super::BLOB_PENDING_SOURCES)?,
        &write.open_table(super::BLOB_CARRIER_PREFIXES)?,
        &write.open_table(super::BLOB_IMPORTS)?,
        &write.open_table(super::pack_lifecycle::BLOB_PROFILE5_PACKS)?,
        &write.open_table(super::BLOB_CHUNKS)?,
        next,
        super::lifecycle::publication_encoding_write(write)?,
        PressurePendingRootEncodingGeneration::PressureV4,
        PressureImageEncodingGeneration::LegacyV4,
    )?;
    write.delete_table(BLOB_PRESSURE_PUBLICATION_ROOTS)?;
    write.delete_table(BLOB_PRESSURE_PENDING_ROOTS)?;
    write.delete_table(BLOB_PRESSURE_VARIANT_SUMMARIES)?;
    write.delete_table(BLOB_PRESSURE_PUBLICATIONS)?;
    write.delete_table(BLOB_PRESSURE_CONTENT_PUBLICATIONS)?;
    write.delete_table(BLOB_PRESSURE_PENDING_SOURCES)?;
    write.delete_table(BLOB_PRESSURE_VARIANTS)?;
    write.delete_table(BLOB_PRESSURE_REANCHOR_CURSORS)?;
    write.delete_table(BLOB_PRESSURE_DURABLE_PUBLICATIONS)?;
    write.delete_table(BLOB_PRESSURE_DURABLE_CONTENT_PUBLICATIONS)?;
    write.delete_table(BLOB_PRESSURE_DURABLE_PENDING_SOURCES)?;
    write.delete_table(BLOB_PRESSURE_DURABLE_VARIANTS)?;
    apply_index_maps(write, &image)?;
    let mut metadata = write.open_table(BLOB_PRESSURE_METADATA)?;
    metadata.insert(PRESSURE_SCHEMA_VERSION_FIELD, PRESSURE_V4_SCHEMA_VERSION)?;
    metadata.remove(REANCHOR_TARGET_GENERATION)?;
    metadata.remove(REANCHOR_DIRTY)?;
    metadata.remove(REANCHOR_NEXT_PHASE)?;
    Ok(())
}

fn audit_or_migrate_pressure_write_inner(
    write: &redb::WriteTransaction,
    lifecycle_was_predecessor: Option<bool>,
) -> Result<(), StoreError> {
    let state = pressure_schema_state(write)?;
    if let Some(lifecycle_was_predecessor) = lifecycle_was_predecessor {
        match (lifecycle_was_predecessor, state) {
            (false, PressureSchemaState::OldV5 | PressureSchemaState::Current)
            | (true, PressureSchemaState::Predecessor | PressureSchemaState::V4) => {}
            _ => {
                return Err(pressure_corruption(
                    "Blob lifecycle and pressure schema generations are mixed",
                ));
            }
        }
    }
    let publication_generation = super::lifecycle::publication_encoding_write(write)?;
    let pending_generation =
        super::pending_blob_encoding_for_publication_encoding(publication_generation);
    let migrated_next = match state {
        PressureSchemaState::Predecessor | PressureSchemaState::V4 => Some(
            migrate_pending_acceptance_orders(write, pending_generation)?,
        ),
        PressureSchemaState::OldV5 | PressureSchemaState::Current => None,
    };
    match state {
        PressureSchemaState::Predecessor => {
            let mut image = build_pressure_image(
                &write.open_table(super::BLOB_PUBLICATIONS)?,
                &write.open_table(super::BLOB_ACCEPTANCE_MARKERS)?,
                &write.open_table(super::BLOB_PENDING_SOURCES)?,
                &write.open_table(super::BLOB_CARRIER_PREFIXES)?,
                &write.open_table(super::BLOB_IMPORTS)?,
                &write.open_table(super::pack_lifecycle::BLOB_PROFILE5_PACKS)?,
                &write.open_table(super::BLOB_CHUNKS)?,
                migrated_next.ok_or_else(|| {
                    pressure_corruption("predecessor pressure migration order is missing")
                })?,
                super::lifecycle::publication_encoding_write(write)?,
                PressurePendingRootEncodingGeneration::PressureV4,
                PressureImageEncodingGeneration::CurrentV5,
            )?;
            prepare_reanchor_image(write, &mut image)?;
            apply_image(write, &image)
        }
        PressureSchemaState::Current => {
            synchronize_reanchor_state_write(write)?;
            let metadata = write.open_table(BLOB_PRESSURE_METADATA)?;
            let next = metadata
                .get(NEXT_PENDING_ACCEPTANCE_ORDER)?
                .map(|value| value.value())
                .ok_or_else(|| {
                    pressure_corruption("next pending Blob acceptance order is missing")
                })?;
            drop(metadata);
            let image = build_pressure_image(
                &write.open_table(super::BLOB_PUBLICATIONS)?,
                &write.open_table(super::BLOB_ACCEPTANCE_MARKERS)?,
                &write.open_table(super::BLOB_PENDING_SOURCES)?,
                &write.open_table(super::BLOB_CARRIER_PREFIXES)?,
                &write.open_table(super::BLOB_IMPORTS)?,
                &write.open_table(super::pack_lifecycle::BLOB_PROFILE5_PACKS)?,
                &write.open_table(super::BLOB_CHUNKS)?,
                next,
                super::lifecycle::publication_encoding_write(write)?,
                PressurePendingRootEncodingGeneration::PressureV4,
                PressureImageEncodingGeneration::CurrentV5,
            )?;
            audit_image_write(write, &image)?;
            audit_durable_image_write(write, &image)?;
            audit_reanchor_state(
                &write.open_table(BLOB_PRESSURE_METADATA)?,
                &write.open_table(BLOB_PRESSURE_REANCHOR_CURSORS)?,
                crate::custody::lower_bound_continuity_write(write)?,
                false,
                &image.finite_publication_generations,
                &image.finite_pending_generations,
            )
        }
        PressureSchemaState::OldV5 => {
            let metadata = write.open_table(BLOB_PRESSURE_METADATA)?;
            let next = metadata
                .get(NEXT_PENDING_ACCEPTANCE_ORDER)?
                .map(|value| value.value())
                .ok_or_else(|| {
                    pressure_corruption("next pending Blob acceptance order is missing")
                })?;
            drop(metadata);
            let old_image = build_pressure_image(
                &write.open_table(super::BLOB_PUBLICATIONS)?,
                &write.open_table(super::BLOB_ACCEPTANCE_MARKERS)?,
                &write.open_table(super::BLOB_PENDING_SOURCES)?,
                &write.open_table(super::BLOB_CARRIER_PREFIXES)?,
                &write.open_table(super::BLOB_IMPORTS)?,
                &write.open_table(super::pack_lifecycle::BLOB_PROFILE5_PACKS)?,
                &write.open_table(super::BLOB_CHUNKS)?,
                next,
                super::lifecycle::publication_encoding_write(write)?,
                PressurePendingRootEncodingGeneration::PressureV4,
                PressureImageEncodingGeneration::PreTask5V5,
            )?;
            audit_image_write(write, &old_image)?;
            audit_reanchor_state(
                &write.open_table(BLOB_PRESSURE_METADATA)?,
                &write.open_table(BLOB_PRESSURE_REANCHOR_CURSORS)?,
                crate::custody::lower_bound_continuity_write(write)?,
                true,
                &old_image.finite_publication_generations,
                &old_image.finite_pending_generations,
            )?;
            synchronize_reanchor_state_write(write)?;
            let current_image = build_pressure_image(
                &write.open_table(super::BLOB_PUBLICATIONS)?,
                &write.open_table(super::BLOB_ACCEPTANCE_MARKERS)?,
                &write.open_table(super::BLOB_PENDING_SOURCES)?,
                &write.open_table(super::BLOB_CARRIER_PREFIXES)?,
                &write.open_table(super::BLOB_IMPORTS)?,
                &write.open_table(super::pack_lifecycle::BLOB_PROFILE5_PACKS)?,
                &write.open_table(super::BLOB_CHUNKS)?,
                next,
                super::lifecycle::publication_encoding_write(write)?,
                PressurePendingRootEncodingGeneration::PressureV4,
                PressureImageEncodingGeneration::CurrentV5,
            )?;
            audit_reanchor_state(
                &write.open_table(BLOB_PRESSURE_METADATA)?,
                &write.open_table(BLOB_PRESSURE_REANCHOR_CURSORS)?,
                crate::custody::lower_bound_continuity_write(write)?,
                false,
                &current_image.finite_publication_generations,
                &current_image.finite_pending_generations,
            )?;
            replace_current_index_maps(write, &current_image)?;
            audit_image_write(write, &current_image)?;
            audit_durable_image_write(write, &current_image)?;
            audit_reanchor_state(
                &write.open_table(BLOB_PRESSURE_METADATA)?,
                &write.open_table(BLOB_PRESSURE_REANCHOR_CURSORS)?,
                crate::custody::lower_bound_continuity_write(write)?,
                false,
                &current_image.finite_publication_generations,
                &current_image.finite_pending_generations,
            )
        }
        PressureSchemaState::V4 => {
            let metadata = write.open_table(BLOB_PRESSURE_METADATA)?;
            if metadata.len()? != 2 {
                return Err(pressure_corruption(
                    "Blob pressure metadata schema is incomplete or unknown",
                ));
            }
            let version = metadata
                .get(PRESSURE_SCHEMA_VERSION_FIELD)?
                .map(|value| value.value())
                .ok_or_else(|| {
                    pressure_corruption("Blob pressure metadata schema is incomplete or unknown")
                })?;
            if !matches!(
                version,
                2 | PREVIOUS_PRESSURE_SCHEMA_VERSION | PRESSURE_V4_SCHEMA_VERSION
            ) {
                return Err(pressure_corruption(
                    "Blob pressure metadata schema is incomplete or unknown",
                ));
            }
            let next = metadata
                .get(NEXT_PENDING_ACCEPTANCE_ORDER)?
                .map(|value| value.value())
                .ok_or_else(|| {
                    pressure_corruption("next pending Blob acceptance order is missing")
                })?;
            drop(metadata);
            let image = build_pressure_image(
                &write.open_table(super::BLOB_PUBLICATIONS)?,
                &write.open_table(super::BLOB_ACCEPTANCE_MARKERS)?,
                &write.open_table(super::BLOB_PENDING_SOURCES)?,
                &write.open_table(super::BLOB_CARRIER_PREFIXES)?,
                &write.open_table(super::BLOB_IMPORTS)?,
                &write.open_table(super::pack_lifecycle::BLOB_PROFILE5_PACKS)?,
                &write.open_table(super::BLOB_CHUNKS)?,
                next,
                if version == PRESSURE_V4_SCHEMA_VERSION {
                    super::lifecycle::publication_encoding_write(write)?
                } else {
                    super::lifecycle::publication_encoding_migration_write(write)?
                },
                if version == PRESSURE_V4_SCHEMA_VERSION {
                    PressurePendingRootEncodingGeneration::PressureV4
                } else {
                    PressurePendingRootEncodingGeneration::PressureV3
                },
                PressureImageEncodingGeneration::LegacyV4,
            )?;
            audit_image_write(write, &image)?;
            let mut current = build_pressure_image(
                &write.open_table(super::BLOB_PUBLICATIONS)?,
                &write.open_table(super::BLOB_ACCEPTANCE_MARKERS)?,
                &write.open_table(super::BLOB_PENDING_SOURCES)?,
                &write.open_table(super::BLOB_CARRIER_PREFIXES)?,
                &write.open_table(super::BLOB_IMPORTS)?,
                &write.open_table(super::pack_lifecycle::BLOB_PROFILE5_PACKS)?,
                &write.open_table(super::BLOB_CHUNKS)?,
                next,
                super::lifecycle::publication_encoding_write(write)?,
                PressurePendingRootEncodingGeneration::PressureV4,
                PressureImageEncodingGeneration::CurrentV5,
            )?;
            prepare_reanchor_image(write, &mut current)?;
            replace_image(write, &current)
        }
    }
}

pub(crate) fn audit_or_migrate_pressure_write(
    write: &redb::WriteTransaction,
) -> Result<(), StoreError> {
    audit_or_migrate_pressure_write_inner(write, None)
}

pub(crate) fn audit_or_migrate_pressure_after_lifecycle_write(
    write: &redb::WriteTransaction,
    lifecycle_was_predecessor: bool,
) -> Result<(), StoreError> {
    #[cfg(test)]
    if super::lifecycle::TEST_BLOB_LIFECYCLE_MIGRATION_DISABLED.get() {
        // The legacy lifecycle fixture hook deliberately leaves lifecycle
        // initialization disabled while constructing a predecessor database.
        // Its caller pairs the generations before any reopen assertion. Keep
        // this escape hatch test-only so production opens always enforce the
        // exact lifecycle/pressure generation matrix below.
        let state = pressure_schema_state(write)?;
        if !matches!(
            state,
            PressureSchemaState::Predecessor | PressureSchemaState::V4
        ) {
            return Err(pressure_corruption(
                "Blob lifecycle and pressure schema generations are mixed",
            ));
        }
        let publication_generation = super::lifecycle::publication_encoding_migration_write(write)?;
        let pending_generation =
            super::pending_blob_encoding_for_publication_encoding(publication_generation);
        let next = match state {
            PressureSchemaState::Predecessor => {
                migrate_pending_acceptance_orders(write, pending_generation)?
            }
            PressureSchemaState::V4 => write
                .open_table(BLOB_PRESSURE_METADATA)?
                .get(NEXT_PENDING_ACCEPTANCE_ORDER)?
                .map(|value| value.value())
                .ok_or_else(|| {
                    pressure_corruption("next pending Blob acceptance order is missing")
                })?,
            PressureSchemaState::OldV5 | PressureSchemaState::Current => unreachable!(),
        };
        let image = build_pressure_image(
            &write.open_table(super::BLOB_PUBLICATIONS)?,
            &write.open_table(super::BLOB_ACCEPTANCE_MARKERS)?,
            &write.open_table(super::BLOB_PENDING_SOURCES)?,
            &write.open_table(super::BLOB_CARRIER_PREFIXES)?,
            &write.open_table(super::BLOB_IMPORTS)?,
            &write.open_table(super::pack_lifecycle::BLOB_PROFILE5_PACKS)?,
            &write.open_table(super::BLOB_CHUNKS)?,
            next,
            publication_generation,
            PressurePendingRootEncodingGeneration::PressureV4,
            PressureImageEncodingGeneration::LegacyV4,
        )?;
        return match state {
            PressureSchemaState::Predecessor => apply_v4_image(write, &image),
            PressureSchemaState::V4 => audit_image_write(write, &image),
            PressureSchemaState::OldV5 | PressureSchemaState::Current => unreachable!(),
        };
    }
    audit_or_migrate_pressure_write_inner(write, Some(lifecycle_was_predecessor))
}

/// Verifies the complete pressure projection before an authoritative Blob
/// transition starts. This keeps the post-mutation synchronizer from ever
/// turning a pre-existing orphan, partial row, or contradiction into a repair.
pub(crate) fn require_pressure_consistent_write(
    write: &redb::WriteTransaction,
) -> Result<(), StoreError> {
    match pressure_schema_state(write)? {
        PressureSchemaState::V4 | PressureSchemaState::OldV5 | PressureSchemaState::Current => {
            audit_or_migrate_pressure_write(write)
        }
        _ => Err(pressure_corruption(
            "Blob pressure transition requires the current pressure schema",
        )),
    }
}

pub(crate) fn inspect_pressure_read(
    read: &redb::ReadTransaction,
    lifecycle_is_current: bool,
) -> Result<(), StoreError> {
    let state = pressure_schema_state(read)?;
    if state == PressureSchemaState::Predecessor {
        return Err(pressure_corruption(
            "Blob pressure predecessor schema requires writable migration",
        ));
    }
    let metadata = read.open_table(BLOB_PRESSURE_METADATA)?;
    if matches!(
        state,
        PressureSchemaState::OldV5 | PressureSchemaState::Current
    ) {
        if !lifecycle_is_current {
            return Err(pressure_corruption(
                "Blob lifecycle and pressure schema generations are mixed",
            ));
        }
        let next = metadata
            .get(NEXT_PENDING_ACCEPTANCE_ORDER)?
            .map(|value| value.value())
            .ok_or_else(|| pressure_corruption("next pending Blob acceptance order is missing"))?;
        drop(metadata);
        let image = build_pressure_image(
            &read.open_table(super::BLOB_PUBLICATIONS)?,
            &read.open_table(super::BLOB_ACCEPTANCE_MARKERS)?,
            &read.open_table(super::BLOB_PENDING_SOURCES)?,
            &read.open_table(super::BLOB_CARRIER_PREFIXES)?,
            &read.open_table(super::BLOB_IMPORTS)?,
            &read.open_table(super::pack_lifecycle::BLOB_PROFILE5_PACKS)?,
            &read.open_table(super::BLOB_CHUNKS)?,
            next,
            super::lifecycle::publication_encoding_read(read)?,
            PressurePendingRootEncodingGeneration::PressureV4,
            if state == PressureSchemaState::OldV5 {
                PressureImageEncodingGeneration::PreTask5V5
            } else {
                PressureImageEncodingGeneration::CurrentV5
            },
        )?;
        audit_image_read(read, &image)?;
        if state == PressureSchemaState::Current {
            audit_durable_image_read(read, &image)?;
        }
        return audit_reanchor_state(
            &read.open_table(BLOB_PRESSURE_METADATA)?,
            &read.open_table(BLOB_PRESSURE_REANCHOR_CURSORS)?,
            crate::custody::lower_bound_continuity_read(read)?,
            true,
            &image.finite_publication_generations,
            &image.finite_pending_generations,
        );
    }
    if metadata.len()? != 2 {
        return Err(pressure_corruption(
            "Blob pressure metadata schema is incomplete or unknown",
        ));
    }
    let version = metadata
        .get(PRESSURE_SCHEMA_VERSION_FIELD)?
        .map(|value| value.value())
        .ok_or_else(|| {
            pressure_corruption("Blob pressure metadata schema is incomplete or unknown")
        })?;
    if !matches!(
        version,
        2 | PREVIOUS_PRESSURE_SCHEMA_VERSION | PRESSURE_V4_SCHEMA_VERSION
    ) {
        return Err(pressure_corruption(
            "Blob pressure metadata schema is incomplete or unknown",
        ));
    }
    if lifecycle_is_current != (version == ACTIVE_PRESSURE_SCHEMA_VERSION) {
        return Err(pressure_corruption(
            "Blob lifecycle and pressure schema generations are mixed",
        ));
    }
    let next = metadata
        .get(NEXT_PENDING_ACCEPTANCE_ORDER)?
        .map(|value| value.value())
        .ok_or_else(|| pressure_corruption("next pending Blob acceptance order is missing"))?;
    drop(metadata);
    let image = build_pressure_image(
        &read.open_table(super::BLOB_PUBLICATIONS)?,
        &read.open_table(super::BLOB_ACCEPTANCE_MARKERS)?,
        &read.open_table(super::BLOB_PENDING_SOURCES)?,
        &read.open_table(super::BLOB_CARRIER_PREFIXES)?,
        &read.open_table(super::BLOB_IMPORTS)?,
        &read.open_table(super::pack_lifecycle::BLOB_PROFILE5_PACKS)?,
        &read.open_table(super::BLOB_CHUNKS)?,
        next,
        if version == ACTIVE_PRESSURE_SCHEMA_VERSION {
            super::lifecycle::publication_encoding_read(read)?
        } else {
            super::lifecycle::publication_encoding_migration_read(read)?
        },
        if version == PRESSURE_V4_SCHEMA_VERSION {
            PressurePendingRootEncodingGeneration::PressureV4
        } else {
            PressurePendingRootEncodingGeneration::PressureV3
        },
        PressureImageEncodingGeneration::LegacyV4,
    )?;
    audit_image_read(read, &image)?;
    Ok(())
}

/// Allocates one pending-source order only for a source that is not yet staged.
pub(crate) fn allocate_pending_acceptance_order_write(
    write: &redb::WriteTransaction,
) -> Result<u64, StoreError> {
    let mut metadata = write.open_table(BLOB_PRESSURE_METADATA)?;
    let current = metadata
        .get(NEXT_PENDING_ACCEPTANCE_ORDER)?
        .map(|value| value.value())
        .ok_or_else(|| pressure_corruption("next pending Blob acceptance order is missing"))?;
    let next = current.checked_add(1).ok_or_else(|| {
        pressure_corruption("pending Blob acceptance order overflows before allocation")
    })?;
    metadata.insert(NEXT_PENDING_ACCEPTANCE_ORDER, next)?;
    Ok(current)
}

fn variant_progress_write(
    write: &redb::WriteTransaction,
    variant: BlobVariantId,
) -> Result<(PressureFraction, bool), StoreError> {
    if let Some((committed, total)) = super::pack_lifecycle::variant_progress_write(write, variant)?
    {
        return Ok((authenticated_progress_fraction(committed, total)?, true));
    }
    let import_value = write
        .open_table(super::BLOB_IMPORTS)?
        .get(variant.as_bytes().as_slice())?
        .map(|value| value.value().to_vec())
        .ok_or_else(|| pressure_corruption("Blob pressure root lacks its depot import"))?;
    let fact = super::depot::deletion_import_projection(variant.as_bytes(), &import_value)?;
    let first = {
        let mut key = [0u8; 40];
        key[..32].copy_from_slice(variant.as_bytes());
        key
    };
    let last = {
        let mut key = [0xffu8; 40];
        key[..32].copy_from_slice(variant.as_bytes());
        key
    };
    let chunks = write.open_table(super::BLOB_CHUNKS)?;
    let mut committed = 0u64;
    for row in chunks.range::<&[u8]>((
        std::ops::Bound::Included(first.as_slice()),
        std::ops::Bound::Included(last.as_slice()),
    ))? {
        let (key, value) = row?;
        let index = u64::from_be_bytes(
            key.value()[32..]
                .try_into()
                .map_err(|_| pressure_corruption("Blob pressure chunk index is invalid"))?,
        );
        let projection =
            super::depot::deletion_chunk_projection(&import_value, index, value.value())?;
        if let Some(record) = projection.record {
            committed = committed
                .checked_add(u64::from(record.plaintext_len()))
                .ok_or(StoreError::PayloadByteAccountingOverflow)?;
        }
    }
    let finalized = fact.finalized_root.is_some();
    let numerator = if finalized { fact.total_len } else { committed };
    Ok((
        authenticated_progress_fraction(numerator, fact.total_len)?,
        finalized,
    ))
}

pub(super) fn insert_pending_source_write(
    write: &redb::WriteTransaction,
    transfer: BlobTransferId,
    record: &super::PendingBlobSourceRecord,
) -> Result<(), StoreError> {
    if record.pending_acceptance_order == 0 {
        return Err(pressure_corruption(
            "new pending Blob source lacks its authoritative acceptance order",
        ));
    }
    let root = PressurePendingRoot {
        variant_id: record.metadata.variant_id,
        authenticated_source_binding: record.authenticated_source_binding,
        priority: record.metadata.header.priority,
        acceptance_order: record.pending_acceptance_order,
        completion: pending_progress(
            transfer,
            record,
            &write.open_table(super::BLOB_CARRIER_PREFIXES)?,
            &write.open_table(super::BLOB_IMPORTS)?,
            &write.open_table(super::BLOB_CHUNKS)?,
        )?,
        expiry: lifetime_expiry(record.metadata.lifetime)?,
        topic: record.metadata.header.topic.clone(),
        scope: record.metadata.header.scope.clone(),
        blob_id: record.metadata.blob_id,
    };
    let encoded = encode_pending_root(&root)?;
    if write
        .open_table(BLOB_PRESSURE_PENDING_ROOTS)?
        .get(transfer.as_bytes().as_slice())?
        .is_some()
    {
        return Err(pressure_corruption(
            "new pending Blob source already has a pressure root",
        ));
    }
    write
        .open_table(BLOB_PRESSURE_PENDING_ROOTS)?
        .insert(transfer.as_bytes().as_slice(), encoded.as_slice())?;
    let pending_key = pending_index_key_write(write, root.clone(), transfer)?;
    if write
        .open_table(BLOB_PRESSURE_PENDING_SOURCES)?
        .insert(&pending_key, &[] as &[u8])?
        .is_some()
    {
        return Err(pressure_corruption(
            "new pending Blob source duplicates its pressure index",
        ));
    }
    insert_durable_pending_index_write(write, root.clone(), transfer)?;

    if variant_references_write(write, root.variant_id)?.is_empty() {
        add_root_to_variant_summary_without_references(
            write,
            root.variant_id,
            root.priority,
            root.acceptance_order,
            true,
            root.expiry,
        )
    } else {
        refresh_variant_summary(write, root.variant_id, true)
    }
}

pub(super) fn require_pending_source_write(
    write: &redb::WriteTransaction,
    transfer: BlobTransferId,
    record: &super::PendingBlobSourceRecord,
) -> Result<(), StoreError> {
    let encoded = write
        .open_table(BLOB_PRESSURE_PENDING_ROOTS)?
        .get(transfer.as_bytes().as_slice())?
        .map(|value| value.value().to_vec())
        .ok_or_else(|| pressure_corruption("pending Blob source lacks its pressure root"))?;
    let root = decode_pending_root(&encoded)?;
    let expected = PressurePendingRoot {
        variant_id: record.metadata.variant_id,
        authenticated_source_binding: record.authenticated_source_binding,
        priority: record.metadata.header.priority,
        acceptance_order: record.pending_acceptance_order,
        completion: pending_progress(
            transfer,
            record,
            &write.open_table(super::BLOB_CARRIER_PREFIXES)?,
            &write.open_table(super::BLOB_IMPORTS)?,
            &write.open_table(super::BLOB_CHUNKS)?,
        )?,
        expiry: lifetime_expiry(record.metadata.lifetime)?,
        topic: record.metadata.header.topic.clone(),
        scope: record.metadata.header.scope.clone(),
        blob_id: record.metadata.blob_id,
    };
    if root != expected
        || root.variant_id != record.metadata.variant_id
        || root.priority != record.metadata.header.priority
        || root.acceptance_order != record.pending_acceptance_order
        || root.topic != record.metadata.header.topic
        || root.scope != record.metadata.header.scope
        || root.blob_id != record.metadata.blob_id
    {
        return Err(pressure_corruption(
            "pending Blob pressure root contradicts its source",
        ));
    }
    let key = pending_index_key_write(write, root.clone(), transfer)?;
    if write
        .open_table(BLOB_PRESSURE_PENDING_SOURCES)?
        .get(&key)?
        .as_ref()
        .is_none_or(|value| !value.value().is_empty())
    {
        return Err(pressure_corruption(
            "pending Blob pressure root lacks its exact index",
        ));
    }
    if expiry_indexes_active_write(write)?
        && write
            .open_table(BLOB_PRESSURE_DURABLE_PENDING_SOURCES)?
            .get(&key)?
            .is_some()
            != (root.expiry == PressureExpiry::Durable)
    {
        return Err(pressure_corruption(
            "pending Blob durable pressure index contradicts its root",
        ));
    }
    Ok(())
}

pub(super) fn rekey_pending_source_lifetime_write(
    write: &redb::WriteTransaction,
    transfer: BlobTransferId,
    record: &super::PendingBlobSourceRecord,
) -> Result<(), StoreError> {
    let old_encoded = write
        .open_table(BLOB_PRESSURE_PENDING_ROOTS)?
        .get(transfer.as_bytes().as_slice())?
        .map(|value| value.value().to_vec())
        .ok_or_else(|| pressure_corruption("pending Blob source lacks its pressure root"))?;
    let old = decode_pending_root(&old_encoded)?;
    remove_durable_pending_index_write(write, old.clone(), transfer)?;
    if write
        .open_table(BLOB_PRESSURE_PENDING_SOURCES)?
        .remove(&pending_index_key_write(write, old.clone(), transfer)?)?
        .as_ref()
        .is_none_or(|value| !value.value().is_empty())
    {
        return Err(pressure_corruption(
            "pending Blob pressure root lacks its exact index",
        ));
    }
    let updated = PressurePendingRoot {
        variant_id: record.metadata.variant_id,
        authenticated_source_binding: record.authenticated_source_binding,
        priority: record.metadata.header.priority,
        acceptance_order: record.pending_acceptance_order,
        completion: pending_progress(
            transfer,
            record,
            &write.open_table(super::BLOB_CARRIER_PREFIXES)?,
            &write.open_table(super::BLOB_IMPORTS)?,
            &write.open_table(super::BLOB_CHUNKS)?,
        )?,
        expiry: lifetime_expiry(record.metadata.lifetime)?,
        topic: record.metadata.header.topic.clone(),
        scope: record.metadata.header.scope.clone(),
        blob_id: record.metadata.blob_id,
    };
    if old.variant_id != updated.variant_id
        || old.priority != updated.priority
        || old.acceptance_order != updated.acceptance_order
        || old.completion != updated.completion
        || old.topic != updated.topic
        || old.scope != updated.scope
        || old.blob_id != updated.blob_id
    {
        return Err(pressure_corruption(
            "pending Blob pressure root contradicts its source during re-key",
        ));
    }
    let encoded = encode_pending_root(&updated)?;
    write
        .open_table(BLOB_PRESSURE_PENDING_ROOTS)?
        .insert(transfer.as_bytes().as_slice(), encoded.as_slice())?;
    if write
        .open_table(BLOB_PRESSURE_PENDING_SOURCES)?
        .insert(
            &pending_index_key_write(write, updated.clone(), transfer)?,
            &[] as &[u8],
        )?
        .is_some()
    {
        return Err(pressure_corruption(
            "pending Blob pressure re-key duplicated its index",
        ));
    }
    insert_durable_pending_index_write(write, updated, transfer)?;
    refresh_variant_summary(write, record.metadata.variant_id, false)
}

fn publication_root_write(
    write: &redb::WriteTransaction,
    transfer: BlobTransferId,
) -> Result<PressurePublicationRoot, StoreError> {
    let encoded = write
        .open_table(super::BLOB_PUBLICATIONS)?
        .get(transfer.as_bytes().as_slice())?
        .map(|value| value.value().to_vec())
        .ok_or_else(|| pressure_corruption("Blob pressure publication is missing"))?;
    if super::lifecycle::publication_record_is_retired(&encoded).map_err(blob_error)? {
        return Err(pressure_corruption(
            "Blob pressure publication root refers to a retired publication",
        ));
    }
    let metadata = super::decode_blob_metadata(&encoded)?;
    if metadata.transfer_id != transfer {
        return Err(pressure_corruption(
            "Blob pressure publication key differs from its metadata",
        ));
    }
    let acceptance_order = write
        .open_table(super::BLOB_ACCEPTANCE_MARKERS)?
        .get(transfer.as_bytes().as_slice())?
        .map(|value| value.value())
        .ok_or_else(|| pressure_corruption("Blob pressure publication lacks its marker"))?;
    Ok(PressurePublicationRoot {
        variant_id: metadata.variant_id,
        semantic_id: metadata.semantic_id,
        priority: metadata.header.priority,
        acceptance_order,
        expiry: lifetime_expiry(metadata.lifetime)?,
        topic: metadata.header.topic,
        scope: metadata.header.scope,
        blob_id: metadata.blob_id,
    })
}

pub(super) fn rekey_publication_lifetime_write(
    write: &redb::WriteTransaction,
    transfer: BlobTransferId,
) -> Result<(), StoreError> {
    let encoded = write
        .open_table(BLOB_PRESSURE_PUBLICATION_ROOTS)?
        .get(transfer.as_bytes().as_slice())?
        .map(|value| value.value().to_vec())
        .ok_or_else(|| pressure_corruption("publication lacks its pressure root"))?;
    let old = decode_publication_root(&encoded)?;
    remove_durable_publication_indexes_write(write, &old, transfer)?;
    let old_global = publication_index_key_write(
        write,
        PressurePublicationKey {
            priority: old.priority,
            expiry: old.expiry,
            acceptance_order: old.acceptance_order,
            transfer_id: transfer,
        },
    )?;
    if write
        .open_table(BLOB_PRESSURE_PUBLICATIONS)?
        .remove(old_global.as_slice())?
        .is_none()
        || write
            .open_table(BLOB_PRESSURE_CONTENT_PUBLICATIONS)?
            .remove(content_publication_index_key_write(write, &old, transfer)?.as_slice())?
            .is_none()
    {
        return Err(pressure_corruption(
            "publication pressure root lacks its exact index",
        ));
    }
    let updated = publication_root_write(write, transfer)?;
    let updated_encoded = encode_publication_root(&updated)?;
    write
        .open_table(BLOB_PRESSURE_PUBLICATION_ROOTS)?
        .insert(transfer.as_bytes().as_slice(), updated_encoded.as_slice())?;
    let global = publication_index_key_write(
        write,
        PressurePublicationKey {
            priority: updated.priority,
            expiry: updated.expiry,
            acceptance_order: updated.acceptance_order,
            transfer_id: transfer,
        },
    )?;
    if write
        .open_table(BLOB_PRESSURE_PUBLICATIONS)?
        .insert(global.as_slice(), &[] as &[u8])?
        .is_some()
        || write
            .open_table(BLOB_PRESSURE_CONTENT_PUBLICATIONS)?
            .insert(
                content_publication_index_key_write(write, &updated, transfer)?.as_slice(),
                &[] as &[u8],
            )?
            .is_some()
    {
        return Err(pressure_corruption(
            "publication pressure re-key duplicated its index",
        ));
    }
    insert_durable_publication_indexes_write(write, &updated, transfer)?;
    refresh_variant_summary(write, updated.variant_id, false)
}

fn require_publication_root_write(
    write: &redb::WriteTransaction,
    transfer: BlobTransferId,
    expected: &PressurePublicationRoot,
) -> Result<(), StoreError> {
    let encoded = write
        .open_table(BLOB_PRESSURE_PUBLICATION_ROOTS)?
        .get(transfer.as_bytes().as_slice())?
        .map(|value| value.value().to_vec())
        .ok_or_else(|| pressure_corruption("publication lacks its pressure root"))?;
    if decode_publication_root(&encoded)? != *expected {
        return Err(pressure_corruption(
            "publication pressure root contradicts authoritative state",
        ));
    }
    let global = publication_index_key_write(
        write,
        PressurePublicationKey {
            priority: expected.priority,
            expiry: expected.expiry,
            acceptance_order: expected.acceptance_order,
            transfer_id: transfer,
        },
    )?;
    if write
        .open_table(BLOB_PRESSURE_PUBLICATIONS)?
        .get(global.as_slice())?
        .as_ref()
        .is_none_or(|value| !value.value().is_empty())
        || write
            .open_table(BLOB_PRESSURE_CONTENT_PUBLICATIONS)?
            .get(content_publication_index_key_write(write, expected, transfer)?.as_slice())?
            .as_ref()
            .is_none_or(|value| !value.value().is_empty())
    {
        return Err(pressure_corruption(
            "publication pressure root lacks its exact indexes",
        ));
    }
    if expiry_indexes_active_write(write)? {
        let content = content_publication_index_key_write(write, expected, transfer)?;
        let durable = expected.expiry == PressureExpiry::Durable;
        if write
            .open_table(BLOB_PRESSURE_DURABLE_PUBLICATIONS)?
            .get(global.as_slice())?
            .is_some()
            != durable
            || write
                .open_table(BLOB_PRESSURE_DURABLE_CONTENT_PUBLICATIONS)?
                .get(content.as_slice())?
                .is_some()
                != durable
        {
            return Err(pressure_corruption(
                "publication durable pressure indexes contradict its root",
            ));
        }
    }
    Ok(())
}

pub(crate) fn require_publication_write(
    write: &redb::WriteTransaction,
    transfer: BlobTransferId,
) -> Result<(), StoreError> {
    let expected = publication_root_write(write, transfer)?;
    require_publication_root_write(write, transfer, &expected)
}

pub(crate) fn variant_references_write(
    write: &redb::WriteTransaction,
    variant: BlobVariantId,
) -> Result<Vec<(super::lifecycle::VariantReferenceOwner, BlobTransferId)>, StoreError> {
    if !write
        .list_tables()?
        .any(|table| table.name() == super::lifecycle::BLOB_VARIANT_REFERENCES.name())
    {
        return Ok(Vec::new());
    }
    let mut first = [0u8; 65];
    first[..32].copy_from_slice(variant.as_bytes());
    let mut last = [0xffu8; 65];
    last[..32].copy_from_slice(variant.as_bytes());
    let table = write.open_table(super::lifecycle::BLOB_VARIANT_REFERENCES)?;
    let mut references = Vec::new();
    for row in table.range::<&[u8]>((
        std::ops::Bound::Included(first.as_slice()),
        std::ops::Bound::Included(last.as_slice()),
    ))? {
        let (key, value) = row?;
        if key.value().len() != 65
            || key.value()[..32] != *variant.as_bytes()
            || !value.value().is_empty()
        {
            return Err(pressure_corruption(
                "Blob pressure variant reference is malformed",
            ));
        }
        references.push((
            super::lifecycle::VariantReferenceOwner::decode(&key.value()[32..33])
                .map_err(blob_error)?,
            BlobTransferId::new(key.value()[33..].try_into().unwrap()),
        ));
    }
    Ok(references)
}

pub(crate) fn bounded_variant_references_write(
    write: &redb::WriteTransaction,
    variant: BlobVariantId,
    root_limit: u64,
    charge: &mut super::MaintenanceCharge,
) -> Result<Option<Vec<(super::lifecycle::VariantReferenceOwner, BlobTransferId)>>, StoreError> {
    if !write
        .list_tables()?
        .any(|table| table.name() == super::lifecycle::BLOB_VARIANT_REFERENCES.name())
    {
        return Ok(Some(Vec::new()));
    }
    let mut first = [0u8; 65];
    first[..32].copy_from_slice(variant.as_bytes());
    let mut last = [0xffu8; 65];
    last[..32].copy_from_slice(variant.as_bytes());
    let table = write.open_table(super::lifecycle::BLOB_VARIANT_REFERENCES)?;
    let mut range = table.range::<&[u8]>((
        std::ops::Bound::Included(first.as_slice()),
        std::ops::Bound::Included(last.as_slice()),
    ))?;
    let mut references = Vec::new();
    loop {
        if !charge.has_capacity_for_row() {
            return Ok(None);
        }
        let Some(row) = range.next() else {
            break;
        };
        let (key, value) = row?;
        if !charge.charge_row(
            super::MaintenanceRowIdentity::new("aster.blob-variant-references.v1", key.value()),
            value.value().len(),
        )? {
            return Ok(None);
        }
        if key.value().len() != 65
            || key.value()[..32] != *variant.as_bytes()
            || !value.value().is_empty()
        {
            return Err(pressure_corruption(
                "Blob pressure variant reference is malformed",
            ));
        }
        if u64::try_from(references.len()).map_err(|_| StoreError::ItemCountAccountingOverflow)?
            >= root_limit
        {
            // This charged plus-one row proves that the highest-ranked atomic
            // unit does not fit the root dimension without allocating it.
            return Ok(None);
        }
        references.push((
            super::lifecycle::VariantReferenceOwner::decode(&key.value()[32..33])
                .map_err(blob_error)?,
            BlobTransferId::new(key.value()[33..].try_into().unwrap()),
        ));
    }
    Ok(Some(references))
}

fn require_variant_references_write(
    write: &redb::WriteTransaction,
    variant: BlobVariantId,
    reference_table_exists: bool,
    references: &[(super::lifecycle::VariantReferenceOwner, BlobTransferId)],
) -> Result<(), StoreError> {
    if references.is_empty() {
        if reference_table_exists
            && write
                .open_table(BLOB_PRESSURE_VARIANT_SUMMARIES)?
                .get(variant.as_bytes().as_slice())?
                .is_some()
        {
            return Err(pressure_corruption(
                "unrooted Blob variant retains a pressure summary",
            ));
        }
        return Ok(());
    }
    let mut effective_priority = Priority::Routine;
    let mut minimum_order = u64::MAX;
    let mut publication_roots = 0u64;
    let mut pending_roots = 0u64;
    let mut final_reference_expiry = PressureExpiry::ExpiredFinite;
    let mut has_finite_roots = false;
    for &(owner, transfer) in references {
        match owner {
            super::lifecycle::VariantReferenceOwner::Publication => {
                let root = publication_root_write(write, transfer)?;
                if root.variant_id != variant {
                    return Err(pressure_corruption(
                        "publication pressure variant contradicts its reference",
                    ));
                }
                require_publication_root_write(write, transfer, &root)?;
                effective_priority = effective_priority.max(root.priority);
                minimum_order = minimum_order.min(root.acceptance_order);
                final_reference_expiry = latest_expiry(final_reference_expiry, root.expiry);
                has_finite_roots |= root.expiry != PressureExpiry::Durable;
                publication_roots = publication_roots
                    .checked_add(1)
                    .ok_or(StoreError::ItemCountAccountingOverflow)?;
            }
            super::lifecycle::VariantReferenceOwner::PendingSource => {
                let record = write
                    .open_table(super::BLOB_PENDING_SOURCES)?
                    .get(transfer.as_bytes().as_slice())?
                    .map(|value| super::decode_pending_blob_source(value.value()))
                    .transpose()?
                    .ok_or_else(|| pressure_corruption("variant reference lacks pending source"))?;
                if record.metadata.variant_id != variant {
                    return Err(pressure_corruption(
                        "pending pressure variant contradicts its reference",
                    ));
                }
                require_pending_source_write(write, transfer, &record)?;
                effective_priority = effective_priority.max(record.metadata.header.priority);
                minimum_order = minimum_order.min(record.pending_acceptance_order);
                let expiry = lifetime_expiry(record.metadata.lifetime)?;
                final_reference_expiry = latest_expiry(final_reference_expiry, expiry);
                has_finite_roots |= expiry != PressureExpiry::Durable;
                pending_roots = pending_roots
                    .checked_add(1)
                    .ok_or(StoreError::ItemCountAccountingOverflow)?;
            }
        }
    }
    let (committed_progress, finalized) = variant_progress_write(write, variant)?;
    let expected = PressureVariantSummary {
        effective_priority,
        minimum_root_acceptance_order: minimum_order,
        committed_progress,
        finalized,
        publication_roots,
        pending_roots,
        final_reference_expiry,
        has_finite_roots,
    };
    let actual = write
        .open_table(BLOB_PRESSURE_VARIANT_SUMMARIES)?
        .get(variant.as_bytes().as_slice())?
        .map(|value| decode_variant_summary(value.value()))
        .transpose()?
        .ok_or_else(|| pressure_corruption("rooted Blob variant lacks pressure summary"))?;
    if actual != expected
        || write
            .open_table(BLOB_PRESSURE_VARIANTS)?
            .get(&variant_index_key_write(write, actual, variant)?)?
            .as_ref()
            .is_none_or(|value| !value.value().is_empty())
    {
        return Err(pressure_corruption(
            "Blob pressure variant summary or index contradicts authoritative state",
        ));
    }
    if expiry_indexes_active_write(write)?
        && write
            .open_table(BLOB_PRESSURE_DURABLE_VARIANTS)?
            .get(&variant_index_key_write(write, actual, variant)?)?
            .is_some()
            != !actual.has_finite_roots
    {
        return Err(pressure_corruption(
            "Blob durable pressure variant index contradicts its summary",
        ));
    }
    Ok(())
}

fn bounded_publication_root_write(
    write: &redb::WriteTransaction,
    transfer: BlobTransferId,
    charge: &mut super::MaintenanceCharge,
) -> Result<Option<PressurePublicationRoot>, StoreError> {
    if !charge.has_capacity_for_row() {
        return Ok(None);
    }
    let publications = write.open_table(super::BLOB_PUBLICATIONS)?;
    let encoded = publications
        .get(transfer.as_bytes().as_slice())?
        .ok_or_else(|| pressure_corruption("Blob pressure publication is missing"))?;
    if !charge.charge_row(
        super::MaintenanceRowIdentity::new(
            "aster.semantic-blob-publications.v1",
            transfer.as_bytes(),
        ),
        encoded.value().len(),
    )? {
        return Ok(None);
    }
    let encoded_bytes = encoded.value().to_vec();
    drop(encoded);
    drop(publications);
    let encoded = encoded_bytes;
    if super::lifecycle::publication_record_is_retired(&encoded).map_err(blob_error)? {
        return Err(pressure_corruption(
            "Blob pressure publication root refers to a retired publication",
        ));
    }
    let metadata = super::decode_blob_metadata(&encoded)?;
    if metadata.transfer_id != transfer {
        return Err(pressure_corruption(
            "Blob pressure publication key differs from its metadata",
        ));
    }
    if !charge.charge_row(
        super::MaintenanceRowIdentity::new("aster.semantic-blob-markers.v1", transfer.as_bytes()),
        std::mem::size_of::<u64>(),
    )? {
        return Ok(None);
    }
    let acceptance_order = write
        .open_table(super::BLOB_ACCEPTANCE_MARKERS)?
        .get(transfer.as_bytes().as_slice())?
        .map(|value| value.value())
        .ok_or_else(|| pressure_corruption("Blob pressure publication lacks its marker"))?;
    let root = PressurePublicationRoot {
        variant_id: metadata.variant_id,
        semantic_id: metadata.semantic_id,
        priority: metadata.header.priority,
        acceptance_order,
        expiry: lifetime_expiry(metadata.lifetime)?,
        topic: metadata.header.topic,
        scope: metadata.header.scope,
        blob_id: metadata.blob_id,
    };
    let roots = write.open_table(BLOB_PRESSURE_PUBLICATION_ROOTS)?;
    let encoded_root = roots
        .get(transfer.as_bytes().as_slice())?
        .ok_or_else(|| pressure_corruption("publication lacks its pressure root"))?;
    if !charge.charge_row(
        super::MaintenanceRowIdentity::new(
            "aster.blob-pressure-publication-roots.v1",
            transfer.as_bytes(),
        ),
        encoded_root.value().len(),
    )? {
        return Ok(None);
    }
    if decode_publication_root(encoded_root.value())? != root {
        return Err(pressure_corruption(
            "publication pressure root contradicts authoritative state",
        ));
    }
    drop(encoded_root);
    drop(roots);
    let global = publication_index_key_write(
        write,
        PressurePublicationKey {
            priority: root.priority,
            expiry: root.expiry,
            acceptance_order: root.acceptance_order,
            transfer_id: transfer,
        },
    )?;
    if !charge.charge_row(
        super::MaintenanceRowIdentity::new(
            "aster.blob-pressure-publications.v1",
            global.as_slice(),
        ),
        0,
    )? {
        return Ok(None);
    }
    if write
        .open_table(BLOB_PRESSURE_PUBLICATIONS)?
        .get(global.as_slice())?
        .as_ref()
        .is_none_or(|value| !value.value().is_empty())
    {
        return Err(pressure_corruption(
            "publication pressure root lacks its exact indexes",
        ));
    }
    let content = content_publication_index_key_write(write, &root, transfer)?;
    if !charge.charge_row(
        super::MaintenanceRowIdentity::new(
            "aster.blob-pressure-content-publications.v1",
            content.as_slice(),
        ),
        0,
    )? {
        return Ok(None);
    }
    if write
        .open_table(BLOB_PRESSURE_CONTENT_PUBLICATIONS)?
        .get(content.as_slice())?
        .as_ref()
        .is_none_or(|value| !value.value().is_empty())
    {
        return Err(pressure_corruption(
            "publication pressure root lacks its exact indexes",
        ));
    }
    if expiry_indexes_active_write(write)? {
        let durable = root.expiry == PressureExpiry::Durable;
        if durable
            && (!charge.charge_row(
                super::MaintenanceRowIdentity::new(
                    BLOB_PRESSURE_DURABLE_PUBLICATIONS.name(),
                    global.as_slice(),
                ),
                0,
            )? || !charge.charge_row(
                super::MaintenanceRowIdentity::new(
                    BLOB_PRESSURE_DURABLE_CONTENT_PUBLICATIONS.name(),
                    content.as_slice(),
                ),
                0,
            )?)
        {
            return Ok(None);
        }
        if write
            .open_table(BLOB_PRESSURE_DURABLE_PUBLICATIONS)?
            .get(global.as_slice())?
            .is_some()
            != durable
            || write
                .open_table(BLOB_PRESSURE_DURABLE_CONTENT_PUBLICATIONS)?
                .get(content.as_slice())?
                .is_some()
                != durable
        {
            return Err(pressure_corruption(
                "publication durable pressure indexes contradict its root",
            ));
        }
    }
    Ok(Some(root))
}

fn bounded_pending_progress_write(
    write: &redb::WriteTransaction,
    source: BlobTransferId,
    record: &super::PendingBlobSourceRecord,
    charge: &mut super::MaintenanceCharge,
) -> Result<Option<PressureFraction>, StoreError> {
    let total = record.carriers.iter().try_fold(0u64, |total, carrier| {
        total
            .checked_add(carrier.total_len)
            .ok_or(StoreError::PayloadByteAccountingOverflow)
    })?;
    let imports = write.open_table(super::BLOB_IMPORTS)?;
    let import = imports
        .get(record.metadata.variant_id.as_bytes().as_slice())?
        .ok_or_else(|| pressure_corruption("pending Blob pressure root lacks its depot import"))?;
    if !charge.charge_row(
        super::MaintenanceRowIdentity::new(
            "aster.blob-imports.v1",
            record.metadata.variant_id.as_bytes(),
        ),
        import.value().len(),
    )? {
        return Ok(None);
    }
    let import_bytes = import.value().to_vec();
    drop(import);
    drop(imports);
    let import = import_bytes;
    let chunks = write.open_table(super::BLOB_CHUNKS)?;
    let prefixes = write.open_table(super::BLOB_CARRIER_PREFIXES)?;
    let mut durable = 0u64;
    for carrier in &record.carriers {
        if !charge.has_capacity_for_row() {
            return Ok(None);
        }
        let mut key = [0u8; 40];
        key[..32].copy_from_slice(record.metadata.variant_id.as_bytes());
        key[32..].copy_from_slice(&carrier.index.to_be_bytes());
        if let Some(state) = chunks.get(key.as_slice())? {
            if !charge.charge_row(
                super::MaintenanceRowIdentity::new("aster.blob-chunks.v1", key.as_slice()),
                state.value().len(),
            )? {
                return Ok(None);
            }
            if super::depot::deletion_chunk_projection(&import, carrier.index, state.value())?
                .record
                .is_some()
            {
                durable = durable
                    .checked_add(carrier.total_len)
                    .ok_or(StoreError::PayloadByteAccountingOverflow)?;
                continue;
            }
        }
        let prefix_key = super::blob_carrier_prefix_key(source, carrier.object);
        if let Some(prefix) = prefixes.get(prefix_key.as_slice())? {
            if !charge.charge_row(
                super::MaintenanceRowIdentity::new(
                    "aster.pending-blob-carrier-prefixes.v1",
                    prefix_key.as_slice(),
                ),
                prefix.value().len(),
            )? {
                return Ok(None);
            }
            let prefix = super::decode_blob_carrier_prefix(prefix.value())?;
            if prefix.source != source || prefix.total_len != carrier.total_len {
                return Err(pressure_corruption(
                    "Blob pressure carrier prefix contradicts its pending source",
                ));
            }
            durable = durable
                .checked_add(
                    u64::try_from(prefix.prefix.len())
                        .map_err(|_| StoreError::PayloadByteAccountingOverflow)?,
                )
                .ok_or(StoreError::PayloadByteAccountingOverflow)?;
        }
    }
    authenticated_progress_fraction(durable, total).map(Some)
}

fn bounded_pending_root_write(
    write: &redb::WriteTransaction,
    transfer: BlobTransferId,
    record: &super::PendingBlobSourceRecord,
    charge: &mut super::MaintenanceCharge,
) -> Result<Option<PressurePendingRoot>, StoreError> {
    let roots = write.open_table(BLOB_PRESSURE_PENDING_ROOTS)?;
    let encoded = roots
        .get(transfer.as_bytes().as_slice())?
        .ok_or_else(|| pressure_corruption("pending Blob source lacks its pressure root"))?;
    if !charge.charge_row(
        super::MaintenanceRowIdentity::new(
            "aster.blob-pressure-pending-roots.v1",
            transfer.as_bytes(),
        ),
        encoded.value().len(),
    )? {
        return Ok(None);
    }
    let root = decode_pending_root(encoded.value())?;
    drop(encoded);
    drop(roots);
    let Some(completion) = bounded_pending_progress_write(write, transfer, record, charge)? else {
        return Ok(None);
    };
    let expected = PressurePendingRoot {
        variant_id: record.metadata.variant_id,
        authenticated_source_binding: record.authenticated_source_binding,
        priority: record.metadata.header.priority,
        acceptance_order: record.pending_acceptance_order,
        completion,
        expiry: lifetime_expiry(record.metadata.lifetime)?,
        topic: record.metadata.header.topic.clone(),
        scope: record.metadata.header.scope.clone(),
        blob_id: record.metadata.blob_id,
    };
    if root != expected {
        return Err(pressure_corruption(
            "pending Blob pressure root contradicts its source",
        ));
    }
    let key = pending_index_key_write(write, root.clone(), transfer)?;
    if !charge.charge_row(
        super::MaintenanceRowIdentity::new(
            "aster.blob-pressure-pending-sources.v1",
            key.as_slice(),
        ),
        0,
    )? {
        return Ok(None);
    }
    if write
        .open_table(BLOB_PRESSURE_PENDING_SOURCES)?
        .get(&key)?
        .as_ref()
        .is_none_or(|value| !value.value().is_empty())
    {
        return Err(pressure_corruption(
            "pending Blob pressure root lacks its exact index",
        ));
    }
    if expiry_indexes_active_write(write)? {
        let durable = root.expiry == PressureExpiry::Durable;
        if durable
            && !charge.charge_row(
                super::MaintenanceRowIdentity::new(
                    BLOB_PRESSURE_DURABLE_PENDING_SOURCES.name(),
                    key.as_slice(),
                ),
                0,
            )?
        {
            return Ok(None);
        }
        if write
            .open_table(BLOB_PRESSURE_DURABLE_PENDING_SOURCES)?
            .get(&key)?
            .is_some()
            != durable
        {
            return Err(pressure_corruption(
                "pending Blob durable pressure index contradicts its root",
            ));
        }
    }
    Ok(Some(root))
}

fn bounded_variant_progress_write(
    write: &redb::WriteTransaction,
    variant: BlobVariantId,
    charge: &mut super::MaintenanceCharge,
) -> Result<Option<(PressureFraction, bool)>, StoreError> {
    let pack_len = write
        .open_table(super::pack_lifecycle::BLOB_PROFILE5_PACKS)?
        .get(variant.as_bytes().as_slice())?
        .map(|pack| pack.value().len());
    if let Some(pack_len) = pack_len {
        if !charge.charge_row(
            super::MaintenanceRowIdentity::new(
                super::pack_lifecycle::BLOB_PROFILE5_PACKS.name(),
                variant.as_bytes(),
            ),
            pack_len,
        )? {
            return Ok(None);
        }
        let (committed, total) = super::pack_lifecycle::variant_progress_write(write, variant)?
            .ok_or_else(|| pressure_corruption("Blob pressure pack disappeared"))?;
        return Ok(Some((
            authenticated_progress_fraction(committed, total)?,
            true,
        )));
    }
    let imports = write.open_table(super::BLOB_IMPORTS)?;
    let import = imports
        .get(variant.as_bytes().as_slice())?
        .ok_or_else(|| pressure_corruption("Blob pressure root lacks its depot import"))?;
    if !charge.charge_row(
        super::MaintenanceRowIdentity::new("aster.blob-imports.v1", variant.as_bytes()),
        import.value().len(),
    )? {
        return Ok(None);
    }
    let import_bytes = import.value().to_vec();
    drop(import);
    drop(imports);
    let fact = super::depot::deletion_import_projection(variant.as_bytes(), &import_bytes)?;
    let mut first = [0u8; 40];
    first[..32].copy_from_slice(variant.as_bytes());
    let mut last = [0xffu8; 40];
    last[..32].copy_from_slice(variant.as_bytes());
    let chunks = write.open_table(super::BLOB_CHUNKS)?;
    let mut committed = 0u64;
    let mut chunk_rows = 0u64;
    for row in chunks.range::<&[u8]>((
        std::ops::Bound::Included(first.as_slice()),
        std::ops::Bound::Included(last.as_slice()),
    ))? {
        let (key, value) = row?;
        if !charge.charge_row(
            super::MaintenanceRowIdentity::new("aster.blob-chunks.v1", key.value()),
            value.value().len(),
        )? {
            return Ok(None);
        }
        chunk_rows = chunk_rows
            .checked_add(1)
            .ok_or(StoreError::ItemCountAccountingOverflow)?;
        if chunk_rows > super::MAX_SELECTED_BLOB_CHUNKS {
            return Err(pressure_corruption(
                "Blob pressure chunk set exceeds its structural bound",
            ));
        }
        let index = u64::from_be_bytes(
            key.value()[32..]
                .try_into()
                .map_err(|_| pressure_corruption("Blob pressure chunk index is invalid"))?,
        );
        let projection =
            super::depot::deletion_chunk_projection(&import_bytes, index, value.value())?;
        if let Some(record) = projection.record {
            committed = committed
                .checked_add(u64::from(record.plaintext_len()))
                .ok_or(StoreError::PayloadByteAccountingOverflow)?;
        }
    }
    let finalized = fact.finalized_root.is_some();
    let numerator = if finalized { fact.total_len } else { committed };
    authenticated_progress_fraction(numerator, fact.total_len)
        .map(|progress| Some((progress, finalized)))
}

pub(crate) fn require_variant_with_references_bounded_write(
    write: &redb::WriteTransaction,
    variant: BlobVariantId,
    references: &[(super::lifecycle::VariantReferenceOwner, BlobTransferId)],
    charge: &mut super::MaintenanceCharge,
) -> Result<bool, StoreError> {
    let mut effective_priority = Priority::Routine;
    let mut minimum_order = u64::MAX;
    let mut publication_roots = 0u64;
    let mut pending_roots = 0u64;
    let mut final_reference_expiry = PressureExpiry::ExpiredFinite;
    let mut has_finite_roots = false;
    for &(owner, transfer) in references {
        match owner {
            super::lifecycle::VariantReferenceOwner::Publication => {
                let Some(root) = bounded_publication_root_write(write, transfer, charge)? else {
                    return Ok(false);
                };
                if root.variant_id != variant {
                    return Err(pressure_corruption(
                        "publication pressure variant contradicts its reference",
                    ));
                }
                effective_priority = effective_priority.max(root.priority);
                minimum_order = minimum_order.min(root.acceptance_order);
                final_reference_expiry = latest_expiry(final_reference_expiry, root.expiry);
                has_finite_roots |= root.expiry != PressureExpiry::Durable;
                publication_roots = publication_roots
                    .checked_add(1)
                    .ok_or(StoreError::ItemCountAccountingOverflow)?;
            }
            super::lifecycle::VariantReferenceOwner::PendingSource => {
                let pending_sources = write.open_table(super::BLOB_PENDING_SOURCES)?;
                let pending_guard = pending_sources
                    .get(transfer.as_bytes().as_slice())?
                    .ok_or_else(|| pressure_corruption("variant reference lacks pending source"))?;
                if !charge.charge_row(
                    super::MaintenanceRowIdentity::new(
                        "aster.pending-blob-sources.v1",
                        transfer.as_bytes(),
                    ),
                    pending_guard.value().len(),
                )? {
                    return Ok(false);
                }
                let pending = super::decode_pending_blob_source(pending_guard.value())?;
                drop(pending_guard);
                drop(pending_sources);
                let Some(root) = bounded_pending_root_write(write, transfer, &pending, charge)?
                else {
                    return Ok(false);
                };
                if root.variant_id != variant {
                    return Err(pressure_corruption(
                        "pending pressure variant contradicts its reference",
                    ));
                }
                effective_priority = effective_priority.max(root.priority);
                minimum_order = minimum_order.min(root.acceptance_order);
                final_reference_expiry = latest_expiry(final_reference_expiry, root.expiry);
                has_finite_roots |= root.expiry != PressureExpiry::Durable;
                pending_roots = pending_roots
                    .checked_add(1)
                    .ok_or(StoreError::ItemCountAccountingOverflow)?;
            }
        }
    }
    let summaries = write.open_table(BLOB_PRESSURE_VARIANT_SUMMARIES)?;
    let encoded = summaries
        .get(variant.as_bytes().as_slice())?
        .ok_or_else(|| pressure_corruption("rooted Blob variant lacks pressure summary"))?;
    if !charge.charge_row(
        super::MaintenanceRowIdentity::new(
            "aster.blob-pressure-variant-summaries.v1",
            variant.as_bytes(),
        ),
        encoded.value().len(),
    )? {
        return Ok(false);
    }
    let actual = decode_variant_summary(encoded.value())?;
    drop(encoded);
    drop(summaries);
    let Some((committed_progress, finalized)) =
        bounded_variant_progress_write(write, variant, charge)?
    else {
        return Ok(false);
    };
    if actual.effective_priority != effective_priority
        || actual.minimum_root_acceptance_order != minimum_order
        || actual.committed_progress != committed_progress
        || actual.finalized != finalized
        || actual.publication_roots != publication_roots
        || actual.pending_roots != pending_roots
        || actual.final_reference_expiry != final_reference_expiry
        || actual.has_finite_roots != has_finite_roots
    {
        return Err(pressure_corruption(
            "Blob pressure variant summary contradicts its bounded roots",
        ));
    }
    let key = variant_index_key_write(write, actual, variant)?;
    if !charge.charge_row(
        super::MaintenanceRowIdentity::new("aster.blob-pressure-variants.v1", key.as_slice()),
        0,
    )? {
        return Ok(false);
    }
    if write
        .open_table(BLOB_PRESSURE_VARIANTS)?
        .get(&key)?
        .as_ref()
        .is_none_or(|value| !value.value().is_empty())
    {
        return Err(pressure_corruption(
            "Blob pressure variant summary lacks its exact index",
        ));
    }
    if expiry_indexes_active_write(write)? {
        let durable = !actual.has_finite_roots;
        if durable
            && !charge.charge_row(
                super::MaintenanceRowIdentity::new(
                    BLOB_PRESSURE_DURABLE_VARIANTS.name(),
                    key.as_slice(),
                ),
                0,
            )?
        {
            return Ok(false);
        }
        if write
            .open_table(BLOB_PRESSURE_DURABLE_VARIANTS)?
            .get(&key)?
            .is_some()
            != durable
        {
            return Err(pressure_corruption(
                "Blob durable pressure variant index contradicts its summary",
            ));
        }
    }
    Ok(true)
}

/// Preflights the complete pressure/lifecycle authority consulted and changed
/// by one TTL or generation-reanchor unit. Existing ordered rows are charged
/// by the bounded audit above; re-key successors are charged independently.
pub(crate) fn preflight_policy_root_mutation_write(
    write: &redb::WriteTransaction,
    variant: BlobVariantId,
    owner: super::lifecycle::VariantReferenceOwner,
    transfer: BlobTransferId,
    root_limit: u64,
    rekey: bool,
    charge: &mut super::MaintenanceCharge,
) -> Result<bool, StoreError> {
    let Some(references) = bounded_variant_references_write(write, variant, root_limit, charge)?
    else {
        return Ok(false);
    };
    if !references.contains(&(owner, transfer)) {
        return Err(pressure_corruption(
            "selected Blob policy root lacks its lifecycle reference",
        ));
    }
    if !require_variant_with_references_bounded_write(write, variant, &references, charge)? {
        return Ok(false);
    }

    if !rekey {
        let remaining = references
            .iter()
            .copied()
            .filter(|candidate| *candidate != (owner, transfer))
            .collect::<Vec<_>>();
        if !remaining.is_empty() {
            let successor = variant_summary_for_references_write(write, variant, &remaining)?;
            let successor_key = variant_index_key_write(write, successor, variant)?;
            if !charge.charge_row(
                super::MaintenanceRowIdentity::new(
                    "aster.blob-pressure-variants.v1",
                    successor_key.as_slice(),
                ),
                0,
            )? {
                return Ok(false);
            }
        }
        return Ok(true);
    }
    // A rekey retains the root, so it always writes one successor variant
    // index. The exact successor publication/pending keys are charged below.
    if !charge.charge_lengths(PRESSURE_VARIANT_INDEX_LEN, 0)? {
        return Ok(false);
    }
    match owner {
        super::lifecycle::VariantReferenceOwner::Publication => {
            let encoded = write
                .open_table(BLOB_PRESSURE_PUBLICATION_ROOTS)?
                .get(transfer.as_bytes().as_slice())?
                .map(|value| value.value().to_vec())
                .ok_or_else(|| pressure_corruption("publication lacks its pressure root"))?;
            let root = decode_publication_root(&encoded)?;
            let global = publication_index_key_write(
                write,
                PressurePublicationKey {
                    priority: root.priority,
                    expiry: root.expiry,
                    acceptance_order: root.acceptance_order,
                    transfer_id: transfer,
                },
            )?;
            let content = content_publication_index_key_write(write, &root, transfer)?;
            if !charge.charge_lengths(global.len(), 0)?
                || !charge.charge_lengths(content.len(), 0)?
            {
                return Ok(false);
            }
        }
        super::lifecycle::VariantReferenceOwner::PendingSource => {
            if !charge.charge_lengths(PRESSURE_PENDING_INDEX_LEN, 0)? {
                return Ok(false);
            }
        }
    }
    Ok(true)
}

fn variant_summary_for_references_write(
    write: &redb::WriteTransaction,
    variant: BlobVariantId,
    references: &[(super::lifecycle::VariantReferenceOwner, BlobTransferId)],
) -> Result<PressureVariantSummary, StoreError> {
    let mut effective_priority = Priority::Routine;
    let mut minimum_order = u64::MAX;
    let mut publication_roots = 0u64;
    let mut pending_roots = 0u64;
    let mut final_reference_expiry = PressureExpiry::ExpiredFinite;
    let mut has_finite_roots = false;
    for &(owner, transfer) in references {
        let (priority, order, expiry) = match owner {
            super::lifecycle::VariantReferenceOwner::Publication => {
                let encoded = write
                    .open_table(BLOB_PRESSURE_PUBLICATION_ROOTS)?
                    .get(transfer.as_bytes().as_slice())?
                    .map(|value| value.value().to_vec())
                    .ok_or_else(|| {
                        pressure_corruption("variant publication lacks pressure root")
                    })?;
                let root = decode_publication_root(&encoded)?;
                if root.variant_id != variant {
                    return Err(pressure_corruption(
                        "variant publication pressure root is contradictory",
                    ));
                }
                publication_roots = publication_roots
                    .checked_add(1)
                    .ok_or(StoreError::ItemCountAccountingOverflow)?;
                (root.priority, root.acceptance_order, root.expiry)
            }
            super::lifecycle::VariantReferenceOwner::PendingSource => {
                let encoded = write
                    .open_table(BLOB_PRESSURE_PENDING_ROOTS)?
                    .get(transfer.as_bytes().as_slice())?
                    .map(|value| value.value().to_vec())
                    .ok_or_else(|| {
                        pressure_corruption("variant pending source lacks pressure root")
                    })?;
                let root = decode_pending_root(&encoded)?;
                if root.variant_id != variant {
                    return Err(pressure_corruption(
                        "variant pending pressure root is contradictory",
                    ));
                }
                pending_roots = pending_roots
                    .checked_add(1)
                    .ok_or(StoreError::ItemCountAccountingOverflow)?;
                (root.priority, root.acceptance_order, root.expiry)
            }
        };
        effective_priority = effective_priority.max(priority);
        minimum_order = minimum_order.min(order);
        final_reference_expiry = latest_expiry(final_reference_expiry, expiry);
        has_finite_roots |= expiry != PressureExpiry::Durable;
    }
    let (committed_progress, finalized) = variant_progress_write(write, variant)?;
    Ok(PressureVariantSummary {
        effective_priority,
        minimum_root_acceptance_order: minimum_order,
        committed_progress,
        finalized,
        publication_roots,
        pending_roots,
        final_reference_expiry,
        has_finite_roots,
    })
}

pub(crate) fn require_variant_write(
    write: &redb::WriteTransaction,
    variant: BlobVariantId,
) -> Result<(), StoreError> {
    let reference_table_exists = write
        .list_tables()?
        .any(|table| table.name() == super::lifecycle::BLOB_VARIANT_REFERENCES.name());
    let references = variant_references_write(write, variant)?;
    require_variant_references_write(write, variant, reference_table_exists, &references)
}

fn add_root_to_variant_summary_without_references(
    write: &redb::WriteTransaction,
    variant: BlobVariantId,
    priority: Priority,
    acceptance_order: u64,
    pending: bool,
    expiry: PressureExpiry,
) -> Result<(), StoreError> {
    let old = write
        .open_table(BLOB_PRESSURE_VARIANT_SUMMARIES)?
        .get(variant.as_bytes().as_slice())?
        .map(|value| decode_variant_summary(value.value()))
        .transpose()?;
    if let Some(old) = old
        && write
            .open_table(BLOB_PRESSURE_VARIANTS)?
            .remove(&variant_index_key_write(write, old, variant)?)?
            .as_ref()
            .is_none_or(|value| !value.value().is_empty())
    {
        return Err(pressure_corruption(
            "Blob pressure variant summary lacks its exact index",
        ));
    }
    if let Some(old) = old {
        remove_durable_variant_index_write(write, old, variant)?;
    }
    let (committed_progress, finalized) = variant_progress_write(write, variant)?;
    let publication_roots = match old {
        Some(value) => value
            .publication_roots
            .checked_add(u64::from(!pending))
            .ok_or(StoreError::ItemCountAccountingOverflow)?,
        None => u64::from(!pending),
    };
    let pending_roots = match old {
        Some(value) => value
            .pending_roots
            .checked_add(u64::from(pending))
            .ok_or(StoreError::ItemCountAccountingOverflow)?,
        None => u64::from(pending),
    };
    let summary = PressureVariantSummary {
        effective_priority: old.map_or(priority, |value| value.effective_priority.max(priority)),
        minimum_root_acceptance_order: old.map_or(acceptance_order, |value| {
            value.minimum_root_acceptance_order.min(acceptance_order)
        }),
        committed_progress,
        finalized,
        publication_roots,
        pending_roots,
        final_reference_expiry: old.map_or(expiry, |value| {
            latest_expiry(value.final_reference_expiry, expiry)
        }),
        has_finite_roots: old.is_some_and(|value| value.has_finite_roots)
            || expiry != PressureExpiry::Durable,
    };
    let encoded = encode_variant_summary_write(write, summary)?;
    write
        .open_table(BLOB_PRESSURE_VARIANT_SUMMARIES)?
        .insert(variant.as_bytes().as_slice(), encoded.as_slice())?;
    if write
        .open_table(BLOB_PRESSURE_VARIANTS)?
        .insert(
            &variant_index_key_write(write, summary, variant)?,
            &[] as &[u8],
        )?
        .is_some()
    {
        return Err(pressure_corruption(
            "Blob pressure variant index duplicates another summary",
        ));
    }
    insert_durable_variant_index_write(write, summary, variant)?;
    Ok(())
}

fn refresh_variant_summary(
    write: &redb::WriteTransaction,
    variant: BlobVariantId,
    allow_first_summary: bool,
) -> Result<(), StoreError> {
    let references = variant_references_write(write, variant)?;
    let old = write
        .open_table(BLOB_PRESSURE_VARIANT_SUMMARIES)?
        .get(variant.as_bytes().as_slice())?
        .map(|value| decode_variant_summary(value.value()))
        .transpose()?;
    if let Some(old) = old {
        let old_key = variant_index_key_write(write, old, variant)?;
        if write
            .open_table(BLOB_PRESSURE_VARIANTS)?
            .remove(&old_key)?
            .as_ref()
            .is_none_or(|value| !value.value().is_empty())
        {
            return Err(pressure_corruption(
                "Blob pressure variant summary lacks its exact index",
            ));
        }
        remove_durable_variant_index_write(write, old, variant)?;
    } else if references.is_empty() {
        return Ok(());
    } else if !allow_first_summary || references.len() != 1 {
        return Err(pressure_corruption(
            "rooted Blob variant lacks its pressure summary",
        ));
    }
    if references.is_empty() {
        if write
            .open_table(BLOB_PRESSURE_VARIANT_SUMMARIES)?
            .remove(variant.as_bytes().as_slice())?
            .is_none()
        {
            return Err(pressure_corruption(
                "final Blob root lacks its pressure summary",
            ));
        }
        return Ok(());
    }
    let mut effective_priority = Priority::Routine;
    let mut minimum_order = u64::MAX;
    let mut publication_roots = 0u64;
    let mut pending_roots = 0u64;
    let mut final_reference_expiry = PressureExpiry::ExpiredFinite;
    let mut has_finite_roots = false;
    for (owner, transfer) in references {
        match owner {
            super::lifecycle::VariantReferenceOwner::Publication => {
                let encoded = write
                    .open_table(BLOB_PRESSURE_PUBLICATION_ROOTS)?
                    .get(transfer.as_bytes().as_slice())?
                    .map(|value| value.value().to_vec())
                    .ok_or_else(|| {
                        pressure_corruption("variant publication lacks pressure root")
                    })?;
                let root = decode_publication_root(&encoded)?;
                if root.variant_id != variant {
                    return Err(pressure_corruption(
                        "variant publication pressure root is contradictory",
                    ));
                }
                effective_priority = effective_priority.max(root.priority);
                minimum_order = minimum_order.min(root.acceptance_order);
                final_reference_expiry = latest_expiry(final_reference_expiry, root.expiry);
                has_finite_roots |= root.expiry != PressureExpiry::Durable;
                publication_roots = publication_roots
                    .checked_add(1)
                    .ok_or(StoreError::ItemCountAccountingOverflow)?;
            }
            super::lifecycle::VariantReferenceOwner::PendingSource => {
                let encoded = write
                    .open_table(BLOB_PRESSURE_PENDING_ROOTS)?
                    .get(transfer.as_bytes().as_slice())?
                    .map(|value| value.value().to_vec())
                    .ok_or_else(|| {
                        pressure_corruption("variant pending source lacks pressure root")
                    })?;
                let root = decode_pending_root(&encoded)?;
                if root.variant_id != variant {
                    return Err(pressure_corruption(
                        "variant pending pressure root is contradictory",
                    ));
                }
                effective_priority = effective_priority.max(root.priority);
                minimum_order = minimum_order.min(root.acceptance_order);
                final_reference_expiry = latest_expiry(final_reference_expiry, root.expiry);
                has_finite_roots |= root.expiry != PressureExpiry::Durable;
                pending_roots = pending_roots
                    .checked_add(1)
                    .ok_or(StoreError::ItemCountAccountingOverflow)?;
            }
        }
    }
    let (committed_progress, finalized) = variant_progress_write(write, variant)?;
    let summary = PressureVariantSummary {
        effective_priority,
        minimum_root_acceptance_order: minimum_order,
        committed_progress,
        finalized,
        publication_roots,
        pending_roots,
        final_reference_expiry,
        has_finite_roots,
    };
    let encoded = encode_variant_summary_write(write, summary)?;
    write
        .open_table(BLOB_PRESSURE_VARIANT_SUMMARIES)?
        .insert(variant.as_bytes().as_slice(), encoded.as_slice())?;
    if write
        .open_table(BLOB_PRESSURE_VARIANTS)?
        .insert(
            &variant_index_key_write(write, summary, variant)?,
            &[] as &[u8],
        )?
        .is_some()
    {
        return Err(pressure_corruption(
            "Blob pressure variant index duplicates another summary",
        ));
    }
    insert_durable_variant_index_write(write, summary, variant)?;
    Ok(())
}

pub(crate) fn reconcile_variant_write(
    write: &redb::WriteTransaction,
    variant: BlobVariantId,
) -> Result<(), StoreError> {
    for (owner, transfer) in variant_references_write(write, variant)? {
        match owner {
            super::lifecycle::VariantReferenceOwner::Publication => {
                let expected = publication_root_write(write, transfer)?;
                require_publication_root_write(write, transfer, &expected)?;
            }
            super::lifecycle::VariantReferenceOwner::PendingSource => {
                let record = write
                    .open_table(super::BLOB_PENDING_SOURCES)?
                    .get(transfer.as_bytes().as_slice())?
                    .map(|value| super::decode_pending_blob_source(value.value()))
                    .transpose()?
                    .ok_or_else(|| pressure_corruption("variant reference lacks pending source"))?;
                let old = write
                    .open_table(BLOB_PRESSURE_PENDING_ROOTS)?
                    .get(transfer.as_bytes().as_slice())?
                    .map(|value| decode_pending_root(value.value()))
                    .transpose()?
                    .ok_or_else(|| pressure_corruption("pending source lacks pressure root"))?;
                if old.variant_id != record.metadata.variant_id
                    || old.priority != record.metadata.header.priority
                    || old.acceptance_order != record.pending_acceptance_order
                    || old.expiry != lifetime_expiry(record.metadata.lifetime)?
                    || old.topic != record.metadata.header.topic
                    || old.scope != record.metadata.header.scope
                    || old.blob_id != record.metadata.blob_id
                {
                    return Err(pressure_corruption(
                        "pending pressure root contradicts authoritative state",
                    ));
                }
                let old_key = pending_index_key_write(write, old.clone(), transfer)?;
                remove_durable_pending_index_write(write, old, transfer)?;
                if write
                    .open_table(BLOB_PRESSURE_PENDING_SOURCES)?
                    .remove(&old_key)?
                    .as_ref()
                    .is_none_or(|value| !value.value().is_empty())
                {
                    return Err(pressure_corruption(
                        "pending pressure root lacks exact index",
                    ));
                }
                let expected = PressurePendingRoot {
                    variant_id: record.metadata.variant_id,
                    authenticated_source_binding: record.authenticated_source_binding,
                    priority: record.metadata.header.priority,
                    acceptance_order: record.pending_acceptance_order,
                    completion: pending_progress(
                        transfer,
                        &record,
                        &write.open_table(super::BLOB_CARRIER_PREFIXES)?,
                        &write.open_table(super::BLOB_IMPORTS)?,
                        &write.open_table(super::BLOB_CHUNKS)?,
                    )?,
                    expiry: lifetime_expiry(record.metadata.lifetime)?,
                    topic: record.metadata.header.topic,
                    scope: record.metadata.header.scope,
                    blob_id: record.metadata.blob_id,
                };
                let encoded = encode_pending_root(&expected)?;
                write
                    .open_table(BLOB_PRESSURE_PENDING_ROOTS)?
                    .insert(transfer.as_bytes().as_slice(), encoded.as_slice())?;
                if write
                    .open_table(BLOB_PRESSURE_PENDING_SOURCES)?
                    .insert(
                        &pending_index_key_write(write, expected.clone(), transfer)?,
                        &[] as &[u8],
                    )?
                    .is_some()
                {
                    return Err(pressure_corruption("pending pressure index is duplicated"));
                }
                insert_durable_pending_index_write(write, expected, transfer)?;
            }
        }
    }
    refresh_variant_summary(write, variant, false)
}

fn insert_publication_root_write(
    write: &redb::WriteTransaction,
    transfer: BlobTransferId,
) -> Result<BlobVariantId, StoreError> {
    let root = publication_root_write(write, transfer)?;
    if write
        .open_table(BLOB_PRESSURE_PUBLICATION_ROOTS)?
        .get(transfer.as_bytes().as_slice())?
        .is_some()
    {
        return Err(pressure_corruption(
            "new publication already has pressure root",
        ));
    }
    let encoded = encode_publication_root(&root)?;
    write
        .open_table(BLOB_PRESSURE_PUBLICATION_ROOTS)?
        .insert(transfer.as_bytes().as_slice(), encoded.as_slice())?;
    let global = publication_index_key_write(
        write,
        PressurePublicationKey {
            priority: root.priority,
            expiry: root.expiry,
            acceptance_order: root.acceptance_order,
            transfer_id: transfer,
        },
    )?;
    if write
        .open_table(BLOB_PRESSURE_PUBLICATIONS)?
        .insert(global.as_slice(), &[] as &[u8])?
        .is_some()
        || write
            .open_table(BLOB_PRESSURE_CONTENT_PUBLICATIONS)?
            .insert(
                content_publication_index_key_write(write, &root, transfer)?.as_slice(),
                &[] as &[u8],
            )?
            .is_some()
    {
        return Err(pressure_corruption(
            "publication pressure index is duplicated",
        ));
    }
    insert_durable_publication_indexes_write(write, &root, transfer)?;
    Ok(root.variant_id)
}

pub(crate) fn insert_publication_write(
    write: &redb::WriteTransaction,
    transfer: BlobTransferId,
) -> Result<(), StoreError> {
    let variant = insert_publication_root_write(write, transfer)?;
    if variant_references_write(write, variant)?.is_empty() {
        let root = publication_root_write(write, transfer)?;
        add_root_to_variant_summary_without_references(
            write,
            variant,
            root.priority,
            root.acceptance_order,
            false,
            root.expiry,
        )
    } else {
        refresh_variant_summary(write, variant, true)
    }
}

fn remove_pending_root_write(
    write: &redb::WriteTransaction,
    transfer: BlobTransferId,
    variant: BlobVariantId,
) -> Result<(), StoreError> {
    let encoded = write
        .open_table(BLOB_PRESSURE_PENDING_ROOTS)?
        .remove(transfer.as_bytes().as_slice())?
        .map(|value| value.value().to_vec())
        .ok_or_else(|| pressure_corruption("removed pending source lacks pressure root"))?;
    let root = decode_pending_root(&encoded)?;
    remove_durable_pending_index_write(write, root.clone(), transfer)?;
    if root.variant_id != variant
        || write
            .open_table(BLOB_PRESSURE_PENDING_SOURCES)?
            .remove(&pending_index_key_write(write, root, transfer)?)?
            .as_ref()
            .is_none_or(|value| !value.value().is_empty())
    {
        return Err(pressure_corruption(
            "removed pending pressure metadata is contradictory",
        ));
    }
    Ok(())
}

pub(crate) fn remove_pending_source_root_write(
    write: &redb::WriteTransaction,
    transfer: BlobTransferId,
    variant: BlobVariantId,
) -> Result<(), StoreError> {
    remove_pending_root_write(write, transfer, variant)
}

pub(crate) fn remove_pending_source_write(
    write: &redb::WriteTransaction,
    transfer: BlobTransferId,
    variant: BlobVariantId,
) -> Result<(), StoreError> {
    remove_pending_root_write(write, transfer, variant)?;
    refresh_variant_summary(write, variant, false)
}

pub(crate) fn promote_pending_source_write(
    write: &redb::WriteTransaction,
    transfer: BlobTransferId,
    variant: BlobVariantId,
) -> Result<(), StoreError> {
    remove_pending_root_write(write, transfer, variant)?;
    if write
        .open_table(BLOB_PRESSURE_PUBLICATION_ROOTS)?
        .get(transfer.as_bytes().as_slice())?
        .is_some()
    {
        let expected = publication_root_write(write, transfer)?;
        require_publication_root_write(write, transfer, &expected)?;
    } else if insert_publication_root_write(write, transfer)? != variant {
        return Err(pressure_corruption(
            "promoted Blob pressure variant changed",
        ));
    }
    refresh_variant_summary(write, variant, false)
}

pub(crate) fn remove_publication_write(
    write: &redb::WriteTransaction,
    transfer: BlobTransferId,
    variant: BlobVariantId,
) -> Result<(), StoreError> {
    remove_publication_root_write(write, transfer, variant)?;
    refresh_variant_summary(write, variant, false)
}

pub(crate) fn remove_publication_root_write(
    write: &redb::WriteTransaction,
    transfer: BlobTransferId,
    variant: BlobVariantId,
) -> Result<(), StoreError> {
    let encoded = write
        .open_table(BLOB_PRESSURE_PUBLICATION_ROOTS)?
        .remove(transfer.as_bytes().as_slice())?
        .map(|value| value.value().to_vec())
        .ok_or_else(|| pressure_corruption("removed publication lacks pressure root"))?;
    let root = decode_publication_root(&encoded)?;
    remove_durable_publication_indexes_write(write, &root, transfer)?;
    let global = publication_index_key_write(
        write,
        PressurePublicationKey {
            priority: root.priority,
            expiry: root.expiry,
            acceptance_order: root.acceptance_order,
            transfer_id: transfer,
        },
    )?;
    if root.variant_id != variant
        || write
            .open_table(BLOB_PRESSURE_PUBLICATIONS)?
            .remove(global.as_slice())?
            .as_ref()
            .is_none_or(|value| !value.value().is_empty())
        || write
            .open_table(BLOB_PRESSURE_CONTENT_PUBLICATIONS)?
            .remove(content_publication_index_key_write(write, &root, transfer)?.as_slice())?
            .as_ref()
            .is_none_or(|value| !value.value().is_empty())
    {
        return Err(pressure_corruption(
            "removed publication pressure metadata is contradictory",
        ));
    }
    Ok(())
}

pub(crate) fn remove_drained_variant_write(
    write: &redb::WriteTransaction,
    variant: BlobVariantId,
) -> Result<(), StoreError> {
    let mut first = [0u8; 65];
    first[..32].copy_from_slice(variant.as_bytes());
    let mut last = [0xffu8; 65];
    last[..32].copy_from_slice(variant.as_bytes());
    if write
        .open_table(super::lifecycle::BLOB_VARIANT_REFERENCES)?
        .range::<&[u8]>((
            std::ops::Bound::Included(first.as_slice()),
            std::ops::Bound::Included(last.as_slice()),
        ))?
        .next()
        .transpose()?
        .is_some()
    {
        return Err(pressure_corruption(
            "drained Blob pressure variant retains a live reference",
        ));
    }
    let summary = write
        .open_table(BLOB_PRESSURE_VARIANT_SUMMARIES)?
        .remove(variant.as_bytes().as_slice())?
        .map(|value| decode_variant_summary(value.value()))
        .transpose()?
        .ok_or_else(|| pressure_corruption("final Blob root lacks its pressure summary"))?;
    remove_durable_variant_index_write(write, summary, variant)?;
    if write
        .open_table(BLOB_PRESSURE_VARIANTS)?
        .remove(&variant_index_key_write(write, summary, variant)?)?
        .as_ref()
        .is_none_or(|value| !value.value().is_empty())
    {
        return Err(pressure_corruption(
            "drained Blob pressure summary lacks its exact index",
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::cmp::Ordering;
    use std::sync::atomic::{AtomicU64, Ordering as AtomicOrdering};

    use aster_mesh::{BlobId, Priority, Scope, Topic};
    use redb::{ReadableDatabase, ReadableTable};

    use super::{
        BLOB_PRESSURE_METADATA, BLOB_PRESSURE_PENDING_ROOTS, BLOB_PRESSURE_PUBLICATION_ROOTS,
        BLOB_PRESSURE_REANCHOR_CURSORS, NEXT_PENDING_ACCEPTANCE_ORDER, PRESSURE_EXPIRY_DURABLE,
        PRESSURE_RECORD_VERSION, PRESSURE_SCHEMA_VERSION, PRESSURE_SCHEMA_VERSION_FIELD,
        PRESSURE_V4_SCHEMA_VERSION, PressureExpiry, PressureFraction, PressurePendingRoot,
        PressurePendingRootEncodingGeneration, PressurePublicationKey, PressurePublicationRoot,
        PressureReanchorCursor, PressureReanchorRoot, PressureVariantSummary, REANCHOR_DIRTY,
        REANCHOR_NEXT_PHASE, REANCHOR_TARGET_GENERATION, compare_pressure_fraction,
        decode_content_publication_key, decode_pending_index_key, decode_pending_root,
        decode_pending_root_for_generation, decode_publication_key, decode_publication_root,
        decode_variant_index_key, decode_variant_summary, encode_content_publication_key,
        encode_pending_index_key, encode_pending_root, encode_pending_root_for_generation,
        encode_publication_key, encode_publication_root, encode_reanchor_cursor,
        encode_variant_index_key, encode_variant_summary, encode_variant_summary_for_generation,
        finish_reanchor_turn_write, plan_reanchor_turn_write, pressure_ready_write,
        synchronize_reanchor_state_write,
    };
    use crate::StoreError;
    use crate::blob::{BlobSemanticId, BlobTransferId, BlobVariantId};

    static NEXT_PRESSURE_DATABASE: AtomicU64 = AtomicU64::new(1);

    fn pressure_database(label: &str) -> (std::path::PathBuf, redb::Database) {
        let ordinal = NEXT_PRESSURE_DATABASE.fetch_add(1, AtomicOrdering::Relaxed);
        let path = std::env::temp_dir().join(format!(
            "aster-pressure-{label}-{}-{ordinal}.redb",
            std::process::id()
        ));
        let database = redb::Database::create(&path).expect("pressure test database");
        // Direct index fixtures model the exact neutral predecessor unless a
        // test explicitly replaces this row with a complete v5 gate image.
        let write = database.begin_write().expect("pressure fixture writer");
        write
            .open_table(BLOB_PRESSURE_METADATA)
            .expect("pressure fixture metadata")
            .insert(PRESSURE_SCHEMA_VERSION_FIELD, PRESSURE_V4_SCHEMA_VERSION)
            .expect("pressure fixture schema");
        write
            .open_table(BLOB_PRESSURE_PUBLICATION_ROOTS)
            .expect("pressure fixture publication roots");
        write
            .open_table(BLOB_PRESSURE_PENDING_ROOTS)
            .expect("pressure fixture pending roots");
        write
            .open_table(super::BLOB_PRESSURE_VARIANT_SUMMARIES)
            .expect("pressure fixture variant summaries");
        write
            .open_table(super::BLOB_PRESSURE_PUBLICATIONS)
            .expect("pressure fixture publications");
        write
            .open_table(super::BLOB_PRESSURE_CONTENT_PUBLICATIONS)
            .expect("pressure fixture content publications");
        write
            .open_table(super::BLOB_PRESSURE_PENDING_SOURCES)
            .expect("pressure fixture pending sources");
        write
            .open_table(super::BLOB_PRESSURE_VARIANTS)
            .expect("pressure fixture variants");
        write.commit().expect("commit pressure fixture schema");
        (path, database)
    }

    fn publication_root() -> PressurePublicationRoot {
        PressurePublicationRoot {
            variant_id: BlobVariantId::from_bytes([0x22; 32]),
            semantic_id: BlobSemanticId::new([0x33; 32]),
            priority: Priority::Immediate,
            acceptance_order: 0x0102_0304_0506_0708,
            expiry: PressureExpiry::Durable,
            topic: Topic::new("ops").expect("topic"),
            scope: Scope::new("alpha/bravo").expect("scope"),
            blob_id: BlobId::from_bytes([0x44; 32]),
        }
    }

    #[test]
    fn finite_lifetime_pressure_expiry_and_shared_root_dominance_are_exact() {
        let finite = crate::blob::BlobLifetime::Finite {
            ttl_ms: 1_000,
            age: crate::custody::LowerBoundAgeCheckpoint {
                cumulative_age_ms: 250,
                checkpoint: Some(aster_mesh::CustodySample {
                    clock_id: [0x21; 16],
                    tick_ms: 4_000,
                }),
                continuity_generation: 1,
                continuity_lost: false,
            },
            provenance: crate::blob::BlobFiniteProvenance::Local,
        };
        // Mutation caught: pressure ranking must use the authoritative
        // checkpoint plus remaining lower-bound lifetime, not raw TTL.
        assert_eq!(
            super::lifetime_expiry(finite).unwrap(),
            PressureExpiry::Finite(4_750)
        );
        assert_eq!(
            super::latest_expiry(PressureExpiry::Finite(4_750), PressureExpiry::Finite(9_000),),
            PressureExpiry::Finite(9_000)
        );
        // Mutation caught: one durable shared root dominates every finite
        // final-reference expiry in the variant summary.
        assert_eq!(
            super::latest_expiry(PressureExpiry::Finite(9_000), PressureExpiry::Durable),
            PressureExpiry::Durable
        );
    }

    #[test]
    fn pressure_publication_key_keeps_expiry_inactive_until_task_four() {
        let minimum = PressurePublicationKey {
            priority: Priority::Routine,
            expiry: PressureExpiry::Durable,
            acceptance_order: 1,
            transfer_id: BlobTransferId::new([0; 32]),
        };
        let maximum = PressurePublicationKey {
            priority: Priority::Flash,
            expiry: PressureExpiry::Finite(u64::MAX),
            acceptance_order: u64::MAX,
            transfer_id: BlobTransferId::new([0xff; 32]),
        };

        let minimum_bytes = encode_publication_key(minimum);
        assert_eq!(
            minimum_bytes,
            [
                vec![2, 0, 1, 2],
                vec![0; 8],
                vec![0, 0, 0, 0, 0, 0, 0, 1],
                vec![0; 32],
            ]
            .concat()
        );
        let maximum_bytes = encode_publication_key(maximum);
        assert_eq!(
            maximum_bytes,
            [vec![2, 3, 1, 2], vec![0; 8], vec![0xff; 8], vec![0xff; 32],].concat()
        );
        assert_eq!(minimum_bytes.len(), maximum_bytes.len());
        assert_eq!(decode_publication_key(&minimum_bytes).unwrap(), minimum);
        assert_eq!(
            decode_publication_key(&maximum_bytes).unwrap(),
            PressurePublicationKey {
                expiry: PressureExpiry::Durable,
                ..maximum
            }
        );
        assert!(decode_publication_key(&minimum_bytes[..minimum_bytes.len() - 1]).is_err());
        let mut unknown = minimum_bytes;
        unknown[0] = PRESSURE_RECORD_VERSION.wrapping_add(1);
        assert!(decode_publication_key(&unknown).is_err());
    }

    #[test]
    fn pressure_index_encoding_activates_expiry_only_for_exact_v5_schema() {
        // Mutations caught: keeping ordinary v5 mutations on the neutral v4
        // key encoding, or enabling expiry ordering for a predecessor image.
        let (path, database) = pressure_database("schema-selected-expiry-index");
        let key = PressurePublicationKey {
            priority: Priority::Routine,
            expiry: PressureExpiry::Finite(900),
            acceptance_order: 7,
            transfer_id: BlobTransferId::new([0x7a; 32]),
        };
        let write = database.begin_write().expect("pressure schema writer");
        {
            let mut metadata = write.open_table(BLOB_PRESSURE_METADATA).unwrap();
            metadata
                .insert(PRESSURE_SCHEMA_VERSION_FIELD, PRESSURE_V4_SCHEMA_VERSION)
                .unwrap();
            metadata.insert(NEXT_PENDING_ACCEPTANCE_ORDER, 1).unwrap();
        }
        assert_eq!(
            decode_publication_key(&super::publication_index_key_write(&write, key).unwrap())
                .unwrap()
                .expiry,
            PressureExpiry::Durable
        );
        write
            .open_table(BLOB_PRESSURE_METADATA)
            .unwrap()
            .insert(PRESSURE_SCHEMA_VERSION_FIELD, PRESSURE_SCHEMA_VERSION)
            .unwrap();
        assert_eq!(
            decode_publication_key(&super::publication_index_key_write(&write, key).unwrap())
                .unwrap()
                .expiry,
            PressureExpiry::Finite(900)
        );
        drop(write);
        drop(database);
        std::fs::remove_file(path).unwrap();
    }

    #[test]
    fn pressure_v5_dirty_gate_returns_no_candidate_before_index_access() {
        // Mutation caught: pressure selection must not inspect or mutate a
        // partially re-anchored index and report a false recovery candidate.
        let (path, database) = pressure_database("dirty-selection-gate");
        let write = database.begin_write().unwrap();
        {
            let mut metadata = write.open_table(BLOB_PRESSURE_METADATA).unwrap();
            for (field, value) in [
                (PRESSURE_SCHEMA_VERSION_FIELD, PRESSURE_SCHEMA_VERSION),
                (NEXT_PENDING_ACCEPTANCE_ORDER, 1),
                (super::REANCHOR_TARGET_GENERATION, 0),
                (super::REANCHOR_DIRTY, 1),
                (super::REANCHOR_NEXT_PHASE, 1),
            ] {
                metadata.insert(field, value).unwrap();
            }
        }
        write.commit().unwrap();
        let read = database.begin_read().unwrap();
        let demand = super::BlobCapacityRecoveryDemand::new(
            super::BlobCapacityPartition::AggregateItems,
            Priority::Immediate,
            1,
        )
        .unwrap();
        let selection = super::select_pressure_candidate_read(
            &read,
            demand,
            super::BlobPressureRecoveryBudget::new(1, 1, 1, 1, 1).unwrap(),
        )
        .expect("dirty pressure gate");
        assert_eq!(selection.candidate(), None);
        assert!(selection.proven());
        assert_eq!(selection.rows_examined(), 0);
        drop(read);
        drop(database);
        std::fs::remove_file(path).unwrap();
    }

    #[test]
    fn durable_selection_charges_finite_index_rows_without_opening_their_roots() {
        // Mutation caught: durable-only selection used to open every skipped
        // finite root without charging it, and variant selection rescanned both
        // complete root tables once per skipped variant.  Finite index rows are
        // bounded scan work, but must not consume the first eligible candidate.
        let (path, database) = pressure_database("durable-selection-bounded-finite-prefix");
        let write = database.begin_write().unwrap();
        {
            let mut metadata = write.open_table(BLOB_PRESSURE_METADATA).unwrap();
            metadata
                .insert(PRESSURE_SCHEMA_VERSION_FIELD, PRESSURE_SCHEMA_VERSION)
                .unwrap();
            metadata.insert(NEXT_PENDING_ACCEPTANCE_ORDER, 1).unwrap();
            metadata.insert(REANCHOR_TARGET_GENERATION, 0).unwrap();
            metadata.insert(REANCHOR_DIRTY, 0).unwrap();
            metadata.insert(REANCHOR_NEXT_PHASE, 1).unwrap();
        }
        write
            .open_table(BLOB_PRESSURE_REANCHOR_CURSORS)
            .expect("current pressure fixture reanchor cursors");
        let topic = Topic::new("bounded-durable-selection").unwrap();
        let scope = Scope::new("mission/bounded-durable-selection").unwrap();
        let blob_id = BlobId::from_bytes([0xf0; 32]);
        for ordinal in 0u8..9 {
            let expiry = if ordinal == 8 {
                PressureExpiry::Durable
            } else {
                PressureExpiry::Finite(100 + u64::from(ordinal))
            };
            let transfer = BlobTransferId::new([0x10 + ordinal; 32]);
            let variant = BlobVariantId::from_bytes([0x30 + ordinal; 32]);
            let publication = PressurePublicationRoot {
                variant_id: variant,
                semantic_id: BlobSemanticId::new([0x50 + ordinal; 32]),
                priority: Priority::Routine,
                acceptance_order: 1 + u64::from(ordinal),
                expiry,
                topic: topic.clone(),
                scope: scope.clone(),
                blob_id,
            };
            let encoded = super::encode_publication_root(&publication).unwrap();
            write
                .open_table(super::BLOB_PRESSURE_PUBLICATION_ROOTS)
                .unwrap()
                .insert(transfer.as_bytes().as_slice(), encoded.as_slice())
                .unwrap();
            let key = super::encode_publication_key_for_generation(
                super::PressurePublicationKey {
                    priority: publication.priority,
                    expiry,
                    acceptance_order: publication.acceptance_order,
                    transfer_id: transfer,
                },
                true,
            );
            write
                .open_table(super::BLOB_PRESSURE_PUBLICATIONS)
                .unwrap()
                .insert(key.as_slice(), &[] as &[u8])
                .unwrap();
            let content_key =
                super::encode_content_publication_key_for_generation(&publication, transfer, true)
                    .unwrap();
            write
                .open_table(super::BLOB_PRESSURE_CONTENT_PUBLICATIONS)
                .unwrap()
                .insert(content_key.as_slice(), &[] as &[u8])
                .unwrap();
            if expiry == PressureExpiry::Durable {
                write
                    .open_table(super::BLOB_PRESSURE_DURABLE_PUBLICATIONS)
                    .unwrap()
                    .insert(key.as_slice(), &[] as &[u8])
                    .unwrap();
                write
                    .open_table(super::BLOB_PRESSURE_DURABLE_CONTENT_PUBLICATIONS)
                    .unwrap()
                    .insert(content_key.as_slice(), &[] as &[u8])
                    .unwrap();
            }

            let pending_transfer = BlobTransferId::new([0x70 + ordinal; 32]);
            let pending = PressurePendingRoot {
                variant_id: BlobVariantId::from_bytes([0x90 + ordinal; 32]),
                authenticated_source_binding: [0xb0 + ordinal; 32],
                priority: Priority::Routine,
                acceptance_order: 1 + u64::from(ordinal),
                completion: PressureFraction::new(1, 2).unwrap(),
                expiry,
                topic: topic.clone(),
                scope: scope.clone(),
                blob_id,
            };
            let encoded = super::encode_pending_root(&pending).unwrap();
            write
                .open_table(super::BLOB_PRESSURE_PENDING_ROOTS)
                .unwrap()
                .insert(pending_transfer.as_bytes().as_slice(), encoded.as_slice())
                .unwrap();
            let key =
                super::encode_pending_index_key_for_generation(pending, pending_transfer, true);
            write
                .open_table(super::BLOB_PRESSURE_PENDING_SOURCES)
                .unwrap()
                .insert(&key, &[] as &[u8])
                .unwrap();
            if expiry == PressureExpiry::Durable {
                write
                    .open_table(super::BLOB_PRESSURE_DURABLE_PENDING_SOURCES)
                    .unwrap()
                    .insert(&key, &[] as &[u8])
                    .unwrap();
            }

            let summary = PressureVariantSummary {
                effective_priority: Priority::Routine,
                minimum_root_acceptance_order: 1 + u64::from(ordinal),
                committed_progress: PressureFraction::new(1, 2).unwrap(),
                finalized: false,
                publication_roots: 1,
                pending_roots: 0,
                final_reference_expiry: expiry,
                has_finite_roots: expiry != PressureExpiry::Durable,
            };
            let encoded = super::encode_variant_summary_for_generation(summary, true);
            write
                .open_table(super::BLOB_PRESSURE_VARIANT_SUMMARIES)
                .unwrap()
                .insert(variant.as_bytes().as_slice(), encoded.as_slice())
                .unwrap();
            let key = super::encode_variant_index_key_for_generation(summary, variant, true, true);
            write
                .open_table(super::BLOB_PRESSURE_VARIANTS)
                .unwrap()
                .insert(&key, &[] as &[u8])
                .unwrap();
            if expiry == PressureExpiry::Durable {
                write
                    .open_table(super::BLOB_PRESSURE_DURABLE_VARIANTS)
                    .unwrap()
                    .insert(&key, &[] as &[u8])
                    .unwrap();
            }
        }
        write.commit().unwrap();

        let budget = super::BlobPressureRecoveryBudget::new(2, 64 * 1024, 1, 1, 1).unwrap();
        let expected = [
            (
                super::BlobCapacityPartition::AggregateItems,
                super::PressureCandidate::Publication(BlobTransferId::new([0x18; 32])),
            ),
            (
                super::BlobCapacityPartition::ContentPublications(
                    super::PressureContentIdentity::new(&topic, &scope, blob_id).unwrap(),
                ),
                super::PressureCandidate::Publication(BlobTransferId::new([0x18; 32])),
            ),
            (
                super::BlobCapacityPartition::NetworkStagingRows,
                super::PressureCandidate::PendingSource(BlobTransferId::new([0x78; 32])),
            ),
            (
                super::BlobCapacityPartition::DepotVariants,
                super::PressureCandidate::Variant(BlobVariantId::from_bytes([0x38; 32])),
            ),
        ];
        let read = database.begin_read().unwrap();
        for (partition, candidate) in expected {
            let selection = super::select_durable_pressure_candidate_read(
                &read,
                super::BlobCapacityRecoveryDemand::new(partition, Priority::Immediate, 1).unwrap(),
                budget,
            )
            .unwrap();
            assert!(selection.proven());
            assert_eq!(selection.candidate(), Some(candidate));
            assert_eq!(selection.rows_examined(), 2);
        }
        drop(read);

        let durable_variant = BlobVariantId::from_bytes([0x38; 32]);
        let write = database.begin_write().unwrap();
        let summaries = write
            .open_table(super::BLOB_PRESSURE_VARIANT_SUMMARIES)
            .unwrap();
        let encoded = summaries
            .get(durable_variant.as_bytes().as_slice())
            .unwrap()
            .unwrap()
            .value()
            .to_vec();
        drop(summaries);
        let contradictory = PressureVariantSummary {
            has_finite_roots: true,
            ..super::decode_variant_summary(&encoded).unwrap()
        };
        let encoded = super::encode_variant_summary_for_generation(contradictory, true);
        write
            .open_table(super::BLOB_PRESSURE_VARIANT_SUMMARIES)
            .unwrap()
            .insert(durable_variant.as_bytes().as_slice(), encoded.as_slice())
            .unwrap();
        write.commit().unwrap();
        let read = database.begin_read().unwrap();
        assert!(
            super::select_durable_pressure_candidate_read(
                &read,
                super::BlobCapacityRecoveryDemand::new(
                    super::BlobCapacityPartition::DepotVariants,
                    Priority::Immediate,
                    1,
                )
                .unwrap(),
                budget,
            )
            .is_err(),
            "a selected durable index must authenticate its aggregate against the summary",
        );
        drop(read);
        drop(database);
        std::fs::remove_file(path).unwrap();
    }

    #[test]
    fn pressure_v5_reanchor_pass_uses_fenced_alternating_root_scans() {
        // Mutations caught: clearing dirty after an unfenced/partial pass,
        // repeatedly favoring publication roots, or scanning a target-normalized
        // root inserted beyond the captured high-water.
        let (path, database) = pressure_database("reanchor-fenced-alternating-pass");
        let write = database.begin_write().unwrap();
        write
            .open_table(crate::custody::CUSTODY_CONTINUITY)
            .unwrap();
        crate::custody::observe_continuity_write(
            &write,
            aster_mesh::CustodySample {
                clock_id: [0xa1; 16],
                tick_ms: 10,
            },
        )
        .unwrap();
        {
            let mut metadata = write.open_table(BLOB_PRESSURE_METADATA).unwrap();
            metadata
                .insert(PRESSURE_SCHEMA_VERSION_FIELD, PRESSURE_SCHEMA_VERSION)
                .unwrap();
            metadata.insert(NEXT_PENDING_ACCEPTANCE_ORDER, 1).unwrap();
            metadata.insert(REANCHOR_TARGET_GENERATION, 0).unwrap();
            metadata.insert(REANCHOR_DIRTY, 0).unwrap();
            metadata.insert(REANCHOR_NEXT_PHASE, 1).unwrap();
        }
        {
            let empty = encode_reanchor_cursor(PressureReanchorCursor::EmptyComplete);
            let mut cursors = write.open_table(BLOB_PRESSURE_REANCHOR_CURSORS).unwrap();
            cursors.insert(1, empty.as_slice()).unwrap();
            cursors.insert(2, empty.as_slice()).unwrap();
        }
        let root = PressurePublicationRoot {
            variant_id: BlobVariantId::from_bytes([0xb1; 32]),
            semantic_id: BlobSemanticId::new([0xb2; 32]),
            priority: Priority::default(),
            acceptance_order: 1,
            expiry: PressureExpiry::Finite(50),
            topic: Topic::new("ttl-reanchor").unwrap(),
            scope: Scope::new("mission/ttl-reanchor").unwrap(),
            blob_id: BlobId::from_bytes([0xb3; 32]),
        };
        let encoded_root = encode_publication_root(&root).unwrap();
        for transfer in [
            BlobTransferId::new([0x10; 32]),
            BlobTransferId::new([0x20; 32]),
        ] {
            write
                .open_table(BLOB_PRESSURE_PUBLICATION_ROOTS)
                .unwrap()
                .insert(transfer.as_bytes().as_slice(), encoded_root.as_slice())
                .unwrap();
        }
        let pending_root = PressurePendingRoot {
            variant_id: BlobVariantId::from_bytes([0xc1; 32]),
            authenticated_source_binding: [0xc2; 32],
            priority: Priority::default(),
            acceptance_order: 1,
            completion: PressureFraction::new(0, 1).unwrap(),
            expiry: PressureExpiry::Finite(40),
            topic: Topic::new("ttl-reanchor").unwrap(),
            scope: Scope::new("mission/ttl-reanchor").unwrap(),
            blob_id: BlobId::from_bytes([0xc3; 32]),
        };
        write
            .open_table(BLOB_PRESSURE_PENDING_ROOTS)
            .unwrap()
            .insert(
                BlobTransferId::new([0x30; 32]).as_bytes().as_slice(),
                encode_pending_root(&pending_root).unwrap().as_slice(),
            )
            .unwrap();

        synchronize_reanchor_state_write(&write).unwrap();
        let first = plan_reanchor_turn_write(&write)
            .unwrap()
            .expect("live root");
        assert_eq!(first.root, PressureReanchorRoot::Publication);
        assert_eq!(first.transfer, Some(BlobTransferId::new([0x10; 32])));
        let (exact_rows, exact_bytes) = {
            let mut charge = crate::blob::MaintenanceCharge::new(
                crate::blob::lifecycle::BlobMaintenanceBudget::new(u64::MAX, 1, u64::MAX).unwrap(),
                0,
                0,
            );
            assert!(super::charge_reanchor_turn_write(&write, first, &mut charge).unwrap());
            assert_eq!(
                charge.rows, 6,
                "two cursors, schema/dirty/phase metadata, and the selected root"
            );
            assert!(
                !charge
                    .identities
                    .contains_key(&crate::blob::MaintenanceRowIdentity::new(
                        "aster.blob-pressure-metadata.v1",
                        REANCHOR_TARGET_GENERATION.as_bytes(),
                    ))
            );
            (charge.rows, charge.bytes)
        };
        for budget in [
            crate::blob::lifecycle::BlobMaintenanceBudget::new(exact_rows - 1, 1, exact_bytes)
                .unwrap(),
            crate::blob::lifecycle::BlobMaintenanceBudget::new(exact_rows, 1, exact_bytes - 1)
                .unwrap(),
        ] {
            let mut charge = crate::blob::MaintenanceCharge::new(budget, 0, 0);
            assert!(!super::charge_reanchor_turn_write(&write, first, &mut charge).unwrap());
            assert_eq!(plan_reanchor_turn_write(&write).unwrap(), Some(first));
        }
        finish_reanchor_turn_write(&write, first).unwrap();

        write
            .open_table(BLOB_PRESSURE_PUBLICATION_ROOTS)
            .unwrap()
            .insert(
                BlobTransferId::new([0x40; 32]).as_bytes().as_slice(),
                encoded_root.as_slice(),
            )
            .unwrap();
        let second = plan_reanchor_turn_write(&write)
            .unwrap()
            .expect("pending root");
        assert_eq!(second.root, PressureReanchorRoot::Pending);
        assert_eq!(second.transfer, Some(BlobTransferId::new([0x30; 32])));
        finish_reanchor_turn_write(&write, second).unwrap();
        write
            .open_table(BLOB_PRESSURE_PUBLICATION_ROOTS)
            .unwrap()
            .remove(BlobTransferId::new([0x20; 32]).as_bytes().as_slice())
            .unwrap();
        let final_progress = plan_reanchor_turn_write(&write)
            .unwrap()
            .expect("final fenced scan completion");
        assert_eq!(final_progress.root, PressureReanchorRoot::Publication);
        assert_eq!(final_progress.transfer, None);
        assert!(
            !pressure_ready_write(&write).unwrap(),
            "planning final EOF must not clear the persisted dirty gate"
        );
        finish_reanchor_turn_write(&write, final_progress).unwrap();
        assert!(plan_reanchor_turn_write(&write).unwrap().is_none());
        assert!(pressure_ready_write(&write).unwrap());
        drop(write);
        drop(database);
        std::fs::remove_file(path).unwrap();
    }

    #[test]
    fn pressure_values_round_trip_and_reject_partial_or_unknown_encodings() {
        let root = publication_root();
        let encoded_root = encode_publication_root(&root).expect("encode root");
        assert_eq!(decode_publication_root(&encoded_root).unwrap(), root);
        assert!(decode_publication_root(&encoded_root[..encoded_root.len() - 1]).is_err());
        let mut unknown_root = encoded_root;
        unknown_root[0] = PRESSURE_RECORD_VERSION.wrapping_add(1);
        assert!(decode_publication_root(&unknown_root).is_err());

        let summary = PressureVariantSummary {
            effective_priority: Priority::Priority,
            minimum_root_acceptance_order: u64::MAX,
            committed_progress: PressureFraction::new(u64::MAX - 1, u64::MAX).unwrap(),
            finalized: false,
            publication_roots: super::PRESSURE_VARIANT_HAS_FINITE_ROOT_MASK - 1,
            pending_roots: 1,
            final_reference_expiry: PressureExpiry::Durable,
            has_finite_roots: true,
        };
        let encoded_summary = encode_variant_summary(summary);
        assert_eq!(
            decode_variant_summary(&encoded_summary).unwrap(),
            PressureVariantSummary {
                has_finite_roots: false,
                ..summary
            }
        );
        assert_eq!(
            &encoded_summary[27..35],
            &(summary.publication_roots).to_be_bytes()
        );
        let encoded_current = encode_variant_summary_for_generation(summary, true);
        assert_eq!(decode_variant_summary(&encoded_current).unwrap(), summary);
        assert_eq!(encoded_current[27] & 0x80, 0x80);
        assert!(decode_variant_summary(&encoded_summary[..encoded_summary.len() - 1]).is_err());
        let mut unknown_summary = encoded_summary;
        unknown_summary[0] = PRESSURE_RECORD_VERSION.wrapping_add(1);
        assert!(decode_variant_summary(&unknown_summary).is_err());

        let pending = PressurePendingRoot {
            variant_id: BlobVariantId::from_bytes([0x55; 32]),
            authenticated_source_binding: [0x56; 32],
            priority: Priority::Routine,
            acceptance_order: u64::MAX,
            completion: PressureFraction::new(u64::MAX - 1, u64::MAX).unwrap(),
            expiry: PressureExpiry::Durable,
            topic: Topic::new("pending").unwrap(),
            scope: Scope::new("scope").unwrap(),
            blob_id: BlobId::from_bytes([0x66; 32]),
        };
        let encoded_pending = encode_pending_root(&pending).expect("encode pending root");
        assert_eq!(decode_pending_root(&encoded_pending).unwrap(), pending);
        assert!(decode_pending_root(&encoded_pending[..encoded_pending.len() - 1]).is_err());
        let mut unknown_pending = encoded_pending.clone();
        unknown_pending[0] = PRESSURE_RECORD_VERSION.wrapping_add(1);
        assert!(decode_pending_root(&unknown_pending).is_err());

        let historical = encode_pending_root_for_generation(
            &pending,
            PressurePendingRootEncodingGeneration::PressureV3,
        )
        .expect("encode exact pressure-v3 pending root");
        assert_eq!(
            historical,
            [
                vec![PRESSURE_RECORD_VERSION],
                pending.variant_id.as_bytes().to_vec(),
                vec![pending.priority as u8],
                pending.acceptance_order.to_be_bytes().to_vec(),
                pending.completion.numerator.to_be_bytes().to_vec(),
                pending.completion.denominator.to_be_bytes().to_vec(),
                vec![PRESSURE_EXPIRY_DURABLE],
                0u64.to_be_bytes().to_vec(),
                7u16.to_be_bytes().to_vec(),
                b"pending".to_vec(),
                5u16.to_be_bytes().to_vec(),
                b"scope".to_vec(),
                pending.blob_id.as_bytes().to_vec(),
            ]
            .concat(),
            "pressure-v3 pending roots have no authenticated binding bytes"
        );
        let mut historical_pending = pending.clone();
        historical_pending.authenticated_source_binding = [0; 32];
        assert_eq!(
            decode_pending_root_for_generation(
                &historical,
                PressurePendingRootEncodingGeneration::PressureV3,
            )
            .unwrap(),
            historical_pending
        );
        assert!(decode_pending_root(&historical).is_err());
        assert!(
            decode_pending_root_for_generation(
                &encoded_pending,
                PressurePendingRootEncodingGeneration::PressureV3,
            )
            .is_err()
        );
    }

    #[test]
    fn pressure_pending_and_variant_indexes_encode_complete_exact_ordering() {
        let minimum_pending = PressurePendingRoot {
            variant_id: BlobVariantId::from_bytes([0; 32]),
            authenticated_source_binding: [0; 32],
            priority: Priority::Routine,
            acceptance_order: 1,
            completion: PressureFraction::new(0, 1).unwrap(),
            expiry: PressureExpiry::ExpiredFinite,
            topic: Topic::new("minimum").unwrap(),
            scope: Scope::new("minimum").unwrap(),
            blob_id: BlobId::from_bytes([0; 32]),
        };
        let minimum_pending_key =
            encode_pending_index_key(minimum_pending.clone(), BlobTransferId::new([0; 32]));
        assert_eq!(
            minimum_pending_key.as_slice(),
            [
                vec![2, 0, 0, 2],
                vec![0; 8],
                vec![0; 8],
                vec![0, 0, 0, 0, 0, 0, 0, 1],
                vec![0, 0, 0, 0, 0, 0, 0, 1],
                vec![0; 32],
            ]
            .concat()
        );
        let decoded_minimum = decode_pending_index_key(&minimum_pending_key).unwrap();
        assert_eq!(decoded_minimum.priority, minimum_pending.priority);
        assert_eq!(decoded_minimum.completion, minimum_pending.completion);
        assert_eq!(decoded_minimum.acceptance_order, 1);
        assert_eq!(decoded_minimum.transfer_id, BlobTransferId::new([0; 32]));
        let maximum_pending = PressurePendingRoot {
            variant_id: BlobVariantId::from_bytes([0xff; 32]),
            authenticated_source_binding: [0xff; 32],
            priority: Priority::Flash,
            acceptance_order: u64::MAX,
            completion: PressureFraction::new(u64::MAX, u64::MAX).unwrap(),
            expiry: PressureExpiry::Durable,
            topic: Topic::new("maximum").unwrap(),
            scope: Scope::new("maximum").unwrap(),
            blob_id: BlobId::from_bytes([0xff; 32]),
        };
        let maximum_transfer = BlobTransferId::new([0xff; 32]);
        let maximum_pending_key =
            encode_pending_index_key(maximum_pending.clone(), maximum_transfer);
        assert_eq!(
            maximum_pending_key.as_slice(),
            [
                vec![2, 3, 0, 2],
                vec![0; 8],
                vec![0xff; 8],
                vec![0xff; 8],
                vec![0xff; 8],
                vec![0xff; 32],
            ]
            .concat()
        );
        let decoded_pending = decode_pending_index_key(&maximum_pending_key).unwrap();
        assert_eq!(decoded_pending.transfer_id, maximum_transfer);
        assert_eq!(decoded_pending.priority, maximum_pending.priority);
        assert_eq!(
            decoded_pending.acceptance_order,
            maximum_pending.acceptance_order
        );
        assert_eq!(decoded_pending.completion, maximum_pending.completion);
        assert_eq!(decoded_pending.expiry, maximum_pending.expiry);
        assert!(
            decode_pending_index_key(&maximum_pending_key[..maximum_pending_key.len() - 1])
                .is_err()
        );
        let mut malformed_pending = maximum_pending_key;
        malformed_pending[0] = PRESSURE_RECORD_VERSION.wrapping_add(1);
        assert!(decode_pending_index_key(&malformed_pending).is_err());
        let mut zero_denominator = maximum_pending_key;
        zero_denominator[20..28].fill(0);
        assert!(decode_pending_index_key(&zero_denominator).is_err());
        let mut durable_with_deadline = maximum_pending_key;
        durable_with_deadline[11] = 1;
        assert!(decode_pending_index_key(&durable_with_deadline).is_err());
        let mut zero_order = minimum_pending_key;
        zero_order[28..36].fill(0);
        assert!(decode_pending_index_key(&zero_order).is_err());

        let maximum_variant = BlobVariantId::from_bytes([0xff; 32]);
        let maximum_summary = PressureVariantSummary {
            effective_priority: Priority::Flash,
            minimum_root_acceptance_order: u64::MAX,
            committed_progress: PressureFraction::new(u64::MAX, u64::MAX).unwrap(),
            finalized: true,
            publication_roots: super::PRESSURE_VARIANT_HAS_FINITE_ROOT_MASK - 1,
            pending_roots: u64::MAX,
            final_reference_expiry: PressureExpiry::Durable,
            has_finite_roots: true,
        };
        let maximum_variant_key = encode_variant_index_key(maximum_summary, maximum_variant);
        assert_eq!(
            maximum_variant_key.as_slice(),
            [
                vec![2, 3, 1, 2],
                vec![0; 8],
                vec![0xff; 8],
                vec![0xff; 8],
                vec![0xff; 8],
                vec![0xff; 32],
                vec![0x7f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff],
                vec![0xff; 8],
            ]
            .concat()
        );
        assert_eq!(
            decode_variant_index_key(&maximum_variant_key).unwrap(),
            (
                PressureVariantSummary {
                    has_finite_roots: false,
                    ..maximum_summary
                },
                maximum_variant,
            )
        );
        assert!(
            decode_variant_index_key(&maximum_variant_key[..maximum_variant_key.len() - 1])
                .is_err()
        );
        let mut malformed_variant = maximum_variant_key;
        malformed_variant[0] = PRESSURE_RECORD_VERSION.wrapping_add(1);
        assert!(decode_variant_index_key(&malformed_variant).is_err());
        let mut invalid_finalization = maximum_variant_key;
        invalid_finalization[2] = 2;
        assert!(decode_variant_index_key(&invalid_finalization).is_err());
        let mut variant_zero_denominator = maximum_variant_key;
        variant_zero_denominator[20..28].fill(0);
        assert!(decode_variant_index_key(&variant_zero_denominator).is_err());
        let mut variant_durable_with_deadline = maximum_variant_key;
        variant_durable_with_deadline[11] = 1;
        assert!(decode_variant_index_key(&variant_durable_with_deadline).is_err());
        let mut variant_zero_order = maximum_variant_key;
        variant_zero_order[28..36].fill(0);
        assert!(decode_variant_index_key(&variant_zero_order).is_err());
        let mut variant_without_roots = maximum_variant_key;
        variant_without_roots[68..84].fill(0);
        assert!(decode_variant_index_key(&variant_without_roots).is_err());
        let minimum_summary = PressureVariantSummary {
            effective_priority: Priority::Routine,
            minimum_root_acceptance_order: 1,
            committed_progress: PressureFraction::new(0, 1).unwrap(),
            finalized: false,
            publication_roots: 0,
            pending_roots: 1,
            final_reference_expiry: PressureExpiry::ExpiredFinite,
            has_finite_roots: true,
        };
        let minimum_variant_key =
            encode_variant_index_key(minimum_summary, BlobVariantId::from_bytes([0; 32]));
        assert_eq!(
            minimum_variant_key.as_slice(),
            [
                vec![2, 0, 0, 2],
                vec![0; 8],
                vec![0; 8],
                vec![0, 0, 0, 0, 0, 0, 0, 1],
                vec![0, 0, 0, 0, 0, 0, 0, 1],
                vec![0; 32],
                vec![0; 8],
                vec![0, 0, 0, 0, 0, 0, 0, 1],
            ]
            .concat()
        );
        assert_eq!(
            decode_variant_index_key(&minimum_variant_key).unwrap(),
            (
                PressureVariantSummary {
                    final_reference_expiry: PressureExpiry::Durable,
                    has_finite_roots: false,
                    ..minimum_summary
                },
                BlobVariantId::from_bytes([0; 32]),
            )
        );
        assert_eq!(
            <super::PressureVariantIndexKey as redb::Key>::compare(
                &minimum_variant_key,
                &maximum_variant_key,
            ),
            Ordering::Less,
        );

        let lower = PressurePendingRoot {
            completion: PressureFraction::new(u64::MAX - 2, u64::MAX - 1).unwrap(),
            acceptance_order: 9,
            ..maximum_pending.clone()
        };
        let higher = PressurePendingRoot {
            completion: PressureFraction::new(u64::MAX - 1, u64::MAX).unwrap(),
            acceptance_order: 1,
            ..maximum_pending
        };
        assert_eq!(
            <super::PressurePendingIndexKey as redb::Key>::compare(
                &encode_pending_index_key(lower, BlobTransferId::new([0x77; 32])),
                &encode_pending_index_key(higher, BlobTransferId::new([0x78; 32])),
            ),
            Ordering::Less,
        );
    }

    #[test]
    fn pressure_index_comparators_keep_equivalent_fraction_bytes_distinct() {
        let pending = PressurePendingRoot {
            variant_id: BlobVariantId::from_bytes([0x11; 32]),
            authenticated_source_binding: [0x12; 32],
            priority: Priority::Routine,
            acceptance_order: 7,
            completion: PressureFraction::new(1, 2).unwrap(),
            expiry: PressureExpiry::Durable,
            topic: Topic::new("topic").unwrap(),
            scope: Scope::new("scope").unwrap(),
            blob_id: BlobId::from_bytes([0x22; 32]),
        };
        let transfer = BlobTransferId::new([0x33; 32]);
        let reduced_pending = encode_pending_index_key(pending.clone(), transfer);
        let equivalent_pending = encode_pending_index_key(
            PressurePendingRoot {
                completion: PressureFraction::new(2, 4).unwrap(),
                ..pending.clone()
            },
            transfer,
        );
        assert_eq!(
            <super::PressurePendingIndexKey as redb::Key>::compare(
                &reduced_pending,
                &equivalent_pending,
            ),
            Ordering::Less,
        );
        let earlier_order = encode_pending_index_key(
            PressurePendingRoot {
                acceptance_order: 6,
                completion: PressureFraction::new(2, 4).unwrap(),
                ..pending.clone()
            },
            BlobTransferId::new([0xff; 32]),
        );
        assert_eq!(
            <super::PressurePendingIndexKey as redb::Key>::compare(
                &earlier_order,
                &reduced_pending,
            ),
            Ordering::Less,
            "semantic acceptance order must precede the raw-fraction tie-break",
        );
        let earlier_identity = encode_pending_index_key(
            PressurePendingRoot {
                completion: PressureFraction::new(2, 4).unwrap(),
                ..pending
            },
            BlobTransferId::new([0x22; 32]),
        );
        assert_eq!(
            <super::PressurePendingIndexKey as redb::Key>::compare(
                &earlier_identity,
                &reduced_pending,
            ),
            Ordering::Less,
            "candidate identity must precede the raw-fraction tie-break",
        );

        let variant = BlobVariantId::from_bytes([0x44; 32]);
        let summary = PressureVariantSummary {
            effective_priority: Priority::Routine,
            minimum_root_acceptance_order: 7,
            committed_progress: PressureFraction::new(1, 2).unwrap(),
            finalized: false,
            publication_roots: 0,
            pending_roots: 1,
            final_reference_expiry: PressureExpiry::Durable,
            has_finite_roots: false,
        };
        let reduced_variant = encode_variant_index_key(summary, variant);
        let equivalent_variant = encode_variant_index_key(
            PressureVariantSummary {
                committed_progress: PressureFraction::new(2, 4).unwrap(),
                ..summary
            },
            variant,
        );
        assert_eq!(
            <super::PressureVariantIndexKey as redb::Key>::compare(
                &reduced_variant,
                &equivalent_variant,
            ),
            Ordering::Less,
        );
        let earlier_variant_identity = encode_variant_index_key(
            PressureVariantSummary {
                committed_progress: PressureFraction::new(2, 4).unwrap(),
                ..summary
            },
            BlobVariantId::from_bytes([0x33; 32]),
        );
        assert_eq!(
            <super::PressureVariantIndexKey as redb::Key>::compare(
                &earlier_variant_identity,
                &reduced_variant,
            ),
            Ordering::Less,
            "variant identity must precede the raw-fraction tie-break",
        );
    }

    #[test]
    fn pressure_content_key_retains_and_validates_complete_identity() {
        let minimum = PressurePublicationRoot {
            variant_id: BlobVariantId::from_bytes([0; 32]),
            semantic_id: BlobSemanticId::new([0; 32]),
            priority: Priority::Routine,
            acceptance_order: 1,
            expiry: PressureExpiry::Durable,
            topic: Topic::new("-").unwrap(),
            scope: Scope::new("-").unwrap(),
            blob_id: BlobId::from_bytes([0; 32]),
        };
        let minimum_transfer = BlobTransferId::new([0; 32]);
        let minimum_key = encode_content_publication_key(&minimum, minimum_transfer).unwrap();
        assert_eq!(
            minimum_key,
            [
                vec![2],
                vec![
                    15, 100, 135, 151, 250, 42, 136, 95, 239, 94, 144, 174, 168, 53, 15, 160, 229,
                    46, 40, 122, 143, 158, 69, 237, 125, 96, 244, 158, 177, 96, 166, 189,
                ],
                vec![0, 1, b'-', 0, 1, b'-'],
                vec![0; 32],
                vec![0, 1, 2],
                vec![0; 8],
                vec![0, 0, 0, 0, 0, 0, 0, 1],
                vec![0; 32],
            ]
            .concat()
        );
        let maximum_name = "z".repeat(128);
        let maximum = PressurePublicationRoot {
            variant_id: BlobVariantId::from_bytes([0xff; 32]),
            semantic_id: BlobSemanticId::new([0xff; 32]),
            priority: Priority::Flash,
            acceptance_order: u64::MAX,
            expiry: PressureExpiry::Finite(u64::MAX),
            topic: Topic::new(maximum_name.clone()).unwrap(),
            scope: Scope::new(maximum_name).unwrap(),
            blob_id: BlobId::from_bytes([0xff; 32]),
        };
        let maximum_transfer = BlobTransferId::new([0xff; 32]);
        let maximum_key = encode_content_publication_key(&maximum, maximum_transfer).unwrap();
        assert_eq!(
            maximum_key,
            [
                vec![2],
                vec![
                    167, 122, 171, 102, 27, 246, 210, 76, 79, 242, 211, 146, 78, 208, 106, 13, 156,
                    238, 0, 106, 209, 184, 115, 21, 139, 204, 41, 29, 12, 38, 68, 171,
                ],
                vec![0, 128],
                vec![b'z'; 128],
                vec![0, 128],
                vec![b'z'; 128],
                vec![0xff; 32],
                vec![3, 1, 2],
                vec![0; 8],
                vec![0xff; 8],
                vec![0xff; 32],
            ]
            .concat()
        );
        assert_eq!(
            decode_content_publication_key(&minimum_key)
                .unwrap()
                .publication,
            PressurePublicationKey {
                priority: Priority::Routine,
                expiry: PressureExpiry::Durable,
                acceptance_order: 1,
                transfer_id: minimum_transfer,
            }
        );
        assert_eq!(
            decode_content_publication_key(&maximum_key)
                .unwrap()
                .publication
                .transfer_id,
            maximum_transfer
        );
        assert!(decode_content_publication_key(&minimum_key[..minimum_key.len() - 1]).is_err());
        let mut malformed = minimum_key;
        malformed[0] = PRESSURE_RECORD_VERSION.wrapping_add(1);
        assert!(decode_content_publication_key(&malformed).is_err());
        let mut invalid_completion = encode_content_publication_key(&minimum, minimum_transfer)
            .expect("minimum content key");
        invalid_completion[72] = 0;
        assert!(decode_content_publication_key(&invalid_completion).is_err());
        let mut zero_order = encode_content_publication_key(&minimum, minimum_transfer)
            .expect("minimum content key");
        zero_order[82..90].fill(0);
        assert!(decode_content_publication_key(&zero_order).is_err());
        let mut contradictory_identity =
            encode_content_publication_key(&maximum, maximum_transfer).unwrap();
        contradictory_identity[35] ^= 1;
        assert!(decode_content_publication_key(&contradictory_identity).is_err());
    }

    #[test]
    fn pressure_fraction_comparison_is_exact_beyond_f64_precision() {
        let lower = PressureFraction::new(u64::MAX - 2, u64::MAX - 1).unwrap();
        let higher = PressureFraction::new(u64::MAX - 1, u64::MAX).unwrap();
        assert_eq!(
            lower.numerator() as f64 / lower.denominator() as f64,
            higher.numerator() as f64 / higher.denominator() as f64
        );
        assert_eq!(compare_pressure_fraction(lower, higher), Ordering::Less);
        assert_eq!(compare_pressure_fraction(higher, lower), Ordering::Greater);
        assert_eq!(compare_pressure_fraction(lower, lower), Ordering::Equal);

        assert!(PressureFraction::new(0, 0).is_err());
        assert!(PressureFraction::new(2, 1).is_err());
        let near_max = PressureFraction::new(u64::MAX - 1, u64::MAX).unwrap();
        assert_eq!(
            compare_pressure_fraction(near_max, PressureFraction::ONE),
            Ordering::Less
        );
    }

    #[test]
    fn pressure_recovery_demand_is_fixed_size_and_binds_full_content_identity() {
        // Break caught: retaining only the content digest permits a digest
        // bucket row for another topic/scope/Blob identity to be selected.
        assert!(!std::mem::needs_drop::<super::BlobCapacityRecoveryDemand>());
        let identity = super::PressureContentIdentity::new(
            &Topic::new("selected-blob").unwrap(),
            &Scope::new("mission/selected-blob").unwrap(),
            BlobId::from_bytes([0x44; 32]),
        )
        .unwrap();
        assert!(identity.matches(
            &Topic::new("selected-blob").unwrap(),
            &Scope::new("mission/selected-blob").unwrap(),
            BlobId::from_bytes([0x44; 32]),
        ));
        assert!(!identity.matches(
            &Topic::new("selected-blob-other").unwrap(),
            &Scope::new("mission/selected-blob").unwrap(),
            BlobId::from_bytes([0x44; 32]),
        ));

        let demand = super::BlobCapacityRecoveryDemand::new(
            super::BlobCapacityPartition::ContentPublications(identity),
            Priority::Immediate,
            3,
        )
        .unwrap();
        assert_eq!(demand.incoming_priority(), Priority::Immediate);
        assert_eq!(demand.deficit(), 3);
        assert!(matches!(
            demand.partition(),
            super::BlobCapacityPartition::ContentPublications(actual) if actual == identity
        ));
        assert!(
            super::BlobCapacityRecoveryDemand::new(
                super::BlobCapacityPartition::AggregateItems,
                Priority::Immediate,
                0,
            )
            .is_err()
        );
    }

    #[test]
    fn pressure_capacity_failures_map_first_partition_and_exact_deficit() {
        // Break caught: treating every capacity error as a generic depot
        // shortage can evict from the wrong partition or overclaim recovery.
        let content = super::PressureContentIdentity::new(
            &Topic::new("selected-blob").unwrap(),
            &Scope::new("mission/selected-blob").unwrap(),
            BlobId::from_bytes([0x71; 32]),
        )
        .unwrap();
        let context = super::BlobCapacityRecoveryContext::new(Priority::Immediate)
            .with_content(content)
            .with_depot_units(3, 1);
        let cases = [
            (
                StoreError::ItemLimitExceeded {
                    current: 9,
                    limit: 9,
                },
                super::BlobCapacityPartition::AggregateItems,
                1,
            ),
            (
                StoreError::PayloadByteLimitExceeded {
                    current: 90,
                    incoming: 15,
                    limit: 100,
                },
                super::BlobCapacityPartition::AggregateBytes,
                5,
            ),
            (
                StoreError::Blob(super::BlobStoreError::PublicationLimitExceeded {
                    current: 1_024,
                    limit: 1_024,
                }),
                super::BlobCapacityPartition::ContentPublications(content),
                1,
            ),
            (
                StoreError::Blob(super::BlobStoreError::NetworkStagingRowLimitExceeded {
                    current: 9_999,
                    incoming: 3,
                    limit: 10_000,
                }),
                super::BlobCapacityPartition::NetworkStagingRows,
                2,
            ),
            (
                StoreError::Blob(super::BlobStoreError::NetworkStagingByteLimitExceeded {
                    current: 100,
                    incoming: 25,
                    limit: 110,
                }),
                super::BlobCapacityPartition::NetworkStagingBytes,
                15,
            ),
            (
                StoreError::Blob(super::BlobStoreError::DepotByteLimitExceeded {
                    current: 100,
                    incoming: 25,
                    limit: 110,
                }),
                super::BlobCapacityPartition::DepotBytes,
                15,
            ),
            (
                StoreError::Blob(super::BlobStoreError::DepotChunkLimitExceeded {
                    current: 99,
                    limit: 100,
                }),
                super::BlobCapacityPartition::DepotChunks,
                2,
            ),
            (
                StoreError::Blob(super::BlobStoreError::DepotVariantLimitExceeded {
                    current: 4,
                    limit: 4,
                }),
                super::BlobCapacityPartition::DepotVariants,
                1,
            ),
            (
                StoreError::Blob(super::BlobStoreError::OperationByteLimitExceeded {
                    current: 500,
                    incoming: 20,
                    limit: 510,
                }),
                super::BlobCapacityPartition::Operation,
                10,
            ),
            (
                StoreError::Blob(super::BlobStoreError::PublicationLifecycleCapacity {
                    required_rows: 12,
                    max_rows: 10,
                }),
                super::BlobCapacityPartition::PublicationLifecycle,
                2,
            ),
        ];
        for (error, partition, deficit) in cases {
            let demand = super::capacity_recovery_demand(&error, context)
                .unwrap()
                .expect("eligible typed capacity failure");
            assert_eq!(demand.partition(), partition);
            assert_eq!(demand.deficit(), deficit);
            assert_eq!(demand.incoming_priority(), Priority::Immediate);
        }

        let cleanup_only = [
            StoreError::Blob(super::BlobStoreError::CausalFrontierLimitExceeded {
                current: 64,
                limit: 64,
            }),
            StoreError::Blob(super::BlobStoreError::LineageFenceCapacity {
                required_rows: 2,
                required_bytes: 2,
                max_rows: 1,
                max_bytes: 1,
            }),
            StoreError::Blob(super::BlobStoreError::ReplayFenceCapacity {
                required_rows: 2,
                required_bytes: 2,
                max_rows: 1,
                max_bytes: 1,
            }),
            StoreError::Blob(super::BlobStoreError::LeaseCapacity),
        ];
        for error in cleanup_only {
            assert_eq!(
                super::capacity_recovery_demand(&error, context).unwrap(),
                None
            );
        }
    }

    #[test]
    fn pressure_publication_selection_is_strict_partition_specific_and_content_exact() {
        // Break caught: a global scan, <= priority predicate, or digest-only
        // content lookup can evict protected or unrelated publications.
        let (path, database) = pressure_database("publication-selection");
        let low_transfer = BlobTransferId::new([0x11; 32]);
        let equal_transfer = BlobTransferId::new([0x22; 32]);
        let other_transfer = BlobTransferId::new([0x33; 32]);
        let low = PressurePublicationRoot {
            variant_id: BlobVariantId::from_bytes([0x41; 32]),
            semantic_id: BlobSemanticId::new([0x51; 32]),
            priority: Priority::Routine,
            acceptance_order: 2,
            expiry: PressureExpiry::Durable,
            topic: Topic::new("selected-blob").unwrap(),
            scope: Scope::new("mission/selected-blob").unwrap(),
            blob_id: BlobId::from_bytes([0x61; 32]),
        };
        let equal = PressurePublicationRoot {
            variant_id: BlobVariantId::from_bytes([0x42; 32]),
            semantic_id: BlobSemanticId::new([0x52; 32]),
            priority: Priority::Immediate,
            acceptance_order: 1,
            expiry: PressureExpiry::Durable,
            topic: low.topic.clone(),
            scope: low.scope.clone(),
            blob_id: low.blob_id,
        };
        let other = PressurePublicationRoot {
            variant_id: BlobVariantId::from_bytes([0x43; 32]),
            semantic_id: BlobSemanticId::new([0x53; 32]),
            priority: Priority::Routine,
            acceptance_order: 1,
            expiry: PressureExpiry::Durable,
            topic: Topic::new("other-topic").unwrap(),
            scope: low.scope.clone(),
            blob_id: low.blob_id,
        };
        {
            let write = database.begin_write().unwrap();
            let mut roots = write
                .open_table(super::BLOB_PRESSURE_PUBLICATION_ROOTS)
                .unwrap();
            let mut global = write.open_table(super::BLOB_PRESSURE_PUBLICATIONS).unwrap();
            let mut content = write
                .open_table(super::BLOB_PRESSURE_CONTENT_PUBLICATIONS)
                .unwrap();
            for (transfer, root) in [
                (low_transfer, &low),
                (equal_transfer, &equal),
                (other_transfer, &other),
            ] {
                let encoded = super::encode_publication_root(root).unwrap();
                roots
                    .insert(transfer.as_bytes().as_slice(), encoded.as_slice())
                    .unwrap();
                let key = super::encode_publication_key(super::PressurePublicationKey {
                    priority: root.priority,
                    expiry: root.expiry,
                    acceptance_order: root.acceptance_order,
                    transfer_id: transfer,
                });
                global.insert(key.as_slice(), &[] as &[u8]).unwrap();
                let key = super::encode_content_publication_key(root, transfer).unwrap();
                content.insert(key.as_slice(), &[] as &[u8]).unwrap();
            }
            drop(content);
            drop(global);
            drop(roots);
            write.commit().unwrap();
        }

        let budget = super::BlobPressureRecoveryBudget::new(8, 4_096, 2, 2, 1).unwrap();
        let read = database.begin_read().unwrap();
        let global = super::select_pressure_candidate_read(
            &read,
            super::BlobCapacityRecoveryDemand::new(
                super::BlobCapacityPartition::AggregateItems,
                Priority::Immediate,
                1,
            )
            .unwrap(),
            budget,
        )
        .unwrap();
        assert!(global.proven());
        assert_eq!(
            global.candidate(),
            Some(super::PressureCandidate::Publication(other_transfer))
        );

        let protected = super::select_pressure_candidate_read(
            &read,
            super::BlobCapacityRecoveryDemand::new(
                super::BlobCapacityPartition::AggregateItems,
                Priority::Routine,
                1,
            )
            .unwrap(),
            budget,
        )
        .unwrap();
        assert!(protected.proven());
        assert_eq!(protected.candidate(), None);

        let identity =
            super::PressureContentIdentity::new(&low.topic, &low.scope, low.blob_id).unwrap();
        let content = super::select_pressure_candidate_read(
            &read,
            super::BlobCapacityRecoveryDemand::new(
                super::BlobCapacityPartition::ContentPublications(identity),
                Priority::Immediate,
                1,
            )
            .unwrap(),
            budget,
        )
        .unwrap();
        assert_eq!(
            content.candidate(),
            Some(super::PressureCandidate::Publication(low_transfer))
        );

        let cleanup_only = super::select_pressure_candidate_read(
            &read,
            super::BlobCapacityRecoveryDemand::new(
                super::BlobCapacityPartition::Operation,
                Priority::Flash,
                1,
            )
            .unwrap(),
            budget,
        )
        .unwrap();
        assert!(cleanup_only.proven());
        assert_eq!(cleanup_only.candidate(), None);
        assert_eq!(cleanup_only.rows_examined(), 0);
        drop(read);
        drop(database);
        std::fs::remove_file(path).unwrap();
    }

    #[test]
    fn pressure_real_indexes_persist_expiry_without_activating_selection() {
        // Task 3 retains authoritative finite expiry in roots and summaries,
        // while the pre-Task-4 selector continues to use acceptance/progress.
        let (path, database) = pressure_database("expiry-persisted-selection-inactive");
        let durable_transfer = BlobTransferId::new([0x91; 32]);
        let finite_transfer = BlobTransferId::new([0x92; 32]);
        let durable_variant = BlobVariantId::from_bytes([0xa1; 32]);
        let finite_variant = BlobVariantId::from_bytes([0xa2; 32]);
        let topic = Topic::new("durable-order").unwrap();
        let scope = Scope::new("mission/durable-order").unwrap();
        let blob_id = BlobId::from_bytes([0xb1; 32]);
        let durable_publication = PressurePublicationRoot {
            variant_id: durable_variant,
            semantic_id: BlobSemanticId::new([0xc1; 32]),
            priority: Priority::Routine,
            acceptance_order: 1,
            expiry: PressureExpiry::Durable,
            topic: topic.clone(),
            scope: scope.clone(),
            blob_id,
        };
        let finite_publication = PressurePublicationRoot {
            variant_id: finite_variant,
            semantic_id: BlobSemanticId::new([0xc2; 32]),
            priority: Priority::Routine,
            acceptance_order: 9,
            expiry: PressureExpiry::ExpiredFinite,
            topic: topic.clone(),
            scope: scope.clone(),
            blob_id,
        };
        let durable_pending = PressurePendingRoot {
            variant_id: durable_variant,
            authenticated_source_binding: [0xd1; 32],
            priority: Priority::Routine,
            acceptance_order: 1,
            completion: PressureFraction::new(1, 2).unwrap(),
            expiry: PressureExpiry::Durable,
            topic: topic.clone(),
            scope: scope.clone(),
            blob_id,
        };
        let finite_pending = PressurePendingRoot {
            variant_id: finite_variant,
            authenticated_source_binding: [0xd2; 32],
            priority: Priority::Routine,
            acceptance_order: 9,
            completion: PressureFraction::new(1, 2).unwrap(),
            expiry: PressureExpiry::ExpiredFinite,
            topic,
            scope,
            blob_id,
        };
        let durable_summary = PressureVariantSummary {
            effective_priority: Priority::Routine,
            minimum_root_acceptance_order: 1,
            committed_progress: PressureFraction::new(1, 2).unwrap(),
            finalized: false,
            publication_roots: 0,
            pending_roots: 1,
            final_reference_expiry: PressureExpiry::Durable,
            has_finite_roots: false,
        };
        let finite_summary = PressureVariantSummary {
            effective_priority: Priority::Routine,
            minimum_root_acceptance_order: 9,
            committed_progress: PressureFraction::new(1, 2).unwrap(),
            finalized: false,
            publication_roots: 0,
            pending_roots: 1,
            final_reference_expiry: PressureExpiry::ExpiredFinite,
            has_finite_roots: true,
        };
        {
            let write = database.begin_write().unwrap();
            let mut publication_roots = write
                .open_table(super::BLOB_PRESSURE_PUBLICATION_ROOTS)
                .unwrap();
            let mut publications = write.open_table(super::BLOB_PRESSURE_PUBLICATIONS).unwrap();
            let mut pending_roots = write
                .open_table(super::BLOB_PRESSURE_PENDING_ROOTS)
                .unwrap();
            let mut pending = write
                .open_table(super::BLOB_PRESSURE_PENDING_SOURCES)
                .unwrap();
            let mut summaries = write
                .open_table(super::BLOB_PRESSURE_VARIANT_SUMMARIES)
                .unwrap();
            let mut variants = write.open_table(super::BLOB_PRESSURE_VARIANTS).unwrap();
            for (transfer, root) in [
                (durable_transfer, &durable_publication),
                (finite_transfer, &finite_publication),
            ] {
                let encoded = super::encode_publication_root(root).unwrap();
                publication_roots
                    .insert(transfer.as_bytes().as_slice(), encoded.as_slice())
                    .unwrap();
                publications
                    .insert(
                        super::encode_publication_key(super::PressurePublicationKey {
                            priority: root.priority,
                            expiry: root.expiry,
                            acceptance_order: root.acceptance_order,
                            transfer_id: transfer,
                        })
                        .as_slice(),
                        &[] as &[u8],
                    )
                    .unwrap();
            }
            for (transfer, root) in [
                (durable_transfer, &durable_pending),
                (finite_transfer, &finite_pending),
            ] {
                let encoded = super::encode_pending_root(root).unwrap();
                pending_roots
                    .insert(transfer.as_bytes().as_slice(), encoded.as_slice())
                    .unwrap();
                pending
                    .insert(
                        &super::encode_pending_index_key(root.clone(), transfer),
                        &[] as &[u8],
                    )
                    .unwrap();
            }
            for (variant, summary) in [
                (durable_variant, durable_summary),
                (finite_variant, finite_summary),
            ] {
                let encoded = super::encode_variant_summary(summary);
                summaries
                    .insert(variant.as_bytes().as_slice(), encoded.as_slice())
                    .unwrap();
                variants
                    .insert(
                        &super::encode_variant_index_key(summary, variant),
                        &[] as &[u8],
                    )
                    .unwrap();
            }
            drop(variants);
            drop(summaries);
            drop(pending);
            drop(pending_roots);
            drop(publications);
            drop(publication_roots);
            write.commit().unwrap();
        }
        let budget = super::BlobPressureRecoveryBudget::new(8, 8_192, 2, 2, 1).unwrap();
        let read = database.begin_read().unwrap();
        for (partition, expected) in [
            (
                super::BlobCapacityPartition::AggregateItems,
                super::PressureCandidate::Publication(durable_transfer),
            ),
            (
                super::BlobCapacityPartition::NetworkStagingRows,
                super::PressureCandidate::PendingSource(durable_transfer),
            ),
            (
                super::BlobCapacityPartition::DepotVariants,
                super::PressureCandidate::Variant(durable_variant),
            ),
        ] {
            let selected = super::select_pressure_candidate_read(
                &read,
                super::BlobCapacityRecoveryDemand::new(partition, Priority::Immediate, 1).unwrap(),
                budget,
            )
            .unwrap();
            assert!(selected.proven());
            assert_eq!(selected.candidate(), Some(expected));
        }
        assert_eq!(
            super::decode_publication_root(
                read.open_table(super::BLOB_PRESSURE_PUBLICATION_ROOTS)
                    .unwrap()
                    .get(finite_transfer.as_bytes().as_slice())
                    .unwrap()
                    .unwrap()
                    .value(),
            )
            .unwrap()
            .expiry,
            PressureExpiry::ExpiredFinite
        );
        assert_eq!(
            super::decode_variant_summary(
                read.open_table(super::BLOB_PRESSURE_VARIANT_SUMMARIES)
                    .unwrap()
                    .get(finite_variant.as_bytes().as_slice())
                    .unwrap()
                    .unwrap()
                    .value(),
            )
            .unwrap()
            .final_reference_expiry,
            PressureExpiry::ExpiredFinite
        );
        drop(read);
        drop(database);
        std::fs::remove_file(path).unwrap();
    }

    #[test]
    fn pressure_expiry_encoding_orders_expired_live_finite_then_durable() {
        let mut expired = [0u8; 9];
        let mut live = [0u8; 9];
        let mut durable = [0u8; 9];
        super::encode_fixed_expiry(PressureExpiry::ExpiredFinite, &mut expired);
        super::encode_fixed_expiry(PressureExpiry::Finite(17), &mut live);
        super::encode_fixed_expiry(PressureExpiry::Durable, &mut durable);

        assert!(expired < live);
        assert!(live < durable);
        assert_eq!(
            super::decode_fixed_expiry(&expired).unwrap(),
            PressureExpiry::ExpiredFinite
        );
        assert_eq!(
            super::decode_fixed_expiry(&live).unwrap(),
            PressureExpiry::Finite(17)
        );
        assert_eq!(
            super::decode_fixed_expiry(&durable).unwrap(),
            PressureExpiry::Durable
        );
    }

    #[test]
    fn pressure_real_publication_index_ignores_deadline_until_task_four() {
        // All candidates tie on priority and acceptance order, so the
        // pre-Task-4 selector uses exact transfer identity, not deadline.
        let (path, database) = pressure_database("real-publication-finite-and-identity");
        let topic = Topic::new("finite-publication-order").unwrap();
        let scope = Scope::new("mission/finite-publication-order").unwrap();
        let blob_id = BlobId::from_bytes([0xd2; 32]);
        let cases = [(0x31, 10), (0x32, 10), (0x20, 20)];
        {
            let write = database.begin_write().unwrap();
            let mut roots = write
                .open_table(super::BLOB_PRESSURE_PUBLICATION_ROOTS)
                .unwrap();
            let mut index = write.open_table(super::BLOB_PRESSURE_PUBLICATIONS).unwrap();
            for (identity, deadline) in cases {
                let transfer = BlobTransferId::new([identity; 32]);
                let root = PressurePublicationRoot {
                    variant_id: BlobVariantId::from_bytes([identity + 0x40; 32]),
                    semantic_id: BlobSemanticId::new([identity + 0x60; 32]),
                    priority: Priority::Routine,
                    acceptance_order: 7,
                    expiry: PressureExpiry::Finite(deadline),
                    topic: topic.clone(),
                    scope: scope.clone(),
                    blob_id,
                };
                roots
                    .insert(
                        transfer.as_bytes().as_slice(),
                        super::encode_publication_root(&root).unwrap().as_slice(),
                    )
                    .unwrap();
                index
                    .insert(
                        super::encode_publication_key(super::PressurePublicationKey {
                            priority: root.priority,
                            expiry: root.expiry,
                            acceptance_order: root.acceptance_order,
                            transfer_id: transfer,
                        })
                        .as_slice(),
                        &[] as &[u8],
                    )
                    .unwrap();
            }
            drop(index);
            drop(roots);
            write.commit().unwrap();
        }

        let budget = super::BlobPressureRecoveryBudget::new(16, 16 * 1024, 3, 3, 1).unwrap();
        for expected in [0x20, 0x31, 0x32] {
            let read = database.begin_read().unwrap();
            let selection = super::select_pressure_candidate_read(
                &read,
                super::BlobCapacityRecoveryDemand::new(
                    super::BlobCapacityPartition::AggregateItems,
                    Priority::Immediate,
                    1,
                )
                .unwrap(),
                budget,
            )
            .unwrap();
            assert_eq!(
                selection.candidate(),
                Some(super::PressureCandidate::Publication(BlobTransferId::new(
                    [expected; 32]
                )))
            );
            drop(read);

            let write = database.begin_write().unwrap();
            let transfer = BlobTransferId::new([expected; 32]);
            let encoded = write
                .open_table(super::BLOB_PRESSURE_PUBLICATION_ROOTS)
                .unwrap()
                .remove(transfer.as_bytes().as_slice())
                .unwrap()
                .unwrap()
                .value()
                .to_vec();
            let root = super::decode_publication_root(&encoded).unwrap();
            write
                .open_table(super::BLOB_PRESSURE_PUBLICATIONS)
                .unwrap()
                .remove(
                    super::encode_publication_key(super::PressurePublicationKey {
                        priority: root.priority,
                        expiry: root.expiry,
                        acceptance_order: root.acceptance_order,
                        transfer_id: transfer,
                    })
                    .as_slice(),
                )
                .unwrap()
                .unwrap();
            write.commit().unwrap();
        }
        drop(database);
        std::fs::remove_file(path).unwrap();
    }

    #[test]
    fn pressure_real_pending_and_variant_indexes_obey_progress_order_and_exact_ties() {
        let (path, database) = pressure_database("real-progress-and-ties");
        let topic = Topic::new("progress-order").unwrap();
        let scope = Scope::new("mission/progress-order").unwrap();
        let blob_id = BlobId::from_bytes([0xd1; 32]);
        let pending_cases = [
            (0x14, 9, PressureFraction::new(0, 2).unwrap()),
            (0x13, 2, PressureFraction::new(0, 2).unwrap()),
            (0x12, 2, PressureFraction::new(0, 2).unwrap()),
            (0x11, 1, PressureFraction::new(1, 2).unwrap()),
        ];
        let variant_cases = [
            (0x24, false, 9, PressureFraction::new(0, 2).unwrap()),
            (0x23, false, 2, PressureFraction::new(0, 2).unwrap()),
            (0x22, false, 2, PressureFraction::new(0, 2).unwrap()),
            (0x21, false, 1, PressureFraction::new(1, 2).unwrap()),
            (0x20, true, 1, PressureFraction::ONE),
        ];
        {
            let write = database.begin_write().unwrap();
            let mut pending_roots = write
                .open_table(super::BLOB_PRESSURE_PENDING_ROOTS)
                .unwrap();
            let mut pending_index = write
                .open_table(super::BLOB_PRESSURE_PENDING_SOURCES)
                .unwrap();
            for (identity, order, completion) in pending_cases {
                let transfer = BlobTransferId::new([identity; 32]);
                let root = PressurePendingRoot {
                    variant_id: BlobVariantId::from_bytes([identity; 32]),
                    authenticated_source_binding: [identity.wrapping_add(1); 32],
                    priority: Priority::Routine,
                    acceptance_order: order,
                    completion,
                    expiry: PressureExpiry::Durable,
                    topic: topic.clone(),
                    scope: scope.clone(),
                    blob_id,
                };
                let encoded = super::encode_pending_root(&root).unwrap();
                pending_roots
                    .insert(transfer.as_bytes().as_slice(), encoded.as_slice())
                    .unwrap();
                pending_index
                    .insert(
                        &super::encode_pending_index_key(root, transfer),
                        &[] as &[u8],
                    )
                    .unwrap();
            }
            let mut summaries = write
                .open_table(super::BLOB_PRESSURE_VARIANT_SUMMARIES)
                .unwrap();
            let mut variant_index = write.open_table(super::BLOB_PRESSURE_VARIANTS).unwrap();
            for (identity, finalized, order, completion) in variant_cases {
                let variant = BlobVariantId::from_bytes([identity; 32]);
                let summary = PressureVariantSummary {
                    effective_priority: Priority::Routine,
                    minimum_root_acceptance_order: order,
                    committed_progress: completion,
                    finalized,
                    publication_roots: u64::from(finalized),
                    pending_roots: u64::from(!finalized),
                    final_reference_expiry: PressureExpiry::Durable,
                    has_finite_roots: false,
                };
                let encoded = super::encode_variant_summary(summary);
                summaries
                    .insert(variant.as_bytes().as_slice(), encoded.as_slice())
                    .unwrap();
                variant_index
                    .insert(
                        &super::encode_variant_index_key(summary, variant),
                        &[] as &[u8],
                    )
                    .unwrap();
            }
            drop(variant_index);
            drop(summaries);
            drop(pending_index);
            drop(pending_roots);
            write.commit().unwrap();
        }

        let budget = super::BlobPressureRecoveryBudget::new(64, 64 * 1024, 8, 8, 1).unwrap();
        for expected in [0x12, 0x13, 0x14, 0x11] {
            let read = database.begin_read().unwrap();
            let selection = super::select_pressure_candidate_read(
                &read,
                super::BlobCapacityRecoveryDemand::new(
                    super::BlobCapacityPartition::NetworkStagingRows,
                    Priority::Immediate,
                    1,
                )
                .unwrap(),
                budget,
            )
            .unwrap();
            assert_eq!(
                selection.candidate(),
                Some(super::PressureCandidate::PendingSource(
                    BlobTransferId::new([expected; 32])
                ))
            );
            drop(read);
            let write = database.begin_write().unwrap();
            let transfer = BlobTransferId::new([expected; 32]);
            let encoded = write
                .open_table(super::BLOB_PRESSURE_PENDING_ROOTS)
                .unwrap()
                .remove(transfer.as_bytes().as_slice())
                .unwrap()
                .unwrap()
                .value()
                .to_vec();
            let root = super::decode_pending_root(&encoded).unwrap();
            write
                .open_table(super::BLOB_PRESSURE_PENDING_SOURCES)
                .unwrap()
                .remove(&super::encode_pending_index_key(root, transfer))
                .unwrap()
                .unwrap();
            write.commit().unwrap();
        }

        for expected in [0x22, 0x23, 0x24, 0x21, 0x20] {
            let read = database.begin_read().unwrap();
            let selection = super::select_pressure_candidate_read(
                &read,
                super::BlobCapacityRecoveryDemand::new(
                    super::BlobCapacityPartition::DepotVariants,
                    Priority::Immediate,
                    1,
                )
                .unwrap(),
                budget,
            )
            .unwrap();
            assert_eq!(
                selection.candidate(),
                Some(super::PressureCandidate::Variant(
                    BlobVariantId::from_bytes([expected; 32])
                ))
            );
            drop(read);
            let write = database.begin_write().unwrap();
            let variant = BlobVariantId::from_bytes([expected; 32]);
            let encoded = write
                .open_table(super::BLOB_PRESSURE_VARIANT_SUMMARIES)
                .unwrap()
                .remove(variant.as_bytes().as_slice())
                .unwrap()
                .unwrap()
                .value()
                .to_vec();
            let summary = super::decode_variant_summary(&encoded).unwrap();
            write
                .open_table(super::BLOB_PRESSURE_VARIANTS)
                .unwrap()
                .remove(&super::encode_variant_index_key(summary, variant))
                .unwrap()
                .unwrap();
            write.commit().unwrap();
        }
        drop(database);
        std::fs::remove_file(path).unwrap();
    }
}
