//! Monotonic custody age, finite-TTL decisions, and semantic-v3 custody claims.
//!
//! This module never consults a wall clock.  A caller supplies readings from one
//! elapsed-clock continuity domain and persists the resulting [`CustodyAge`].
//! Losing that domain is sticky: finite-TTL work stays durable but cannot be
//! forwarded until an application-specific recovery policy replaces the item.

use crate::model::Priority;
use core::cmp::Ordering;
use core::error::Error;
use core::fmt::{self, Display, Formatter};

/// First semantic replication version which carries authenticated custody claims.
pub const MIN_CUSTODY_SEMANTIC_VERSION: u16 = 3;

/// Exact canonical plaintext length of one semantic-v3 custody claim.
pub const CUSTODY_CLAIMS_ENCODED_LEN: usize = 150;

/// Hard bound for the reference session's authenticated custody wrapper.
///
/// The selected v3 encoding currently occupies 202 bytes.  The larger public
/// bound leaves a small, explicit framing reserve without admitting ordinary
/// source objects or range payloads into this control seam.
pub const MAX_CUSTODY_WRAPPER_BYTES: usize = 256;

const CUSTODY_MAGIC: &[u8; 8] = b"ASTRCU03";
const CUSTODY_FORMAT_VERSION: u16 = 1;

/// One reading from a local elapsed-clock continuity domain.
///
/// `tick_ms` is a monotonic elapsed value, not a wall-clock timestamp.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct CustodySample {
    /// Stable identifier for one continuous elapsed-clock domain.
    pub clock_id: [u8; 16],
    /// Milliseconds elapsed within that domain.
    pub tick_ms: u64,
}

/// Whether elapsed custody time can still be accounted for exactly.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[repr(u8)]
pub enum CustodyContinuity {
    /// The persisted checkpoint and the current sample share one monotonic domain.
    Continuous = 0,
    /// Some elapsed interval is unmeasurable.  This state is sticky.
    Lost = 1,
}

impl CustodyContinuity {
    /// Decodes the stable durable representation.
    pub const fn from_wire(value: u8) -> Option<Self> {
        match value {
            0 => Some(Self::Continuous),
            1 => Some(Self::Lost),
            _ => None,
        }
    }

    /// Returns the stable durable representation.
    pub const fn to_wire(self) -> u8 {
        self as u8
    }
}

/// Sanitized failure from custody-state or claim validation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CustodyError {
    /// Persisted fields do not form a canonical custody state.
    InvalidState,
    /// Elapsed-clock continuity is unavailable.
    ContinuityUnavailable,
    /// Checked cumulative-age arithmetic overflowed.
    AgeOverflow,
    /// A custody claim is malformed or non-canonical.
    InvalidClaims,
    /// An authenticated claim does not match the expected transfer/source context.
    ContextMismatch,
}

impl Display for CustodyError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::InvalidState => "invalid custody state",
            Self::ContinuityUnavailable => "custody clock continuity is unavailable",
            Self::AgeOverflow => "custody age arithmetic overflow",
            Self::InvalidClaims => "invalid custody claims",
            Self::ContextMismatch => "custody claim context mismatch",
        })
    }
}

impl Error for CustodyError {}

/// Durable cumulative custody age and its local elapsed-clock checkpoint.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CustodyAge {
    cumulative_age_ms: u64,
    checkpoint: Option<CustodySample>,
    continuity: CustodyContinuity,
}

impl CustodyAge {
    /// Starts or receives custody with a usable elapsed-clock sample.
    pub const fn new(cumulative_age_ms: u64, checkpoint: CustodySample) -> Self {
        Self {
            cumulative_age_ms,
            checkpoint: Some(checkpoint),
            continuity: CustodyContinuity::Continuous,
        }
    }

    /// Starts or receives custody when elapsed continuity is already unknown.
    pub const fn unknown(cumulative_age_ms: u64) -> Self {
        Self {
            cumulative_age_ms,
            checkpoint: None,
            continuity: CustodyContinuity::Lost,
        }
    }

    /// Reconstructs a checked state from durable fields.
    pub const fn from_parts(
        cumulative_age_ms: u64,
        checkpoint: Option<CustodySample>,
        continuity: CustodyContinuity,
    ) -> Result<Self, CustodyError> {
        if matches!(continuity, CustodyContinuity::Continuous) && checkpoint.is_none() {
            return Err(CustodyError::InvalidState);
        }
        Ok(Self {
            cumulative_age_ms,
            checkpoint,
            continuity,
        })
    }

    /// Returns the persisted cumulative lower bound.
    pub const fn cumulative_age_ms(self) -> u64 {
        self.cumulative_age_ms
    }

    /// Returns the last persisted local elapsed-clock sample, if any.
    pub const fn checkpoint_sample(self) -> Option<CustodySample> {
        self.checkpoint
    }

    /// Returns the sticky continuity state.
    pub const fn continuity(self) -> CustodyContinuity {
        self.continuity
    }

    /// Returns whether exact elapsed accounting is still available.
    pub const fn is_continuous(self) -> bool {
        matches!(self.continuity, CustodyContinuity::Continuous)
    }

    /// Irreversibly marks elapsed continuity unavailable.
    pub fn mark_continuity_lost(&mut self) {
        self.continuity = CustodyContinuity::Lost;
    }

    /// Accounts the current cumulative age with checked arithmetic.
    ///
    /// Exact continuity returns the updated age.  Once continuity is lost, the
    /// method still persists provable same-domain intervals as a conservative
    /// lower bound but returns [`CustodyError::ContinuityUnavailable`].  A
    /// missing sample clears the old anchor; a changed domain or tick rollback
    /// installs the supplied sample as a new zero-delta anchor.  Overflow
    /// saturates the lower bound and returns [`CustodyError::AgeOverflow`].
    pub fn effective_age(&mut self, current: Option<CustodySample>) -> Result<u64, CustodyError> {
        self.account_current(current, false)
    }

    /// Accounts elapsed time and persists `current` as the new checkpoint.
    pub fn checkpoint(&mut self, current: Option<CustodySample>) -> Result<u64, CustodyError> {
        self.account_current(current, false)
    }

    /// Merges an authenticated duplicate without ever decreasing age.
    ///
    /// Local elapsed residence is first accounted at `current`; the greater of
    /// that value and `received_age_ms` becomes the new durable checkpoint.
    pub fn merge_authenticated_age(
        &mut self,
        received_age_ms: u64,
        current: Option<CustodySample>,
    ) -> Result<u64, CustodyError> {
        match self.account_current(current, true) {
            Ok(_) | Err(CustodyError::ContinuityUnavailable) => {}
            Err(error) => return Err(error),
        }
        let merged = self.cumulative_age_ms.max(received_age_ms);
        self.cumulative_age_ms = merged;
        Ok(merged)
    }

    fn account_current(
        &mut self,
        current: Option<CustodySample>,
        preserve_same_domain_rollback: bool,
    ) -> Result<u64, CustodyError> {
        let Some(current) = current else {
            self.mark_continuity_lost();
            self.checkpoint = None;
            return Err(CustodyError::ContinuityUnavailable);
        };

        let Some(checkpoint) = self.checkpoint else {
            self.mark_continuity_lost();
            self.checkpoint = Some(current);
            return Err(CustodyError::ContinuityUnavailable);
        };

        if checkpoint.clock_id != current.clock_id {
            self.mark_continuity_lost();
            self.checkpoint = Some(current);
            return Err(CustodyError::ContinuityUnavailable);
        }
        if current.tick_ms < checkpoint.tick_ms {
            self.mark_continuity_lost();
            if !preserve_same_domain_rollback {
                self.checkpoint = Some(current);
            }
            return Err(CustodyError::ContinuityUnavailable);
        }

        let elapsed = current.tick_ms - checkpoint.tick_ms;
        self.checkpoint = Some(current);
        match self.cumulative_age_ms.checked_add(elapsed) {
            Some(age) => {
                self.cumulative_age_ms = age;
                if self.is_continuous() {
                    Ok(age)
                } else {
                    Err(CustodyError::ContinuityUnavailable)
                }
            }
            None => {
                self.cumulative_age_ms = u64::MAX;
                self.mark_continuity_lost();
                Err(CustodyError::AgeOverflow)
            }
        }
    }
}

/// Result of applying tombstone, TTL, and custody-continuity policy.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CustodyDisposition {
    /// A tombstone or an item without finite TTL remains durable and forwardable.
    Durable,
    /// A finite-TTL item is live at the supplied elapsed-clock sample.
    LiveFinite {
        /// Accounted cumulative custody age.
        age_ms: u64,
        /// Milliseconds until `age >= TTL`.
        remaining_ms: u64,
    },
    /// A finite-TTL item has reached or exceeded its authenticated TTL.
    Expired {
        /// Proven cumulative custody-age lower bound.
        age_ms: u64,
    },
    /// Finite-TTL forwarding is withheld because age cannot be bounded.
    Indeterminate,
}

impl CustodyDisposition {
    /// Returns whether policy permits forwarding this item.
    pub const fn is_forwardable(self) -> bool {
        matches!(self, Self::Durable | Self::LiveFinite { .. })
    }

    /// Returns whether finite-TTL garbage collection is eligible.
    pub const fn is_expired(self) -> bool {
        matches!(self, Self::Expired { .. })
    }
}

/// Evaluates one item without consulting wall-clock time.
///
/// Tombstones follow the retained profile's durable-marker rule even if a
/// legacy source supplied a finite TTL.  Finite items fail closed whenever
/// elapsed continuity is missing or checked arithmetic overflows.
pub fn evaluate_custody(
    ttl_ms: Option<u64>,
    tombstone: bool,
    age: &mut CustodyAge,
    current: Option<CustodySample>,
) -> CustodyDisposition {
    let Some(ttl_ms) = ttl_ms.filter(|_| !tombstone) else {
        return CustodyDisposition::Durable;
    };
    // This durable value remains a sound lower bound after elapsed-clock
    // continuity is lost. Once it reaches the TTL, expiry is certain without
    // reconstructing any missing residence time.
    if age.cumulative_age_ms() >= ttl_ms {
        return CustodyDisposition::Expired {
            age_ms: age.cumulative_age_ms(),
        };
    }
    let exact_age = age.checkpoint(current);
    let age_ms = age.cumulative_age_ms();
    if age_ms >= ttl_ms {
        CustodyDisposition::Expired { age_ms }
    } else if exact_age.is_err() {
        CustodyDisposition::Indeterminate
    } else {
        CustodyDisposition::LiveFinite {
            age_ms,
            remaining_ms: ttl_ms - age_ms,
        }
    }
}

/// Checked cumulative age placed in an authenticated forwarding claim.
pub const fn checked_forwarding_age(
    prior_age_ms: u64,
    hop_delta_ms: u64,
) -> Result<u64, CustodyError> {
    match prior_age_ms.checked_add(hop_delta_ms) {
        Some(value) => Ok(value),
        None => Err(CustodyError::AgeOverflow),
    }
}

/// Digest identifier of the exact stable source transfer bytes.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct CustodyTransferId([u8; 32]);

impl CustodyTransferId {
    /// Wraps the already-verified digest of the exact stable transfer bytes.
    pub const fn from_exact_hash(value: [u8; 32]) -> Self {
        Self(value)
    }

    /// Borrows the exact transfer digest.
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// Returns the exact transfer digest.
    pub const fn into_bytes(self) -> [u8; 32] {
        self.0
    }
}

/// Authenticated source fields repeated in a custody claim for exact recheck.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CustodyTransferClaims {
    transfer_id: CustodyTransferId,
    exact_len: u64,
    source_ttl_ms: Option<u64>,
    source_priority: Priority,
}

impl CustodyTransferClaims {
    /// Creates claims copied from a freshly verified stable source header.
    pub const fn new(
        transfer_id: CustodyTransferId,
        exact_len: u64,
        source_ttl_ms: Option<u64>,
        source_priority: Priority,
    ) -> Result<Self, CustodyError> {
        if exact_len == 0 {
            return Err(CustodyError::InvalidClaims);
        }
        Ok(Self {
            transfer_id,
            exact_len,
            source_ttl_ms,
            source_priority,
        })
    }

    /// Returns the exact stable transfer identifier.
    pub const fn transfer_id(self) -> CustodyTransferId {
        self.transfer_id
    }

    /// Returns the exact stable transfer byte length.
    pub const fn exact_len(self) -> u64 {
        self.exact_len
    }

    /// Returns the source-authenticated TTL copied into the wrapper.
    ///
    /// `Some(0)` is canonical and represents immediate expiry.
    pub const fn source_ttl_ms(self) -> Option<u64> {
        self.source_ttl_ms
    }

    /// Returns the source-authenticated priority copied into the wrapper.
    pub const fn source_priority(self) -> Priority {
        self.source_priority
    }
}

/// One sender's authenticated custody-age contribution.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CustodyHop {
    prior_age_ms: u64,
    sample: CustodySample,
    delta_ms: u64,
    forwarding_age_ms: u64,
}

impl CustodyHop {
    /// Creates a hop after checking cumulative-age arithmetic.
    pub const fn new(
        prior_age_ms: u64,
        sample: CustodySample,
        delta_ms: u64,
    ) -> Result<Self, CustodyError> {
        match checked_forwarding_age(prior_age_ms, delta_ms) {
            Ok(forwarding_age_ms) => Ok(Self {
                prior_age_ms,
                sample,
                delta_ms,
                forwarding_age_ms,
            }),
            Err(error) => Err(error),
        }
    }

    /// Returns cumulative age before this hop's elapsed residence.
    pub const fn prior_age_ms(self) -> u64 {
        self.prior_age_ms
    }

    /// Returns the sender's monotonic elapsed-clock sample.
    pub const fn sample(self) -> CustodySample {
        self.sample
    }

    /// Returns elapsed residence contributed by this hop.
    pub const fn delta_ms(self) -> u64 {
        self.delta_ms
    }

    /// Returns checked cumulative age authenticated for the receiver.
    pub const fn forwarding_age_ms(self) -> u64 {
        self.forwarding_age_ms
    }
}

/// Complete bounded semantic-v3 custody claim.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CustodyClaims {
    transfer: CustodyTransferClaims,
    exchange_id: u64,
    policy_revision: u64,
    hop: CustodyHop,
}

impl CustodyClaims {
    /// Creates an exact transfer- and exchange-bound claim.
    ///
    /// Every `u64` exchange identifier, including zero, is valid in the stable
    /// replication protocol.  Policy revision zero is reserved and rejected.
    pub const fn new(
        transfer: CustodyTransferClaims,
        exchange_id: u64,
        policy_revision: u64,
        hop: CustodyHop,
    ) -> Result<Self, CustodyError> {
        if policy_revision == 0 {
            return Err(CustodyError::InvalidClaims);
        }
        Ok(Self {
            transfer,
            exchange_id,
            policy_revision,
            hop,
        })
    }

    /// Returns the stable transfer/source fields.
    pub const fn transfer(self) -> CustodyTransferClaims {
        self.transfer
    }

    /// Returns the session exchange identifier.
    pub const fn exchange_id(self) -> u64 {
        self.exchange_id
    }

    /// Returns the nonzero operator-policy revision applied by the sender.
    pub const fn policy_revision(self) -> u64 {
        self.policy_revision
    }

    /// Returns the sender's checked hop contribution.
    pub const fn hop(self) -> CustodyHop {
        self.hop
    }

    /// Verifies exact transfer, exchange, TTL, and priority context.
    pub fn verify_expected(self, expected: CustodyExpectation) -> Result<(), CustodyError> {
        if self.transfer == expected.transfer && self.exchange_id == expected.exchange_id {
            Ok(())
        } else {
            Err(CustodyError::ContextMismatch)
        }
    }
}

/// Fresh receiver context used to recheck authenticated custody claims.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CustodyExpectation {
    transfer: CustodyTransferClaims,
    exchange_id: u64,
}

/// Session-authenticated and exact-context-checked custody capability.
///
/// Fields and construction are private.  An external caller can obtain this
/// token only from a completed semantic-v3 session's custody-wrapper open
/// operation after AEAD authentication, replay rejection, transcript binding,
/// and exact transfer/source-context recheck.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VerifiedCustodyClaims {
    claims: CustodyClaims,
}

impl VerifiedCustodyClaims {
    pub(crate) const fn from_authenticated(claims: CustodyClaims) -> Self {
        Self { claims }
    }

    /// Returns the digest of the exact stable transfer bytes.
    pub const fn transfer_id(&self) -> CustodyTransferId {
        self.claims.transfer.transfer_id
    }

    /// Returns the exact stable transfer byte length.
    pub const fn exact_len(&self) -> u64 {
        self.claims.transfer.exact_len
    }

    /// Returns the authenticated live exchange identifier.
    pub const fn exchange_id(&self) -> u64 {
        self.claims.exchange_id
    }

    /// Returns the authenticated sender policy revision.
    pub const fn policy_revision(&self) -> u64 {
        self.claims.policy_revision
    }

    /// Returns cumulative age before this sender's elapsed residence.
    pub const fn prior_age_ms(&self) -> u64 {
        self.claims.hop.prior_age_ms
    }

    /// Returns the sender's authenticated monotonic sample.
    pub const fn hop_sample(&self) -> CustodySample {
        self.claims.hop.sample
    }

    /// Returns elapsed residence contributed by this sender.
    pub const fn hop_delta_ms(&self) -> u64 {
        self.claims.hop.delta_ms
    }

    /// Returns the checked nondecreasing age authenticated for the receiver.
    pub const fn forwarding_age_ms(&self) -> u64 {
        self.claims.hop.forwarding_age_ms()
    }

    /// Returns source-authenticated finite TTL, if any.
    pub const fn source_ttl_ms(&self) -> Option<u64> {
        self.claims.transfer.source_ttl_ms
    }

    /// Returns source-authenticated scheduling priority.
    pub const fn source_priority(&self) -> Priority {
        self.claims.transfer.source_priority
    }
}

impl CustodyExpectation {
    /// Creates an expectation from the freshly verified source header.
    ///
    /// Exchange identifier zero is valid and remains exact-context-bound.
    pub const fn new(transfer: CustodyTransferClaims, exchange_id: u64) -> Self {
        Self {
            transfer,
            exchange_id,
        }
    }

    /// Returns the expected exact transfer/source fields.
    pub const fn transfer(self) -> CustodyTransferClaims {
        self.transfer
    }

    /// Returns the expected live exchange identifier.
    pub const fn exchange_id(self) -> u64 {
        self.exchange_id
    }
}

/// Stable key whose natural ascending order is the transmission order.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TransmissionOrderKey {
    priority: Priority,
    enqueue_sequence: u64,
    transfer_id: CustodyTransferId,
}

impl TransmissionOrderKey {
    /// Creates a deterministic priority/FIFO/tie-break key.
    pub const fn new(
        priority: Priority,
        enqueue_sequence: u64,
        transfer_id: CustodyTransferId,
    ) -> Self {
        Self {
            priority,
            enqueue_sequence,
            transfer_id,
        }
    }
}

impl Ord for TransmissionOrderKey {
    fn cmp(&self, other: &Self) -> Ordering {
        other
            .priority
            .cmp(&self.priority)
            .then_with(|| self.enqueue_sequence.cmp(&other.enqueue_sequence))
            .then_with(|| self.transfer_id.cmp(&other.transfer_id))
    }
}

impl PartialOrd for TransmissionOrderKey {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

/// Priority-sensitive deterministic retry delay with a bounded exponent.
pub const fn retry_delay_ms(priority: Priority, attempt: u16, link_floor_ms: u64) -> u64 {
    let base_ms = match priority {
        Priority::Flash => 125_u64,
        Priority::Immediate => 250,
        Priority::Priority => 500,
        Priority::Routine => 1_000,
    };
    let exponent = if attempt > 6 { 6 } else { attempt };
    let delay = base_ms * (1_u64 << exponent);
    if delay < link_floor_ms {
        link_floor_ms
    } else {
        delay
    }
}

pub(crate) fn encode_claims(
    claims: CustodyClaims,
    session_id: [u8; 32],
) -> Result<Vec<u8>, CustodyError> {
    // Re-run the checked proof at the encoding boundary in case construction
    // rules are ever extended.
    checked_forwarding_age(claims.hop.prior_age_ms, claims.hop.delta_ms)?;
    let mut output = Vec::with_capacity(CUSTODY_CLAIMS_ENCODED_LEN);
    output.extend_from_slice(CUSTODY_MAGIC);
    output.extend_from_slice(&CUSTODY_FORMAT_VERSION.to_be_bytes());
    output.extend_from_slice(&MIN_CUSTODY_SEMANTIC_VERSION.to_be_bytes());
    output.extend_from_slice(&session_id);
    output.extend_from_slice(claims.transfer.transfer_id.as_bytes());
    output.extend_from_slice(&claims.transfer.exact_len.to_be_bytes());
    output.extend_from_slice(&claims.exchange_id.to_be_bytes());
    output.extend_from_slice(&claims.policy_revision.to_be_bytes());
    output.extend_from_slice(&claims.hop.prior_age_ms.to_be_bytes());
    output.extend_from_slice(&claims.hop.sample.clock_id);
    output.extend_from_slice(&claims.hop.sample.tick_ms.to_be_bytes());
    output.extend_from_slice(&claims.hop.delta_ms.to_be_bytes());
    output.push(claims.transfer.source_priority as u8);
    match claims.transfer.source_ttl_ms {
        None => {
            output.push(0);
            output.extend_from_slice(&0_u64.to_be_bytes());
        }
        Some(ttl_ms) => {
            output.push(1);
            output.extend_from_slice(&ttl_ms.to_be_bytes());
        }
    }
    if claims.transfer.exact_len == 0 || claims.policy_revision == 0 {
        return Err(CustodyError::InvalidClaims);
    }
    if output.len() != CUSTODY_CLAIMS_ENCODED_LEN {
        return Err(CustodyError::InvalidClaims);
    }
    Ok(output)
}

pub(crate) fn decode_claims(
    encoded: &[u8],
    session_id: [u8; 32],
) -> Result<CustodyClaims, CustodyError> {
    if encoded.len() != CUSTODY_CLAIMS_ENCODED_LEN {
        return Err(CustodyError::InvalidClaims);
    }
    let mut reader = ClaimsReader::new(encoded);
    if reader.take::<8>()? != *CUSTODY_MAGIC
        || reader.u16()? != CUSTODY_FORMAT_VERSION
        || reader.u16()? != MIN_CUSTODY_SEMANTIC_VERSION
        || reader.take::<32>()? != session_id
    {
        return Err(CustodyError::InvalidClaims);
    }
    let transfer_id = CustodyTransferId::from_exact_hash(reader.take::<32>()?);
    let exact_len = reader.u64()?;
    let exchange_id = reader.u64()?;
    let policy_revision = reader.u64()?;
    let prior_age_ms = reader.u64()?;
    let sample = CustodySample {
        clock_id: reader.take::<16>()?,
        tick_ms: reader.u64()?,
    };
    let delta_ms = reader.u64()?;
    let priority = Priority::from_wire(reader.u8()?).ok_or(CustodyError::InvalidClaims)?;
    let ttl_tag = reader.u8()?;
    let ttl_value = reader.u64()?;
    reader.finish()?;
    let source_ttl_ms = match (ttl_tag, ttl_value) {
        (0, 0) => None,
        (1, value) => Some(value),
        _ => return Err(CustodyError::InvalidClaims),
    };
    let hop = CustodyHop::new(prior_age_ms, sample, delta_ms)?;
    CustodyClaims::new(
        CustodyTransferClaims::new(transfer_id, exact_len, source_ttl_ms, priority)?,
        exchange_id,
        policy_revision,
        hop,
    )
}

struct ClaimsReader<'a> {
    bytes: &'a [u8],
    offset: usize,
}

impl<'a> ClaimsReader<'a> {
    const fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, offset: 0 }
    }

    fn take<const N: usize>(&mut self) -> Result<[u8; N], CustodyError> {
        let end = self
            .offset
            .checked_add(N)
            .ok_or(CustodyError::InvalidClaims)?;
        let value = self
            .bytes
            .get(self.offset..end)
            .ok_or(CustodyError::InvalidClaims)?
            .try_into()
            .map_err(|_| CustodyError::InvalidClaims)?;
        self.offset = end;
        Ok(value)
    }

    fn u8(&mut self) -> Result<u8, CustodyError> {
        Ok(self.take::<1>()?[0])
    }

    fn u16(&mut self) -> Result<u16, CustodyError> {
        Ok(u16::from_be_bytes(self.take::<2>()?))
    }

    fn u64(&mut self) -> Result<u64, CustodyError> {
        Ok(u64::from_be_bytes(self.take::<8>()?))
    }

    fn finish(self) -> Result<(), CustodyError> {
        if self.offset == self.bytes.len() {
            Ok(())
        } else {
            Err(CustodyError::InvalidClaims)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const CLOCK: [u8; 16] = [0x11; 16];
    const CLOCK_B: [u8; 16] = [0x22; 16];
    const CLOCK_C: [u8; 16] = [0x33; 16];

    fn sample(tick_ms: u64) -> CustodySample {
        sample_in(CLOCK, tick_ms)
    }

    fn sample_in(clock_id: [u8; 16], tick_ms: u64) -> CustodySample {
        CustodySample { clock_id, tick_ms }
    }

    fn claims(ttl_ms: Option<u64>) -> CustodyClaims {
        CustodyClaims::new(
            CustodyTransferClaims::new(
                CustodyTransferId::from_exact_hash([0x22; 32]),
                4_096,
                ttl_ms,
                Priority::Immediate,
            )
            .expect("nonempty exact transfer"),
            41,
            7,
            CustodyHop::new(90, sample(1_000), 10).expect("bounded hop"),
        )
        .expect("nonzero policy revision")
    }

    #[test]
    fn ttl_boundary_is_age_greater_than_or_equal() {
        for (age_ms, expected) in [
            (
                99,
                CustodyDisposition::LiveFinite {
                    age_ms: 99,
                    remaining_ms: 1,
                },
            ),
            (100, CustodyDisposition::Expired { age_ms: 100 }),
            (101, CustodyDisposition::Expired { age_ms: 101 }),
        ] {
            let mut age = CustodyAge::new(age_ms, sample(5));
            assert_eq!(
                evaluate_custody(Some(100), false, &mut age, Some(sample(5))),
                expected
            );
        }
    }

    #[test]
    fn durable_and_tombstone_items_ignore_finite_age_policy() {
        let mut unknown = CustodyAge::unknown(u64::MAX);
        assert_eq!(
            evaluate_custody(None, false, &mut unknown, None),
            CustodyDisposition::Durable
        );
        assert_eq!(
            evaluate_custody(Some(0), true, &mut unknown, None),
            CustodyDisposition::Durable
        );
        assert!(!unknown.is_continuous());

        let mut zero_age = CustodyAge::new(0, sample(0));
        assert_eq!(
            evaluate_custody(Some(0), false, &mut zero_age, Some(sample(0))),
            CustodyDisposition::Expired { age_ms: 0 }
        );
    }

    #[test]
    fn discontinuity_conditions_are_sticky_and_fail_closed() {
        let cases = [
            None,
            Some(CustodySample {
                clock_id: [0x33; 16],
                tick_ms: 11,
            }),
            Some(sample(9)),
        ];
        for current in cases {
            let mut age = CustodyAge::new(5, sample(10));
            assert_eq!(
                evaluate_custody(Some(100), false, &mut age, current),
                CustodyDisposition::Indeterminate
            );
            assert_eq!(age.continuity(), CustodyContinuity::Lost);
            assert_eq!(
                age.effective_age(Some(sample(20))),
                Err(CustodyError::ContinuityUnavailable)
            );
        }
    }

    #[test]
    fn discontinuous_lower_bound_proves_expiry_at_and_above_ttl() {
        for (age_ms, expected) in [
            (99, CustodyDisposition::Indeterminate),
            (100, CustodyDisposition::Expired { age_ms: 100 }),
            (101, CustodyDisposition::Expired { age_ms: 101 }),
        ] {
            let mut age = CustodyAge::unknown(age_ms);
            assert_eq!(evaluate_custody(Some(100), false, &mut age, None), expected);
            assert_eq!(age.continuity(), CustodyContinuity::Lost);
        }
    }

    #[test]
    fn checked_age_overflow_is_sticky() {
        let mut age = CustodyAge::new(u64::MAX - 1, sample(0));
        assert_eq!(
            age.effective_age(Some(sample(2))),
            Err(CustodyError::AgeOverflow)
        );
        assert_eq!(age.continuity(), CustodyContinuity::Lost);
        assert_eq!(
            evaluate_custody(Some(u64::MAX), false, &mut age, Some(sample(2))),
            CustodyDisposition::Expired { age_ms: u64::MAX }
        );

        let mut expired_lower_bound = CustodyAge::unknown(u64::MAX);
        assert_eq!(
            evaluate_custody(Some(u64::MAX), false, &mut expired_lower_bound, None),
            CustodyDisposition::Expired { age_ms: u64::MAX }
        );
        assert_eq!(
            checked_forwarding_age(u64::MAX, 1),
            Err(CustodyError::AgeOverflow)
        );
    }

    #[test]
    fn duplicate_merge_never_reduces_age() {
        let mut age = CustodyAge::new(100, sample(10));
        assert_eq!(age.merge_authenticated_age(90, Some(sample(20))), Ok(110));
        assert_eq!(age.merge_authenticated_age(110, Some(sample(20))), Ok(110));
        assert_eq!(age.merge_authenticated_age(150, Some(sample(25))), Ok(150));
        assert_eq!(age.cumulative_age_ms(), 150);
    }

    #[test]
    fn lost_age_reanchors_without_counting_unknown_gap() {
        let mut age = CustodyAge::new(10, sample_in(CLOCK, 100));

        assert_eq!(
            evaluate_custody(Some(30), false, &mut age, Some(sample_in(CLOCK_B, 9_000)),),
            CustodyDisposition::Indeterminate
        );
        assert_eq!(age.cumulative_age_ms(), 10);
        assert_eq!(age.checkpoint_sample(), Some(sample_in(CLOCK_B, 9_000)));
        assert_eq!(
            evaluate_custody(Some(30), false, &mut age, Some(sample_in(CLOCK_B, 9_020)),),
            CustodyDisposition::Expired { age_ms: 30 }
        );
        assert_eq!(age.continuity(), CustodyContinuity::Lost);
    }

    #[test]
    fn lost_age_accumulates_later_same_domain_intervals() {
        let mut age = CustodyAge::unknown(5);

        assert_eq!(
            age.checkpoint(Some(sample_in(CLOCK_B, 100))),
            Err(CustodyError::ContinuityUnavailable)
        );
        assert_eq!(age.cumulative_age_ms(), 5);
        assert_eq!(
            age.checkpoint(Some(sample_in(CLOCK_B, 112))),
            Err(CustodyError::ContinuityUnavailable)
        );
        assert_eq!(age.cumulative_age_ms(), 17);
        assert_eq!(age.checkpoint_sample(), Some(sample_in(CLOCK_B, 112)));
        assert_eq!(age.continuity(), CustodyContinuity::Lost);
    }

    #[test]
    fn multiple_lost_domains_accumulate_only_proven_intervals() {
        let mut age = CustodyAge::new(10, sample_in(CLOCK, 100));

        assert_eq!(
            age.checkpoint(Some(sample_in(CLOCK_B, 1_000))),
            Err(CustodyError::ContinuityUnavailable)
        );
        assert_eq!(
            age.checkpoint(Some(sample_in(CLOCK_B, 1_010))),
            Err(CustodyError::ContinuityUnavailable)
        );
        assert_eq!(
            age.checkpoint(Some(sample_in(CLOCK_C, 5_000))),
            Err(CustodyError::ContinuityUnavailable)
        );
        assert_eq!(
            age.checkpoint(Some(sample_in(CLOCK_C, 5_007))),
            Err(CustodyError::ContinuityUnavailable)
        );

        assert_eq!(age.cumulative_age_ms(), 27);
        assert_eq!(age.checkpoint_sample(), Some(sample_in(CLOCK_C, 5_007)));
        assert_eq!(age.continuity(), CustodyContinuity::Lost);
    }

    #[test]
    fn lost_duplicate_merge_never_rejuvenates() {
        let mut age = CustodyAge::new(10, sample_in(CLOCK, 100));
        assert_eq!(
            age.checkpoint(Some(sample_in(CLOCK_B, 1_000))),
            Err(CustodyError::ContinuityUnavailable)
        );

        assert_eq!(
            age.merge_authenticated_age(8, Some(sample_in(CLOCK_B, 1_010))),
            Ok(20)
        );
        assert_eq!(
            age.merge_authenticated_age(50, Some(sample_in(CLOCK_B, 1_015))),
            Ok(50)
        );
        assert_eq!(
            age.merge_authenticated_age(7, Some(sample_in(CLOCK_B, 1_014))),
            Ok(50)
        );
        assert_eq!(age.cumulative_age_ms(), 50);
        assert_eq!(age.checkpoint_sample(), Some(sample_in(CLOCK_B, 1_015)));
        assert_eq!(age.continuity(), CustodyContinuity::Lost);
    }

    #[test]
    fn missing_sample_discards_the_old_anchor() {
        let mut age =
            CustodyAge::from_parts(20, Some(sample_in(CLOCK, 100)), CustodyContinuity::Lost)
                .expect("lost state may retain an anchor");

        assert_eq!(
            age.checkpoint(None),
            Err(CustodyError::ContinuityUnavailable)
        );
        assert_eq!(age.checkpoint_sample(), None);
        assert_eq!(
            age.checkpoint(Some(sample_in(CLOCK, 1_000))),
            Err(CustodyError::ContinuityUnavailable)
        );
        assert_eq!(age.cumulative_age_ms(), 20);
        assert_eq!(
            age.checkpoint(Some(sample_in(CLOCK, 1_009))),
            Err(CustodyError::ContinuityUnavailable)
        );
        assert_eq!(age.cumulative_age_ms(), 29);
    }

    #[test]
    fn overflow_saturates_the_proven_lower_bound() {
        let mut age = CustodyAge::new(u64::MAX - 1, sample(0));

        assert_eq!(
            age.checkpoint(Some(sample(2))),
            Err(CustodyError::AgeOverflow)
        );
        assert_eq!(age.cumulative_age_ms(), u64::MAX);
        assert_eq!(age.checkpoint_sample(), Some(sample(2)));
        assert_eq!(age.continuity(), CustodyContinuity::Lost);
        assert_eq!(
            evaluate_custody(Some(u64::MAX), false, &mut age, Some(sample(3))),
            CustodyDisposition::Expired { age_ms: u64::MAX }
        );
    }

    #[test]
    fn persisted_parts_require_a_checkpoint_for_continuity() {
        assert_eq!(
            CustodyAge::from_parts(1, None, CustodyContinuity::Continuous),
            Err(CustodyError::InvalidState)
        );
        assert!(CustodyAge::from_parts(1, Some(sample(2)), CustodyContinuity::Lost).is_ok());
    }

    #[test]
    fn claims_codec_is_fixed_canonical_and_session_bound() {
        let original = claims(Some(500));
        let session = [0x44; 32];
        let encoded = encode_claims(original, session).expect("encode");
        assert_eq!(encoded.len(), CUSTODY_CLAIMS_ENCODED_LEN);
        assert_eq!(decode_claims(&encoded, session), Ok(original));
        assert_eq!(
            decode_claims(&encoded, [0x45; 32]),
            Err(CustodyError::InvalidClaims)
        );

        let mut bad_priority = encoded.clone();
        bad_priority[CUSTODY_CLAIMS_ENCODED_LEN - 10] = 4;
        assert_eq!(
            decode_claims(&bad_priority, session),
            Err(CustodyError::InvalidClaims)
        );

        let mut noncanonical_none = encode_claims(claims(None), session).expect("none");
        *noncanonical_none.last_mut().expect("last") = 1;
        assert_eq!(
            decode_claims(&noncanonical_none, session),
            Err(CustodyError::InvalidClaims)
        );

        let mut zero_policy_revision = encoded;
        zero_policy_revision[92..100].fill(0);
        assert_eq!(
            decode_claims(&zero_policy_revision, session),
            Err(CustodyError::InvalidClaims)
        );
    }

    #[test]
    fn claim_invariants_and_exact_expectation_are_checked() {
        let original = claims(Some(500));
        let expected = CustodyExpectation::new(original.transfer(), 41);
        assert_eq!(original.verify_expected(expected), Ok(()));
        assert_eq!(
            CustodyTransferClaims::new(
                original.transfer().transfer_id(),
                0,
                Some(500),
                original.transfer().source_priority(),
            ),
            Err(CustodyError::InvalidClaims)
        );
        assert_eq!(
            CustodyClaims::new(original.transfer(), 41, 0, original.hop()),
            Err(CustodyError::InvalidClaims)
        );
        assert!(CustodyClaims::new(original.transfer(), 0, 1, original.hop()).is_ok());

        let transfer_id = original.transfer().transfer_id();
        let exact_len = original.transfer().exact_len();
        let ttl = original.transfer().source_ttl_ms();
        let priority = original.transfer().source_priority();
        let mismatches = [
            CustodyExpectation::new(
                CustodyTransferClaims::new(
                    CustodyTransferId::from_exact_hash([0x23; 32]),
                    exact_len,
                    ttl,
                    priority,
                )
                .expect("nonempty exact transfer"),
                41,
            ),
            CustodyExpectation::new(
                CustodyTransferClaims::new(transfer_id, exact_len + 1, ttl, priority)
                    .expect("nonempty exact transfer"),
                41,
            ),
            CustodyExpectation::new(
                CustodyTransferClaims::new(transfer_id, exact_len, Some(501), priority)
                    .expect("nonempty exact transfer"),
                41,
            ),
            CustodyExpectation::new(
                CustodyTransferClaims::new(transfer_id, exact_len, ttl, Priority::Routine)
                    .expect("nonempty exact transfer"),
                41,
            ),
            CustodyExpectation::new(original.transfer(), 42),
        ];
        for mismatch in mismatches {
            assert_eq!(
                original.verify_expected(mismatch),
                Err(CustodyError::ContextMismatch)
            );
        }
    }

    #[test]
    fn deterministic_priority_and_retry_primitives() {
        let routine = TransmissionOrderKey::new(
            Priority::Routine,
            0,
            CustodyTransferId::from_exact_hash([1; 32]),
        );
        let flash_late = TransmissionOrderKey::new(
            Priority::Flash,
            2,
            CustodyTransferId::from_exact_hash([2; 32]),
        );
        let flash_early = TransmissionOrderKey::new(
            Priority::Flash,
            1,
            CustodyTransferId::from_exact_hash([3; 32]),
        );
        let mut order = [routine, flash_late, flash_early];
        order.sort();
        assert_eq!(order, [flash_early, flash_late, routine]);
        assert_eq!(retry_delay_ms(Priority::Flash, 0, 200), 200);
        assert_eq!(retry_delay_ms(Priority::Routine, 0, 200), 1_000);
        assert!(retry_delay_ms(Priority::Flash, 3, 0) < retry_delay_ms(Priority::Routine, 3, 0));
        assert_eq!(retry_delay_ms(Priority::Routine, u16::MAX, 0), 64_000);
    }
}
