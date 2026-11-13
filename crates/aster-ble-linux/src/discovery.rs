use crate::{
    ASTER_ROSTER_BEACON_V1_BYTES, AsterRosterBeaconV1, DiscoveryGeneration, DiscoveryRecordError,
    LeasedDiscoveryCredentialSet,
};
use bluer::{Address, AddressType};
use std::{
    fmt,
    time::{Duration, Instant},
};

const MAX_CALLBACKS_PER_WINDOW: u16 = 256;
const MAX_HMACS_PER_WINDOW: u16 = 128;
const MAX_NEW_TOKENS_PER_WINDOW: u8 = 32;
const MAX_CANDIDATES: usize = 32;
const MAX_REPLAY_ENTRIES: usize = 256;
const MAX_NEGATIVE_ENTRIES: usize = 32;
const CANDIDATE_FRESHNESS: Duration = Duration::from_secs(90);
const REPLAY_TTL: Duration = Duration::from_secs(10 * 60);
const NEGATIVE_CACHE_TTL: Duration = Duration::from_secs(30);
pub(crate) const SCAN_ACTIVE_INTERVAL: Duration = Duration::from_secs(10);
pub(crate) const SCAN_IDLE_INTERVAL: Duration = Duration::from_secs(20);
const ATTEMPT_BUCKET_CAPACITY: u8 = 4;
const ATTEMPT_TOKEN_REFILL: Duration = Duration::from_secs(30);
const AUTHENTICATED_HEADER_BYTES: usize = 24;

/// Canonical-locator construction failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CanonicalLocatorError {
    /// BR/EDR addresses cannot identify an LE discovery observation.
    NonLeAddress,
}

/// Exact transient Linux Bluetooth address and LE address type.
#[derive(Clone, Copy, Eq, Ord, PartialEq, PartialOrd)]
pub struct CanonicalLocator {
    address: Address,
    address_type: AddressType,
}

impl CanonicalLocator {
    /// Constructs a locator without aliasing or address-type coercion.
    pub fn new(address: Address, address_type: AddressType) -> Result<Self, CanonicalLocatorError> {
        if !matches!(address_type, AddressType::LePublic | AddressType::LeRandom) {
            return Err(CanonicalLocatorError::NonLeAddress);
        }
        Ok(Self {
            address,
            address_type,
        })
    }

    /// Exact transient Bluetooth address bytes.
    pub const fn address(self) -> Address {
        self.address
    }

    /// Exact observed LE address type.
    pub const fn address_type(self) -> AddressType {
        self.address_type
    }
}

impl fmt::Debug for CanonicalLocator {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("CanonicalLocator([REDACTED])")
    }
}

/// Authenticated transient candidate retained for bounded connection work.
#[derive(Clone, Copy, Eq, PartialEq)]
pub struct DiscoveryCandidate {
    locator: CanonicalLocator,
    listener_psm: u16,
    generation: DiscoveryGeneration,
    nonce: [u8; 16],
    record: [u8; ASTER_ROSTER_BEACON_V1_BYTES],
    authenticated_at: Instant,
}

impl DiscoveryCandidate {
    /// Exact transient locator observed in the current controller epoch.
    pub const fn locator(self) -> CanonicalLocator {
        self.locator
    }

    /// Authenticated dynamic LE CoC PSM.
    pub const fn listener_psm(self) -> u16 {
        self.listener_psm
    }

    /// Authenticated credential generation.
    pub const fn generation(self) -> DiscoveryGeneration {
        self.generation
    }

    /// Authenticated replay nonce.
    pub const fn nonce(self) -> [u8; 16] {
        self.nonce
    }
}

impl fmt::Debug for DiscoveryCandidate {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DiscoveryCandidate")
            .field("generation", &self.generation)
            .field("transient", &"[REDACTED]")
            .finish()
    }
}

/// Structural or authenticated observation rejection.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ObservationRejection {
    /// The service-data record is not structurally canonical.
    Malformed,
    /// The active credential set did not authenticate the record.
    InvalidProof,
    /// A replay token was reused with another header or locator.
    ReplayOrRelay,
}

/// Fixed reason that ended a scan window before its timer.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ScanStopReason {
    /// The 256-callback window budget was consumed.
    CallbackBudget,
    /// The 128-proof-attempt window budget was consumed.
    HmacBudget,
    /// The 32-new-token window budget was consumed.
    NewTokenBudget,
    /// All 256 replay slots remain live and may not be evicted.
    ReplayCapacity,
    /// The bounded platform callback queue overflowed.
    CallbackQueueOverflow,
}

/// Result of processing one scan observation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ObservationOutcome {
    /// A new proof-valid replay token updated bounded candidate state.
    Accepted,
    /// The exact already-bound observation was seen without refreshing it.
    Duplicate,
    /// The observation was rejected without candidate allocation.
    Rejected(ObservationRejection),
    /// A fixed budget was exhausted and the active window stopped.
    StopWindow(ScanStopReason),
    /// No active scan window owns this callback.
    NotScanning,
}

/// Current pure scan-policy state.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ScanState {
    /// A new window may start now.
    Ready,
    /// A ten-second active window owns callbacks.
    Active,
    /// The mandatory twenty-second idle interval is running.
    Idle,
    /// An authenticated contact suppresses scanning.
    Contact,
}

/// Result of requesting a new scan window.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ScanStartOutcome {
    /// A fresh bounded window started and its counters reset.
    Started,
    /// The current window is still active.
    AlreadyActive,
    /// The mandatory idle interval has not elapsed.
    Idle,
    /// An authenticated contact currently suppresses scanning.
    Contact,
}

/// Exact counters for the current or most recently stopped scan window.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct ScanWindowCounters {
    callbacks: u16,
    hmac_verifications: u16,
    accepted_tokens: u8,
}

impl ScanWindowCounters {
    /// Total callbacks structurally considered in this window.
    pub const fn callbacks(self) -> u16 {
        self.callbacks
    }

    /// Total bounded proof attempts in this window.
    pub const fn hmac_verifications(self) -> u16 {
        self.hmac_verifications
    }

    /// Newly bound proof-valid replay tokens in this window.
    pub const fn accepted_tokens(self) -> u8 {
        self.accepted_tokens
    }
}

/// Independently rate-limited expensive attempt category.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AttemptKind {
    /// Outbound LE CoC open.
    OutboundOpen,
    /// Inbound contact before mission authentication.
    InboundAccept,
    /// Mission handshake slot.
    MissionHandshake,
}

impl AttemptKind {
    const fn index(self) -> usize {
        match self {
            Self::OutboundOpen => 0,
            Self::InboundAccept => 1,
            Self::MissionHandshake => 2,
        }
    }
}

#[derive(Clone, Copy)]
struct ReplayEntry {
    generation: DiscoveryGeneration,
    nonce: [u8; 16],
    header: [u8; AUTHENTICATED_HEADER_BYTES],
    locator: CanonicalLocator,
    accepted_at: Instant,
}

struct ReplayCache {
    entries: [Option<ReplayEntry>; MAX_REPLAY_ENTRIES],
}

impl ReplayCache {
    const fn new() -> Self {
        Self {
            entries: [None; MAX_REPLAY_ENTRIES],
        }
    }

    fn binding(
        &mut self,
        generation: DiscoveryGeneration,
        nonce: [u8; 16],
        now: Instant,
    ) -> Option<ReplayEntry> {
        self.purge(now);
        self.entries
            .iter()
            .flatten()
            .copied()
            .find(|entry| entry.generation == generation && entry.nonce == nonce)
    }

    fn insert(&mut self, entry: ReplayEntry) -> bool {
        let Some(slot) = self.entries.iter_mut().find(|slot| slot.is_none()) else {
            return false;
        };
        *slot = Some(entry);
        true
    }

    fn len(&mut self, now: Instant) -> usize {
        self.purge(now);
        self.entries.iter().flatten().count()
    }

    fn purge(&mut self, now: Instant) {
        for slot in &mut self.entries {
            if slot.is_some_and(|entry| expired(now, entry.accepted_at, REPLAY_TTL)) {
                *slot = None;
            }
        }
    }
}

struct CandidateCache {
    entries: [Option<DiscoveryCandidate>; MAX_CANDIDATES],
}

impl CandidateCache {
    const fn new() -> Self {
        Self {
            entries: [None; MAX_CANDIDATES],
        }
    }

    fn insert(&mut self, candidate: DiscoveryCandidate, now: Instant) {
        self.purge(now);
        if let Some(slot) = self
            .entries
            .iter_mut()
            .find(|slot| slot.is_some_and(|current| current.locator == candidate.locator))
        {
            *slot = Some(candidate);
            return;
        }
        if let Some(slot) = self.entries.iter_mut().find(|slot| slot.is_none()) {
            *slot = Some(candidate);
            return;
        }
        let victim = self
            .entries
            .iter()
            .enumerate()
            .filter_map(|(index, candidate)| candidate.map(|candidate| (index, candidate)))
            .min_by_key(|(_, candidate)| (candidate.authenticated_at, candidate.locator))
            .map(|(index, _)| index)
            .expect("fixed candidate array is known full");
        self.entries[victim] = Some(candidate);
    }

    fn get(&mut self, locator: CanonicalLocator, now: Instant) -> Option<DiscoveryCandidate> {
        self.purge(now);
        self.entries
            .iter()
            .flatten()
            .copied()
            .find(|candidate| candidate.locator == locator)
    }

    fn selected(&mut self, negative: &NegativeCache, now: Instant) -> Option<DiscoveryCandidate> {
        self.purge(now);
        let mut selected: Option<DiscoveryCandidate> = None;
        for candidate in self.entries.iter().flatten().copied() {
            if negative.contains(candidate.locator, candidate.listener_psm) {
                continue;
            }
            selected = match selected {
                None => Some(candidate),
                Some(current)
                    if candidate.authenticated_at > current.authenticated_at
                        || (candidate.authenticated_at == current.authenticated_at
                            && candidate.locator < current.locator) =>
                {
                    Some(candidate)
                }
                Some(current) => Some(current),
            };
        }
        selected
    }

    fn remove(&mut self, candidate: DiscoveryCandidate) {
        if let Some(slot) = self
            .entries
            .iter_mut()
            .find(|slot| slot.is_some_and(|current| current == candidate))
        {
            *slot = None;
        }
    }

    fn len(&mut self, now: Instant) -> usize {
        self.purge(now);
        self.entries.iter().flatten().count()
    }

    fn purge(&mut self, now: Instant) {
        for slot in &mut self.entries {
            if slot.is_some_and(|candidate| {
                expired(now, candidate.authenticated_at, CANDIDATE_FRESHNESS)
            }) {
                *slot = None;
            }
        }
    }
}

#[derive(Clone, Copy)]
struct NegativeEntry {
    locator: CanonicalLocator,
    listener_psm: u16,
    inserted_at: Instant,
}

struct NegativeCache {
    entries: [Option<NegativeEntry>; MAX_NEGATIVE_ENTRIES],
}

impl NegativeCache {
    const fn new() -> Self {
        Self {
            entries: [None; MAX_NEGATIVE_ENTRIES],
        }
    }

    fn insert(&mut self, locator: CanonicalLocator, listener_psm: u16, now: Instant) {
        self.purge(now);
        let entry = NegativeEntry {
            locator,
            listener_psm,
            inserted_at: now,
        };
        if let Some(slot) = self.entries.iter_mut().find(|slot| {
            slot.is_some_and(|current| {
                current.locator == locator && current.listener_psm == listener_psm
            })
        }) {
            *slot = Some(entry);
            return;
        }
        if let Some(slot) = self.entries.iter_mut().find(|slot| slot.is_none()) {
            *slot = Some(entry);
            return;
        }
        let victim = self
            .entries
            .iter()
            .enumerate()
            .filter_map(|(index, entry)| entry.map(|entry| (index, entry)))
            .min_by_key(|(_, entry)| (entry.inserted_at, entry.locator, entry.listener_psm))
            .map(|(index, _)| index)
            .expect("fixed negative array is known full");
        self.entries[victim] = Some(entry);
    }

    fn contains(&self, locator: CanonicalLocator, listener_psm: u16) -> bool {
        self.entries
            .iter()
            .flatten()
            .any(|entry| entry.locator == locator && entry.listener_psm == listener_psm)
    }

    fn len(&mut self, now: Instant) -> usize {
        self.purge(now);
        self.entries.iter().flatten().count()
    }

    fn purge(&mut self, now: Instant) {
        for slot in &mut self.entries {
            if slot.is_some_and(|entry| expired(now, entry.inserted_at, NEGATIVE_CACHE_TTL)) {
                *slot = None;
            }
        }
    }
}

#[derive(Clone, Copy)]
enum ScanClock {
    Ready,
    Active { until: Instant },
    Idle { until: Instant },
    Contact,
}

struct ScanPolicy {
    clock: ScanClock,
    counters: ScanWindowCounters,
}

impl ScanPolicy {
    const fn new() -> Self {
        Self {
            clock: ScanClock::Ready,
            counters: ScanWindowCounters {
                callbacks: 0,
                hmac_verifications: 0,
                accepted_tokens: 0,
            },
        }
    }

    fn start(&mut self, now: Instant) -> ScanStartOutcome {
        self.normalize(now);
        match self.clock {
            ScanClock::Ready => {
                self.clock = ScanClock::Active {
                    until: now + SCAN_ACTIVE_INTERVAL,
                };
                self.counters = ScanWindowCounters::default();
                ScanStartOutcome::Started
            }
            ScanClock::Active { .. } => ScanStartOutcome::AlreadyActive,
            ScanClock::Idle { .. } => ScanStartOutcome::Idle,
            ScanClock::Contact => ScanStartOutcome::Contact,
        }
    }

    fn stop(&mut self, now: Instant) {
        if matches!(self.clock, ScanClock::Active { .. }) {
            self.clock = ScanClock::Idle {
                until: now + SCAN_IDLE_INTERVAL,
            };
        }
    }

    fn state(&self, now: Instant) -> ScanState {
        match self.clock {
            ScanClock::Ready => ScanState::Ready,
            ScanClock::Active { until } if now < until => ScanState::Active,
            ScanClock::Active { until } if now < until + SCAN_IDLE_INTERVAL => ScanState::Idle,
            ScanClock::Active { .. } => ScanState::Ready,
            ScanClock::Idle { until } if now < until => ScanState::Idle,
            ScanClock::Idle { .. } => ScanState::Ready,
            ScanClock::Contact => ScanState::Contact,
        }
    }

    fn enter_contact(&mut self) {
        self.clock = ScanClock::Contact;
    }

    fn contact_closed(&mut self, now: Instant) {
        if matches!(self.clock, ScanClock::Contact) {
            self.clock = ScanClock::Idle {
                until: now + SCAN_IDLE_INTERVAL,
            };
        }
    }

    fn count_callback(&mut self) -> bool {
        if self.counters.callbacks >= MAX_CALLBACKS_PER_WINDOW {
            return false;
        }
        self.counters.callbacks += 1;
        true
    }

    fn count_hmac(&mut self) -> bool {
        if self.counters.hmac_verifications >= MAX_HMACS_PER_WINDOW {
            return false;
        }
        self.counters.hmac_verifications += 1;
        true
    }

    fn count_new_token(&mut self) -> bool {
        if self.counters.accepted_tokens >= MAX_NEW_TOKENS_PER_WINDOW {
            return false;
        }
        self.counters.accepted_tokens += 1;
        true
    }

    fn normalize(&mut self, now: Instant) {
        self.clock = match self.clock {
            ScanClock::Active { until } if now >= until + SCAN_IDLE_INTERVAL => ScanClock::Ready,
            ScanClock::Active { until } if now >= until => ScanClock::Idle {
                until: until + SCAN_IDLE_INTERVAL,
            },
            ScanClock::Idle { until } if now >= until => ScanClock::Ready,
            state => state,
        };
    }
}

#[derive(Clone, Copy)]
struct TokenBucket {
    available: u8,
    last_refill: Option<Instant>,
}

impl TokenBucket {
    const fn new() -> Self {
        Self {
            available: ATTEMPT_BUCKET_CAPACITY,
            last_refill: None,
        }
    }

    fn consume(&mut self, now: Instant) -> bool {
        self.refill(now);
        if self.available == 0 {
            return false;
        }
        self.available -= 1;
        true
    }

    fn refill(&mut self, now: Instant) {
        let Some(last) = self.last_refill else {
            self.last_refill = Some(now);
            return;
        };
        let Some(elapsed) = now.checked_duration_since(last) else {
            return;
        };
        let intervals = elapsed.as_secs() / ATTEMPT_TOKEN_REFILL.as_secs();
        if intervals == 0 {
            return;
        }
        let added = u8::try_from(intervals).unwrap_or(u8::MAX);
        self.available = self
            .available
            .saturating_add(added)
            .min(ATTEMPT_BUCKET_CAPACITY);
        self.last_refill = last.checked_add(
            ATTEMPT_TOKEN_REFILL.saturating_mul(u32::try_from(intervals).unwrap_or(u32::MAX)),
        );
    }

    fn retry_at(&mut self, now: Instant) -> Instant {
        self.refill(now);
        if self.available > 0 {
            return now;
        }
        self.last_refill
            .and_then(|last| last.checked_add(ATTEMPT_TOKEN_REFILL))
            .unwrap_or(now)
    }
}

/// Fixed-capacity roster observation, replay, retry, and scan policy state.
pub struct DiscoveryAdmission {
    candidates: CandidateCache,
    replay: ReplayCache,
    negative: NegativeCache,
    scan: ScanPolicy,
    attempts: [TokenBucket; 3],
}

impl DiscoveryAdmission {
    /// Constructs empty state for one controller-availability epoch.
    pub const fn new() -> Self {
        Self {
            candidates: CandidateCache::new(),
            replay: ReplayCache::new(),
            negative: NegativeCache::new(),
            scan: ScanPolicy::new(),
            attempts: [TokenBucket::new(); 3],
        }
    }

    /// Starts a window only after the fixed idle policy permits it.
    pub fn start_scan(&mut self, now: Instant) -> ScanStartOutcome {
        self.scan.start(now)
    }

    /// Stops an owned window and starts the mandatory idle interval.
    pub fn stop_scan(&mut self, now: Instant) {
        self.scan.stop(now);
    }

    /// Ends the current window when the platform callback queue overflows.
    pub fn callback_queue_overflow(&mut self, now: Instant) -> ObservationOutcome {
        if self.scan_state(now) != ScanState::Active {
            return ObservationOutcome::NotScanning;
        }
        self.stop_with(ScanStopReason::CallbackQueueOverflow, now)
    }

    /// Suppresses scanning while an authenticated contact is active.
    pub fn enter_authenticated_contact(&mut self, _now: Instant) {
        self.scan.enter_contact();
    }

    /// Starts the full idle interval after an authenticated contact closes.
    pub fn contact_closed(&mut self, now: Instant) {
        self.scan.contact_closed(now);
    }

    /// Reports scan policy from injected monotonic time without sleeping.
    pub fn scan_state(&self, now: Instant) -> ScanState {
        self.scan.state(now)
    }

    /// Returns exact bounded counters for the current or last window.
    pub const fn window_counters(&self) -> ScanWindowCounters {
        self.scan.counters
    }

    /// Parses, authenticates, and admits one observation without growing state.
    pub fn observe(
        &mut self,
        locator: CanonicalLocator,
        record: &[u8],
        credentials: &LeasedDiscoveryCredentialSet,
        now: Instant,
    ) -> ObservationOutcome {
        if self.scan_state(now) != ScanState::Active {
            return ObservationOutcome::NotScanning;
        }
        if !self.scan.count_callback() {
            return self.stop_with(ScanStopReason::CallbackBudget, now);
        }

        let beacon = match AsterRosterBeaconV1::decode_structure(record) {
            Ok(beacon) => beacon,
            Err(_) => return ObservationOutcome::Rejected(ObservationRejection::Malformed),
        };
        if !self.scan.count_hmac() {
            return self.stop_with(ScanStopReason::HmacBudget, now);
        }
        let beacon = match beacon.verify(record, credentials, now) {
            Ok(beacon) => beacon,
            Err(
                DiscoveryRecordError::InvalidProof
                | DiscoveryRecordError::UnknownGeneration
                | DiscoveryRecordError::CredentialExpired,
            ) => return ObservationOutcome::Rejected(ObservationRejection::InvalidProof),
            Err(_) => return ObservationOutcome::Rejected(ObservationRejection::Malformed),
        };

        let token = (beacon.generation(), beacon.nonce());
        let header: [u8; AUTHENTICATED_HEADER_BYTES] = record[..AUTHENTICATED_HEADER_BYTES]
            .try_into()
            .expect("structural validation fixed the record length");
        if let Some(existing) = self.replay.binding(token.0, token.1, now) {
            return if existing.header == header && existing.locator == locator {
                ObservationOutcome::Duplicate
            } else {
                ObservationOutcome::Rejected(ObservationRejection::ReplayOrRelay)
            };
        }
        if self.scan.counters.accepted_tokens >= MAX_NEW_TOKENS_PER_WINDOW {
            return self.stop_with(ScanStopReason::NewTokenBudget, now);
        }
        let record: [u8; ASTER_ROSTER_BEACON_V1_BYTES] = record
            .try_into()
            .expect("structural validation fixed the record length");
        if !self.replay.insert(ReplayEntry {
            generation: token.0,
            nonce: token.1,
            header,
            locator,
            accepted_at: now,
        }) {
            return self.stop_with(ScanStopReason::ReplayCapacity, now);
        }
        let token_counted = self.scan.count_new_token();
        debug_assert!(token_counted);
        self.candidates.insert(
            DiscoveryCandidate {
                locator,
                listener_psm: beacon.listener_psm(),
                generation: token.0,
                nonce: token.1,
                record,
                authenticated_at: now,
            },
            now,
        );
        ObservationOutcome::Accepted
    }

    /// Returns the exact current candidate for a transient locator.
    pub fn candidate(
        &mut self,
        locator: CanonicalLocator,
        now: Instant,
    ) -> Option<DiscoveryCandidate> {
        self.candidates.get(locator, now)
    }

    /// Selects newest proof-valid non-negative candidate, then lowest locator.
    pub fn selected_candidate(&mut self, now: Instant) -> Option<DiscoveryCandidate> {
        self.negative.purge(now);
        self.candidates.selected(&self.negative, now)
    }

    /// Number of currently fresh retained candidates.
    pub fn candidate_count(&mut self, now: Instant) -> usize {
        self.candidates.len(now)
    }

    /// Number of currently live replay bindings.
    pub fn replay_count(&mut self, now: Instant) -> usize {
        self.replay.len(now)
    }

    /// Removes a failed current candidate and records its exact locator/PSM.
    pub fn invalidate_after_open_failure(&mut self, candidate: DiscoveryCandidate, now: Instant) {
        self.candidates.remove(candidate);
        self.negative
            .insert(candidate.locator, candidate.listener_psm, now);
    }

    /// Reports whether one exact locator/PSM is still in retry suppression.
    pub fn is_negative(
        &mut self,
        locator: CanonicalLocator,
        listener_psm: u16,
        now: Instant,
    ) -> bool {
        self.negative.purge(now);
        self.negative.contains(locator, listener_psm)
    }

    /// Number of live exact retry-suppression entries.
    pub fn negative_count(&mut self, now: Instant) -> usize {
        self.negative.len(now)
    }

    /// Consumes one token from an independent fixed-capacity attempt bucket.
    pub fn try_consume_attempt(&mut self, kind: AttemptKind, now: Instant) -> bool {
        self.attempts[kind.index()].consume(now)
    }

    /// Earliest time at which the attempt bucket can provide a token.
    pub fn attempt_retry_at(&mut self, kind: AttemptKind, now: Instant) -> Instant {
        self.attempts[kind.index()].retry_at(now)
    }

    /// Admits an inbound pre-authentication contact only for a recent locator.
    pub fn admit_inbound(&mut self, locator: CanonicalLocator, now: Instant) -> bool {
        if self.candidate(locator, now).is_none() {
            return false;
        }
        self.try_consume_attempt(AttemptKind::InboundAccept, now)
    }

    fn stop_with(&mut self, reason: ScanStopReason, now: Instant) -> ObservationOutcome {
        self.stop_scan(now);
        ObservationOutcome::StopWindow(reason)
    }
}

impl Default for DiscoveryAdmission {
    fn default() -> Self {
        Self::new()
    }
}

fn expired(now: Instant, inserted_at: Instant, ttl: Duration) -> bool {
    now.checked_duration_since(inserted_at)
        .is_some_and(|elapsed| elapsed >= ttl)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        AsterRosterBeaconV1, DiscoveryCredential, DiscoveryGeneration, DiscoverySecret,
        LeasedDiscoveryCredentialSet,
    };
    use bluer::{Address, AddressType};
    use std::time::{Duration, Instant};

    const SECRET: [u8; 32] = [0x42; 32];

    fn credentials(now: Instant) -> LeasedDiscoveryCredentialSet {
        LeasedDiscoveryCredentialSet::new(
            DiscoveryCredential::new(
                DiscoveryGeneration::new(7).unwrap(),
                DiscoverySecret::new(SECRET).unwrap(),
            ),
            None,
            now + Duration::from_secs(1_000),
        )
        .unwrap()
    }

    fn locator(index: u16) -> CanonicalLocator {
        let [high, low] = index.to_be_bytes();
        CanonicalLocator::new(
            Address::new([0x02, 0, 0, 0, high, low]),
            if index.is_multiple_of(2) {
                AddressType::LeRandom
            } else {
                AddressType::LePublic
            },
        )
        .unwrap()
    }

    fn nonce(index: u16) -> [u8; 16] {
        let mut nonce = [0_u8; 16];
        nonce[..2].copy_from_slice(&index.to_be_bytes());
        nonce
    }

    fn record(
        psm: u16,
        nonce_index: u16,
        credentials: &LeasedDiscoveryCredentialSet,
        now: Instant,
    ) -> [u8; 40] {
        AsterRosterBeaconV1::encode(psm, nonce(nonce_index), credentials, now).unwrap()
    }

    fn active_admission(now: Instant) -> DiscoveryAdmission {
        let mut admission = DiscoveryAdmission::new();
        assert_eq!(admission.start_scan(now), ScanStartOutcome::Started);
        admission
    }

    #[test]
    fn canonical_locator_accepts_only_exact_le_address_types() {
        assert!(CanonicalLocator::new(Address::new([1; 6]), AddressType::LePublic).is_ok());
        assert!(CanonicalLocator::new(Address::new([1; 6]), AddressType::LeRandom).is_ok());
        assert_eq!(
            CanonicalLocator::new(Address::new([1; 6]), AddressType::BrEdr),
            Err(CanonicalLocatorError::NonLeAddress)
        );
    }

    #[test]
    fn scan_window_enforces_callback_hmac_and_new_token_budgets() {
        let now = Instant::now();
        let credentials = credentials(now);

        let mut callbacks = active_admission(now);
        for _ in 0..MAX_CALLBACKS_PER_WINDOW {
            assert_eq!(
                callbacks.observe(locator(1), &[0], &credentials, now),
                ObservationOutcome::Rejected(ObservationRejection::Malformed)
            );
        }
        assert_eq!(
            callbacks.observe(locator(1), &[0], &credentials, now),
            ObservationOutcome::StopWindow(ScanStopReason::CallbackBudget)
        );
        assert_eq!(callbacks.window_counters().callbacks(), 256);
        assert_eq!(callbacks.window_counters().hmac_verifications(), 0);

        let mut hmac = active_admission(now);
        let mut invalid = record(0x0081, 1, &credentials, now);
        invalid[39] ^= 1;
        for _ in 0..MAX_HMACS_PER_WINDOW {
            assert_eq!(
                hmac.observe(locator(1), &invalid, &credentials, now),
                ObservationOutcome::Rejected(ObservationRejection::InvalidProof)
            );
        }
        assert_eq!(
            hmac.observe(locator(1), &invalid, &credentials, now),
            ObservationOutcome::StopWindow(ScanStopReason::HmacBudget)
        );
        assert_eq!(hmac.window_counters().callbacks(), 129);
        assert_eq!(hmac.window_counters().hmac_verifications(), 128);

        let mut tokens = active_admission(now);
        for index in 0..MAX_NEW_TOKENS_PER_WINDOW as u16 {
            assert_eq!(
                tokens.observe(
                    locator(index),
                    &record(0x0081, index, &credentials, now),
                    &credentials,
                    now,
                ),
                ObservationOutcome::Accepted
            );
        }
        assert_eq!(
            tokens.observe(
                locator(100),
                &record(0x0081, 100, &credentials, now),
                &credentials,
                now,
            ),
            ObservationOutcome::StopWindow(ScanStopReason::NewTokenBudget)
        );
        assert_eq!(tokens.window_counters().accepted_tokens(), 32);

        let mut queue = active_admission(now);
        assert_eq!(
            queue.callback_queue_overflow(now),
            ObservationOutcome::StopWindow(ScanStopReason::CallbackQueueOverflow)
        );
        assert_eq!(queue.scan_state(now), ScanState::Idle);
    }

    #[test]
    fn locator_supersession_and_replay_binding_do_not_refresh_duplicates() {
        let now = Instant::now();
        let credentials = credentials(now);
        let mut admission = active_admission(now);
        let first = record(0x0081, 1, &credentials, now);
        assert_eq!(
            admission.observe(locator(1), &first, &credentials, now),
            ObservationOutcome::Accepted
        );
        assert_eq!(
            admission.observe(
                locator(1),
                &first,
                &credentials,
                now + Duration::from_secs(1),
            ),
            ObservationOutcome::Duplicate
        );
        assert_eq!(
            admission.observe(locator(2), &first, &credentials, now),
            ObservationOutcome::Rejected(ObservationRejection::ReplayOrRelay)
        );
        let changed_header = record(0x0083, 1, &credentials, now);
        assert_eq!(
            admission.observe(locator(1), &changed_header, &credentials, now),
            ObservationOutcome::Rejected(ObservationRejection::ReplayOrRelay)
        );

        let replacement = record(0x0083, 2, &credentials, now);
        assert_eq!(
            admission.observe(locator(1), &replacement, &credentials, now),
            ObservationOutcome::Accepted
        );
        assert_eq!(admission.candidate_count(now), 1);
        let candidate = admission.candidate(locator(1), now).unwrap();
        assert_eq!(candidate.listener_psm(), 0x0083);
        assert_eq!(candidate.nonce(), nonce(2));
        assert_eq!(admission.replay_count(now), 2);

        let expired_at = now + CANDIDATE_FRESHNESS + Duration::from_secs(1);
        assert_eq!(admission.start_scan(expired_at), ScanStartOutcome::Started);
        assert_eq!(admission.candidate_count(expired_at), 0);
        assert_eq!(
            admission.observe(locator(1), &replacement, &credentials, expired_at,),
            ObservationOutcome::Duplicate
        );
        assert_eq!(admission.candidate_count(expired_at), 0);
    }

    #[test]
    fn replay_cache_full_fails_closed_without_evicting_live_entries() {
        let started = Instant::now();
        let credentials = credentials(started);
        let mut admission = DiscoveryAdmission::new();
        for window in 0..8_u16 {
            let now = started + Duration::from_secs(u64::from(window) * 21);
            assert_eq!(admission.start_scan(now), ScanStartOutcome::Started);
            for offset in 0..32_u16 {
                let index = window * 32 + offset;
                assert_eq!(
                    admission.observe(
                        locator(index),
                        &record(0x0081, index, &credentials, now),
                        &credentials,
                        now,
                    ),
                    ObservationOutcome::Accepted
                );
            }
            admission.stop_scan(now);
        }
        let now = started + Duration::from_secs(8 * 21);
        assert_eq!(admission.start_scan(now), ScanStartOutcome::Started);
        assert_eq!(admission.replay_count(now), MAX_REPLAY_ENTRIES);
        assert_eq!(
            admission.observe(
                locator(400),
                &record(0x0081, 400, &credentials, now),
                &credentials,
                now,
            ),
            ObservationOutcome::StopWindow(ScanStopReason::ReplayCapacity)
        );
        assert_eq!(admission.replay_count(now), MAX_REPLAY_ENTRIES);
    }

    #[test]
    fn candidate_selection_and_eviction_are_deterministic() {
        let now = Instant::now();
        let credentials = credentials(now);
        let mut admission = active_admission(now);
        for index in 0..MAX_CANDIDATES as u16 {
            assert_eq!(
                admission.observe(
                    locator(index),
                    &record(0x0081, index, &credentials, now),
                    &credentials,
                    now,
                ),
                ObservationOutcome::Accepted
            );
        }
        assert_eq!(
            admission.selected_candidate(now).unwrap().locator(),
            locator(0)
        );

        admission.stop_scan(now);
        let later = now + SCAN_IDLE_INTERVAL;
        assert_eq!(admission.start_scan(later), ScanStartOutcome::Started);
        assert_eq!(
            admission.observe(
                locator(50),
                &record(0x0081, 50, &credentials, later),
                &credentials,
                later,
            ),
            ObservationOutcome::Accepted
        );
        assert!(admission.candidate(locator(0), later).is_none());
        assert_eq!(admission.candidate_count(later), MAX_CANDIDATES);
        assert_eq!(
            admission.selected_candidate(later).unwrap().locator(),
            locator(50)
        );
    }

    #[test]
    fn negative_cache_is_exact_bounded_and_expires() {
        let now = Instant::now();
        let credentials = credentials(now);
        let mut admission = active_admission(now);
        for index in 0..MAX_NEGATIVE_ENTRIES as u16 {
            admission.observe(
                locator(index),
                &record(0x0081, index, &credentials, now),
                &credentials,
                now,
            );
            let candidate = admission.candidate(locator(index), now).unwrap();
            admission.invalidate_after_open_failure(candidate, now);
        }
        assert_eq!(admission.negative_count(now), MAX_NEGATIVE_ENTRIES);

        admission.stop_scan(now);
        let later = now + SCAN_IDLE_INTERVAL;
        admission.start_scan(later);
        admission.observe(
            locator(50),
            &record(0x0081, 50, &credentials, later),
            &credentials,
            later,
        );
        let candidate = admission.candidate(locator(50), later).unwrap();
        admission.invalidate_after_open_failure(candidate, later);
        assert!(!admission.is_negative(locator(0), 0x0081, later));
        assert!(admission.is_negative(locator(50), 0x0081, later));

        admission.observe(
            locator(50),
            &record(0x0083, 51, &credentials, later),
            &credentials,
            later,
        );
        assert_eq!(
            admission.selected_candidate(later).unwrap().listener_psm(),
            0x0083
        );
        assert!(!admission.is_negative(locator(50), 0x0081, later + NEGATIVE_CACHE_TTL));
    }

    #[test]
    fn attempt_token_buckets_are_separate_and_refill_monotonically() {
        let now = Instant::now();
        let mut admission = DiscoveryAdmission::new();
        for kind in [
            AttemptKind::OutboundOpen,
            AttemptKind::InboundAccept,
            AttemptKind::MissionHandshake,
        ] {
            for _ in 0..ATTEMPT_BUCKET_CAPACITY {
                assert!(admission.try_consume_attempt(kind, now));
            }
            assert!(!admission.try_consume_attempt(kind, now));
            assert_eq!(
                admission.attempt_retry_at(kind, now),
                now + ATTEMPT_TOKEN_REFILL
            );
            assert!(
                !admission.try_consume_attempt(
                    kind,
                    now + ATTEMPT_TOKEN_REFILL - Duration::from_nanos(1)
                )
            );
            assert!(admission.try_consume_attempt(kind, now + ATTEMPT_TOKEN_REFILL));
        }
    }

    #[test]
    fn scan_duty_cycle_and_contact_idle_are_enforced_without_sleeping() {
        let now = Instant::now();
        let mut admission = DiscoveryAdmission::new();
        assert_eq!(admission.start_scan(now), ScanStartOutcome::Started);
        assert_eq!(admission.scan_state(now), ScanState::Active);
        assert_eq!(
            admission.start_scan(now + SCAN_ACTIVE_INTERVAL),
            ScanStartOutcome::Idle
        );
        assert_eq!(
            admission.start_scan(now + SCAN_ACTIVE_INTERVAL + SCAN_IDLE_INTERVAL),
            ScanStartOutcome::Started
        );
        admission.enter_authenticated_contact(now + Duration::from_secs(31));
        assert_eq!(
            admission.scan_state(now + Duration::from_secs(31)),
            ScanState::Contact
        );
        admission.contact_closed(now + Duration::from_secs(35));
        assert_eq!(
            admission.start_scan(now + Duration::from_secs(54)),
            ScanStartOutcome::Idle
        );
        assert_eq!(
            admission.start_scan(now + Duration::from_secs(55)),
            ScanStartOutcome::Started
        );
    }

    #[test]
    fn inbound_admission_requires_a_recent_exact_locator_and_its_own_token() {
        let now = Instant::now();
        let credentials = credentials(now);
        let mut admission = active_admission(now);
        admission.observe(
            locator(1),
            &record(0x0081, 1, &credentials, now),
            &credentials,
            now,
        );
        assert!(!admission.admit_inbound(locator(2), now));
        for _ in 0..ATTEMPT_BUCKET_CAPACITY {
            assert!(admission.admit_inbound(locator(1), now));
        }
        assert!(!admission.admit_inbound(locator(1), now));
        assert!(!admission.admit_inbound(locator(1), now + CANDIDATE_FRESHNESS));
    }
}
