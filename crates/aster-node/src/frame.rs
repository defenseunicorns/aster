use aster_mesh::{
    BLOB_CUSTODY_CLAIM_V1_BYTES, BlobCustodyClaimV1, MAX_CUSTODY_WRAPPER_BYTES,
    MAX_SELECTED_BRIDGE_WRAPPER_BYTES, Priority, Scope, Topic,
};
use aster_negentropy::{MAX_CARDINALITY_LIMIT, MAX_FRAME_SIZE_LIMIT};
use aster_redb_store::{
    BlobTransferId, ControlTransferId, EventTransferId, RecordTransferId, StateTransferId,
};

use crate::NodeError;
use crate::event_pages::{
    ChangePageV7, ChangeTurnFinishedV1, ChangeTurnHeaderV1, EventTurnPlanV1, TransferProfileOfferV1,
};
use crate::stream_transfer::{STREAM_TAGS, StreamFrame};

const MAGIC: &[u8; 4] = b"ASM\x01";
pub(crate) const MECHANICS_FRAME_PREFIX_BYTES: usize = MAGIC.len() + 1;
const EVENT_INTEREST: u8 = 0x09;
const EVENT_INTEREST_REPLY: u8 = 0x0a;
const EVENT_INTEREST_REPLY_V3: u8 = 0x0b;
const EVENT_INTEREST_V3: u8 = 0x0c;
const INVENTORY_QUERY: u8 = 0x11;
const INVENTORY_REPLY: u8 = 0x12;
const INVENTORY_COMPLETE: u8 = 0x13;
const INVENTORY_COMPLETE_ACK: u8 = 0x14;
const DIFFERENCE_QUERY: u8 = 0x15;
const DIFFERENCE_REPLY: u8 = 0x16;
const DIFFERENCE_BOUND: u8 = 0x17;
const DIFFERENCE_BOUND_ACK: u8 = 0x18;
const EVENT_LANE_DEFERRED: u8 = 0x19;
const EVENT_LANE_DEFERRED_ACK: u8 = 0x1a;
const FETCH: u8 = 0x21;
const OBJECT: u8 = 0x22;
const OFFER: u8 = 0x23;
const APPLY_RESULT: u8 = 0x24;
const OFFER_V3: u8 = 0x25;
const APPLY_RESULT_V3: u8 = 0x26;
const FINISH: u8 = 0x31;
const FINISHED: u8 = 0x32;
const FINISH_V3: u8 = 0x33;
const FINISHED_V3: u8 = 0x34;
const CONTROL_INVENTORY_QUERY: u8 = 0x41;
const CONTROL_INVENTORY_REPLY: u8 = 0x42;
const CONTROL_INVENTORY_COMPLETE: u8 = 0x43;
const CONTROL_INVENTORY_COMPLETE_ACK: u8 = 0x44;
const CONTROL_DIFFERENCE_QUERY: u8 = 0x45;
const CONTROL_DIFFERENCE_REPLY: u8 = 0x46;
const CONTROL_DIFFERENCE_BOUND: u8 = 0x47;
const CONTROL_DIFFERENCE_BOUND_ACK: u8 = 0x48;
const CONTROL_INVENTORY_REPLY_V3: u8 = 0x49;
const CONTROL_FETCH: u8 = 0x51;
const CONTROL_OBJECT: u8 = 0x52;
const CONTROL_OFFER: u8 = 0x53;
const CONTROL_APPLY_RESULT: u8 = 0x54;
const CONTROL_FINISH: u8 = 0x61;
const CONTROL_FINISHED: u8 = 0x62;
const MUTABLE_INTEREST: u8 = 0x69;
const MUTABLE_INTEREST_REPLY: u8 = 0x6a;
const BLOB_INTEREST: u8 = 0x6b;
const BLOB_INTEREST_REPLY: u8 = 0x6c;
const MUTABLE_INVENTORY_QUERY: u8 = 0x71;
const MUTABLE_INVENTORY_REPLY: u8 = 0x72;
const MUTABLE_INVENTORY_COMPLETE: u8 = 0x73;
const MUTABLE_INVENTORY_COMPLETE_ACK: u8 = 0x74;
const MUTABLE_DIFFERENCE_QUERY: u8 = 0x75;
const MUTABLE_DIFFERENCE_REPLY: u8 = 0x76;
const MUTABLE_DIFFERENCE_BOUND: u8 = 0x77;
const MUTABLE_DIFFERENCE_BOUND_ACK: u8 = 0x78;
const MUTABLE_LANE_DEFERRED: u8 = 0x79;
const MUTABLE_LANE_DEFERRED_ACK: u8 = 0x7a;
const MUTABLE_FETCH: u8 = 0x81;
const MUTABLE_OBJECT: u8 = 0x82;
const MUTABLE_OFFER: u8 = 0x83;
const MUTABLE_APPLY_RESULT: u8 = 0x84;
const MUTABLE_FETCH_RESULT: u8 = 0x85;
const MUTABLE_FETCH_RESULT_ACK: u8 = 0x86;
const MUTABLE_FINISH: u8 = 0x91;
const MUTABLE_FINISHED: u8 = 0x92;
const BLOB_RANGE_FETCH: u8 = 0xa1;
const BLOB_RANGE: u8 = 0xa2;
const BLOB_RANGE_RESULT: u8 = 0xa5;
const BLOB_RANGE_RESULT_ACK: u8 = 0xa6;
const BLOB_CARRIER_FINISH: u8 = 0xb1;
const BLOB_CARRIER_FINISHED: u8 = 0xb2;
const BRIDGE_HELLO: u8 = 0xc1;
const BRIDGE_HELLO_ACK: u8 = 0xc2;
const BRIDGE_ROUTE_OFFER: u8 = 0xc3;
const BRIDGE_ROUTE_RESULT: u8 = 0xc4;
const BRIDGE_FINISH: u8 = 0xc5;
const BRIDGE_FINISHED: u8 = 0xc6;
const TRANSFER_PROFILE_OFFER_V1: u8 = 0xd1;
const EVENT_TURN_PLAN_V1: u8 = 0xd2;
const CHANGE_TURN_HEADER_V1: u8 = 0xd3;
const CHANGE_PAGE_V7: u8 = 0xd4;
const CHANGE_TURN_FINISHED_V1: u8 = 0xd5;
const BLOB_STREAM_PLAN_V1: u8 = 0xe1;
const BLOB_STREAM_PLAN_ACK_V1: u8 = 0xe2;
pub(crate) const MAX_OBJECT_BYTES: usize = 1024 * 1024;
pub(crate) const MAX_BLOB_RANGE_BYTES: usize = 16 * 1024;
pub(crate) const BLOB_CONTENT_PROOF_BYTES: usize = 32;
pub(crate) const BLOB_CUSTODY_CLAIM_FIELD_MAX_BYTES: usize = 1 + 2 + BLOB_CUSTODY_CLAIM_V1_BYTES;
pub(crate) const BLOB_CUSTODY_DIGEST_FIELD_MAX_BYTES: usize = 1 + 32;
pub(crate) const MAX_EVENT_INTEREST_SELECTORS: usize = 256;
const MAX_EVENT_NAME_BYTES: usize = 128;
pub(crate) const MAX_EVENT_INTEREST_BYTES: usize =
    2 + MAX_EVENT_INTEREST_SELECTORS * (2 + MAX_EVENT_NAME_BYTES + 2 + MAX_EVENT_NAME_BYTES + 1);
pub(crate) const MAX_BLOB_INTEREST_BYTES: usize = 2 + MAX_EVENT_INTEREST_SELECTORS
    * (2 + MAX_EVENT_NAME_BYTES + 2 + MAX_EVENT_NAME_BYTES + 8 + BLOB_CONTENT_PROOF_BYTES);

/// Receiver of Events selected by one directional reconciliation lane.
///
/// The role is stable for the complete authenticated contact; it is never
/// interpreted relative to the endpoint currently encoding a frame.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub(crate) enum EventDirection {
    ToSessionInitiator,
    ToSessionResponder,
}

/// Bounded operator emission state disclosed only as a protected v3 response.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum FrameEmissionPolicy {
    Normal,
    AtLeast(Priority),
    ReceiveOnly,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct BlobStreamSourceOfferV1 {
    pub transfer_id: [u8; 32],
    pub topic: Topic,
    pub scope: Scope,
    pub key_epoch: u64,
    pub content_proof: [u8; BLOB_CONTENT_PROOF_BYTES],
    pub source_len: u32,
    pub source_digest: [u8; 32],
    pub finite: bool,
}

/// Receiver-relative result for one authenticated semantic-v3 Event offer.
///
/// This reports whether the exact bytes satisfied the receiver's requested
/// durability level. `Satisfied` preserves ambiguity between Carry retention
/// and Consume acceptance. `ContentAcceptancePending` deliberately reveals,
/// only for this offered object, that stronger acceptance was required but
/// unavailable; it discloses neither the selector set nor unrelated inventory.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum EventApplyDisposition {
    Satisfied,
    ContentAcceptancePending,
}

impl EventApplyDisposition {
    const fn encode(self) -> u8 {
        match self {
            Self::Satisfied => 1,
            Self::ContentAcceptancePending => 2,
        }
    }

    fn decode(value: u8) -> Result<Self, NodeError> {
        match value {
            1 => Ok(Self::Satisfied),
            2 => Ok(Self::ContentAcceptancePending),
            _ => Err(NodeError::Protocol(
                "v3 Event apply disposition is unknown".into(),
            )),
        }
    }
}

impl FrameEmissionPolicy {
    const fn encode(self) -> u8 {
        match self {
            Self::Normal => 0,
            Self::AtLeast(Priority::Routine) => 1,
            Self::AtLeast(Priority::Priority) => 2,
            Self::AtLeast(Priority::Immediate) => 3,
            Self::AtLeast(Priority::Flash) => 4,
            Self::ReceiveOnly => 5,
        }
    }

    fn decode(value: u8) -> Result<Self, NodeError> {
        match value {
            0 => Ok(Self::Normal),
            1 => Ok(Self::AtLeast(Priority::Routine)),
            2 => Ok(Self::AtLeast(Priority::Priority)),
            3 => Ok(Self::AtLeast(Priority::Immediate)),
            4 => Ok(Self::AtLeast(Priority::Flash)),
            5 => Ok(Self::ReceiveOnly),
            _ => Err(NodeError::Protocol(
                "protected emission policy is unknown".into(),
            )),
        }
    }
}

impl EventDirection {
    const fn encode(self) -> u8 {
        match self {
            Self::ToSessionInitiator => 1,
            Self::ToSessionResponder => 2,
        }
    }

    fn decode(value: u8) -> Result<Self, NodeError> {
        match value {
            1 => Ok(Self::ToSessionInitiator),
            2 => Ok(Self::ToSessionResponder),
            _ => Err(NodeError::Protocol(
                "Event direction is unknown or missing".into(),
            )),
        }
    }
}

/// Receiver-local outcome for one fully authenticated semantic-v6 bridge route.
///
/// Authentication and policy failures remain fatal and therefore never acquire
/// a wire disposition.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum BridgeRouteDisposition {
    Duplicate,
    Promoted,
    StoredInactive,
    NotSelected,
}

impl BridgeRouteDisposition {
    const fn encode(self) -> u8 {
        match self {
            Self::Duplicate => 0,
            Self::Promoted => 1,
            Self::StoredInactive => 2,
            Self::NotSelected => 3,
        }
    }

    fn decode(value: u8) -> Result<Self, NodeError> {
        match value {
            0 => Ok(Self::Duplicate),
            1 => Ok(Self::Promoted),
            2 => Ok(Self::StoredInactive),
            3 => Ok(Self::NotSelected),
            _ => Err(NodeError::Protocol(
                "bridge route disposition is unknown".into(),
            )),
        }
    }
}

/// Mutable source-object class carried by one class-specific lane.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub(crate) enum MutableClass {
    State,
    Record,
    Blob,
}

impl MutableClass {
    const fn encode(self) -> u8 {
        match self {
            Self::State => 1,
            Self::Record => 2,
            Self::Blob => 3,
        }
    }

    fn decode(value: u8) -> Result<Self, NodeError> {
        match value {
            1 => Ok(Self::State),
            2 => Ok(Self::Record),
            3 => Ok(Self::Blob),
            _ => Err(NodeError::Protocol(
                "mutable source-object class is unknown or missing".into(),
            )),
        }
    }
}

/// Receiver-local outcome for one fully verified mutable source object.
///
/// Capacity deferral is distinct from a duplicate: the authenticated object
/// remains outstanding for a later lane, while integrity and policy failures
/// remain fatal and never acquire a wire disposition.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum MutableApplyDisposition {
    Duplicate,
    Inserted,
    DeferredCapacity,
}

impl MutableApplyDisposition {
    const fn encode(self) -> u8 {
        match self {
            Self::Duplicate => 0,
            Self::Inserted => 1,
            Self::DeferredCapacity => 2,
        }
    }

    fn decode(value: u8) -> Result<Self, NodeError> {
        match value {
            0 => Ok(Self::Duplicate),
            1 => Ok(Self::Inserted),
            2 => Ok(Self::DeferredCapacity),
            _ => Err(NodeError::Protocol(
                "mutable apply disposition is unknown".into(),
            )),
        }
    }
}

/// Typed exact transfer identity used only inside a matching mutable lane.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub(crate) enum MutableTransferId {
    State(StateTransferId),
    Record(RecordTransferId),
    Blob(BlobTransferId),
}

impl MutableTransferId {
    pub(crate) const fn class(self) -> MutableClass {
        match self {
            Self::State(_) => MutableClass::State,
            Self::Record(_) => MutableClass::Record,
            Self::Blob(_) => MutableClass::Blob,
        }
    }

    pub(crate) const fn as_bytes(&self) -> &[u8; 32] {
        match self {
            Self::State(id) => id.as_bytes(),
            Self::Record(id) => id.as_bytes(),
            Self::Blob(id) => id.as_bytes(),
        }
    }
}

/// Exact typed identity of one canonical encrypted Blob chunk carrier.
///
/// The fixed representation is the protocol `ObjectId` wire form
/// `BlobChunk(2):u8 || digest:32`. No other object kind is accepted here.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub(crate) struct BlobObjectId([u8; 33]);

impl BlobObjectId {
    const BLOB_CHUNK_KIND: u8 = 2;

    pub(crate) fn new(digest: [u8; 32]) -> Self {
        let mut bytes = [0u8; 33];
        bytes[0] = Self::BLOB_CHUNK_KIND;
        bytes[1..].copy_from_slice(&digest);
        Self(bytes)
    }

    pub(crate) const fn as_bytes(&self) -> &[u8; 33] {
        &self.0
    }

    fn decode(bytes: &[u8]) -> Result<Self, NodeError> {
        if bytes.len() != 33 || bytes[0] != Self::BLOB_CHUNK_KIND {
            return Err(NodeError::Protocol(
                "Blob carrier object identifier differs".into(),
            ));
        }
        let mut object = [0u8; 33];
        object.copy_from_slice(bytes);
        Ok(Self(object))
    }
}

/// Sender outcome for one exact Blob carrier range request.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum BlobRangeDisposition {
    Data,
    Unavailable,
}

impl BlobRangeDisposition {
    const fn encode(self) -> u8 {
        match self {
            Self::Data => 1,
            Self::Unavailable => 2,
        }
    }

    fn decode(value: u8) -> Result<Self, NodeError> {
        match value {
            1 => Ok(Self::Data),
            2 => Ok(Self::Unavailable),
            _ => Err(NodeError::Protocol(
                "Blob range disposition is unknown".into(),
            )),
        }
    }
}

/// Receiver outcome for one exact Blob carrier range response.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum BlobRangeApplyDisposition {
    Partial,
    Complete,
    Duplicate,
    DeferredCapacity,
    Unavailable,
}

impl BlobRangeApplyDisposition {
    const fn encode(self) -> u8 {
        match self {
            Self::Partial => 1,
            Self::Complete => 2,
            Self::Duplicate => 3,
            Self::DeferredCapacity => 4,
            Self::Unavailable => 5,
        }
    }

    fn decode(value: u8) -> Result<Self, NodeError> {
        match value {
            1 => Ok(Self::Partial),
            2 => Ok(Self::Complete),
            3 => Ok(Self::Duplicate),
            4 => Ok(Self::DeferredCapacity),
            5 => Ok(Self::Unavailable),
            _ => Err(NodeError::Protocol(
                "Blob range apply disposition is unknown".into(),
            )),
        }
    }
}

/// One exact topic/scope pair requested for Event replication.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub(crate) struct EventInterestSelector {
    topic: Topic,
    scope: Scope,
    include_descendant_scopes: bool,
}

impl EventInterestSelector {
    pub(crate) const fn new(topic: Topic, scope: Scope, include_descendant_scopes: bool) -> Self {
        Self {
            topic,
            scope,
            include_descendant_scopes,
        }
    }

    pub(crate) const fn topic(&self) -> &Topic {
        &self.topic
    }

    pub(crate) const fn scope(&self) -> &Scope {
        &self.scope
    }

    pub(crate) const fn include_descendant_scopes(&self) -> bool {
        self.include_descendant_scopes
    }

    pub(crate) fn matches(&self, topic: &Topic, scope: &Scope) -> bool {
        &self.topic == topic
            && if self.include_descendant_scopes {
                self.scope.contains(scope)
            } else {
                &self.scope == scope
            }
    }
}

/// Canonical bounded receive interest authenticated inside one mission session.
///
/// An empty interest is valid and means receive no Events. This value can only
/// narrow the provider's independent scope/epoch route authorization.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub(crate) struct EventInterest(Vec<EventInterestSelector>);

impl EventInterest {
    pub(crate) fn new(mut selectors: Vec<EventInterestSelector>) -> Result<Self, NodeError> {
        if selectors.len() > MAX_EVENT_INTEREST_SELECTORS {
            return Err(NodeError::Protocol(format!(
                "Event interest selector count exceeds {MAX_EVENT_INTEREST_SELECTORS}"
            )));
        }
        selectors.sort_unstable();
        selectors.dedup();
        Ok(Self(selectors))
    }

    pub(crate) const fn empty() -> Self {
        Self(Vec::new())
    }

    pub(crate) fn selectors(&self) -> &[EventInterestSelector] {
        &self.0
    }

    pub(crate) fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    pub(crate) fn len(&self) -> usize {
        self.0.len()
    }

    pub(crate) fn matches(&self, topic: &Topic, scope: &Scope) -> bool {
        self.0.iter().any(|selector| selector.matches(topic, scope))
    }
}

/// One exact content-key entitlement offered for protected Blob replication.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub(crate) struct BlobInterestSelector {
    topic: Topic,
    scope: Scope,
    epoch: u64,
    content_proof: [u8; BLOB_CONTENT_PROOF_BYTES],
}

impl BlobInterestSelector {
    pub(crate) const fn new(
        topic: Topic,
        scope: Scope,
        epoch: u64,
        content_proof: [u8; BLOB_CONTENT_PROOF_BYTES],
    ) -> Self {
        Self {
            topic,
            scope,
            epoch,
            content_proof,
        }
    }

    pub(crate) const fn topic(&self) -> &Topic {
        &self.topic
    }

    pub(crate) const fn scope(&self) -> &Scope {
        &self.scope
    }

    pub(crate) const fn epoch(&self) -> u64 {
        self.epoch
    }

    pub(crate) const fn content_proof(&self) -> &[u8; BLOB_CONTENT_PROOF_BYTES] {
        &self.content_proof
    }
}

/// Canonical protected v5 Blob interest with exact topic/scope selectors.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub(crate) struct BlobInterest(Vec<BlobInterestSelector>);

impl BlobInterest {
    pub(crate) fn new(mut selectors: Vec<BlobInterestSelector>) -> Result<Self, NodeError> {
        if selectors.len() > MAX_EVENT_INTEREST_SELECTORS {
            return Err(NodeError::Protocol(format!(
                "Blob interest selector count exceeds {MAX_EVENT_INTEREST_SELECTORS}"
            )));
        }
        selectors.sort_unstable();
        selectors.dedup();
        if selectors
            .windows(2)
            .any(|pair| pair[0].topic() == pair[1].topic() && pair[0].scope() == pair[1].scope())
        {
            return Err(NodeError::Protocol(
                "Blob interest repeats an exact topic/scope selector".into(),
            ));
        }
        Ok(Self(selectors))
    }

    pub(crate) const fn empty() -> Self {
        Self(Vec::new())
    }

    pub(crate) fn selectors(&self) -> &[BlobInterestSelector] {
        &self.0
    }

    pub(crate) fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    pub(crate) fn len(&self) -> usize {
        self.0.len()
    }

    pub(crate) fn selector(&self, topic: &Topic, scope: &Scope) -> Option<&BlobInterestSelector> {
        self.0
            .iter()
            .find(|selector| selector.topic() == topic && selector.scope() == scope)
    }
}

#[derive(Debug, Eq, PartialEq)]
pub(crate) enum Frame {
    EventInterest(EventInterest),
    EventInterestV3 {
        interest: EventInterest,
        selector_revision: u64,
        policy: FrameEmissionPolicy,
        policy_revision: u64,
    },
    EventInterestReply(EventInterest),
    EventInterestReplyV3 {
        interest: EventInterest,
        selector_revision: u64,
        policy: FrameEmissionPolicy,
        policy_revision: u64,
    },
    BlobInterest(BlobInterest),
    BlobInterestReply(BlobInterest),
    InventoryQuery {
        direction: EventDirection,
        bytes: Vec<u8>,
    },
    InventoryReply {
        direction: EventDirection,
        bytes: Vec<u8>,
    },
    InventoryComplete {
        direction: EventDirection,
    },
    InventoryCompleteAck {
        direction: EventDirection,
    },
    DifferenceQuery {
        direction: EventDirection,
        bytes: Vec<u8>,
    },
    DifferenceReply {
        direction: EventDirection,
        bytes: Vec<u8>,
    },
    DifferenceBound {
        direction: EventDirection,
    },
    DifferenceBoundAck {
        direction: EventDirection,
    },
    EventLaneDeferred {
        direction: EventDirection,
    },
    EventLaneDeferredAck {
        direction: EventDirection,
    },
    Fetch {
        direction: EventDirection,
        id: EventTransferId,
    },
    Object {
        direction: EventDirection,
        id: EventTransferId,
        bytes: Vec<u8>,
    },
    Offer {
        direction: EventDirection,
        id: EventTransferId,
        bytes: Vec<u8>,
    },
    OfferV3 {
        direction: EventDirection,
        id: EventTransferId,
        exchange_id: u64,
        custody: Vec<u8>,
        bytes: Vec<u8>,
    },
    ApplyResult {
        direction: EventDirection,
        id: EventTransferId,
        inserted: bool,
    },
    ApplyResultV3 {
        direction: EventDirection,
        id: EventTransferId,
        exchange_id: u64,
        inserted: bool,
        disposition: EventApplyDisposition,
    },
    ControlInventoryQuery(Vec<u8>),
    ControlInventoryReply(Vec<u8>),
    ControlInventoryReplyV3 {
        bytes: Vec<u8>,
        policy: FrameEmissionPolicy,
        policy_revision: u64,
    },
    ControlInventoryComplete,
    ControlInventoryCompleteAck,
    ControlDifferenceQuery(Vec<u8>),
    ControlDifferenceReply(Vec<u8>),
    ControlDifferenceBound,
    ControlDifferenceBoundAck,
    ControlFetch(ControlTransferId),
    ControlObject {
        id: ControlTransferId,
        bytes: Vec<u8>,
    },
    ControlOffer {
        id: ControlTransferId,
        bytes: Vec<u8>,
    },
    ControlApplyResult {
        id: ControlTransferId,
        retained: bool,
    },
    ControlFinish,
    ControlFinished,
    Finish {
        direction: EventDirection,
    },
    Finished {
        direction: EventDirection,
    },
    FinishV3 {
        direction: EventDirection,
        remaining: u64,
    },
    FinishedV3 {
        direction: EventDirection,
        remaining: u64,
    },
    MutableInterest {
        class: MutableClass,
        interest: EventInterest,
    },
    MutableInterestReply {
        class: MutableClass,
        interest: EventInterest,
    },
    MutableInventoryQuery {
        class: MutableClass,
        direction: EventDirection,
        bytes: Vec<u8>,
    },
    MutableInventoryReply {
        class: MutableClass,
        direction: EventDirection,
        bytes: Vec<u8>,
    },
    MutableInventoryComplete {
        class: MutableClass,
        direction: EventDirection,
    },
    MutableInventoryCompleteAck {
        class: MutableClass,
        direction: EventDirection,
    },
    MutableDifferenceQuery {
        class: MutableClass,
        direction: EventDirection,
        bytes: Vec<u8>,
    },
    MutableDifferenceReply {
        class: MutableClass,
        direction: EventDirection,
        bytes: Vec<u8>,
    },
    MutableDifferenceBound {
        class: MutableClass,
        direction: EventDirection,
    },
    MutableDifferenceBoundAck {
        class: MutableClass,
        direction: EventDirection,
    },
    MutableLaneDeferred {
        class: MutableClass,
        direction: EventDirection,
    },
    MutableLaneDeferredAck {
        class: MutableClass,
        direction: EventDirection,
    },
    MutableFetch {
        direction: EventDirection,
        id: MutableTransferId,
    },
    MutableObject {
        direction: EventDirection,
        id: MutableTransferId,
        bytes: Vec<u8>,
        claim: Option<BlobCustodyClaimV1>,
    },
    MutableOffer {
        direction: EventDirection,
        id: MutableTransferId,
        bytes: Vec<u8>,
        claim: Option<BlobCustodyClaimV1>,
    },
    MutableApplyResult {
        direction: EventDirection,
        id: MutableTransferId,
        disposition: MutableApplyDisposition,
        custody_digest: Option<[u8; 32]>,
    },
    MutableFetchResult {
        direction: EventDirection,
        id: MutableTransferId,
        disposition: MutableApplyDisposition,
        custody_digest: Option<[u8; 32]>,
    },
    MutableFetchResultAck {
        direction: EventDirection,
        id: MutableTransferId,
        disposition: MutableApplyDisposition,
        custody_digest: Option<[u8; 32]>,
    },
    MutableFinish {
        class: MutableClass,
        direction: EventDirection,
        remaining: u64,
    },
    MutableFinished {
        class: MutableClass,
        direction: EventDirection,
        remaining: u64,
    },
    BlobRangeFetch {
        direction: EventDirection,
        source_id: BlobTransferId,
        object_id: BlobObjectId,
        total_len: u64,
        offset: u64,
        requested_len: u32,
        content_proof: [u8; BLOB_CONTENT_PROOF_BYTES],
    },
    BlobRange {
        direction: EventDirection,
        source_id: BlobTransferId,
        object_id: BlobObjectId,
        total_len: u64,
        offset: u64,
        requested_len: u32,
        disposition: BlobRangeDisposition,
        bytes: Vec<u8>,
    },
    BlobRangeResult {
        direction: EventDirection,
        source_id: BlobTransferId,
        object_id: BlobObjectId,
        total_len: u64,
        offset: u64,
        accepted_len: u32,
        disposition: BlobRangeApplyDisposition,
    },
    BlobRangeResultAck {
        direction: EventDirection,
        source_id: BlobTransferId,
        object_id: BlobObjectId,
        total_len: u64,
        offset: u64,
        accepted_len: u32,
        disposition: BlobRangeApplyDisposition,
    },
    BlobCarrierFinish {
        direction: EventDirection,
        remaining: u64,
    },
    BlobCarrierFinished {
        direction: EventDirection,
        remaining: u64,
    },
    /// Negotiates the semantic-v6 bridge lane without disclosing route state.
    BridgeHello {
        enabled: bool,
    },
    /// Confirms whether the responder has enabled the semantic-v6 bridge lane.
    BridgeHelloAck {
        enabled: bool,
    },
    /// Offers one exact bridge wrapper/source pair for fresh receiver verification.
    BridgeRouteOffer {
        wrapper_id: [u8; 32],
        wrapper: Vec<u8>,
        source: Vec<u8>,
    },
    /// Reports the durable receiver-local result for one verified bridge route.
    BridgeRouteResult {
        wrapper_id: [u8; 32],
        disposition: BridgeRouteDisposition,
    },
    /// Completes one bounded semantic-v6 bridge lane.
    BridgeFinish {
        remaining: u64,
    },
    /// Acknowledges completion of one bounded semantic-v6 bridge lane.
    BridgeFinished {
        remaining: u64,
    },
    TransferProfileOffer(TransferProfileOfferV1),
    EventTurnPlan(EventTurnPlanV1),
    ChangeTurnHeader(ChangeTurnHeaderV1),
    ChangePage(ChangePageV7),
    ChangeTurnFinished(ChangeTurnFinishedV1),
    /// Announces whether one direction will open a profile-5 transport
    /// attempt. A present nonce bootstraps the attempt-bound record context.
    BlobStreamPlan {
        direction: EventDirection,
        attempt_nonce: Option<[u8; 32]>,
        source: Option<BlobStreamSourceOfferV1>,
    },
    BlobStreamPlanAck {
        direction: EventDirection,
        attempt_nonce: Option<[u8; 32]>,
    },
    #[allow(dead_code)] // Activated by the profile-5 runtime driver.
    Stream(StreamFrame),
}

impl Frame {
    pub(crate) const fn serves_application_or_control_object(&self) -> bool {
        matches!(
            self,
            Self::Object { .. }
                | Self::Offer { .. }
                | Self::OfferV3 { .. }
                | Self::ControlObject { .. }
                | Self::ControlOffer { .. }
                | Self::MutableObject { .. }
                | Self::MutableOffer { .. }
                | Self::BlobRange { .. }
                | Self::BridgeRouteOffer { .. }
        )
    }

    pub(crate) fn encode(&self) -> Result<Vec<u8>, NodeError> {
        self.encode_with_v8_blob_fields(false)
    }

    fn encode_with_v8_blob_fields(
        &self,
        include_v8_blob_fields: bool,
    ) -> Result<Vec<u8>, NodeError> {
        let mut output = Vec::new();
        output.extend_from_slice(MAGIC);
        match self {
            Self::EventInterest(interest) => {
                output.push(EVENT_INTEREST);
                encode_event_interest(&mut output, interest)?;
            }
            Self::EventInterestV3 {
                interest,
                selector_revision,
                policy,
                policy_revision,
            } => {
                require_selector_revision(interest, *selector_revision)?;
                output.push(EVENT_INTEREST_V3);
                output.push(policy.encode());
                output.extend_from_slice(&policy_revision.to_be_bytes());
                output.extend_from_slice(&selector_revision.to_be_bytes());
                encode_event_interest(&mut output, interest)?;
            }
            Self::EventInterestReply(interest) => {
                output.push(EVENT_INTEREST_REPLY);
                encode_event_interest(&mut output, interest)?;
            }
            Self::EventInterestReplyV3 {
                interest,
                selector_revision,
                policy,
                policy_revision,
            } => {
                require_selector_revision(interest, *selector_revision)?;
                output.push(EVENT_INTEREST_REPLY_V3);
                output.push(policy.encode());
                output.extend_from_slice(&policy_revision.to_be_bytes());
                output.extend_from_slice(&selector_revision.to_be_bytes());
                encode_event_interest(&mut output, interest)?;
            }
            Self::BlobInterest(interest) => {
                output.push(BLOB_INTEREST);
                encode_blob_interest(&mut output, interest)?;
            }
            Self::BlobInterestReply(interest) => {
                output.push(BLOB_INTEREST_REPLY);
                encode_blob_interest(&mut output, interest)?;
            }
            Self::InventoryQuery { direction, bytes } => {
                output.push(INVENTORY_QUERY);
                output.push(direction.encode());
                encode_bytes(&mut output, bytes, MAX_FRAME_SIZE_LIMIT, "inventory query")?;
            }
            Self::InventoryReply { direction, bytes } => {
                output.push(INVENTORY_REPLY);
                output.push(direction.encode());
                encode_bytes(&mut output, bytes, MAX_FRAME_SIZE_LIMIT, "inventory reply")?;
            }
            Self::InventoryComplete { direction } => {
                output.push(INVENTORY_COMPLETE);
                output.push(direction.encode());
            }
            Self::InventoryCompleteAck { direction } => {
                output.push(INVENTORY_COMPLETE_ACK);
                output.push(direction.encode());
            }
            Self::DifferenceQuery { direction, bytes } => {
                output.push(DIFFERENCE_QUERY);
                output.push(direction.encode());
                encode_bytes(&mut output, bytes, MAX_FRAME_SIZE_LIMIT, "difference query")?;
            }
            Self::DifferenceReply { direction, bytes } => {
                output.push(DIFFERENCE_REPLY);
                output.push(direction.encode());
                encode_bytes(&mut output, bytes, MAX_FRAME_SIZE_LIMIT, "difference reply")?;
            }
            Self::DifferenceBound { direction } => {
                output.push(DIFFERENCE_BOUND);
                output.push(direction.encode());
            }
            Self::DifferenceBoundAck { direction } => {
                output.push(DIFFERENCE_BOUND_ACK);
                output.push(direction.encode());
            }
            Self::EventLaneDeferred { direction } => {
                output.push(EVENT_LANE_DEFERRED);
                output.push(direction.encode());
            }
            Self::EventLaneDeferredAck { direction } => {
                output.push(EVENT_LANE_DEFERRED_ACK);
                output.push(direction.encode());
            }
            Self::Fetch { direction, id } => {
                output.push(FETCH);
                output.push(direction.encode());
                output.extend_from_slice(id.as_bytes());
            }
            Self::Object {
                direction,
                id,
                bytes,
            } => {
                output.push(OBJECT);
                output.push(direction.encode());
                output.extend_from_slice(id.as_bytes());
                encode_bytes(&mut output, bytes, MAX_OBJECT_BYTES, "Event object")?;
            }
            Self::Offer {
                direction,
                id,
                bytes,
            } => {
                output.push(OFFER);
                output.push(direction.encode());
                output.extend_from_slice(id.as_bytes());
                encode_bytes(&mut output, bytes, MAX_OBJECT_BYTES, "Event offer")?;
            }
            Self::OfferV3 {
                direction,
                id,
                exchange_id,
                custody,
                bytes,
            } => {
                output.push(OFFER_V3);
                output.push(direction.encode());
                output.extend_from_slice(id.as_bytes());
                output.extend_from_slice(&exchange_id.to_be_bytes());
                encode_bytes(
                    &mut output,
                    custody,
                    MAX_CUSTODY_WRAPPER_BYTES,
                    "custody wrapper",
                )?;
                encode_bytes(&mut output, bytes, MAX_OBJECT_BYTES, "Event object")?;
            }
            Self::ApplyResult {
                direction,
                id,
                inserted,
            } => {
                output.push(APPLY_RESULT);
                output.push(direction.encode());
                output.extend_from_slice(id.as_bytes());
                output.push(u8::from(*inserted));
            }
            Self::ApplyResultV3 {
                direction,
                id,
                exchange_id,
                inserted,
                disposition,
            } => {
                output.push(APPLY_RESULT_V3);
                output.push(direction.encode());
                output.extend_from_slice(id.as_bytes());
                output.extend_from_slice(&exchange_id.to_be_bytes());
                output.push(u8::from(*inserted));
                output.push(disposition.encode());
            }
            Self::ControlInventoryQuery(bytes) => {
                output.push(CONTROL_INVENTORY_QUERY);
                encode_bytes(
                    &mut output,
                    bytes,
                    MAX_FRAME_SIZE_LIMIT,
                    "control inventory query",
                )?;
            }
            Self::ControlInventoryReply(bytes) => {
                output.push(CONTROL_INVENTORY_REPLY);
                encode_bytes(
                    &mut output,
                    bytes,
                    MAX_FRAME_SIZE_LIMIT,
                    "control inventory reply",
                )?;
            }
            Self::ControlInventoryReplyV3 {
                bytes,
                policy,
                policy_revision,
            } => {
                output.push(CONTROL_INVENTORY_REPLY_V3);
                output.push(policy.encode());
                output.extend_from_slice(&policy_revision.to_be_bytes());
                encode_bytes(
                    &mut output,
                    bytes,
                    MAX_FRAME_SIZE_LIMIT,
                    "control inventory reply",
                )?;
            }
            Self::ControlInventoryComplete => output.push(CONTROL_INVENTORY_COMPLETE),
            Self::ControlInventoryCompleteAck => output.push(CONTROL_INVENTORY_COMPLETE_ACK),
            Self::ControlDifferenceQuery(bytes) => {
                output.push(CONTROL_DIFFERENCE_QUERY);
                encode_bytes(
                    &mut output,
                    bytes,
                    MAX_FRAME_SIZE_LIMIT,
                    "control difference query",
                )?;
            }
            Self::ControlDifferenceReply(bytes) => {
                output.push(CONTROL_DIFFERENCE_REPLY);
                encode_bytes(
                    &mut output,
                    bytes,
                    MAX_FRAME_SIZE_LIMIT,
                    "control difference reply",
                )?;
            }
            Self::ControlDifferenceBound => output.push(CONTROL_DIFFERENCE_BOUND),
            Self::ControlDifferenceBoundAck => output.push(CONTROL_DIFFERENCE_BOUND_ACK),
            Self::ControlFetch(id) => {
                output.push(CONTROL_FETCH);
                output.extend_from_slice(id.as_bytes());
            }
            Self::ControlObject { id, bytes } => {
                output.push(CONTROL_OBJECT);
                output.extend_from_slice(id.as_bytes());
                encode_bytes(&mut output, bytes, MAX_OBJECT_BYTES, "control object")?;
            }
            Self::ControlOffer { id, bytes } => {
                output.push(CONTROL_OFFER);
                output.extend_from_slice(id.as_bytes());
                encode_bytes(&mut output, bytes, MAX_OBJECT_BYTES, "control offer")?;
            }
            Self::ControlApplyResult { id, retained } => {
                output.push(CONTROL_APPLY_RESULT);
                output.extend_from_slice(id.as_bytes());
                output.push(u8::from(*retained));
            }
            Self::ControlFinish => output.push(CONTROL_FINISH),
            Self::ControlFinished => output.push(CONTROL_FINISHED),
            Self::Finish { direction } => {
                output.push(FINISH);
                output.push(direction.encode());
            }
            Self::Finished { direction } => {
                output.push(FINISHED);
                output.push(direction.encode());
            }
            Self::FinishV3 {
                direction,
                remaining,
            } => encode_v3_finish(&mut output, FINISH_V3, *direction, *remaining)?,
            Self::FinishedV3 {
                direction,
                remaining,
            } => encode_v3_finish(&mut output, FINISHED_V3, *direction, *remaining)?,
            Self::MutableInterest { class, interest } => {
                if *class == MutableClass::Blob {
                    return Err(NodeError::Protocol(
                        "Blob interest requires the protected v5 Blob interest frame".into(),
                    ));
                }
                output.push(MUTABLE_INTEREST);
                output.push(class.encode());
                encode_event_interest(&mut output, interest)?;
            }
            Self::MutableInterestReply { class, interest } => {
                if *class == MutableClass::Blob {
                    return Err(NodeError::Protocol(
                        "Blob interest reply requires the protected v5 Blob interest frame".into(),
                    ));
                }
                output.push(MUTABLE_INTEREST_REPLY);
                output.push(class.encode());
                encode_event_interest(&mut output, interest)?;
            }
            Self::MutableInventoryQuery {
                class,
                direction,
                bytes,
            } => {
                output.push(MUTABLE_INVENTORY_QUERY);
                encode_mutable_lane(&mut output, *class, *direction);
                encode_bytes(
                    &mut output,
                    bytes,
                    MAX_FRAME_SIZE_LIMIT,
                    "mutable inventory query",
                )?;
            }
            Self::MutableInventoryReply {
                class,
                direction,
                bytes,
            } => {
                output.push(MUTABLE_INVENTORY_REPLY);
                encode_mutable_lane(&mut output, *class, *direction);
                encode_bytes(
                    &mut output,
                    bytes,
                    MAX_FRAME_SIZE_LIMIT,
                    "mutable inventory reply",
                )?;
            }
            Self::MutableInventoryComplete { class, direction } => {
                output.push(MUTABLE_INVENTORY_COMPLETE);
                encode_mutable_lane(&mut output, *class, *direction);
            }
            Self::MutableInventoryCompleteAck { class, direction } => {
                output.push(MUTABLE_INVENTORY_COMPLETE_ACK);
                encode_mutable_lane(&mut output, *class, *direction);
            }
            Self::MutableDifferenceQuery {
                class,
                direction,
                bytes,
            } => {
                output.push(MUTABLE_DIFFERENCE_QUERY);
                encode_mutable_lane(&mut output, *class, *direction);
                encode_bytes(
                    &mut output,
                    bytes,
                    MAX_FRAME_SIZE_LIMIT,
                    "mutable difference query",
                )?;
            }
            Self::MutableDifferenceReply {
                class,
                direction,
                bytes,
            } => {
                output.push(MUTABLE_DIFFERENCE_REPLY);
                encode_mutable_lane(&mut output, *class, *direction);
                encode_bytes(
                    &mut output,
                    bytes,
                    MAX_FRAME_SIZE_LIMIT,
                    "mutable difference reply",
                )?;
            }
            Self::MutableDifferenceBound { class, direction } => {
                output.push(MUTABLE_DIFFERENCE_BOUND);
                encode_mutable_lane(&mut output, *class, *direction);
            }
            Self::MutableDifferenceBoundAck { class, direction } => {
                output.push(MUTABLE_DIFFERENCE_BOUND_ACK);
                encode_mutable_lane(&mut output, *class, *direction);
            }
            Self::MutableLaneDeferred { class, direction } => {
                output.push(MUTABLE_LANE_DEFERRED);
                encode_mutable_lane(&mut output, *class, *direction);
            }
            Self::MutableLaneDeferredAck { class, direction } => {
                output.push(MUTABLE_LANE_DEFERRED_ACK);
                encode_mutable_lane(&mut output, *class, *direction);
            }
            Self::MutableFetch { direction, id } => {
                output.push(MUTABLE_FETCH);
                encode_mutable_id(&mut output, *direction, *id);
            }
            Self::MutableObject {
                direction,
                id,
                bytes,
                claim,
            } => {
                output.push(MUTABLE_OBJECT);
                encode_mutable_id(&mut output, *direction, *id);
                encode_bytes(&mut output, bytes, MAX_OBJECT_BYTES, "mutable object")?;
                encode_blob_claim_field(&mut output, *id, claim.as_ref(), include_v8_blob_fields)?;
            }
            Self::MutableOffer {
                direction,
                id,
                bytes,
                claim,
            } => {
                output.push(MUTABLE_OFFER);
                encode_mutable_id(&mut output, *direction, *id);
                encode_bytes(&mut output, bytes, MAX_OBJECT_BYTES, "mutable offer")?;
                encode_blob_claim_field(&mut output, *id, claim.as_ref(), include_v8_blob_fields)?;
            }
            Self::MutableApplyResult {
                direction,
                id,
                disposition,
                custody_digest,
            } => {
                output.push(MUTABLE_APPLY_RESULT);
                encode_mutable_id(&mut output, *direction, *id);
                output.push(disposition.encode());
                encode_blob_digest_field(
                    &mut output,
                    *id,
                    custody_digest.as_ref(),
                    include_v8_blob_fields,
                )?;
            }
            Self::MutableFetchResult {
                direction,
                id,
                disposition,
                custody_digest,
            } => {
                output.push(MUTABLE_FETCH_RESULT);
                encode_mutable_id(&mut output, *direction, *id);
                output.push(disposition.encode());
                encode_blob_digest_field(
                    &mut output,
                    *id,
                    custody_digest.as_ref(),
                    include_v8_blob_fields,
                )?;
            }
            Self::MutableFetchResultAck {
                direction,
                id,
                disposition,
                custody_digest,
            } => {
                output.push(MUTABLE_FETCH_RESULT_ACK);
                encode_mutable_id(&mut output, *direction, *id);
                output.push(disposition.encode());
                encode_blob_digest_field(
                    &mut output,
                    *id,
                    custody_digest.as_ref(),
                    include_v8_blob_fields,
                )?;
            }
            Self::MutableFinish {
                class,
                direction,
                remaining,
            } => {
                output.push(MUTABLE_FINISH);
                encode_mutable_lane(&mut output, *class, *direction);
                encode_mutable_remaining(&mut output, *remaining)?;
            }
            Self::MutableFinished {
                class,
                direction,
                remaining,
            } => {
                output.push(MUTABLE_FINISHED);
                encode_mutable_lane(&mut output, *class, *direction);
                encode_mutable_remaining(&mut output, *remaining)?;
            }
            Self::BlobRangeFetch {
                direction,
                source_id,
                object_id,
                total_len,
                offset,
                requested_len,
                content_proof,
            } => {
                output.push(BLOB_RANGE_FETCH);
                encode_blob_range_tuple(
                    &mut output,
                    *direction,
                    *source_id,
                    *object_id,
                    *total_len,
                    *offset,
                    *requested_len,
                )?;
                output.extend_from_slice(content_proof);
            }
            Self::BlobRange {
                direction,
                source_id,
                object_id,
                total_len,
                offset,
                requested_len,
                disposition,
                bytes,
            } => {
                output.push(BLOB_RANGE);
                encode_blob_range_tuple(
                    &mut output,
                    *direction,
                    *source_id,
                    *object_id,
                    *total_len,
                    *offset,
                    *requested_len,
                )?;
                output.push(disposition.encode());
                encode_blob_range_payload(&mut output, *disposition, *requested_len, bytes)?;
            }
            Self::BlobRangeResult {
                direction,
                source_id,
                object_id,
                total_len,
                offset,
                accepted_len,
                disposition,
            } => {
                output.push(BLOB_RANGE_RESULT);
                encode_blob_range_result(
                    &mut output,
                    *direction,
                    *source_id,
                    *object_id,
                    *total_len,
                    *offset,
                    *accepted_len,
                    *disposition,
                )?;
            }
            Self::BlobRangeResultAck {
                direction,
                source_id,
                object_id,
                total_len,
                offset,
                accepted_len,
                disposition,
            } => {
                output.push(BLOB_RANGE_RESULT_ACK);
                encode_blob_range_result(
                    &mut output,
                    *direction,
                    *source_id,
                    *object_id,
                    *total_len,
                    *offset,
                    *accepted_len,
                    *disposition,
                )?;
            }
            Self::BlobCarrierFinish {
                direction,
                remaining,
            } => encode_blob_carrier_finish(
                &mut output,
                BLOB_CARRIER_FINISH,
                *direction,
                *remaining,
            )?,
            Self::BlobCarrierFinished {
                direction,
                remaining,
            } => encode_blob_carrier_finish(
                &mut output,
                BLOB_CARRIER_FINISHED,
                *direction,
                *remaining,
            )?,
            Self::BridgeHello { enabled } => {
                output.push(BRIDGE_HELLO);
                output.push(u8::from(*enabled));
            }
            Self::BridgeHelloAck { enabled } => {
                output.push(BRIDGE_HELLO_ACK);
                output.push(u8::from(*enabled));
            }
            Self::BridgeRouteOffer {
                wrapper_id,
                wrapper,
                source,
            } => {
                output.push(BRIDGE_ROUTE_OFFER);
                output.extend_from_slice(wrapper_id);
                encode_bytes(
                    &mut output,
                    wrapper,
                    MAX_SELECTED_BRIDGE_WRAPPER_BYTES,
                    "bridge route wrapper",
                )?;
                encode_bytes(&mut output, source, MAX_OBJECT_BYTES, "bridge route source")?;
            }
            Self::BridgeRouteResult {
                wrapper_id,
                disposition,
            } => {
                output.push(BRIDGE_ROUTE_RESULT);
                output.extend_from_slice(wrapper_id);
                output.push(disposition.encode());
            }
            Self::BridgeFinish { remaining } => {
                encode_bridge_remaining(&mut output, BRIDGE_FINISH, *remaining)?;
            }
            Self::BridgeFinished { remaining } => {
                encode_bridge_remaining(&mut output, BRIDGE_FINISHED, *remaining)?;
            }
            Self::TransferProfileOffer(offer) => {
                output.push(TRANSFER_PROFILE_OFFER_V1);
                output.extend_from_slice(&offer.encode().map_err(event_pages_protocol_error)?);
            }
            Self::EventTurnPlan(plan) => {
                output.push(EVENT_TURN_PLAN_V1);
                output.extend_from_slice(&plan.encode().map_err(event_pages_protocol_error)?);
            }
            Self::ChangeTurnHeader(header) => {
                output.push(CHANGE_TURN_HEADER_V1);
                output.extend_from_slice(&header.encode().map_err(event_pages_protocol_error)?);
            }
            Self::ChangePage(page) => {
                output.push(CHANGE_PAGE_V7);
                output.extend_from_slice(&page.encode().map_err(event_pages_protocol_error)?);
            }
            Self::ChangeTurnFinished(finished) => {
                output.push(CHANGE_TURN_FINISHED_V1);
                output.extend_from_slice(
                    &finished
                        .encode()
                        .map_err(|error| NodeError::Protocol(error.to_string()))?,
                );
            }
            Self::BlobStreamPlan {
                direction,
                attempt_nonce,
                source,
            } => encode_blob_stream_plan_offer(
                &mut output,
                *direction,
                *attempt_nonce,
                source.clone(),
            )?,
            Self::BlobStreamPlanAck {
                direction,
                attempt_nonce,
            } => encode_blob_stream_plan(
                &mut output,
                BLOB_STREAM_PLAN_ACK_V1,
                *direction,
                *attempt_nonce,
            )?,
            Self::Stream(_) => {
                return Err(NodeError::Protocol(
                    "stream frame requires an authenticated semantic/profile context".into(),
                ));
            }
        }
        Ok(output)
    }

    pub(crate) fn encode_for_semantic_version(
        &self,
        semantic_version: u16,
    ) -> Result<Vec<u8>, NodeError> {
        validate_semantic_version(semantic_version)?;
        if semantic_version < crate::event_pages::SEMANTIC_PROTOCOL_V7 && self.is_v7_only() {
            return Err(NodeError::Protocol(
                "semantic v1-v6 session cannot emit a v7-only mechanics frame".into(),
            ));
        }
        if semantic_version != crate::event_pages::SEMANTIC_PROTOCOL_V9 && self.is_v9_only() {
            return Err(NodeError::Protocol(
                "Blob stream plan requires semantic v9".into(),
            ));
        }
        if semantic_version >= crate::event_pages::SEMANTIC_PROTOCOL_V8 {
            self.encode_with_v8_blob_fields(true)
        } else {
            self.encode()
        }
    }

    #[allow(dead_code)] // Activated by the profile-5 runtime driver.
    pub(crate) fn encode_for_semantic_profile(
        &self,
        semantic_version: u16,
        profile_id: u16,
    ) -> Result<Vec<u8>, NodeError> {
        match self {
            Self::Stream(frame) => frame
                .encode_for_context(semantic_version, profile_id)
                .map_err(|error| NodeError::Protocol(error.to_string())),
            _ => self.encode_for_semantic_version(semantic_version),
        }
    }

    #[allow(dead_code)] // Activated by the profile-5 runtime driver.
    pub(crate) fn decode_for_semantic_profile(
        input: &[u8],
        semantic_version: u16,
        profile_id: u16,
    ) -> Result<Self, NodeError> {
        if input.len() >= 5 && STREAM_TAGS.contains(&input[4]) {
            return StreamFrame::decode_for_context(semantic_version, profile_id, input)
                .map(Self::Stream)
                .map_err(|error| NodeError::Protocol(error.to_string()));
        }
        Self::decode_for_semantic_version(input, semantic_version)
    }

    pub(crate) fn decode_for_semantic_version(
        input: &[u8],
        semantic_version: u16,
    ) -> Result<Self, NodeError> {
        validate_semantic_version(semantic_version)?;
        if input.len() < 5 || &input[..4] != MAGIC {
            return Err(NodeError::Protocol(
                "invalid mechanics frame version".into(),
            ));
        }
        if semantic_version < crate::event_pages::SEMANTIC_PROTOCOL_V7 && is_v7_only_tag(input[4]) {
            return Err(NodeError::Protocol(
                "semantic v1-v6 session rejected a v7-only mechanics frame".into(),
            ));
        }
        if semantic_version != crate::event_pages::SEMANTIC_PROTOCOL_V9 && is_v9_only_tag(input[4])
        {
            return Err(NodeError::Protocol(
                "semantic session rejected a v9-only mechanics frame".into(),
            ));
        }
        if semantic_version >= crate::event_pages::SEMANTIC_PROTOCOL_V8 {
            Self::decode_v8_blob_fields(input)
        } else {
            Self::decode(input)
        }
    }

    fn decode_v8_blob_fields(input: &[u8]) -> Result<Self, NodeError> {
        if input.len() < 5 || &input[..4] != MAGIC {
            return Err(NodeError::Protocol(
                "invalid mechanics frame version".into(),
            ));
        }
        let tag = input[4];
        let body = &input[5..];
        match tag {
            MUTABLE_OBJECT | MUTABLE_OFFER => {
                let (direction, id, body) = decode_mutable_id(body)?;
                if id.class() != MutableClass::Blob {
                    return Self::decode(input);
                }
                let (bytes, trailing) =
                    decode_leading_bytes(body, MAX_OBJECT_BYTES, "mutable object")?;
                let claim = decode_blob_claim_field(trailing)?;
                if tag == MUTABLE_OBJECT {
                    Ok(Self::MutableObject {
                        direction,
                        id,
                        bytes: bytes.to_vec(),
                        claim,
                    })
                } else {
                    Ok(Self::MutableOffer {
                        direction,
                        id,
                        bytes: bytes.to_vec(),
                        claim,
                    })
                }
            }
            MUTABLE_APPLY_RESULT | MUTABLE_FETCH_RESULT | MUTABLE_FETCH_RESULT_ACK => {
                let (direction, id, body) = decode_mutable_id(body)?;
                if id.class() != MutableClass::Blob {
                    return Self::decode(input);
                }
                let Some((&disposition, trailing)) = body.split_first() else {
                    return Err(NodeError::Protocol(
                        "mutable Blob result disposition is missing".into(),
                    ));
                };
                let disposition = MutableApplyDisposition::decode(disposition)?;
                let custody_digest = decode_blob_digest_field(trailing)?;
                match tag {
                    MUTABLE_APPLY_RESULT => Ok(Self::MutableApplyResult {
                        direction,
                        id,
                        disposition,
                        custody_digest,
                    }),
                    MUTABLE_FETCH_RESULT => Ok(Self::MutableFetchResult {
                        direction,
                        id,
                        disposition,
                        custody_digest,
                    }),
                    MUTABLE_FETCH_RESULT_ACK => Ok(Self::MutableFetchResultAck {
                        direction,
                        id,
                        disposition,
                        custody_digest,
                    }),
                    _ => unreachable!("matched one of three result tags"),
                }
            }
            _ => Self::decode(input),
        }
    }

    const fn is_v7_only(&self) -> bool {
        matches!(
            self,
            Self::TransferProfileOffer(_)
                | Self::EventTurnPlan(_)
                | Self::ChangeTurnHeader(_)
                | Self::ChangePage(_)
                | Self::ChangeTurnFinished(_)
        )
    }

    const fn is_v9_only(&self) -> bool {
        matches!(
            self,
            Self::BlobStreamPlan { .. } | Self::BlobStreamPlanAck { .. } | Self::Stream(_)
        )
    }

    pub(crate) fn decode(input: &[u8]) -> Result<Self, NodeError> {
        if input.len() < 5 || &input[..4] != MAGIC {
            return Err(NodeError::Protocol(
                "invalid mechanics frame version".into(),
            ));
        }
        let tag = input[4];
        let body = &input[5..];
        match tag {
            EVENT_INTEREST => Ok(Self::EventInterest(decode_event_interest(body)?)),
            EVENT_INTEREST_V3 => {
                if body.len() < 17 {
                    return Err(NodeError::Protocol(
                        "v3 Event interest request is truncated".into(),
                    ));
                }
                let policy = FrameEmissionPolicy::decode(body[0])?;
                let policy_revision = u64::from_be_bytes(
                    body[1..9]
                        .try_into()
                        .map_err(|_| NodeError::Protocol("v3 policy revision differs".into()))?,
                );
                let selector_revision = u64::from_be_bytes(
                    body[9..17]
                        .try_into()
                        .map_err(|_| NodeError::Protocol("v3 selector revision differs".into()))?,
                );
                let interest = decode_event_interest(&body[17..])?;
                require_selector_revision(&interest, selector_revision)?;
                Ok(Self::EventInterestV3 {
                    interest,
                    selector_revision,
                    policy,
                    policy_revision,
                })
            }
            EVENT_INTEREST_REPLY => Ok(Self::EventInterestReply(decode_event_interest(body)?)),
            EVENT_INTEREST_REPLY_V3 => {
                if body.len() < 17 {
                    return Err(NodeError::Protocol(
                        "v3 Event interest reply is truncated".into(),
                    ));
                }
                let policy = FrameEmissionPolicy::decode(body[0])?;
                let policy_revision = u64::from_be_bytes(
                    body[1..9]
                        .try_into()
                        .map_err(|_| NodeError::Protocol("v3 policy revision differs".into()))?,
                );
                let selector_revision = u64::from_be_bytes(
                    body[9..17]
                        .try_into()
                        .map_err(|_| NodeError::Protocol("v3 selector revision differs".into()))?,
                );
                let interest = decode_event_interest(&body[17..])?;
                require_selector_revision(&interest, selector_revision)?;
                Ok(Self::EventInterestReplyV3 {
                    interest,
                    selector_revision,
                    policy,
                    policy_revision,
                })
            }
            BLOB_INTEREST => Ok(Self::BlobInterest(decode_blob_interest(body)?)),
            BLOB_INTEREST_REPLY => Ok(Self::BlobInterestReply(decode_blob_interest(body)?)),
            INVENTORY_QUERY => {
                let (direction, body) = decode_direction(body)?;
                Ok(Self::InventoryQuery {
                    direction,
                    bytes: decode_bytes(body, MAX_FRAME_SIZE_LIMIT, "inventory query")?.to_vec(),
                })
            }
            INVENTORY_REPLY => {
                let (direction, body) = decode_direction(body)?;
                Ok(Self::InventoryReply {
                    direction,
                    bytes: decode_bytes(body, MAX_FRAME_SIZE_LIMIT, "inventory reply")?.to_vec(),
                })
            }
            INVENTORY_COMPLETE => Ok(Self::InventoryComplete {
                direction: decode_direction_only(body)?,
            }),
            INVENTORY_COMPLETE_ACK => Ok(Self::InventoryCompleteAck {
                direction: decode_direction_only(body)?,
            }),
            DIFFERENCE_QUERY => {
                let (direction, body) = decode_direction(body)?;
                Ok(Self::DifferenceQuery {
                    direction,
                    bytes: decode_bytes(body, MAX_FRAME_SIZE_LIMIT, "difference query")?.to_vec(),
                })
            }
            DIFFERENCE_REPLY => {
                let (direction, body) = decode_direction(body)?;
                Ok(Self::DifferenceReply {
                    direction,
                    bytes: decode_bytes(body, MAX_FRAME_SIZE_LIMIT, "difference reply")?.to_vec(),
                })
            }
            DIFFERENCE_BOUND => Ok(Self::DifferenceBound {
                direction: decode_direction_only(body)?,
            }),
            DIFFERENCE_BOUND_ACK => Ok(Self::DifferenceBoundAck {
                direction: decode_direction_only(body)?,
            }),
            EVENT_LANE_DEFERRED => Ok(Self::EventLaneDeferred {
                direction: decode_direction_only(body)?,
            }),
            EVENT_LANE_DEFERRED_ACK => Ok(Self::EventLaneDeferredAck {
                direction: decode_direction_only(body)?,
            }),
            FETCH => {
                let (direction, body) = decode_direction(body)?;
                Ok(Self::Fetch {
                    direction,
                    id: decode_exact_id(body)?,
                })
            }
            OBJECT | OFFER => {
                let (direction, body) = decode_direction(body)?;
                if body.len() < 32 {
                    return Err(NodeError::Protocol("object frame is truncated".into()));
                }
                let id = decode_exact_id(&body[..32])?;
                let bytes = decode_bytes(&body[32..], MAX_OBJECT_BYTES, "Event object")?.to_vec();
                if tag == OBJECT {
                    Ok(Self::Object {
                        direction,
                        id,
                        bytes,
                    })
                } else {
                    Ok(Self::Offer {
                        direction,
                        id,
                        bytes,
                    })
                }
            }
            OFFER_V3 => {
                let (direction, body) = decode_direction(body)?;
                if body.len() < 40 {
                    return Err(NodeError::Protocol("v3 Event object is truncated".into()));
                }
                let id = decode_exact_id(&body[..32])?;
                let exchange_id = u64::from_be_bytes(body[32..40].try_into().map_err(|_| {
                    NodeError::Protocol("v3 Event exchange identifier differs".into())
                })?);
                let (custody, body) = decode_leading_bytes(
                    &body[40..],
                    MAX_CUSTODY_WRAPPER_BYTES,
                    "custody wrapper",
                )?;
                let bytes = decode_bytes(body, MAX_OBJECT_BYTES, "Event object")?.to_vec();
                Ok(Self::OfferV3 {
                    direction,
                    id,
                    exchange_id,
                    custody: custody.to_vec(),
                    bytes,
                })
            }
            APPLY_RESULT => {
                let (direction, body) = decode_direction(body)?;
                if body.len() != 33 || body[32] > 1 {
                    return Err(NodeError::Protocol("apply result frame differs".into()));
                }
                Ok(Self::ApplyResult {
                    direction,
                    id: decode_exact_id(&body[..32])?,
                    inserted: body[32] == 1,
                })
            }
            APPLY_RESULT_V3 => {
                let (direction, body) = decode_direction(body)?;
                if body.len() != 42 || body[40] > 1 {
                    return Err(NodeError::Protocol("v3 apply result frame differs".into()));
                }
                Ok(Self::ApplyResultV3 {
                    direction,
                    id: decode_exact_id(&body[..32])?,
                    exchange_id: u64::from_be_bytes(body[32..40].try_into().map_err(|_| {
                        NodeError::Protocol("v3 apply exchange identifier differs".into())
                    })?),
                    inserted: body[40] == 1,
                    disposition: EventApplyDisposition::decode(body[41])?,
                })
            }
            CONTROL_INVENTORY_QUERY => Ok(Self::ControlInventoryQuery(
                decode_bytes(body, MAX_FRAME_SIZE_LIMIT, "control inventory query")?.to_vec(),
            )),
            CONTROL_INVENTORY_REPLY => Ok(Self::ControlInventoryReply(
                decode_bytes(body, MAX_FRAME_SIZE_LIMIT, "control inventory reply")?.to_vec(),
            )),
            CONTROL_INVENTORY_REPLY_V3 => {
                if body.len() < 9 {
                    return Err(NodeError::Protocol(
                        "v3 control inventory reply is truncated".into(),
                    ));
                }
                Ok(Self::ControlInventoryReplyV3 {
                    policy: FrameEmissionPolicy::decode(body[0])?,
                    policy_revision: u64::from_be_bytes(
                        body[1..9].try_into().map_err(|_| {
                            NodeError::Protocol("v3 policy revision differs".into())
                        })?,
                    ),
                    bytes: decode_bytes(
                        &body[9..],
                        MAX_FRAME_SIZE_LIMIT,
                        "control inventory reply",
                    )?
                    .to_vec(),
                })
            }
            CONTROL_INVENTORY_COMPLETE if body.is_empty() => Ok(Self::ControlInventoryComplete),
            CONTROL_INVENTORY_COMPLETE_ACK if body.is_empty() => {
                Ok(Self::ControlInventoryCompleteAck)
            }
            CONTROL_DIFFERENCE_QUERY => Ok(Self::ControlDifferenceQuery(
                decode_bytes(body, MAX_FRAME_SIZE_LIMIT, "control difference query")?.to_vec(),
            )),
            CONTROL_DIFFERENCE_REPLY => Ok(Self::ControlDifferenceReply(
                decode_bytes(body, MAX_FRAME_SIZE_LIMIT, "control difference reply")?.to_vec(),
            )),
            CONTROL_DIFFERENCE_BOUND if body.is_empty() => Ok(Self::ControlDifferenceBound),
            CONTROL_DIFFERENCE_BOUND_ACK if body.is_empty() => Ok(Self::ControlDifferenceBoundAck),
            CONTROL_FETCH => Ok(Self::ControlFetch(decode_control_id(body)?)),
            CONTROL_OBJECT | CONTROL_OFFER => {
                if body.len() < 32 {
                    return Err(NodeError::Protocol(
                        "control object frame is truncated".into(),
                    ));
                }
                let id = decode_control_id(&body[..32])?;
                let bytes = decode_bytes(&body[32..], MAX_OBJECT_BYTES, "control object")?.to_vec();
                if tag == CONTROL_OBJECT {
                    Ok(Self::ControlObject { id, bytes })
                } else {
                    Ok(Self::ControlOffer { id, bytes })
                }
            }
            CONTROL_APPLY_RESULT => {
                if body.len() != 33 || body[32] > 1 {
                    return Err(NodeError::Protocol(
                        "control apply result frame differs".into(),
                    ));
                }
                Ok(Self::ControlApplyResult {
                    id: decode_control_id(&body[..32])?,
                    retained: body[32] == 1,
                })
            }
            CONTROL_FINISH if body.is_empty() => Ok(Self::ControlFinish),
            CONTROL_FINISHED if body.is_empty() => Ok(Self::ControlFinished),
            FINISH => Ok(Self::Finish {
                direction: decode_direction_only(body)?,
            }),
            FINISHED => Ok(Self::Finished {
                direction: decode_direction_only(body)?,
            }),
            FINISH_V3 => {
                let (direction, remaining) = decode_v3_finish(body)?;
                Ok(Self::FinishV3 {
                    direction,
                    remaining,
                })
            }
            FINISHED_V3 => {
                let (direction, remaining) = decode_v3_finish(body)?;
                Ok(Self::FinishedV3 {
                    direction,
                    remaining,
                })
            }
            MUTABLE_INTEREST | MUTABLE_INTEREST_REPLY => {
                let (class, body) = decode_mutable_class(body)?;
                if class == MutableClass::Blob {
                    return Err(NodeError::Protocol(
                        "Blob interest requires the protected v5 Blob interest frame".into(),
                    ));
                }
                let interest = decode_event_interest(body)?;
                if tag == MUTABLE_INTEREST {
                    Ok(Self::MutableInterest { class, interest })
                } else {
                    Ok(Self::MutableInterestReply { class, interest })
                }
            }
            MUTABLE_INVENTORY_QUERY | MUTABLE_INVENTORY_REPLY => {
                let (class, direction, body) = decode_mutable_lane(body)?;
                let bytes = decode_bytes(body, MAX_FRAME_SIZE_LIMIT, "mutable inventory")?.to_vec();
                if tag == MUTABLE_INVENTORY_QUERY {
                    Ok(Self::MutableInventoryQuery {
                        class,
                        direction,
                        bytes,
                    })
                } else {
                    Ok(Self::MutableInventoryReply {
                        class,
                        direction,
                        bytes,
                    })
                }
            }
            MUTABLE_INVENTORY_COMPLETE | MUTABLE_INVENTORY_COMPLETE_ACK => {
                let (class, direction) = decode_mutable_lane_only(body)?;
                if tag == MUTABLE_INVENTORY_COMPLETE {
                    Ok(Self::MutableInventoryComplete { class, direction })
                } else {
                    Ok(Self::MutableInventoryCompleteAck { class, direction })
                }
            }
            MUTABLE_DIFFERENCE_QUERY | MUTABLE_DIFFERENCE_REPLY => {
                let (class, direction, body) = decode_mutable_lane(body)?;
                let bytes =
                    decode_bytes(body, MAX_FRAME_SIZE_LIMIT, "mutable difference")?.to_vec();
                if tag == MUTABLE_DIFFERENCE_QUERY {
                    Ok(Self::MutableDifferenceQuery {
                        class,
                        direction,
                        bytes,
                    })
                } else {
                    Ok(Self::MutableDifferenceReply {
                        class,
                        direction,
                        bytes,
                    })
                }
            }
            MUTABLE_DIFFERENCE_BOUND | MUTABLE_DIFFERENCE_BOUND_ACK => {
                let (class, direction) = decode_mutable_lane_only(body)?;
                if tag == MUTABLE_DIFFERENCE_BOUND {
                    Ok(Self::MutableDifferenceBound { class, direction })
                } else {
                    Ok(Self::MutableDifferenceBoundAck { class, direction })
                }
            }
            MUTABLE_LANE_DEFERRED | MUTABLE_LANE_DEFERRED_ACK => {
                let (class, direction) = decode_mutable_lane_only(body)?;
                if tag == MUTABLE_LANE_DEFERRED {
                    Ok(Self::MutableLaneDeferred { class, direction })
                } else {
                    Ok(Self::MutableLaneDeferredAck { class, direction })
                }
            }
            MUTABLE_FETCH => {
                let (direction, id, body) = decode_mutable_id(body)?;
                if !body.is_empty() {
                    return Err(NodeError::Protocol(
                        "mutable fetch has trailing bytes".into(),
                    ));
                }
                Ok(Self::MutableFetch { direction, id })
            }
            MUTABLE_OBJECT | MUTABLE_OFFER => {
                let (direction, id, body) = decode_mutable_id(body)?;
                let bytes = decode_bytes(body, MAX_OBJECT_BYTES, "mutable object")?.to_vec();
                if tag == MUTABLE_OBJECT {
                    Ok(Self::MutableObject {
                        direction,
                        id,
                        bytes,
                        claim: None,
                    })
                } else {
                    Ok(Self::MutableOffer {
                        direction,
                        id,
                        bytes,
                        claim: None,
                    })
                }
            }
            MUTABLE_APPLY_RESULT => {
                let (direction, id, body) = decode_mutable_id(body)?;
                if body.len() != 1 {
                    return Err(NodeError::Protocol(
                        "mutable apply result frame differs".into(),
                    ));
                }
                Ok(Self::MutableApplyResult {
                    direction,
                    id,
                    disposition: MutableApplyDisposition::decode(body[0])?,
                    custody_digest: None,
                })
            }
            MUTABLE_FETCH_RESULT | MUTABLE_FETCH_RESULT_ACK => {
                let (direction, id, body) = decode_mutable_id(body)?;
                if body.len() != 1 {
                    return Err(NodeError::Protocol(
                        "mutable fetch result frame differs".into(),
                    ));
                }
                let disposition = MutableApplyDisposition::decode(body[0])?;
                if tag == MUTABLE_FETCH_RESULT {
                    Ok(Self::MutableFetchResult {
                        direction,
                        id,
                        disposition,
                        custody_digest: None,
                    })
                } else {
                    Ok(Self::MutableFetchResultAck {
                        direction,
                        id,
                        disposition,
                        custody_digest: None,
                    })
                }
            }
            MUTABLE_FINISH | MUTABLE_FINISHED => {
                let (class, direction, body) = decode_mutable_lane(body)?;
                let remaining = decode_mutable_remaining(body)?;
                if tag == MUTABLE_FINISH {
                    Ok(Self::MutableFinish {
                        class,
                        direction,
                        remaining,
                    })
                } else {
                    Ok(Self::MutableFinished {
                        class,
                        direction,
                        remaining,
                    })
                }
            }
            BLOB_RANGE_FETCH => {
                let (direction, source_id, object_id, total_len, offset, requested_len, body) =
                    decode_blob_range_tuple(body)?;
                if body.len() != BLOB_CONTENT_PROOF_BYTES {
                    return Err(NodeError::Protocol(
                        "Blob range fetch content proof length differs".into(),
                    ));
                }
                let content_proof = body.try_into().map_err(|_| {
                    NodeError::Protocol("Blob range fetch content proof length differs".into())
                })?;
                Ok(Self::BlobRangeFetch {
                    direction,
                    source_id,
                    object_id,
                    total_len,
                    offset,
                    requested_len,
                    content_proof,
                })
            }
            BLOB_RANGE => {
                let (direction, source_id, object_id, total_len, offset, requested_len, body) =
                    decode_blob_range_tuple(body)?;
                let Some((&encoded_disposition, body)) = body.split_first() else {
                    return Err(NodeError::Protocol(
                        "Blob range disposition is missing".into(),
                    ));
                };
                let disposition = BlobRangeDisposition::decode(encoded_disposition)?;
                let bytes = decode_bytes(body, MAX_BLOB_RANGE_BYTES, "Blob range")?.to_vec();
                validate_blob_range_payload(disposition, requested_len, &bytes)?;
                Ok(Self::BlobRange {
                    direction,
                    source_id,
                    object_id,
                    total_len,
                    offset,
                    requested_len,
                    disposition,
                    bytes,
                })
            }
            BLOB_RANGE_RESULT | BLOB_RANGE_RESULT_ACK => {
                let (direction, source_id, object_id, total_len, offset, accepted_len, disposition) =
                    decode_blob_range_result(body)?;
                if tag == BLOB_RANGE_RESULT {
                    Ok(Self::BlobRangeResult {
                        direction,
                        source_id,
                        object_id,
                        total_len,
                        offset,
                        accepted_len,
                        disposition,
                    })
                } else {
                    Ok(Self::BlobRangeResultAck {
                        direction,
                        source_id,
                        object_id,
                        total_len,
                        offset,
                        accepted_len,
                        disposition,
                    })
                }
            }
            BLOB_CARRIER_FINISH | BLOB_CARRIER_FINISHED => {
                let (direction, remaining) = decode_blob_carrier_finish(body)?;
                if tag == BLOB_CARRIER_FINISH {
                    Ok(Self::BlobCarrierFinish {
                        direction,
                        remaining,
                    })
                } else {
                    Ok(Self::BlobCarrierFinished {
                        direction,
                        remaining,
                    })
                }
            }
            BRIDGE_HELLO | BRIDGE_HELLO_ACK => {
                let enabled = decode_bridge_enabled(body)?;
                if tag == BRIDGE_HELLO {
                    Ok(Self::BridgeHello { enabled })
                } else {
                    Ok(Self::BridgeHelloAck { enabled })
                }
            }
            BRIDGE_ROUTE_OFFER => {
                let mut body = body;
                let wrapper_id: [u8; 32] =
                    take_exact(&mut body, 32, "bridge route wrapper identifier")?
                        .try_into()
                        .map_err(|_| {
                            NodeError::Protocol(
                                "bridge route wrapper identifier length differs".into(),
                            )
                        })?;
                let (wrapper, body) = decode_leading_bytes(
                    body,
                    MAX_SELECTED_BRIDGE_WRAPPER_BYTES,
                    "bridge route wrapper",
                )?;
                let source = decode_bytes(body, MAX_OBJECT_BYTES, "bridge route source")?;
                Ok(Self::BridgeRouteOffer {
                    wrapper_id,
                    wrapper: wrapper.to_vec(),
                    source: source.to_vec(),
                })
            }
            BRIDGE_ROUTE_RESULT => {
                if body.len() != 33 {
                    return Err(NodeError::Protocol(
                        "bridge route result length differs".into(),
                    ));
                }
                Ok(Self::BridgeRouteResult {
                    wrapper_id: body[..32].try_into().map_err(|_| {
                        NodeError::Protocol("bridge route wrapper identifier length differs".into())
                    })?,
                    disposition: BridgeRouteDisposition::decode(body[32])?,
                })
            }
            BRIDGE_FINISH | BRIDGE_FINISHED => {
                let remaining = decode_bridge_remaining(body)?;
                if tag == BRIDGE_FINISH {
                    Ok(Self::BridgeFinish { remaining })
                } else {
                    Ok(Self::BridgeFinished { remaining })
                }
            }
            TRANSFER_PROFILE_OFFER_V1 => Ok(Self::TransferProfileOffer(
                TransferProfileOfferV1::decode(body).map_err(event_pages_protocol_error)?,
            )),
            EVENT_TURN_PLAN_V1 => Ok(Self::EventTurnPlan(
                EventTurnPlanV1::decode(body).map_err(event_pages_protocol_error)?,
            )),
            CHANGE_TURN_HEADER_V1 => Ok(Self::ChangeTurnHeader(
                ChangeTurnHeaderV1::decode(body).map_err(event_pages_protocol_error)?,
            )),
            CHANGE_PAGE_V7 => Ok(Self::ChangePage(
                ChangePageV7::decode(body).map_err(event_pages_protocol_error)?,
            )),
            CHANGE_TURN_FINISHED_V1 => Ok(Self::ChangeTurnFinished(
                ChangeTurnFinishedV1::decode(body).map_err(event_pages_protocol_error)?,
            )),
            BLOB_STREAM_PLAN_V1 | BLOB_STREAM_PLAN_ACK_V1 => {
                if tag == BLOB_STREAM_PLAN_V1 {
                    let (direction, attempt_nonce, source) = decode_blob_stream_plan_offer(body)?;
                    Ok(Self::BlobStreamPlan {
                        direction,
                        attempt_nonce,
                        source,
                    })
                } else {
                    let (direction, attempt_nonce) = decode_blob_stream_plan(body)?;
                    Ok(Self::BlobStreamPlanAck {
                        direction,
                        attempt_nonce,
                    })
                }
            }
            _ => Err(NodeError::Protocol(
                "unknown or malformed mechanics frame".into(),
            )),
        }
    }
}

fn decode_bridge_enabled(body: &[u8]) -> Result<bool, NodeError> {
    match body {
        [0] => Ok(false),
        [1] => Ok(true),
        _ => Err(NodeError::Protocol(
            "bridge enabled flag is not one canonical boolean".into(),
        )),
    }
}

fn event_pages_protocol_error(error: crate::event_pages::EventPagesError) -> NodeError {
    NodeError::Protocol(error.to_string())
}

const fn is_v7_only_tag(tag: u8) -> bool {
    matches!(
        tag,
        TRANSFER_PROFILE_OFFER_V1
            | EVENT_TURN_PLAN_V1
            | CHANGE_TURN_HEADER_V1
            | CHANGE_PAGE_V7
            | CHANGE_TURN_FINISHED_V1
    )
}

const fn is_v9_only_tag(tag: u8) -> bool {
    matches!(tag, BLOB_STREAM_PLAN_V1 | BLOB_STREAM_PLAN_ACK_V1)
}

fn validate_semantic_version(semantic_version: u16) -> Result<(), NodeError> {
    if !(1..=crate::event_pages::SEMANTIC_PROTOCOL_V9).contains(&semantic_version) {
        return Err(NodeError::Protocol(format!(
            "unsupported semantic protocol version {semantic_version}"
        )));
    }
    Ok(())
}

fn encode_blob_stream_plan(
    output: &mut Vec<u8>,
    tag: u8,
    direction: EventDirection,
    attempt_nonce: Option<[u8; 32]>,
) -> Result<(), NodeError> {
    output.push(tag);
    output.push(direction.encode());
    match attempt_nonce {
        None => output.push(0),
        Some(nonce) if nonce != [0; 32] => {
            output.push(1);
            output.extend_from_slice(&nonce);
        }
        Some(_) => {
            return Err(NodeError::Protocol(
                "Blob stream plan attempt nonce is zero".into(),
            ));
        }
    }
    Ok(())
}

fn encode_blob_stream_plan_offer(
    output: &mut Vec<u8>,
    direction: EventDirection,
    attempt_nonce: Option<[u8; 32]>,
    source: Option<BlobStreamSourceOfferV1>,
) -> Result<(), NodeError> {
    output.push(BLOB_STREAM_PLAN_V1);
    output.push(direction.encode());
    match attempt_nonce {
        None if source.is_none() => output.push(0),
        Some(nonce) if nonce != [0; 32] && source.is_some() => {
            let source = source.expect("source presence checked");
            if source.source_len == 0
                || usize::try_from(source.source_len)
                    .ok()
                    .is_none_or(|length| {
                        length > crate::stream_transfer::MAX_STREAM_AUTHENTICATED_OPEN_BYTES
                    })
            {
                return Err(NodeError::Protocol(
                    "Blob stream source length is out of bounds".into(),
                ));
            }
            output.push(1);
            output.extend_from_slice(&nonce);
            output.extend_from_slice(&source.transfer_id);
            encode_event_name(output, source.topic.as_str(), "Blob stream topic")?;
            encode_event_name(output, source.scope.as_str(), "Blob stream scope")?;
            output.extend_from_slice(&source.key_epoch.to_be_bytes());
            output.extend_from_slice(&source.content_proof);
            output.extend_from_slice(&source.source_len.to_be_bytes());
            output.extend_from_slice(&source.source_digest);
            output.push(u8::from(source.finite));
        }
        _ => {
            return Err(NodeError::Protocol(
                "Blob stream plan offer is not canonical".into(),
            ));
        }
    }
    Ok(())
}

type DecodedBlobStreamPlanOffer = (
    EventDirection,
    Option<[u8; 32]>,
    Option<BlobStreamSourceOfferV1>,
);

fn decode_blob_stream_plan_offer(body: &[u8]) -> Result<DecodedBlobStreamPlanOffer, NodeError> {
    let (&direction, body) = body
        .split_first()
        .ok_or_else(|| NodeError::Protocol("Blob stream plan direction is missing".into()))?;
    let direction = EventDirection::decode(direction)?;
    match body {
        [0] => Ok((direction, None, None)),
        [1, rest @ ..] => {
            let mut rest = rest;
            let nonce: [u8; 32] = take_exact(&mut rest, 32, "Blob stream plan nonce")?
                .try_into()
                .map_err(|_| NodeError::Protocol("Blob stream plan nonce length differs".into()))?;
            let transfer_id = take_exact(&mut rest, 32, "Blob stream source id")?
                .try_into()
                .map_err(|_| NodeError::Protocol("Blob stream source id differs".into()))?;
            let topic = decode_event_topic(&mut rest)?;
            let scope = decode_event_scope(&mut rest)?;
            let key_epoch = u64::from_be_bytes(
                take_exact(&mut rest, 8, "Blob stream key epoch")?
                    .try_into()
                    .map_err(|_| NodeError::Protocol("Blob stream key epoch differs".into()))?,
            );
            let content_proof = take_exact(
                &mut rest,
                BLOB_CONTENT_PROOF_BYTES,
                "Blob stream source content proof",
            )?
            .try_into()
            .map_err(|_| NodeError::Protocol("Blob stream source proof differs".into()))?;
            let source_len = u32::from_be_bytes(
                take_exact(&mut rest, 4, "Blob stream source length")?
                    .try_into()
                    .map_err(|_| NodeError::Protocol("Blob stream source length differs".into()))?,
            );
            let source_digest = take_exact(&mut rest, 32, "Blob stream source digest")?
                .try_into()
                .map_err(|_| NodeError::Protocol("Blob stream source digest differs".into()))?;
            let finite = match take_exact(&mut rest, 1, "Blob stream lifetime class")?[0] {
                0 => false,
                1 => true,
                _ => {
                    return Err(NodeError::Protocol(
                        "Blob stream lifetime class is not canonical".into(),
                    ));
                }
            };
            if nonce == [0; 32]
                || key_epoch == 0
                || source_len == 0
                || !rest.is_empty()
                || usize::try_from(source_len).ok().is_none_or(|length| {
                    length > crate::stream_transfer::MAX_STREAM_AUTHENTICATED_OPEN_BYTES
                })
            {
                return Err(NodeError::Protocol(
                    "Blob stream plan offer is not canonical".into(),
                ));
            }
            Ok((
                direction,
                Some(nonce),
                Some(BlobStreamSourceOfferV1 {
                    transfer_id,
                    topic,
                    scope,
                    key_epoch,
                    content_proof,
                    source_len,
                    source_digest,
                    finite,
                }),
            ))
        }
        _ => Err(NodeError::Protocol(
            "Blob stream plan offer is not canonical".into(),
        )),
    }
}

fn decode_blob_stream_plan(body: &[u8]) -> Result<(EventDirection, Option<[u8; 32]>), NodeError> {
    let (&direction, body) = body
        .split_first()
        .ok_or_else(|| NodeError::Protocol("Blob stream plan direction is missing".into()))?;
    let direction = EventDirection::decode(direction)?;
    match body {
        [0] => Ok((direction, None)),
        [1, nonce @ ..] if nonce.len() == 32 && nonce.iter().any(|byte| *byte != 0) => Ok((
            direction,
            Some(nonce.try_into().map_err(|_| {
                NodeError::Protocol("Blob stream plan nonce length differs".into())
            })?),
        )),
        _ => Err(NodeError::Protocol(
            "Blob stream plan nonce field is not canonical".into(),
        )),
    }
}

fn encode_bridge_remaining(output: &mut Vec<u8>, tag: u8, remaining: u64) -> Result<(), NodeError> {
    if remaining > MAX_CARDINALITY_LIMIT as u64 {
        return Err(NodeError::Protocol(
            "bridge remaining count exceeds the selected cardinality bound".into(),
        ));
    }
    output.push(tag);
    output.extend_from_slice(&remaining.to_be_bytes());
    Ok(())
}

fn decode_bridge_remaining(body: &[u8]) -> Result<u64, NodeError> {
    if body.len() != 8 {
        return Err(NodeError::Protocol(
            "bridge remaining count length differs".into(),
        ));
    }
    let remaining = u64::from_be_bytes(
        body.try_into()
            .map_err(|_| NodeError::Protocol("bridge remaining count differs".into()))?,
    );
    if remaining > MAX_CARDINALITY_LIMIT as u64 {
        return Err(NodeError::Protocol(
            "bridge remaining count exceeds the selected cardinality bound".into(),
        ));
    }
    Ok(remaining)
}

fn encode_blob_range_tuple(
    output: &mut Vec<u8>,
    direction: EventDirection,
    source_id: BlobTransferId,
    object_id: BlobObjectId,
    total_len: u64,
    offset: u64,
    requested_len: u32,
) -> Result<(), NodeError> {
    validate_blob_range_bounds(total_len, offset, requested_len)?;
    output.push(direction.encode());
    output.extend_from_slice(source_id.as_bytes());
    output.extend_from_slice(object_id.as_bytes());
    output.extend_from_slice(&total_len.to_be_bytes());
    output.extend_from_slice(&offset.to_be_bytes());
    output.extend_from_slice(&requested_len.to_be_bytes());
    Ok(())
}

type DecodedBlobRangeTuple<'a> = (
    EventDirection,
    BlobTransferId,
    BlobObjectId,
    u64,
    u64,
    u32,
    &'a [u8],
);

fn decode_blob_range_tuple(input: &[u8]) -> Result<DecodedBlobRangeTuple<'_>, NodeError> {
    let (direction, mut body) = decode_direction(input)?;
    let source = take_exact(&mut body, 32, "Blob source transfer identifier")?;
    let object = take_exact(&mut body, 33, "Blob carrier object identifier")?;
    let total = take_exact(&mut body, 8, "Blob carrier total length")?;
    let offset = take_exact(&mut body, 8, "Blob range offset")?;
    let requested = take_exact(&mut body, 4, "Blob requested range length")?;
    let source_id = BlobTransferId::new(source.try_into().map_err(|_| {
        NodeError::Protocol("Blob source transfer identifier length differs".into())
    })?);
    let object_id = BlobObjectId::decode(object)?;
    let total_len = u64::from_be_bytes(
        total
            .try_into()
            .map_err(|_| NodeError::Protocol("Blob carrier total length differs".into()))?,
    );
    let offset = u64::from_be_bytes(
        offset
            .try_into()
            .map_err(|_| NodeError::Protocol("Blob range offset differs".into()))?,
    );
    let requested_len = u32::from_be_bytes(
        requested
            .try_into()
            .map_err(|_| NodeError::Protocol("Blob requested range length differs".into()))?,
    );
    validate_blob_range_bounds(total_len, offset, requested_len)?;
    Ok((
        direction,
        source_id,
        object_id,
        total_len,
        offset,
        requested_len,
        body,
    ))
}

fn validate_blob_range_bounds(
    total_len: u64,
    offset: u64,
    requested_len: u32,
) -> Result<(), NodeError> {
    if total_len == 0 {
        return Err(NodeError::Protocol(
            "Blob carrier total length is zero".into(),
        ));
    }
    if requested_len == 0 || requested_len as usize > MAX_BLOB_RANGE_BYTES {
        return Err(NodeError::Protocol(format!(
            "Blob requested range length must be 1..={MAX_BLOB_RANGE_BYTES} bytes"
        )));
    }
    if offset >= total_len
        || offset
            .checked_add(u64::from(requested_len))
            .is_none_or(|end| end > total_len)
    {
        return Err(NodeError::Protocol(
            "Blob requested range exceeds the carrier length".into(),
        ));
    }
    Ok(())
}

fn encode_blob_range_payload(
    output: &mut Vec<u8>,
    disposition: BlobRangeDisposition,
    requested_len: u32,
    bytes: &[u8],
) -> Result<(), NodeError> {
    validate_blob_range_payload(disposition, requested_len, bytes)?;
    encode_bytes(output, bytes, MAX_BLOB_RANGE_BYTES, "Blob range")
}

fn validate_blob_range_payload(
    disposition: BlobRangeDisposition,
    requested_len: u32,
    bytes: &[u8],
) -> Result<(), NodeError> {
    match disposition {
        BlobRangeDisposition::Data
            if bytes.len()
                == usize::try_from(requested_len).expect("u32 range length fits usize") =>
        {
            Ok(())
        }
        BlobRangeDisposition::Unavailable if bytes.is_empty() => Ok(()),
        BlobRangeDisposition::Data => Err(NodeError::Protocol(
            "Blob Data range length differs from the exact request".into(),
        )),
        BlobRangeDisposition::Unavailable => Err(NodeError::Protocol(
            "unavailable Blob range must have an empty payload".into(),
        )),
    }
}

#[allow(clippy::too_many_arguments)]
fn encode_blob_range_result(
    output: &mut Vec<u8>,
    direction: EventDirection,
    source_id: BlobTransferId,
    object_id: BlobObjectId,
    total_len: u64,
    offset: u64,
    accepted_len: u32,
    disposition: BlobRangeApplyDisposition,
) -> Result<(), NodeError> {
    validate_blob_range_result(total_len, offset, accepted_len, disposition)?;
    output.push(direction.encode());
    output.extend_from_slice(source_id.as_bytes());
    output.extend_from_slice(object_id.as_bytes());
    output.extend_from_slice(&total_len.to_be_bytes());
    output.extend_from_slice(&offset.to_be_bytes());
    output.extend_from_slice(&accepted_len.to_be_bytes());
    output.push(disposition.encode());
    Ok(())
}

type DecodedBlobRangeResult = (
    EventDirection,
    BlobTransferId,
    BlobObjectId,
    u64,
    u64,
    u32,
    BlobRangeApplyDisposition,
);

fn decode_blob_range_result(input: &[u8]) -> Result<DecodedBlobRangeResult, NodeError> {
    if input.len() != 87 {
        return Err(NodeError::Protocol(
            "Blob range result length differs".into(),
        ));
    }
    let (direction, mut body) = decode_direction(input)?;
    let source = take_exact(&mut body, 32, "Blob source transfer identifier")?;
    let object = take_exact(&mut body, 33, "Blob carrier object identifier")?;
    let total = take_exact(&mut body, 8, "Blob carrier total length")?;
    let offset = take_exact(&mut body, 8, "Blob range offset")?;
    let accepted = take_exact(&mut body, 4, "Blob accepted range length")?;
    let disposition = BlobRangeApplyDisposition::decode(body[0])?;
    let source_id = BlobTransferId::new(source.try_into().map_err(|_| {
        NodeError::Protocol("Blob source transfer identifier length differs".into())
    })?);
    let object_id = BlobObjectId::decode(object)?;
    let total_len = u64::from_be_bytes(
        total
            .try_into()
            .map_err(|_| NodeError::Protocol("Blob carrier total length differs".into()))?,
    );
    let offset = u64::from_be_bytes(
        offset
            .try_into()
            .map_err(|_| NodeError::Protocol("Blob range offset differs".into()))?,
    );
    let accepted_len = u32::from_be_bytes(
        accepted
            .try_into()
            .map_err(|_| NodeError::Protocol("Blob accepted range length differs".into()))?,
    );
    validate_blob_range_result(total_len, offset, accepted_len, disposition)?;
    Ok((
        direction,
        source_id,
        object_id,
        total_len,
        offset,
        accepted_len,
        disposition,
    ))
}

fn validate_blob_range_result(
    total_len: u64,
    offset: u64,
    accepted_len: u32,
    disposition: BlobRangeApplyDisposition,
) -> Result<(), NodeError> {
    if total_len == 0 || offset >= total_len {
        return Err(NodeError::Protocol(
            "Blob range result bounds differ".into(),
        ));
    }
    match disposition {
        BlobRangeApplyDisposition::Partial | BlobRangeApplyDisposition::Complete
            if accepted_len == 0 || accepted_len as usize > MAX_BLOB_RANGE_BYTES =>
        {
            return Err(NodeError::Protocol(format!(
                "accepted Blob range length must be 1..={MAX_BLOB_RANGE_BYTES} bytes"
            )));
        }
        BlobRangeApplyDisposition::Duplicate
        | BlobRangeApplyDisposition::DeferredCapacity
        | BlobRangeApplyDisposition::Unavailable
            if accepted_len != 0 =>
        {
            return Err(NodeError::Protocol(
                "non-writing Blob range result must accept zero bytes".into(),
            ));
        }
        _ => {}
    }
    let end = offset
        .checked_add(u64::from(accepted_len))
        .ok_or_else(|| NodeError::Protocol("Blob accepted range end overflows".into()))?;
    if end > total_len {
        return Err(NodeError::Protocol(
            "accepted Blob range exceeds the carrier length".into(),
        ));
    }
    match disposition {
        BlobRangeApplyDisposition::Partial if end >= total_len => Err(NodeError::Protocol(
            "partial Blob range result reaches the carrier end".into(),
        )),
        BlobRangeApplyDisposition::Complete if end != total_len => Err(NodeError::Protocol(
            "complete Blob range result does not reach the carrier end".into(),
        )),
        _ => Ok(()),
    }
}

fn encode_blob_carrier_finish(
    output: &mut Vec<u8>,
    tag: u8,
    direction: EventDirection,
    remaining: u64,
) -> Result<(), NodeError> {
    if remaining > MAX_CARDINALITY_LIMIT as u64 {
        return Err(NodeError::Protocol(
            "Blob carrier remaining count exceeds the selected cardinality bound".into(),
        ));
    }
    output.push(tag);
    output.push(direction.encode());
    output.extend_from_slice(&remaining.to_be_bytes());
    Ok(())
}

fn decode_blob_carrier_finish(body: &[u8]) -> Result<(EventDirection, u64), NodeError> {
    let (direction, body) = decode_direction(body)?;
    if body.len() != 8 {
        return Err(NodeError::Protocol(
            "Blob carrier remaining count length differs".into(),
        ));
    }
    let remaining =
        u64::from_be_bytes(body.try_into().map_err(|_| {
            NodeError::Protocol("Blob carrier remaining count length differs".into())
        })?);
    if remaining > MAX_CARDINALITY_LIMIT as u64 {
        return Err(NodeError::Protocol(
            "Blob carrier remaining count exceeds the selected cardinality bound".into(),
        ));
    }
    Ok((direction, remaining))
}

fn encode_v3_finish(
    output: &mut Vec<u8>,
    tag: u8,
    direction: EventDirection,
    remaining: u64,
) -> Result<(), NodeError> {
    if remaining > MAX_CARDINALITY_LIMIT as u64 {
        return Err(NodeError::Protocol(
            "v3 Event lane remaining count exceeds the selected cardinality bound".into(),
        ));
    }
    output.push(tag);
    output.push(direction.encode());
    output.extend_from_slice(&remaining.to_be_bytes());
    Ok(())
}

fn encode_mutable_remaining(output: &mut Vec<u8>, remaining: u64) -> Result<(), NodeError> {
    if remaining > MAX_CARDINALITY_LIMIT as u64 {
        return Err(NodeError::Protocol(
            "mutable lane remaining count exceeds the selected cardinality bound".into(),
        ));
    }
    output.extend_from_slice(&remaining.to_be_bytes());
    Ok(())
}

fn decode_mutable_remaining(body: &[u8]) -> Result<u64, NodeError> {
    if body.len() != 8 {
        return Err(NodeError::Protocol(
            "mutable lane remaining count length differs".into(),
        ));
    }
    let remaining =
        u64::from_be_bytes(body.try_into().map_err(|_| {
            NodeError::Protocol("mutable lane remaining count length differs".into())
        })?);
    if remaining > MAX_CARDINALITY_LIMIT as u64 {
        return Err(NodeError::Protocol(
            "mutable lane remaining count exceeds the selected cardinality bound".into(),
        ));
    }
    Ok(remaining)
}

fn decode_v3_finish(body: &[u8]) -> Result<(EventDirection, u64), NodeError> {
    let (direction, body) = decode_direction(body)?;
    if body.len() != 8 {
        return Err(NodeError::Protocol(
            "v3 Event lane remaining count length differs".into(),
        ));
    }
    let remaining = u64::from_be_bytes(
        body.try_into()
            .map_err(|_| NodeError::Protocol("v3 Event lane remaining count differs".into()))?,
    );
    if remaining > MAX_CARDINALITY_LIMIT as u64 {
        return Err(NodeError::Protocol(
            "v3 Event lane remaining count exceeds the selected cardinality bound".into(),
        ));
    }
    Ok((direction, remaining))
}

fn encode_event_interest(output: &mut Vec<u8>, interest: &EventInterest) -> Result<(), NodeError> {
    if interest.len() > MAX_EVENT_INTEREST_SELECTORS {
        return Err(NodeError::Protocol(format!(
            "Event interest selector count exceeds {MAX_EVENT_INTEREST_SELECTORS}"
        )));
    }
    let count = u16::try_from(interest.len())
        .map_err(|_| NodeError::Protocol("Event interest selector count exceeds u16".into()))?;
    let start = output.len();
    output.extend_from_slice(&count.to_be_bytes());
    let mut previous = None;
    for selector in interest.selectors() {
        if previous.is_some_and(|previous| previous >= selector) {
            return Err(NodeError::Protocol(
                "Event interest selectors are not strictly canonical".into(),
            ));
        }
        encode_event_name(output, selector.topic().as_str(), "topic")?;
        encode_event_name(output, selector.scope().as_str(), "scope")?;
        output.push(u8::from(selector.include_descendant_scopes()));
        previous = Some(selector);
    }
    let encoded = output
        .len()
        .checked_sub(start)
        .ok_or_else(|| NodeError::Protocol("Event interest length underflow".into()))?;
    if encoded > MAX_EVENT_INTEREST_BYTES {
        return Err(NodeError::Protocol(format!(
            "Event interest exceeds {MAX_EVENT_INTEREST_BYTES} bytes"
        )));
    }
    Ok(())
}

fn require_selector_revision(
    interest: &EventInterest,
    selector_revision: u64,
) -> Result<(), NodeError> {
    let selector_count = u64::try_from(interest.len())
        .map_err(|_| NodeError::Protocol("Event interest selector count exceeds u64".into()))?;
    if selector_revision < selector_count {
        return Err(NodeError::Protocol(
            "v3 selector revision precedes its canonical Event interest".into(),
        ));
    }
    Ok(())
}

fn encode_event_name(output: &mut Vec<u8>, value: &str, label: &str) -> Result<(), NodeError> {
    if value.is_empty() || value.len() > MAX_EVENT_NAME_BYTES {
        return Err(NodeError::Protocol(format!(
            "Event interest {label} length is outside 1..={MAX_EVENT_NAME_BYTES}"
        )));
    }
    let length = u16::try_from(value.len())
        .map_err(|_| NodeError::Protocol("Event interest name exceeds u16".into()))?;
    output.extend_from_slice(&length.to_be_bytes());
    output.extend_from_slice(value.as_bytes());
    Ok(())
}

fn decode_event_interest(input: &[u8]) -> Result<EventInterest, NodeError> {
    if input.len() > MAX_EVENT_INTEREST_BYTES {
        return Err(NodeError::Protocol(format!(
            "Event interest exceeds {MAX_EVENT_INTEREST_BYTES} bytes"
        )));
    }
    let mut input = input;
    let count = usize::from(take_u16(&mut input, "Event interest selector count")?);
    if count > MAX_EVENT_INTEREST_SELECTORS {
        return Err(NodeError::Protocol(format!(
            "Event interest selector count exceeds {MAX_EVENT_INTEREST_SELECTORS}"
        )));
    }
    let mut selectors: Vec<EventInterestSelector> = Vec::with_capacity(count);
    for _ in 0..count {
        let topic = decode_event_topic(&mut input)?;
        let scope = decode_event_scope(&mut input)?;
        let include_descendant_scopes = match take_exact(&mut input, 1, "Event interest flags")?[0]
        {
            0 => false,
            1 => true,
            _ => {
                return Err(NodeError::Protocol(
                    "Event interest descendant flag is not boolean".into(),
                ));
            }
        };
        let selector = EventInterestSelector::new(topic, scope, include_descendant_scopes);
        if selectors
            .last()
            .is_some_and(|previous| previous >= &selector)
        {
            return Err(NodeError::Protocol(
                "Event interest selectors are not strictly canonical".into(),
            ));
        }
        selectors.push(selector);
    }
    if !input.is_empty() {
        return Err(NodeError::Protocol(
            "Event interest has trailing bytes".into(),
        ));
    }
    Ok(EventInterest(selectors))
}

fn encode_blob_interest(output: &mut Vec<u8>, interest: &BlobInterest) -> Result<(), NodeError> {
    if interest.len() > MAX_EVENT_INTEREST_SELECTORS {
        return Err(NodeError::Protocol(format!(
            "Blob interest selector count exceeds {MAX_EVENT_INTEREST_SELECTORS}"
        )));
    }
    let count = u16::try_from(interest.len())
        .map_err(|_| NodeError::Protocol("Blob interest selector count exceeds u16".into()))?;
    let start = output.len();
    output.extend_from_slice(&count.to_be_bytes());
    let mut previous: Option<&BlobInterestSelector> = None;
    for selector in interest.selectors() {
        if previous.is_some_and(|previous| previous >= selector) {
            return Err(NodeError::Protocol(
                "Blob interest selectors are not strictly canonical".into(),
            ));
        }
        if previous.is_some_and(|previous| {
            previous.topic() == selector.topic() && previous.scope() == selector.scope()
        }) {
            return Err(NodeError::Protocol(
                "Blob interest repeats an exact topic/scope selector".into(),
            ));
        }
        encode_event_name(output, selector.topic().as_str(), "Blob topic")?;
        encode_event_name(output, selector.scope().as_str(), "Blob scope")?;
        output.extend_from_slice(&selector.epoch().to_be_bytes());
        output.extend_from_slice(selector.content_proof());
        previous = Some(selector);
    }
    let encoded = output
        .len()
        .checked_sub(start)
        .ok_or_else(|| NodeError::Protocol("Blob interest length underflow".into()))?;
    if encoded > MAX_BLOB_INTEREST_BYTES {
        return Err(NodeError::Protocol(format!(
            "Blob interest exceeds {MAX_BLOB_INTEREST_BYTES} bytes"
        )));
    }
    Ok(())
}

fn decode_blob_interest(input: &[u8]) -> Result<BlobInterest, NodeError> {
    if input.len() > MAX_BLOB_INTEREST_BYTES {
        return Err(NodeError::Protocol(format!(
            "Blob interest exceeds {MAX_BLOB_INTEREST_BYTES} bytes"
        )));
    }
    let mut input = input;
    let count = usize::from(take_u16(&mut input, "Blob interest selector count")?);
    if count > MAX_EVENT_INTEREST_SELECTORS {
        return Err(NodeError::Protocol(format!(
            "Blob interest selector count exceeds {MAX_EVENT_INTEREST_SELECTORS}"
        )));
    }
    let mut selectors: Vec<BlobInterestSelector> = Vec::with_capacity(count);
    for _ in 0..count {
        let topic = decode_event_topic(&mut input)?;
        let scope = decode_event_scope(&mut input)?;
        let epoch = u64::from_be_bytes(
            take_exact(&mut input, 8, "Blob interest epoch")?
                .try_into()
                .map_err(|_| NodeError::Protocol("Blob interest epoch length differs".into()))?,
        );
        let content_proof = take_exact(
            &mut input,
            BLOB_CONTENT_PROOF_BYTES,
            "Blob interest content proof",
        )?
        .try_into()
        .map_err(|_| NodeError::Protocol("Blob interest content proof length differs".into()))?;
        let selector = BlobInterestSelector::new(topic, scope, epoch, content_proof);
        if let Some(previous) = selectors.last() {
            if previous >= &selector {
                return Err(NodeError::Protocol(
                    "Blob interest selectors are not strictly canonical".into(),
                ));
            }
            if previous.topic() == selector.topic() && previous.scope() == selector.scope() {
                return Err(NodeError::Protocol(
                    "Blob interest repeats an exact topic/scope selector".into(),
                ));
            }
        }
        selectors.push(selector);
    }
    if !input.is_empty() {
        return Err(NodeError::Protocol(
            "Blob interest has trailing bytes".into(),
        ));
    }
    Ok(BlobInterest(selectors))
}

fn decode_event_topic(input: &mut &[u8]) -> Result<Topic, NodeError> {
    let value = decode_event_name(input, "topic")?;
    Topic::new(value)
        .map_err(|_| NodeError::Protocol("Event interest topic is not canonical".into()))
}

fn decode_event_scope(input: &mut &[u8]) -> Result<Scope, NodeError> {
    let value = decode_event_name(input, "scope")?;
    Scope::new(value)
        .map_err(|_| NodeError::Protocol("Event interest scope is not canonical".into()))
}

fn decode_event_name(input: &mut &[u8], label: &str) -> Result<String, NodeError> {
    let length = usize::from(take_u16(input, "Event interest name length")?);
    if length == 0 || length > MAX_EVENT_NAME_BYTES {
        return Err(NodeError::Protocol(format!(
            "Event interest {label} length is outside 1..={MAX_EVENT_NAME_BYTES}"
        )));
    }
    let encoded = take_exact(input, length, "Event interest name")?;
    std::str::from_utf8(encoded)
        .map(str::to_owned)
        .map_err(|_| NodeError::Protocol(format!("Event interest {label} is not UTF-8")))
}

fn take_u16(input: &mut &[u8], label: &str) -> Result<u16, NodeError> {
    let bytes = take_exact(input, 2, label)?;
    Ok(u16::from_be_bytes(bytes.try_into().map_err(|_| {
        NodeError::Protocol(format!("{label} length differs"))
    })?))
}

fn take_exact<'a>(input: &mut &'a [u8], length: usize, label: &str) -> Result<&'a [u8], NodeError> {
    if input.len() < length {
        return Err(NodeError::Protocol(format!("{label} is truncated")));
    }
    let (head, tail) = input.split_at(length);
    *input = tail;
    Ok(head)
}

fn encode_mutable_lane(output: &mut Vec<u8>, class: MutableClass, direction: EventDirection) {
    output.push(class.encode());
    output.push(direction.encode());
}

fn encode_mutable_id(output: &mut Vec<u8>, direction: EventDirection, id: MutableTransferId) {
    encode_mutable_lane(output, id.class(), direction);
    output.extend_from_slice(id.as_bytes());
}

fn decode_mutable_class(input: &[u8]) -> Result<(MutableClass, &[u8]), NodeError> {
    let Some((&class, body)) = input.split_first() else {
        return Err(NodeError::Protocol(
            "mutable source-object class is missing".into(),
        ));
    };
    Ok((MutableClass::decode(class)?, body))
}

fn decode_mutable_lane(input: &[u8]) -> Result<(MutableClass, EventDirection, &[u8]), NodeError> {
    let (class, body) = decode_mutable_class(input)?;
    let (direction, body) = decode_direction(body)?;
    Ok((class, direction, body))
}

fn decode_mutable_lane_only(input: &[u8]) -> Result<(MutableClass, EventDirection), NodeError> {
    let (class, direction, body) = decode_mutable_lane(input)?;
    if !body.is_empty() {
        return Err(NodeError::Protocol(
            "mutable lane control has trailing bytes".into(),
        ));
    }
    Ok((class, direction))
}

fn decode_mutable_id(
    input: &[u8],
) -> Result<(EventDirection, MutableTransferId, &[u8]), NodeError> {
    let (class, direction, body) = decode_mutable_lane(input)?;
    if body.len() < 32 {
        return Err(NodeError::Protocol(
            "mutable transfer identifier is truncated".into(),
        ));
    }
    let bytes: [u8; 32] = body[..32]
        .try_into()
        .map_err(|_| NodeError::Protocol("mutable transfer identifier differs".into()))?;
    let id = match class {
        MutableClass::State => MutableTransferId::State(StateTransferId::new(bytes)),
        MutableClass::Record => MutableTransferId::Record(RecordTransferId::new(bytes)),
        MutableClass::Blob => MutableTransferId::Blob(BlobTransferId::new(bytes)),
    };
    Ok((direction, id, &body[32..]))
}

fn decode_direction(input: &[u8]) -> Result<(EventDirection, &[u8]), NodeError> {
    let Some((&direction, body)) = input.split_first() else {
        return Err(NodeError::Protocol("Event direction is missing".into()));
    };
    Ok((EventDirection::decode(direction)?, body))
}

fn decode_direction_only(input: &[u8]) -> Result<EventDirection, NodeError> {
    let (direction, body) = decode_direction(input)?;
    if !body.is_empty() {
        return Err(NodeError::Protocol(
            "directional Event control has trailing bytes".into(),
        ));
    }
    Ok(direction)
}

fn decode_control_id(input: &[u8]) -> Result<ControlTransferId, NodeError> {
    if input.len() != 32 {
        return Err(NodeError::Protocol(
            "control transfer identifier length differs".into(),
        ));
    }
    let mut bytes = [0u8; 32];
    bytes.copy_from_slice(input);
    Ok(ControlTransferId::new(bytes))
}

fn encode_bytes(
    output: &mut Vec<u8>,
    bytes: &[u8],
    maximum: usize,
    label: &str,
) -> Result<(), NodeError> {
    if bytes.len() > maximum {
        return Err(NodeError::Protocol(format!(
            "{label} body exceeds {maximum} bytes"
        )));
    }
    let length = u32::try_from(bytes.len())
        .map_err(|_| NodeError::Protocol("frame body exceeds u32".into()))?;
    output.extend_from_slice(&length.to_be_bytes());
    output.extend_from_slice(bytes);
    Ok(())
}

fn encode_blob_claim_field(
    output: &mut Vec<u8>,
    id: MutableTransferId,
    claim: Option<&BlobCustodyClaimV1>,
    include_v8_blob_fields: bool,
) -> Result<(), NodeError> {
    if id.class() != MutableClass::Blob {
        if claim.is_some() {
            return Err(NodeError::Protocol(
                "Blob custody claim crossed mutable classes".into(),
            ));
        }
        return Ok(());
    }
    if !include_v8_blob_fields {
        if claim.is_some() {
            return Err(NodeError::Protocol(
                "Blob custody claim requires semantic v8".into(),
            ));
        }
        return Ok(());
    }
    match claim {
        None => output.push(0),
        Some(claim) => {
            output.push(1);
            output.extend_from_slice(
                &u16::try_from(BLOB_CUSTODY_CLAIM_V1_BYTES)
                    .expect("fixed Blob custody claim length fits u16")
                    .to_be_bytes(),
            );
            output.extend_from_slice(&claim.encode());
        }
    }
    Ok(())
}

fn decode_blob_claim_field(input: &[u8]) -> Result<Option<BlobCustodyClaimV1>, NodeError> {
    match input {
        [0] => Ok(None),
        [1, length @ ..] if length.len() >= 2 => {
            let encoded_len = u16::from_be_bytes([length[0], length[1]]) as usize;
            let encoded = &length[2..];
            if encoded_len != BLOB_CUSTODY_CLAIM_V1_BYTES || encoded.len() != encoded_len {
                return Err(NodeError::Protocol(
                    "v8 Blob custody claim length differs".into(),
                ));
            }
            BlobCustodyClaimV1::decode(encoded)
                .map(Some)
                .map_err(|_| NodeError::Protocol("v8 Blob custody claim is invalid".into()))
        }
        [] => Err(NodeError::Protocol(
            "v8 Blob custody claim presence is missing".into(),
        )),
        _ => Err(NodeError::Protocol(
            "v8 Blob custody claim field differs".into(),
        )),
    }
}

fn encode_blob_digest_field(
    output: &mut Vec<u8>,
    id: MutableTransferId,
    digest: Option<&[u8; 32]>,
    include_v8_blob_fields: bool,
) -> Result<(), NodeError> {
    if id.class() != MutableClass::Blob {
        if digest.is_some() {
            return Err(NodeError::Protocol(
                "Blob custody digest crossed mutable classes".into(),
            ));
        }
        return Ok(());
    }
    if !include_v8_blob_fields {
        if digest.is_some() {
            return Err(NodeError::Protocol(
                "Blob custody digest requires semantic v8".into(),
            ));
        }
        return Ok(());
    }
    match digest {
        None => output.push(0),
        Some(digest) => {
            output.push(1);
            output.extend_from_slice(digest);
        }
    }
    Ok(())
}

fn decode_blob_digest_field(input: &[u8]) -> Result<Option<[u8; 32]>, NodeError> {
    match input {
        [0] => Ok(None),
        [1, digest @ ..] if digest.len() == 32 => {
            Ok(Some(digest.try_into().map_err(|_| {
                NodeError::Protocol("v8 Blob custody digest length differs".into())
            })?))
        }
        [] => Err(NodeError::Protocol(
            "v8 Blob custody digest presence is missing".into(),
        )),
        _ => Err(NodeError::Protocol(
            "v8 Blob custody digest field differs".into(),
        )),
    }
}

fn decode_bytes<'a>(input: &'a [u8], maximum: usize, label: &str) -> Result<&'a [u8], NodeError> {
    if input.len() < 4 {
        return Err(NodeError::Protocol(
            "length-prefixed body is truncated".into(),
        ));
    }
    let length = u32::from_be_bytes(
        input[..4]
            .try_into()
            .map_err(|_| NodeError::Protocol("body length differs".into()))?,
    ) as usize;
    if length > maximum {
        return Err(NodeError::Protocol(format!(
            "{label} body exceeds {maximum} bytes"
        )));
    }
    let expected = 4usize
        .checked_add(length)
        .ok_or_else(|| NodeError::Protocol("body length overflows usize".into()))?;
    if input.len() != expected {
        return Err(NodeError::Protocol("body length differs".into()));
    }
    Ok(&input[4..])
}

fn decode_leading_bytes<'a>(
    input: &'a [u8],
    maximum: usize,
    label: &str,
) -> Result<(&'a [u8], &'a [u8]), NodeError> {
    if input.len() < 4 {
        return Err(NodeError::Protocol(format!("{label} length is truncated")));
    }
    let length = u32::from_be_bytes(
        input[..4]
            .try_into()
            .map_err(|_| NodeError::Protocol(format!("{label} length differs")))?,
    ) as usize;
    if length > maximum {
        return Err(NodeError::Protocol(format!(
            "{label} body exceeds {maximum} bytes"
        )));
    }
    let end = 4usize
        .checked_add(length)
        .ok_or_else(|| NodeError::Protocol(format!("{label} length overflows usize")))?;
    if input.len() < end {
        return Err(NodeError::Protocol(format!("{label} is truncated")));
    }
    Ok((&input[4..end], &input[end..]))
}

fn decode_exact_id(input: &[u8]) -> Result<EventTransferId, NodeError> {
    if input.len() != 32 {
        return Err(NodeError::Protocol(
            "Event transfer identifier length differs".into(),
        ));
    }
    let mut bytes = [0u8; 32];
    bytes.copy_from_slice(input);
    Ok(EventTransferId::new(bytes))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn selector(topic: &str, scope: &str, descendants: bool) -> EventInterestSelector {
        EventInterestSelector::new(
            Topic::new(topic).expect("topic"),
            Scope::new(scope).expect("scope"),
            descendants,
        )
    }

    #[test]
    fn every_frame_round_trips_and_rejects_trailing_bytes() {
        let id = EventTransferId::new([0x44; 32]);
        let control_id = ControlTransferId::new([0x55; 32]);
        let state_id = MutableTransferId::State(StateTransferId::new([0x66; 32]));
        let record_id = MutableTransferId::Record(RecordTransferId::new([0x77; 32]));
        let blob_source = BlobTransferId::new([0x88; 32]);
        let blob_id = MutableTransferId::Blob(blob_source);
        let blob_object = BlobObjectId::new([0x99; 32]);
        let blob_interest = BlobInterest::new(vec![BlobInterestSelector::new(
            Topic::new("blob").expect("Blob topic"),
            Scope::new("mission/blob").expect("Blob scope"),
            9,
            [0xab; BLOB_CONTENT_PROOF_BYTES],
        )])
        .expect("Blob interest");
        let interest = EventInterest::new(vec![
            selector("zulu", "mission/bravo", true),
            selector("alpha", "mission/alpha", false),
        ])
        .expect("interest");
        let to_initiator = EventDirection::ToSessionInitiator;
        let to_responder = EventDirection::ToSessionResponder;
        let frames = [
            Frame::EventInterest(EventInterest::empty()),
            Frame::EventInterestV3 {
                interest: EventInterest::empty(),
                selector_revision: 0,
                policy: FrameEmissionPolicy::Normal,
                policy_revision: 5,
            },
            Frame::EventInterestReply(interest.clone()),
            Frame::EventInterestReplyV3 {
                interest,
                selector_revision: 11,
                policy: FrameEmissionPolicy::AtLeast(Priority::Immediate),
                policy_revision: 7,
            },
            Frame::BlobInterest(blob_interest.clone()),
            Frame::BlobInterestReply(blob_interest),
            Frame::InventoryQuery {
                direction: to_responder,
                bytes: vec![1, 2],
            },
            Frame::InventoryReply {
                direction: to_responder,
                bytes: vec![3, 4],
            },
            Frame::InventoryComplete {
                direction: to_responder,
            },
            Frame::InventoryCompleteAck {
                direction: to_responder,
            },
            Frame::DifferenceQuery {
                direction: to_responder,
                bytes: vec![5, 6],
            },
            Frame::DifferenceReply {
                direction: to_responder,
                bytes: vec![7, 8],
            },
            Frame::DifferenceBound {
                direction: to_responder,
            },
            Frame::DifferenceBoundAck {
                direction: to_responder,
            },
            Frame::EventLaneDeferred {
                direction: to_responder,
            },
            Frame::EventLaneDeferredAck {
                direction: to_initiator,
            },
            Frame::Fetch {
                direction: to_initiator,
                id,
            },
            Frame::Object {
                direction: to_initiator,
                id,
                bytes: b"object".to_vec(),
            },
            Frame::Offer {
                direction: to_responder,
                id,
                bytes: b"offer".to_vec(),
            },
            Frame::OfferV3 {
                direction: to_responder,
                id,
                exchange_id: 17,
                custody: b"bounded-custody-offer".to_vec(),
                bytes: b"v3-offer".to_vec(),
            },
            Frame::ApplyResult {
                direction: to_responder,
                id,
                inserted: true,
            },
            Frame::ApplyResultV3 {
                direction: to_responder,
                id,
                exchange_id: 17,
                inserted: false,
                disposition: EventApplyDisposition::ContentAcceptancePending,
            },
            Frame::ControlInventoryQuery(vec![9, 10]),
            Frame::ControlInventoryReply(vec![11, 12]),
            Frame::ControlInventoryReplyV3 {
                bytes: vec![11, 12],
                policy: FrameEmissionPolicy::ReceiveOnly,
                policy_revision: 9,
            },
            Frame::ControlInventoryComplete,
            Frame::ControlInventoryCompleteAck,
            Frame::ControlDifferenceQuery(vec![13, 14]),
            Frame::ControlDifferenceReply(vec![15, 16]),
            Frame::ControlDifferenceBound,
            Frame::ControlDifferenceBoundAck,
            Frame::ControlFetch(control_id),
            Frame::ControlObject {
                id: control_id,
                bytes: b"control-object".to_vec(),
            },
            Frame::ControlOffer {
                id: control_id,
                bytes: b"control-offer".to_vec(),
            },
            Frame::ControlApplyResult {
                id: control_id,
                retained: true,
            },
            Frame::ControlFinish,
            Frame::ControlFinished,
            Frame::Finish {
                direction: to_responder,
            },
            Frame::Finished {
                direction: to_initiator,
            },
            Frame::FinishV3 {
                direction: to_responder,
                remaining: 17,
            },
            Frame::FinishedV3 {
                direction: to_initiator,
                remaining: 17,
            },
            Frame::MutableInterest {
                class: MutableClass::State,
                interest: EventInterest::empty(),
            },
            Frame::MutableInterestReply {
                class: MutableClass::Record,
                interest: EventInterest::new(vec![selector("record", "mission/record", false)])
                    .expect("mutable interest"),
            },
            Frame::MutableInventoryQuery {
                class: MutableClass::State,
                direction: to_responder,
                bytes: vec![17, 18],
            },
            Frame::MutableInventoryReply {
                class: MutableClass::Record,
                direction: to_initiator,
                bytes: vec![19, 20],
            },
            Frame::MutableInventoryComplete {
                class: MutableClass::State,
                direction: to_responder,
            },
            Frame::MutableInventoryCompleteAck {
                class: MutableClass::State,
                direction: to_responder,
            },
            Frame::MutableDifferenceQuery {
                class: MutableClass::Record,
                direction: to_initiator,
                bytes: vec![21, 22],
            },
            Frame::MutableDifferenceReply {
                class: MutableClass::Record,
                direction: to_initiator,
                bytes: vec![23, 24],
            },
            Frame::MutableDifferenceBound {
                class: MutableClass::State,
                direction: to_responder,
            },
            Frame::MutableDifferenceBoundAck {
                class: MutableClass::State,
                direction: to_responder,
            },
            Frame::MutableLaneDeferred {
                class: MutableClass::State,
                direction: to_responder,
            },
            Frame::MutableLaneDeferredAck {
                class: MutableClass::Record,
                direction: to_initiator,
            },
            Frame::MutableFetch {
                direction: to_initiator,
                id: state_id,
            },
            Frame::MutableObject {
                direction: to_initiator,
                id: state_id,
                bytes: b"state".to_vec(),
                claim: None,
            },
            Frame::MutableOffer {
                direction: to_responder,
                id: record_id,
                bytes: b"record".to_vec(),
                claim: None,
            },
            Frame::MutableApplyResult {
                direction: to_responder,
                id: record_id,
                disposition: MutableApplyDisposition::Inserted,
                custody_digest: None,
            },
            Frame::MutableFetchResult {
                direction: to_initiator,
                id: state_id,
                disposition: MutableApplyDisposition::DeferredCapacity,
                custody_digest: None,
            },
            Frame::MutableFetchResultAck {
                direction: to_initiator,
                id: state_id,
                disposition: MutableApplyDisposition::DeferredCapacity,
                custody_digest: None,
            },
            Frame::MutableFinish {
                class: MutableClass::Record,
                direction: to_initiator,
                remaining: 17,
            },
            Frame::MutableFinished {
                class: MutableClass::Record,
                direction: to_initiator,
                remaining: 17,
            },
            Frame::MutableFetch {
                direction: to_initiator,
                id: blob_id,
            },
            Frame::BlobRangeFetch {
                direction: to_initiator,
                source_id: blob_source,
                object_id: blob_object,
                total_len: 8,
                offset: 0,
                requested_len: 4,
                content_proof: [0xaa; BLOB_CONTENT_PROOF_BYTES],
            },
            Frame::BlobRange {
                direction: to_initiator,
                source_id: blob_source,
                object_id: blob_object,
                total_len: 8,
                offset: 0,
                requested_len: 4,
                disposition: BlobRangeDisposition::Data,
                bytes: vec![1, 2, 3, 4],
            },
            Frame::BlobRange {
                direction: to_initiator,
                source_id: blob_source,
                object_id: blob_object,
                total_len: 8,
                offset: 4,
                requested_len: 4,
                disposition: BlobRangeDisposition::Unavailable,
                bytes: Vec::new(),
            },
            Frame::BlobRangeResult {
                direction: to_initiator,
                source_id: blob_source,
                object_id: blob_object,
                total_len: 8,
                offset: 0,
                accepted_len: 4,
                disposition: BlobRangeApplyDisposition::Partial,
            },
            Frame::BlobRangeResultAck {
                direction: to_initiator,
                source_id: blob_source,
                object_id: blob_object,
                total_len: 8,
                offset: 4,
                accepted_len: 4,
                disposition: BlobRangeApplyDisposition::Complete,
            },
            Frame::BlobCarrierFinish {
                direction: to_initiator,
                remaining: 1,
            },
            Frame::BlobCarrierFinished {
                direction: to_initiator,
                remaining: 0,
            },
            Frame::BridgeHello { enabled: true },
            Frame::BridgeHelloAck { enabled: false },
            Frame::BridgeRouteOffer {
                wrapper_id: [0xca; 32],
                wrapper: b"bridge-wrapper".to_vec(),
                source: b"bridge-source".to_vec(),
            },
            Frame::BridgeRouteResult {
                wrapper_id: [0xca; 32],
                disposition: BridgeRouteDisposition::Promoted,
            },
            Frame::BridgeFinish { remaining: 1 },
            Frame::BridgeFinished { remaining: 0 },
        ];
        for frame in frames {
            let encoded = frame.encode().expect("encode");
            assert_eq!(Frame::decode(&encoded).expect("decode"), frame);
            let mut trailing = encoded;
            trailing.push(0);
            assert!(Frame::decode(&trailing).is_err());
        }
    }

    #[test]
    fn unknown_version_and_tag_fail_closed() {
        assert!(Frame::decode(b"BAD!\x11\0\0\0\0").is_err());
        assert!(Frame::decode(b"ASM\x01\xff").is_err());
    }

    #[test]
    fn mutable_finish_remaining_is_bounded_and_exact() {
        let frame = Frame::MutableFinish {
            class: MutableClass::State,
            direction: EventDirection::ToSessionResponder,
            remaining: MAX_CARDINALITY_LIMIT as u64,
        };
        let encoded = frame.encode().expect("encode bounded mutable finish");
        assert_eq!(
            Frame::decode(&encoded).expect("decode mutable finish"),
            frame
        );

        assert!(
            Frame::MutableFinished {
                class: MutableClass::Record,
                direction: EventDirection::ToSessionInitiator,
                remaining: MAX_CARDINALITY_LIMIT as u64 + 1,
            }
            .encode()
            .is_err()
        );

        let mut truncated = encoded;
        truncated.pop();
        assert!(Frame::decode(&truncated).is_err());
    }

    #[test]
    fn mutable_apply_dispositions_use_one_bounded_outcome_byte() {
        let id = MutableTransferId::State(StateTransferId::new([0x5a; 32]));
        for (disposition, encoded_outcome) in [
            (MutableApplyDisposition::Duplicate, 0),
            (MutableApplyDisposition::Inserted, 1),
            (MutableApplyDisposition::DeferredCapacity, 2),
        ] {
            let frame = Frame::MutableApplyResult {
                direction: EventDirection::ToSessionResponder,
                id,
                disposition,
                custody_digest: None,
            };
            let encoded = frame.encode().expect("encode mutable apply result");
            assert_eq!(encoded.last().copied(), Some(encoded_outcome));
            assert_eq!(Frame::decode(&encoded).expect("decode disposition"), frame);
        }

        let mut unknown = Frame::MutableApplyResult {
            direction: EventDirection::ToSessionResponder,
            id,
            disposition: MutableApplyDisposition::Inserted,
            custody_digest: None,
        }
        .encode()
        .expect("encode mutable apply result");
        *unknown.last_mut().expect("outcome byte") = 3;
        assert!(Frame::decode(&unknown).is_err());
    }

    #[test]
    fn mutable_fetch_result_codec_binds_tag_class_direction_id_and_disposition() {
        let id = MutableTransferId::State(StateTransferId::new([0x5a; 32]));
        for disposition in [
            MutableApplyDisposition::Duplicate,
            MutableApplyDisposition::Inserted,
            MutableApplyDisposition::DeferredCapacity,
        ] {
            let result = Frame::MutableFetchResult {
                direction: EventDirection::ToSessionInitiator,
                id,
                disposition,
                custody_digest: None,
            };
            let ack = Frame::MutableFetchResultAck {
                direction: EventDirection::ToSessionInitiator,
                id,
                disposition,
                custody_digest: None,
            };
            let encoded_result = result.encode().expect("encode mutable fetch result");
            let encoded_ack = ack.encode().expect("encode mutable fetch result ack");
            assert_eq!(encoded_result.len(), 40);
            assert_eq!(encoded_ack.len(), 40);
            assert_eq!(encoded_result[4], MUTABLE_FETCH_RESULT);
            assert_eq!(encoded_ack[4], MUTABLE_FETCH_RESULT_ACK);
            assert_eq!(&encoded_result[5..], &encoded_ack[5..]);
            assert_eq!(
                Frame::decode(&encoded_result).expect("decode mutable fetch result"),
                result
            );
            assert_eq!(
                Frame::decode(&encoded_ack).expect("decode mutable fetch result ack"),
                ack
            );
        }

        let result = Frame::MutableFetchResult {
            direction: EventDirection::ToSessionInitiator,
            id,
            disposition: MutableApplyDisposition::DeferredCapacity,
            custody_digest: None,
        };
        let encoded = result.encode().expect("encode exact fetch-result tuple");

        let mut wrong_tag = encoded.clone();
        wrong_tag[4] = MUTABLE_FETCH_RESULT_ACK;
        assert_eq!(
            Frame::decode(&wrong_tag).expect("decode result as acknowledgement"),
            Frame::MutableFetchResultAck {
                direction: EventDirection::ToSessionInitiator,
                id,
                disposition: MutableApplyDisposition::DeferredCapacity,
                custody_digest: None,
            }
        );

        let mut wrong_class = encoded.clone();
        wrong_class[5] = MutableClass::Record.encode();
        assert_ne!(
            Frame::decode(&wrong_class).expect("decode wrong-class fetch result"),
            result
        );

        let mut wrong_direction = encoded.clone();
        wrong_direction[6] = EventDirection::ToSessionResponder.encode();
        assert_ne!(
            Frame::decode(&wrong_direction).expect("decode wrong-direction fetch result"),
            result
        );

        let mut wrong_id = encoded.clone();
        wrong_id[7] ^= 1;
        assert_ne!(
            Frame::decode(&wrong_id).expect("decode wrong-id fetch result"),
            result
        );

        let mut wrong_disposition = encoded.clone();
        *wrong_disposition.last_mut().expect("disposition byte") =
            MutableApplyDisposition::Inserted.encode();
        assert_ne!(
            Frame::decode(&wrong_disposition).expect("decode wrong-disposition fetch result"),
            result
        );

        let mut unknown_disposition = encoded.clone();
        *unknown_disposition.last_mut().expect("disposition byte") = 3;
        assert!(Frame::decode(&unknown_disposition).is_err());

        let mut trailing = encoded.clone();
        trailing.push(0);
        assert!(Frame::decode(&trailing).is_err());

        let mut truncated = encoded;
        truncated.pop();
        assert!(Frame::decode(&truncated).is_err());
    }

    #[test]
    fn blob_source_class_and_chunk_object_id_are_exactly_typed() {
        let source = BlobTransferId::new([0x5b; 32]);
        let frame = Frame::MutableFetch {
            direction: EventDirection::ToSessionInitiator,
            id: MutableTransferId::Blob(source),
        };
        let encoded = frame.encode().expect("encode Blob source fetch");
        assert_eq!(encoded[5], 3);
        assert_eq!(
            Frame::decode(&encoded).expect("decode Blob source fetch"),
            frame
        );

        let blob_interest = BlobInterest::new(vec![BlobInterestSelector::new(
            Topic::new("blob").expect("Blob topic"),
            Scope::new("mission/blob").expect("Blob scope"),
            7,
            [0x5c; BLOB_CONTENT_PROOF_BYTES],
        )])
        .expect("Blob interest");
        for source_frame in [
            Frame::BlobInterest(blob_interest.clone()),
            Frame::BlobInterestReply(blob_interest),
            Frame::MutableInventoryQuery {
                class: MutableClass::Blob,
                direction: EventDirection::ToSessionInitiator,
                bytes: vec![1, 2, 3],
            },
            Frame::MutableFinish {
                class: MutableClass::Blob,
                direction: EventDirection::ToSessionInitiator,
                remaining: 1,
            },
        ] {
            let encoded = source_frame.encode().expect("encode Blob source phase");
            assert_eq!(
                Frame::decode(&encoded).expect("decode Blob source phase"),
                source_frame
            );
        }

        let object = BlobObjectId::new([0x6c; 32]);
        assert_eq!(object.as_bytes()[0], 2);
        assert_eq!(&object.as_bytes()[1..], &[0x6c; 32]);

        let mut wrong_kind = Frame::BlobRangeFetch {
            direction: EventDirection::ToSessionInitiator,
            source_id: source,
            object_id: object,
            total_len: 1,
            offset: 0,
            requested_len: 1,
            content_proof: [0x6d; BLOB_CONTENT_PROOF_BYTES],
        }
        .encode()
        .expect("encode Blob fetch");
        assert_eq!(wrong_kind.len(), 123);
        assert_eq!(&wrong_kind[91..], &[0x6d; BLOB_CONTENT_PROOF_BYTES]);
        wrong_kind[38] = 1;
        assert!(Frame::decode(&wrong_kind).is_err());
        wrong_kind[38] = 0xff;
        assert!(Frame::decode(&wrong_kind).is_err());

        assert!(
            Frame::MutableInterest {
                class: MutableClass::Blob,
                interest: EventInterest::empty(),
            }
            .encode()
            .is_err()
        );
    }

    #[test]
    fn blob_interest_is_exact_canonical_and_proof_bound() {
        assert_eq!(MAX_BLOB_INTEREST_BYTES, 76_802);
        let alpha = BlobInterestSelector::new(
            Topic::new("alpha").expect("topic"),
            Scope::new("mission/alpha").expect("scope"),
            7,
            [0xa1; BLOB_CONTENT_PROOF_BYTES],
        );
        let bravo = BlobInterestSelector::new(
            Topic::new("bravo").expect("topic"),
            Scope::new("mission/bravo").expect("scope"),
            8,
            [0xb2; BLOB_CONTENT_PROOF_BYTES],
        );
        let interest = BlobInterest::new(vec![bravo.clone(), alpha.clone(), alpha.clone()])
            .expect("canonical Blob interest");
        assert_eq!(interest.selectors(), &[alpha.clone(), bravo.clone()]);
        assert_eq!(
            interest
                .selector(alpha.topic(), alpha.scope())
                .expect("exact selector")
                .content_proof(),
            &[0xa1; BLOB_CONTENT_PROOF_BYTES]
        );
        assert!(!interest.is_empty());

        assert!(
            BlobInterest::new(vec![
                alpha.clone(),
                BlobInterestSelector::new(
                    alpha.topic().clone(),
                    alpha.scope().clone(),
                    9,
                    [0xc3; BLOB_CONTENT_PROOF_BYTES],
                ),
            ])
            .is_err()
        );

        let frame = Frame::BlobInterest(interest);
        let encoded = frame.encode().expect("encode Blob interest");
        assert_eq!(
            Frame::decode(&encoded).expect("decode Blob interest"),
            frame
        );

        let mut noncanonical = encoded.clone();
        let selector_len = 2 + 5 + 2 + 13 + 8 + BLOB_CONTENT_PROOF_BYTES;
        let first = noncanonical[7..7 + selector_len].to_vec();
        let second = noncanonical[7 + selector_len..7 + 2 * selector_len].to_vec();
        noncanonical[7..7 + selector_len].copy_from_slice(&second);
        noncanonical[7 + selector_len..7 + 2 * selector_len].copy_from_slice(&first);
        assert!(Frame::decode(&noncanonical).is_err());

        let mut truncated_proof =
            Frame::BlobInterestReply(BlobInterest::new(vec![alpha]).expect("single Blob interest"))
                .encode()
                .expect("encode Blob interest proof");
        truncated_proof.pop();
        assert!(Frame::decode(&truncated_proof).is_err());
    }

    #[test]
    fn blob_range_fetch_and_data_enforce_exact_bounded_ranges() {
        let source_id = BlobTransferId::new([0x71; 32]);
        let object_id = BlobObjectId::new([0x72; 32]);
        let maximum = Frame::BlobRange {
            direction: EventDirection::ToSessionInitiator,
            source_id,
            object_id,
            total_len: MAX_BLOB_RANGE_BYTES as u64,
            offset: 0,
            requested_len: MAX_BLOB_RANGE_BYTES as u32,
            disposition: BlobRangeDisposition::Data,
            bytes: vec![0x73; MAX_BLOB_RANGE_BYTES],
        };
        let encoded = maximum.encode().expect("encode maximum Blob range");
        assert_eq!(
            Frame::decode(&encoded).expect("decode maximum Blob range"),
            maximum
        );

        for invalid in [
            Frame::BlobRangeFetch {
                direction: EventDirection::ToSessionInitiator,
                source_id,
                object_id,
                total_len: 0,
                offset: 0,
                requested_len: 1,
                content_proof: [0x74; BLOB_CONTENT_PROOF_BYTES],
            },
            Frame::BlobRangeFetch {
                direction: EventDirection::ToSessionInitiator,
                source_id,
                object_id,
                total_len: 1,
                offset: 0,
                requested_len: 0,
                content_proof: [0x74; BLOB_CONTENT_PROOF_BYTES],
            },
            Frame::BlobRangeFetch {
                direction: EventDirection::ToSessionInitiator,
                source_id,
                object_id,
                total_len: MAX_BLOB_RANGE_BYTES as u64 + 1,
                offset: 0,
                requested_len: MAX_BLOB_RANGE_BYTES as u32 + 1,
                content_proof: [0x74; BLOB_CONTENT_PROOF_BYTES],
            },
            Frame::BlobRangeFetch {
                direction: EventDirection::ToSessionInitiator,
                source_id,
                object_id,
                total_len: 8,
                offset: 4,
                requested_len: 5,
                content_proof: [0x74; BLOB_CONTENT_PROOF_BYTES],
            },
        ] {
            assert!(invalid.encode().is_err());
        }

        assert!(
            Frame::BlobRange {
                direction: EventDirection::ToSessionInitiator,
                source_id,
                object_id,
                total_len: 4,
                offset: 0,
                requested_len: 4,
                disposition: BlobRangeDisposition::Data,
                bytes: vec![0; 3],
            }
            .encode()
            .is_err()
        );
        assert!(
            Frame::BlobRange {
                direction: EventDirection::ToSessionInitiator,
                source_id,
                object_id,
                total_len: 4,
                offset: 0,
                requested_len: 4,
                disposition: BlobRangeDisposition::Unavailable,
                bytes: vec![0],
            }
            .encode()
            .is_err()
        );

        let mut noncanonical = Frame::BlobRange {
            direction: EventDirection::ToSessionInitiator,
            source_id,
            object_id,
            total_len: 4,
            offset: 0,
            requested_len: 4,
            disposition: BlobRangeDisposition::Data,
            bytes: vec![0; 4],
        }
        .encode()
        .expect("encode exact Blob range");
        noncanonical[92..96].copy_from_slice(&3u32.to_be_bytes());
        noncanonical.pop();
        assert!(Frame::decode(&noncanonical).is_err());

        let mut unknown = encoded;
        unknown[91] = 0xff;
        assert!(Frame::decode(&unknown).is_err());
    }

    #[test]
    fn blob_range_result_and_ack_bind_exact_canonical_outcome() {
        let source_id = BlobTransferId::new([0x81; 32]);
        let object_id = BlobObjectId::new([0x82; 32]);
        let cases = [
            (BlobRangeApplyDisposition::Partial, 8, 0, 4),
            (BlobRangeApplyDisposition::Complete, 8, 4, 4),
            (BlobRangeApplyDisposition::Duplicate, 8, 0, 0),
            (BlobRangeApplyDisposition::DeferredCapacity, 8, 0, 0),
            (BlobRangeApplyDisposition::Unavailable, 8, 0, 0),
        ];
        for (disposition, total_len, offset, accepted_len) in cases {
            let result = Frame::BlobRangeResult {
                direction: EventDirection::ToSessionInitiator,
                source_id,
                object_id,
                total_len,
                offset,
                accepted_len,
                disposition,
            };
            let ack = Frame::BlobRangeResultAck {
                direction: EventDirection::ToSessionInitiator,
                source_id,
                object_id,
                total_len,
                offset,
                accepted_len,
                disposition,
            };
            let encoded_result = result.encode().expect("encode Blob range result");
            let encoded_ack = ack.encode().expect("encode Blob range result ack");
            assert_eq!(encoded_result.len(), 92);
            assert_eq!(encoded_ack.len(), 92);
            assert_eq!(&encoded_result[5..], &encoded_ack[5..]);
            assert_eq!(
                Frame::decode(&encoded_result).expect("decode result"),
                result
            );
            assert_eq!(Frame::decode(&encoded_ack).expect("decode ack"), ack);
        }

        for invalid in [
            Frame::BlobRangeResult {
                direction: EventDirection::ToSessionInitiator,
                source_id,
                object_id,
                total_len: 8,
                offset: 0,
                accepted_len: 0,
                disposition: BlobRangeApplyDisposition::Partial,
            },
            Frame::BlobRangeResult {
                direction: EventDirection::ToSessionInitiator,
                source_id,
                object_id,
                total_len: 8,
                offset: 0,
                accepted_len: 1,
                disposition: BlobRangeApplyDisposition::Duplicate,
            },
            Frame::BlobRangeResult {
                direction: EventDirection::ToSessionInitiator,
                source_id,
                object_id,
                total_len: 8,
                offset: 0,
                accepted_len: 1,
                disposition: BlobRangeApplyDisposition::Unavailable,
            },
            Frame::BlobRangeResult {
                direction: EventDirection::ToSessionInitiator,
                source_id,
                object_id,
                total_len: 8,
                offset: 0,
                accepted_len: 8,
                disposition: BlobRangeApplyDisposition::Partial,
            },
            Frame::BlobRangeResult {
                direction: EventDirection::ToSessionInitiator,
                source_id,
                object_id,
                total_len: 8,
                offset: 0,
                accepted_len: 4,
                disposition: BlobRangeApplyDisposition::Complete,
            },
        ] {
            assert!(invalid.encode().is_err());
        }

        let mut unknown = Frame::BlobRangeResult {
            direction: EventDirection::ToSessionInitiator,
            source_id,
            object_id,
            total_len: 8,
            offset: 4,
            accepted_len: 4,
            disposition: BlobRangeApplyDisposition::Complete,
        }
        .encode()
        .expect("encode Blob result");
        *unknown.last_mut().expect("disposition") = 0xff;
        assert!(Frame::decode(&unknown).is_err());
    }

    #[test]
    fn blob_carrier_finish_remaining_is_bounded_and_exact() {
        let frame = Frame::BlobCarrierFinish {
            direction: EventDirection::ToSessionInitiator,
            remaining: MAX_CARDINALITY_LIMIT as u64,
        };
        let encoded = frame.encode().expect("encode Blob carrier finish");
        assert_eq!(
            Frame::decode(&encoded).expect("decode Blob carrier finish"),
            frame
        );
        assert!(
            Frame::BlobCarrierFinished {
                direction: EventDirection::ToSessionInitiator,
                remaining: MAX_CARDINALITY_LIMIT as u64 + 1,
            }
            .encode()
            .is_err()
        );
    }

    #[test]
    fn v3_custody_prefix_is_bounded_before_payload_parsing() {
        let frame = Frame::OfferV3 {
            direction: EventDirection::ToSessionResponder,
            id: EventTransferId::new([0x73; 32]),
            exchange_id: 99,
            custody: vec![0x44; 8],
            bytes: b"stable-source".to_vec(),
        };
        let mut encoded = frame.encode().expect("encode v3 offer");
        encoded[46..50].copy_from_slice(
            &u32::try_from(MAX_CUSTODY_WRAPPER_BYTES + 1)
                .expect("custody bound fits u32")
                .to_be_bytes(),
        );
        assert!(Frame::decode(&encoded).is_err());
        assert!(frame.serves_application_or_control_object());
    }

    #[test]
    fn tag_specific_plaintext_limits_reject_before_body_clone() {
        let oversized = vec![0u8; MAX_OBJECT_BYTES + 1];
        let event_id = EventTransferId::new([0x61; 32]);
        let control_id = ControlTransferId::new([0x62; 32]);
        assert!(
            Frame::Object {
                direction: EventDirection::ToSessionInitiator,
                id: event_id,
                bytes: oversized.clone(),
            }
            .encode()
            .is_err()
        );
        assert!(
            Frame::ControlOffer {
                id: control_id,
                bytes: oversized.clone(),
            }
            .encode()
            .is_err()
        );
        assert!(
            Frame::OfferV3 {
                direction: EventDirection::ToSessionResponder,
                id: event_id,
                exchange_id: 1,
                custody: vec![0u8; MAX_CUSTODY_WRAPPER_BYTES + 1],
                bytes: Vec::new(),
            }
            .encode()
            .is_err()
        );

        for (tag, id) in [
            (OBJECT, event_id.as_bytes()),
            (CONTROL_OBJECT, control_id.as_bytes()),
        ] {
            let is_event = tag == OBJECT;
            let mut encoded = Vec::with_capacity(6 + 32 + 4 + oversized.len());
            encoded.extend_from_slice(MAGIC);
            encoded.push(tag);
            if is_event {
                encoded.push(EventDirection::ToSessionInitiator.encode());
            }
            encoded.extend_from_slice(id);
            encoded.extend_from_slice(
                &u32::try_from(oversized.len())
                    .expect("length")
                    .to_be_bytes(),
            );
            encoded.extend_from_slice(&oversized);
            assert!(Frame::decode(&encoded).is_err());
        }

        let oversized_reconciliation = vec![0u8; MAX_FRAME_SIZE_LIMIT + 1];
        let mut encoded = Vec::with_capacity(9 + oversized_reconciliation.len());
        encoded.extend_from_slice(MAGIC);
        encoded.push(INVENTORY_QUERY);
        encoded.push(EventDirection::ToSessionResponder.encode());
        encoded.extend_from_slice(
            &u32::try_from(oversized_reconciliation.len())
                .expect("reconciliation length")
                .to_be_bytes(),
        );
        encoded.extend_from_slice(&oversized_reconciliation);
        assert!(Frame::decode(&encoded).is_err());
    }

    #[test]
    fn interest_constructor_canonicalizes_and_empty_means_receive_none() {
        let alpha = selector("alpha", "mission/alpha", false);
        let descendants = selector("zulu", "mission/bravo", true);
        let interest = EventInterest::new(vec![descendants.clone(), alpha.clone(), alpha.clone()])
            .expect("canonical interest");
        assert_eq!(interest.selectors(), &[alpha, descendants]);
        assert_eq!(interest.len(), 2);
        assert!(!interest.is_empty());
        assert!(interest.matches(
            &Topic::new("zulu").expect("topic"),
            &Scope::new("mission/bravo/child").expect("scope")
        ));
        assert!(!interest.matches(
            &Topic::new("alpha").expect("topic"),
            &Scope::new("mission/alpha/child").expect("scope")
        ));

        let empty = EventInterest::empty();
        assert!(empty.is_empty());
        assert!(!empty.matches(
            &Topic::new("alpha").expect("topic"),
            &Scope::new("mission/alpha").expect("scope")
        ));
        let encoded = Frame::EventInterest(empty)
            .encode()
            .expect("empty interest");
        assert_eq!(
            Frame::decode(&encoded).expect("decode empty interest"),
            Frame::EventInterest(EventInterest::empty())
        );
    }

    #[test]
    fn v3_interest_binds_a_canonical_selector_revision_and_exact_overhead() {
        let interest = EventInterest::new(vec![
            selector("alpha", "mission/alpha", false),
            selector("bravo", "mission/bravo", true),
        ])
        .expect("canonical interest");
        let legacy_len = Frame::EventInterest(interest.clone())
            .encode()
            .expect("legacy interest")
            .len();
        let encoded = Frame::EventInterestV3 {
            interest: interest.clone(),
            selector_revision: 2,
            policy: FrameEmissionPolicy::Normal,
            policy_revision: 1,
        }
        .encode()
        .expect("v3 interest");
        assert_eq!(encoded.len(), legacy_len + 17);

        assert!(
            Frame::EventInterestV3 {
                interest: interest.clone(),
                selector_revision: 1,
                policy: FrameEmissionPolicy::Normal,
                policy_revision: 1,
            }
            .encode()
            .is_err()
        );

        let mut malformed = encoded;
        malformed[14..22].copy_from_slice(&1u64.to_be_bytes());
        assert!(Frame::decode(&malformed).is_err());

        let empty = Frame::EventInterestReplyV3 {
            interest: EventInterest::empty(),
            selector_revision: 0,
            policy: FrameEmissionPolicy::ReceiveOnly,
            policy_revision: 1,
        }
        .encode()
        .expect("zero-revision empty interest");
        assert_eq!(empty.len(), 4 + 1 + 1 + 8 + 8 + 2);
    }

    #[test]
    fn interest_maximum_round_trips_and_constructor_rejects_cap_plus_one() {
        let selectors = (0..MAX_EVENT_INTEREST_SELECTORS)
            .map(|index| selector(&format!("topic-{index:03}"), "mission/maximum", false))
            .collect::<Vec<_>>();
        let interest = EventInterest::new(selectors.clone()).expect("maximum interest");
        assert_eq!(interest.len(), MAX_EVENT_INTEREST_SELECTORS);
        let frame = Frame::EventInterestReply(interest);
        assert_eq!(
            Frame::decode(&frame.encode().expect("encode maximum")).expect("decode maximum"),
            frame
        );

        let mut too_many = selectors;
        too_many.push(selector("topic-overflow", "mission/maximum", false));
        assert!(EventInterest::new(too_many).is_err());
    }

    #[test]
    fn interest_decode_rejects_noncanonical_malformed_and_oversized_input() {
        fn raw_selector(output: &mut Vec<u8>, topic: &[u8], scope: &[u8], descendants: u8) {
            output.extend_from_slice(
                &u16::try_from(topic.len())
                    .expect("topic length")
                    .to_be_bytes(),
            );
            output.extend_from_slice(topic);
            output.extend_from_slice(
                &u16::try_from(scope.len())
                    .expect("scope length")
                    .to_be_bytes(),
            );
            output.extend_from_slice(scope);
            output.push(descendants);
        }

        fn interest_frame(body: &[u8]) -> Vec<u8> {
            let mut frame = Vec::with_capacity(5 + body.len());
            frame.extend_from_slice(MAGIC);
            frame.push(EVENT_INTEREST);
            frame.extend_from_slice(body);
            frame
        }

        let mut duplicate = 2u16.to_be_bytes().to_vec();
        raw_selector(&mut duplicate, b"alpha", b"mission/alpha", 0);
        raw_selector(&mut duplicate, b"alpha", b"mission/alpha", 0);
        assert!(Frame::decode(&interest_frame(&duplicate)).is_err());

        let mut unsorted = 2u16.to_be_bytes().to_vec();
        raw_selector(&mut unsorted, b"zulu", b"mission/zulu", 0);
        raw_selector(&mut unsorted, b"alpha", b"mission/alpha", 0);
        assert!(Frame::decode(&interest_frame(&unsorted)).is_err());

        let mut invalid_flag = 1u16.to_be_bytes().to_vec();
        raw_selector(&mut invalid_flag, b"alpha", b"mission/alpha", 2);
        assert!(Frame::decode(&interest_frame(&invalid_flag)).is_err());

        let mut invalid_topic = 1u16.to_be_bytes().to_vec();
        raw_selector(&mut invalid_topic, b"bad/topic", b"mission/alpha", 0);
        assert!(Frame::decode(&interest_frame(&invalid_topic)).is_err());

        let mut truncated = 1u16.to_be_bytes().to_vec();
        truncated.extend_from_slice(&5u16.to_be_bytes());
        truncated.extend_from_slice(b"four");
        assert!(Frame::decode(&interest_frame(&truncated)).is_err());

        let mut trailing = Frame::EventInterest(EventInterest::empty())
            .encode()
            .expect("empty interest");
        trailing.push(0);
        assert!(Frame::decode(&trailing).is_err());

        let excessive_count = u16::try_from(MAX_EVENT_INTEREST_SELECTORS + 1)
            .expect("count")
            .to_be_bytes();
        assert!(Frame::decode(&interest_frame(&excessive_count)).is_err());

        let oversized = vec![0u8; MAX_EVENT_INTEREST_BYTES + 1];
        assert!(Frame::decode(&interest_frame(&oversized)).is_err());
    }

    #[test]
    fn every_event_lane_frame_requires_and_preserves_its_direction() {
        let id = EventTransferId::new([0x77; 32]);
        let direction = EventDirection::ToSessionResponder;
        let frames = [
            Frame::InventoryQuery {
                direction,
                bytes: vec![1],
            },
            Frame::InventoryReply {
                direction,
                bytes: vec![2],
            },
            Frame::InventoryComplete { direction },
            Frame::InventoryCompleteAck { direction },
            Frame::DifferenceQuery {
                direction,
                bytes: vec![3],
            },
            Frame::DifferenceReply {
                direction,
                bytes: vec![4],
            },
            Frame::DifferenceBound { direction },
            Frame::DifferenceBoundAck { direction },
            Frame::Fetch { direction, id },
            Frame::Object {
                direction,
                id,
                bytes: vec![5],
            },
            Frame::Offer {
                direction,
                id,
                bytes: vec![6],
            },
            Frame::ApplyResult {
                direction,
                id,
                inserted: false,
            },
            Frame::ApplyResultV3 {
                direction,
                id,
                exchange_id: 19,
                inserted: true,
                disposition: EventApplyDisposition::Satisfied,
            },
            Frame::Finish { direction },
            Frame::Finished { direction },
            Frame::FinishV3 {
                direction,
                remaining: 23,
            },
            Frame::FinishedV3 {
                direction,
                remaining: 23,
            },
        ];
        for frame in frames {
            let encoded = frame.encode().expect("directional encode");
            assert_eq!(encoded[5], direction.encode());
            assert_eq!(Frame::decode(&encoded).expect("directional decode"), frame);

            let mut missing = encoded.clone();
            missing.remove(5);
            assert!(Frame::decode(&missing).is_err());

            let mut unknown = encoded;
            unknown[5] = 3;
            assert!(Frame::decode(&unknown).is_err());
        }

        let mut invalid_disposition = Frame::ApplyResultV3 {
            direction,
            id,
            exchange_id: 23,
            inserted: true,
            disposition: EventApplyDisposition::Satisfied,
        }
        .encode()
        .expect("v3 apply result");
        *invalid_disposition
            .last_mut()
            .expect("v3 apply result has disposition") = 0;
        assert!(Frame::decode(&invalid_disposition).is_err());
    }

    #[test]
    fn v3_finish_remaining_is_canonical_and_cardinality_bounded() {
        let direction = EventDirection::ToSessionResponder;
        let boundary = Frame::FinishV3 {
            direction,
            remaining: MAX_CARDINALITY_LIMIT as u64,
        };
        let encoded = boundary.encode().expect("boundary finish");
        assert_eq!(Frame::decode(&encoded).expect("decode boundary"), boundary);

        assert!(
            Frame::FinishV3 {
                direction,
                remaining: MAX_CARDINALITY_LIMIT as u64 + 1,
            }
            .encode()
            .is_err()
        );
        let mut oversized = encoded;
        oversized[6..14].copy_from_slice(&(MAX_CARDINALITY_LIMIT as u64 + 1).to_be_bytes());
        assert!(Frame::decode(&oversized).is_err());
    }

    #[test]
    fn bridge_v6_frames_are_canonical_and_reject_truncation() {
        let wrapper_id = [0xc3; 32];
        assert!(
            Frame::BridgeRouteOffer {
                wrapper_id,
                wrapper: b"wrapper".to_vec(),
                source: b"source".to_vec(),
            }
            .serves_application_or_control_object()
        );
        assert!(!Frame::BridgeHello { enabled: true }.serves_application_or_control_object());
        assert!(
            !Frame::BridgeRouteResult {
                wrapper_id,
                disposition: BridgeRouteDisposition::Promoted,
            }
            .serves_application_or_control_object()
        );
        let frames = [
            Frame::BridgeHello { enabled: false },
            Frame::BridgeHelloAck { enabled: true },
            Frame::BridgeRouteOffer {
                wrapper_id,
                wrapper: b"wrapper".to_vec(),
                source: b"source".to_vec(),
            },
            Frame::BridgeRouteResult {
                wrapper_id,
                disposition: BridgeRouteDisposition::Duplicate,
            },
            Frame::BridgeRouteResult {
                wrapper_id,
                disposition: BridgeRouteDisposition::Promoted,
            },
            Frame::BridgeRouteResult {
                wrapper_id,
                disposition: BridgeRouteDisposition::StoredInactive,
            },
            Frame::BridgeRouteResult {
                wrapper_id,
                disposition: BridgeRouteDisposition::NotSelected,
            },
            Frame::BridgeFinish {
                remaining: MAX_CARDINALITY_LIMIT as u64,
            },
            Frame::BridgeFinished { remaining: 0 },
        ];
        for frame in frames {
            let encoded = frame.encode().expect("encode bridge frame");
            assert_eq!(Frame::decode(&encoded).expect("decode bridge frame"), frame);
            for end in 0..encoded.len() {
                assert!(
                    Frame::decode(&encoded[..end]).is_err(),
                    "accepted bridge frame truncated at {end}"
                );
            }
            let mut trailing = encoded;
            trailing.push(0);
            assert!(Frame::decode(&trailing).is_err());
        }
    }

    #[test]
    fn bridge_v6_frames_reject_hostile_flags_dispositions_and_bounds() {
        let wrapper_id = [0xc4; 32];
        assert_eq!(MAX_SELECTED_BRIDGE_WRAPPER_BYTES, 524_322);

        let boundary = Frame::BridgeRouteOffer {
            wrapper_id,
            wrapper: vec![0; MAX_SELECTED_BRIDGE_WRAPPER_BYTES],
            source: vec![0; MAX_OBJECT_BYTES],
        };
        let boundary_encoded = boundary.encode().expect("bridge route boundary");
        assert_eq!(
            Frame::decode(&boundary_encoded).expect("decode bridge route boundary"),
            boundary
        );

        let mut unknown_enabled = Frame::BridgeHello { enabled: true }
            .encode()
            .expect("bridge hello");
        unknown_enabled[5] = 2;
        assert!(Frame::decode(&unknown_enabled).is_err());

        let mut unknown_disposition = Frame::BridgeRouteResult {
            wrapper_id,
            disposition: BridgeRouteDisposition::Duplicate,
        }
        .encode()
        .expect("bridge route result");
        *unknown_disposition
            .last_mut()
            .expect("bridge result has disposition") = 4;
        assert!(Frame::decode(&unknown_disposition).is_err());

        assert!(
            Frame::BridgeRouteOffer {
                wrapper_id,
                wrapper: vec![0; MAX_SELECTED_BRIDGE_WRAPPER_BYTES + 1],
                source: Vec::new(),
            }
            .encode()
            .is_err()
        );
        assert!(
            Frame::BridgeRouteOffer {
                wrapper_id,
                wrapper: Vec::new(),
                source: vec![0; MAX_OBJECT_BYTES + 1],
            }
            .encode()
            .is_err()
        );

        let mut oversized_wrapper = MAGIC.to_vec();
        oversized_wrapper.push(BRIDGE_ROUTE_OFFER);
        oversized_wrapper.extend_from_slice(&wrapper_id);
        oversized_wrapper.extend_from_slice(
            &u32::try_from(MAX_SELECTED_BRIDGE_WRAPPER_BYTES + 1)
                .expect("wrapper bound fits u32")
                .to_be_bytes(),
        );
        assert!(Frame::decode(&oversized_wrapper).is_err());

        let mut oversized_source = MAGIC.to_vec();
        oversized_source.push(BRIDGE_ROUTE_OFFER);
        oversized_source.extend_from_slice(&wrapper_id);
        oversized_source.extend_from_slice(&0u32.to_be_bytes());
        oversized_source.extend_from_slice(
            &u32::try_from(MAX_OBJECT_BYTES + 1)
                .expect("source bound fits u32")
                .to_be_bytes(),
        );
        assert!(Frame::decode(&oversized_source).is_err());

        assert!(
            Frame::BridgeFinish {
                remaining: MAX_CARDINALITY_LIMIT as u64 + 1,
            }
            .encode()
            .is_err()
        );
        let mut oversized_remaining = Frame::BridgeFinish {
            remaining: MAX_CARDINALITY_LIMIT as u64,
        }
        .encode()
        .expect("bridge finish boundary");
        oversized_remaining[5..13]
            .copy_from_slice(&(MAX_CARDINALITY_LIMIT as u64 + 1).to_be_bytes());
        assert!(Frame::decode(&oversized_remaining).is_err());
    }

    #[test]
    fn semantic_version_gate_rejects_every_v7_only_frame_for_v1_through_v6() {
        use crate::event_pages::{
            ChangePageEntry, ChangePageV7, ChangeTurnFinishedV1, ChangeTurnHeaderV1,
            EventTurnPlanV1, TransferProfileOfferV1, empty_set_commitment, schedule_digest,
        };

        let direction = EventDirection::ToSessionResponder;
        let scheduled = vec![EventTransferId::new([1; 32])];
        let digest = [2; 32];
        let schedule = schedule_digest(&scheduled);
        let frames = [
            Frame::TransferProfileOffer(TransferProfileOfferV1::current()),
            Frame::EventTurnPlan(EventTurnPlanV1::Empty {
                direction,
                transfer_profile_digest: digest,
                selected_profile: crate::event_pages::TransferProfileId::EventPagesV1,
                set_commitment: empty_set_commitment(),
            }),
            Frame::ChangeTurnHeader(ChangeTurnHeaderV1 {
                direction,
                transfer_profile_digest: digest,
                set_commitment: [3; 32],
                scheduled: scheduled.clone(),
                schedule_digest: schedule,
            }),
            Frame::ChangePage(ChangePageV7 {
                direction,
                transfer_profile_digest: digest,
                schedule_digest: schedule,
                page_number: 0,
                entries: vec![ChangePageEntry {
                    id: scheduled[0],
                    custody: None,
                    source_event: vec![4],
                }],
                remaining: 0,
            }),
            Frame::ChangeTurnFinished(ChangeTurnFinishedV1 {
                direction,
                transfer_profile_digest: digest,
                set_commitment: [3; 32],
                schedule_digest: schedule,
                final_page_count: 1,
            }),
        ];

        for frame in frames {
            for semantic_version in 7..=8 {
                let encoded = frame
                    .encode_for_semantic_version(semantic_version)
                    .expect("v7-or-later frame encodes");
                assert_eq!(
                    Frame::decode_for_semantic_version(&encoded, semantic_version)
                        .expect("v7-or-later frame decodes"),
                    frame
                );
            }
            let encoded = frame.encode().expect("mechanics frame");
            for legacy_version in 1..=6 {
                assert!(frame.encode_for_semantic_version(legacy_version).is_err());
                assert!(Frame::decode_for_semantic_version(&encoded, legacy_version).is_err());
            }
        }
    }

    fn literal_hex(encoded: &str) -> Vec<u8> {
        assert_eq!(encoded.len() % 2, 0, "literal hexadecimal width");
        (0..encoded.len())
            .step_by(2)
            .map(|offset| {
                u8::from_str_radix(&encoded[offset..offset + 2], 16)
                    .expect("literal hexadecimal byte")
            })
            .collect()
    }

    fn literal_blob_custody_claim() -> aster_mesh::BlobCustodyClaimV1 {
        aster_mesh::BlobCustodyClaimV1::decode(&literal_hex("41535452424c30380001000800041111111111111111111111111111111111111111111111111111111111111111000000000000000001222222222222222222222222222222222222222222222222222222222222222200000000000000013333333333333333333333333333333333333333333333333333333333333333444444444444444444444444444444444444444444444444444444444444444400000000000000000100000000000000005555555555555555555555555555555500000000000000000000000000000000"))
            .expect("literal canonical Blob custody claim")
    }

    #[test]
    fn v8_blob_source_claim_field_is_exact_and_v1_through_v7_stay_unchanged() {
        // Mutation caught: changing a legacy Blob/State/Record byte, omitting
        // v8 presence/length framing, accepting duplicates, or crossing classes.
        let id = MutableTransferId::Blob(BlobTransferId::new([0xaa; 32]));
        let legacy = literal_hex(
            "41534d01830302aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa0000000178",
        );
        let durable = Frame::MutableOffer {
            direction: EventDirection::ToSessionResponder,
            id,
            bytes: b"x".to_vec(),
            claim: None,
        };
        for semantic_version in 1..=7 {
            assert_eq!(
                durable
                    .encode_for_semantic_version(semantic_version)
                    .expect("legacy durable Blob offer"),
                legacy
            );
            assert_eq!(
                Frame::decode_for_semantic_version(&legacy, semantic_version)
                    .expect("legacy durable Blob offer decode"),
                durable
            );
        }
        let mut durable_v8 = legacy.clone();
        durable_v8.push(0);
        assert_eq!(
            durable.encode_for_semantic_version(8).expect("v8 durable"),
            durable_v8
        );
        assert_eq!(
            Frame::decode_for_semantic_version(&durable_v8, 8).expect("decode v8 durable"),
            durable
        );
        assert!(Frame::decode_for_semantic_version(&legacy, 8).is_err());

        let claim = literal_blob_custody_claim();
        let finite = Frame::MutableOffer {
            direction: EventDirection::ToSessionResponder,
            id,
            bytes: b"x".to_vec(),
            claim: Some(claim),
        };
        let mut finite_v8 = legacy.clone();
        finite_v8.extend_from_slice(&[1, 0, 208]);
        finite_v8.extend_from_slice(&claim.encode());
        assert_eq!(
            finite.encode_for_semantic_version(8).expect("v8 finite"),
            finite_v8
        );
        assert_eq!(
            Frame::decode_for_semantic_version(&finite_v8, 8).expect("decode v8 finite"),
            finite
        );
        assert!(finite.encode_for_semantic_version(7).is_err());

        let mut invalid_discriminator = legacy.clone();
        invalid_discriminator.push(2);
        assert!(Frame::decode_for_semantic_version(&invalid_discriminator, 8).is_err());
        let mut wrong_length = finite_v8.clone();
        let length_offset = legacy.len() + 1;
        wrong_length[length_offset..length_offset + 2].copy_from_slice(&207u16.to_be_bytes());
        assert!(Frame::decode_for_semantic_version(&wrong_length, 8).is_err());
        let mut truncated = finite_v8.clone();
        truncated.pop();
        assert!(Frame::decode_for_semantic_version(&truncated, 8).is_err());
        let mut duplicated = finite_v8.clone();
        duplicated.extend_from_slice(&[1, 0, 208]);
        duplicated.extend_from_slice(&claim.encode());
        assert!(Frame::decode_for_semantic_version(&duplicated, 8).is_err());
        let mut surplus = durable_v8.clone();
        surplus.push(0);
        assert!(Frame::decode_for_semantic_version(&surplus, 8).is_err());

        for (class, id) in [
            (
                MutableClass::State,
                MutableTransferId::State(StateTransferId::new([0x41; 32])),
            ),
            (
                MutableClass::Record,
                MutableTransferId::Record(RecordTransferId::new([0x42; 32])),
            ),
        ] {
            assert_eq!(id.class(), class);
            let frame = Frame::MutableObject {
                direction: EventDirection::ToSessionInitiator,
                id,
                bytes: b"s".to_vec(),
                claim: None,
            };
            assert_eq!(
                frame.encode_for_semantic_version(8).expect("v8 non-Blob"),
                frame.encode().expect("legacy non-Blob")
            );
        }
    }

    #[test]
    fn v8_blob_settlement_digest_field_is_exact_and_class_scoped() {
        // Mutation caught: omitting a digest presence byte, accepting an
        // unknown/trailing field, or changing legacy/non-Blob result bytes.
        let id = MutableTransferId::Blob(BlobTransferId::new([0xab; 32]));
        let digest = [0xcd; 32];
        type SettlementMaker = fn(MutableTransferId, Option<[u8; 32]>) -> Frame;
        let makers: [SettlementMaker; 3] = [
            |id, custody_digest| Frame::MutableApplyResult {
                direction: EventDirection::ToSessionInitiator,
                id,
                disposition: MutableApplyDisposition::Inserted,
                custody_digest,
            },
            |id, custody_digest| Frame::MutableFetchResult {
                direction: EventDirection::ToSessionInitiator,
                id,
                disposition: MutableApplyDisposition::Inserted,
                custody_digest,
            },
            |id, custody_digest| Frame::MutableFetchResultAck {
                direction: EventDirection::ToSessionInitiator,
                id,
                disposition: MutableApplyDisposition::Inserted,
                custody_digest,
            },
        ];
        for make in makers {
            let durable = make(id, None);
            let legacy = durable.encode().expect("legacy settlement");
            for semantic_version in 1..=7 {
                assert_eq!(
                    durable
                        .encode_for_semantic_version(semantic_version)
                        .expect("legacy durable settlement"),
                    legacy
                );
            }
            let mut durable_v8 = legacy.clone();
            durable_v8.push(0);
            assert_eq!(
                durable
                    .encode_for_semantic_version(8)
                    .expect("v8 durable result"),
                durable_v8
            );
            assert_eq!(
                Frame::decode_for_semantic_version(&durable_v8, 8)
                    .expect("decode v8 durable result"),
                durable
            );

            let finite = make(id, Some(digest));
            let mut finite_v8 = legacy.clone();
            finite_v8.push(1);
            finite_v8.extend_from_slice(&digest);
            assert_eq!(
                finite
                    .encode_for_semantic_version(8)
                    .expect("v8 finite result"),
                finite_v8
            );
            assert_eq!(
                Frame::decode_for_semantic_version(&finite_v8, 8).expect("decode v8 finite result"),
                finite
            );
            assert!(finite.encode_for_semantic_version(7).is_err());

            let mut invalid_discriminator = legacy.clone();
            invalid_discriminator.push(2);
            assert!(Frame::decode_for_semantic_version(&invalid_discriminator, 8).is_err());
            let mut truncated = finite_v8.clone();
            truncated.pop();
            assert!(Frame::decode_for_semantic_version(&truncated, 8).is_err());
            let mut surplus = durable_v8.clone();
            surplus.push(0);
            assert!(Frame::decode_for_semantic_version(&surplus, 8).is_err());
        }

        let state = Frame::MutableApplyResult {
            direction: EventDirection::ToSessionResponder,
            id: MutableTransferId::State(StateTransferId::new([0x51; 32])),
            disposition: MutableApplyDisposition::Duplicate,
            custody_digest: None,
        };
        assert_eq!(
            state
                .encode_for_semantic_version(8)
                .expect("v8 State result"),
            state.encode().expect("legacy State result")
        );
    }

    #[test]
    fn semantic_v7_through_v9_keep_legacy_frame_bytes_and_acceptance_unchanged() {
        let frame = Frame::Finish {
            direction: EventDirection::ToSessionInitiator,
        };
        let raw = frame.encode().unwrap();
        for semantic_version in 1..=9 {
            assert_eq!(
                frame.encode_for_semantic_version(semantic_version).unwrap(),
                raw
            );
            assert_eq!(
                Frame::decode_for_semantic_version(&raw, semantic_version).unwrap(),
                frame
            );
        }
    }

    #[test]
    fn v9_blob_stream_plan_is_bounded_and_version_scoped() {
        for frame in [
            Frame::BlobStreamPlan {
                direction: EventDirection::ToSessionResponder,
                attempt_nonce: Some([0x71; 32]),
                source: Some(BlobStreamSourceOfferV1 {
                    transfer_id: [0xa4; 32],
                    topic: Topic::new("imagery").unwrap(),
                    scope: Scope::new("mission/alpha").unwrap(),
                    key_epoch: 7,
                    content_proof: [0xa6; BLOB_CONTENT_PROOF_BYTES],
                    source_len: u32::try_from(
                        crate::stream_transfer::MAX_STREAM_AUTHENTICATED_OPEN_BYTES,
                    )
                    .unwrap(),
                    source_digest: [0xa5; 32],
                    finite: false,
                }),
            },
            Frame::BlobStreamPlanAck {
                direction: EventDirection::ToSessionResponder,
                attempt_nonce: Some([0x71; 32]),
            },
            Frame::BlobStreamPlan {
                direction: EventDirection::ToSessionInitiator,
                attempt_nonce: None,
                source: None,
            },
        ] {
            let encoded = frame.encode_for_semantic_version(9).expect("v9 plan");
            assert_eq!(
                Frame::decode_for_semantic_version(&encoded, 9).expect("v9 plan decode"),
                frame
            );
            assert!(frame.encode_for_semantic_version(8).is_err());
            assert!(Frame::decode_for_semantic_version(&encoded, 8).is_err());
        }
        let mut zero_nonce = Frame::BlobStreamPlan {
            direction: EventDirection::ToSessionResponder,
            attempt_nonce: Some([1; 32]),
            source: Some(BlobStreamSourceOfferV1 {
                transfer_id: [2; 32],
                topic: Topic::new("imagery").unwrap(),
                scope: Scope::new("mission/alpha").unwrap(),
                key_epoch: 7,
                content_proof: [4; BLOB_CONTENT_PROOF_BYTES],
                source_len: 1,
                source_digest: [3; 32],
                finite: false,
            }),
        }
        .encode_for_semantic_version(9)
        .expect("nonzero nonce");
        zero_nonce[7..].fill(0);
        assert!(Frame::decode_for_semantic_version(&zero_nonce, 9).is_err());
    }
}
