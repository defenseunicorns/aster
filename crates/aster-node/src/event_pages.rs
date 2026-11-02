#![allow(
    dead_code,
    reason = "semantic-v7 profile negotiation consumes these contracts in the runtime"
)]

use aster_mesh::{MAX_CUSTODY_WRAPPER_BYTES, Priority};
use aster_redb_store::EventTransferId;
use std::collections::BTreeSet;

use crate::frame::EventDirection;
use sha2::{Digest, Sha256};

pub(crate) const SEMANTIC_PROTOCOL_V7: u16 = 7;
pub(crate) const SEMANTIC_PROTOCOL_V8: u16 = 8;
pub(crate) const SEMANTIC_PROTOCOL_V9: u16 = 9;
pub(crate) const MAX_CHANGE_PAGE_PROTECTED_BYTES: usize = aster_iroh::DEFAULT_MAX_EXCHANGE_BYTES;
const MECHANICS_FRAME_OVERHEAD_BYTES: usize = crate::frame::MECHANICS_FRAME_PREFIX_BYTES;
pub(crate) const MAX_CHANGE_PAGE_CODEC_BYTES: usize = MAX_CHANGE_PAGE_PROTECTED_BYTES
    - MECHANICS_FRAME_OVERHEAD_BYTES
    - aster_mesh::REFERENCE_SESSION_FRAME_OVERHEAD_BYTES;
pub(crate) const MAX_EVENT_BYTES: usize = crate::frame::MAX_OBJECT_BYTES;
const CHANGE_TURN_HEADER_FIXED_BYTES: usize = 1 + 2 + 2 + 1 + 32 + 32 + 4 + 32;
pub(crate) const CHANGE_TURN_FINISHED_FIXED_BYTES: usize = 1 + 2 + 2 + 1 + 32 + 32 + 32 + 4 + 4;
const UNI_FRAME_LENGTH_PREFIX_BYTES: usize = std::mem::size_of::<u32>();
const PROTECTED_FRAME_FIXED_BYTES: usize =
    MECHANICS_FRAME_OVERHEAD_BYTES + aster_mesh::REFERENCE_SESSION_FRAME_OVERHEAD_BYTES;
pub(crate) const MAX_SCHEDULED_EVENT_IDS: usize =
    (MAX_CHANGE_PAGE_CODEC_BYTES - CHANGE_TURN_HEADER_FIXED_BYTES) / 32;
pub(crate) const CHANGE_PAGE_FIXED_BYTES: usize = 1 + 2 + 2 + 1 + 32 + 32 + 4 + 2 + 4;
pub(crate) const CHANGE_PAGE_ENTRY_FIXED_BYTES: usize = 32 + 1 + 4;
const MINIMUM_CHANGE_PAGE_ENTRY_BYTES: usize = CHANGE_PAGE_ENTRY_FIXED_BYTES + 1;
pub(crate) const MAX_CHANGE_PAGE_ENTRIES: usize =
    (MAX_CHANGE_PAGE_CODEC_BYTES - CHANGE_PAGE_FIXED_BYTES) / MINIMUM_CHANGE_PAGE_ENTRY_BYTES;

fn planned_change_page_entry_bytes(
    metadata: AuthenticatedEventMetadata,
) -> Result<usize, EventPagesError> {
    let source_bytes = usize::try_from(metadata.source_bytes)
        .map_err(|_| EventPagesError::invalid("Event source length overflows"))?;
    let custody_bytes = if metadata.ttl_ms.is_some() && !metadata.tombstone {
        8usize
            .checked_add(2)
            .and_then(|bytes| bytes.checked_add(MAX_CUSTODY_WRAPPER_BYTES))
            .ok_or_else(|| EventPagesError::invalid("custody wrapper size overflows"))?
    } else {
        0
    };
    CHANGE_PAGE_ENTRY_FIXED_BYTES
        .checked_add(custody_bytes)
        .and_then(|bytes| bytes.checked_add(source_bytes))
        .ok_or_else(|| EventPagesError::invalid("Event page entry length overflows"))
}
const _: () = assert!(MAX_CHANGE_PAGE_ENTRIES <= u16::MAX as usize);

pub(crate) const MAX_EVENT_TURN_PLAN_CODEC_BYTES: usize = 1 + 1 + 1 + 32 + 4 + 32 + 4 + 4;
#[cfg(test)]
pub(crate) use aster_mesh::negotiate_transfer_profiles;
pub(crate) use aster_mesh::{
    NegotiatedTransferProfiles, TransferLaneId as LaneId, TransferProfileId,
    TransferProfileOfferV1, negotiate_transfer_profiles_for_semantic_version,
    transfer_profile_digest,
};
pub(crate) type EventPagesError = aster_mesh::TransferProfileError;

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum LegacyDifference {
    Exact {
        difference_count: u32,
        set_commitment: [u8; 32],
    },
    Blind,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum EventTurnPlanV1 {
    PageActive {
        direction: EventDirection,
        transfer_profile_digest: [u8; 32],
        difference_count: u32,
        set_commitment: [u8; 32],
        scheduled_count: u32,
        unscheduled_count: u32,
    },
    PageBlindActive {
        direction: EventDirection,
        transfer_profile_digest: [u8; 32],
        scheduled_count: u32,
        unscheduled_count: u32,
    },
    LegacyActive {
        direction: EventDirection,
        transfer_profile_digest: [u8; 32],
        difference: LegacyDifference,
    },
    Empty {
        direction: EventDirection,
        transfer_profile_digest: [u8; 32],
        selected_profile: TransferProfileId,
        set_commitment: [u8; 32],
    },
    Suppressed {
        direction: EventDirection,
        transfer_profile_digest: [u8; 32],
    },
}

impl EventTurnPlanV1 {
    pub(crate) fn encode(&self) -> Result<Vec<u8>, EventPagesError> {
        let mut output = vec![1];
        match self {
            Self::PageActive {
                direction,
                transfer_profile_digest,
                difference_count,
                set_commitment,
                scheduled_count,
                unscheduled_count,
            } => {
                validate_page_plan_counts(*difference_count, *scheduled_count, *unscheduled_count)?;
                output.push(1);
                encode_plan_prefix(&mut output, *direction, transfer_profile_digest);
                output.extend_from_slice(&difference_count.to_be_bytes());
                output.extend_from_slice(set_commitment);
                output.extend_from_slice(&scheduled_count.to_be_bytes());
                output.extend_from_slice(&unscheduled_count.to_be_bytes());
            }
            Self::LegacyActive {
                direction,
                transfer_profile_digest,
                difference,
            } => {
                output.push(2);
                encode_plan_prefix(&mut output, *direction, transfer_profile_digest);
                match difference {
                    LegacyDifference::Exact {
                        difference_count,
                        set_commitment,
                    } => {
                        output.push(1);
                        output.extend_from_slice(&difference_count.to_be_bytes());
                        output.extend_from_slice(set_commitment);
                    }
                    LegacyDifference::Blind => output.push(2),
                }
            }
            Self::PageBlindActive {
                direction,
                transfer_profile_digest,
                scheduled_count,
                unscheduled_count,
            } => {
                validate_blind_page_counts(*scheduled_count, *unscheduled_count)?;
                output.push(5);
                encode_plan_prefix(&mut output, *direction, transfer_profile_digest);
                output.extend_from_slice(&scheduled_count.to_be_bytes());
                output.extend_from_slice(&unscheduled_count.to_be_bytes());
            }
            Self::Empty {
                direction,
                transfer_profile_digest,
                selected_profile,
                set_commitment,
            } => {
                if *set_commitment != empty_set_commitment() {
                    return Err(EventPagesError::invalid(
                        "empty plan must use the canonical empty-set commitment",
                    ));
                }
                output.push(3);
                encode_plan_prefix(&mut output, *direction, transfer_profile_digest);
                output.extend_from_slice(&(*selected_profile as u16).to_be_bytes());
                output.extend_from_slice(set_commitment);
            }
            Self::Suppressed {
                direction,
                transfer_profile_digest,
            } => {
                output.push(4);
                encode_plan_prefix(&mut output, *direction, transfer_profile_digest);
            }
        }
        Ok(output)
    }

    pub(crate) fn decode(bytes: &[u8]) -> Result<Self, EventPagesError> {
        let mut cursor = Cursor::new(bytes);
        require_version(cursor.u8()?, 1, "Event turn plan")?;
        let variant = cursor.u8()?;
        let direction = decode_event_direction(cursor.u8()?)?;
        let transfer_profile_digest = cursor.array_32()?;
        let plan = match variant {
            1 => {
                let difference_count = cursor.u32()?;
                let set_commitment = cursor.array_32()?;
                let scheduled_count = cursor.u32()?;
                let unscheduled_count = cursor.u32()?;
                validate_page_plan_counts(difference_count, scheduled_count, unscheduled_count)?;
                Self::PageActive {
                    direction,
                    transfer_profile_digest,
                    difference_count,
                    set_commitment,
                    scheduled_count,
                    unscheduled_count,
                }
            }
            2 => {
                let difference = match cursor.u8()? {
                    1 => LegacyDifference::Exact {
                        difference_count: cursor.u32()?,
                        set_commitment: cursor.array_32()?,
                    },
                    2 => LegacyDifference::Blind,
                    _ => return Err(EventPagesError::invalid("invalid legacy difference mode")),
                };
                Self::LegacyActive {
                    direction,
                    transfer_profile_digest,
                    difference,
                }
            }
            3 => {
                let selected_profile = TransferProfileId::decode(cursor.u16()?)
                    .ok_or_else(|| EventPagesError::invalid("unknown Empty plan profile"))?;
                let set_commitment = cursor.array_32()?;
                if set_commitment != empty_set_commitment() {
                    return Err(EventPagesError::invalid(
                        "empty plan has a noncanonical empty-set commitment",
                    ));
                }
                Self::Empty {
                    direction,
                    transfer_profile_digest,
                    selected_profile,
                    set_commitment,
                }
            }
            4 => Self::Suppressed {
                direction,
                transfer_profile_digest,
            },
            5 => {
                let scheduled_count = cursor.u32()?;
                let unscheduled_count = cursor.u32()?;
                validate_blind_page_counts(scheduled_count, unscheduled_count)?;
                Self::PageBlindActive {
                    direction,
                    transfer_profile_digest,
                    scheduled_count,
                    unscheduled_count,
                }
            }
            _ => return Err(EventPagesError::invalid("invalid Event turn-plan variant")),
        };
        cursor.finish()?;
        Ok(plan)
    }
}

fn validate_page_plan_counts(
    difference_count: u32,
    scheduled_count: u32,
    unscheduled_count: u32,
) -> Result<(), EventPagesError> {
    if usize::try_from(scheduled_count)
        .map_err(|_| EventPagesError::invalid("scheduled Event count overflows"))?
        > MAX_SCHEDULED_EVENT_IDS
    {
        return Err(EventPagesError::invalid(
            "Event schedule exceeds the frame-derived codec ceiling",
        ));
    }
    if scheduled_count.checked_add(unscheduled_count) != Some(difference_count) {
        return Err(EventPagesError::invalid(
            "scheduled and unscheduled counts do not equal the difference",
        ));
    }
    Ok(())
}

fn validate_blind_page_counts(
    scheduled_count: u32,
    unscheduled_count: u32,
) -> Result<(), EventPagesError> {
    if usize::try_from(scheduled_count)
        .map_err(|_| EventPagesError::invalid("scheduled Event count overflows"))?
        > MAX_SCHEDULED_EVENT_IDS
    {
        return Err(EventPagesError::invalid(
            "blind Event schedule exceeds the frame-derived codec ceiling",
        ));
    }
    scheduled_count
        .checked_add(unscheduled_count)
        .ok_or_else(|| EventPagesError::invalid("blind Event candidate count overflows"))?;
    Ok(())
}

fn encode_event_direction(direction: EventDirection) -> u8 {
    match direction {
        EventDirection::ToSessionInitiator => 1,
        EventDirection::ToSessionResponder => 2,
    }
}

fn decode_event_direction(value: u8) -> Result<EventDirection, EventPagesError> {
    match value {
        1 => Ok(EventDirection::ToSessionInitiator),
        2 => Ok(EventDirection::ToSessionResponder),
        _ => Err(EventPagesError::invalid("invalid Event direction")),
    }
}

fn encode_plan_prefix(output: &mut Vec<u8>, direction: EventDirection, digest: &[u8; 32]) {
    output.push(encode_event_direction(direction));
    output.extend_from_slice(digest);
}

pub(crate) fn empty_set_commitment() -> [u8; 32] {
    Sha256::digest(b"ASTER/event-difference-set/v1\0empty").into()
}

pub(crate) fn blind_set_commitment() -> [u8; 32] {
    Sha256::digest(b"ASTER/event-difference-set/v1\0blind").into()
}

pub(crate) fn event_difference_set_commitment(
    difference: &[EventTransferId],
) -> Result<[u8; 32], EventPagesError> {
    validate_strict_event_ids(difference)?;
    if difference.is_empty() {
        return Ok(empty_set_commitment());
    }
    let mut hasher = Sha256::new();
    hasher.update(b"ASTER/event-difference-set/v1\0");
    hasher.update(
        u32::try_from(difference.len())
            .map_err(|_| EventPagesError::invalid("Event difference count overflows"))?
            .to_be_bytes(),
    );
    for id in difference {
        hasher.update(id.as_bytes());
    }
    Ok(hasher.finalize().into())
}

fn validate_strict_event_ids(difference: &[EventTransferId]) -> Result<(), EventPagesError> {
    if !difference.windows(2).all(|pair| pair[0] < pair[1]) {
        return Err(EventPagesError::invalid(
            "authenticated Event difference is not strictly ordered",
        ));
    }
    Ok(())
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct AuthenticatedEventMetadata {
    pub(crate) id: EventTransferId,
    pub(crate) acceptance_order: u64,
    pub(crate) priority: Priority,
    pub(crate) ttl_ms: Option<u64>,
    pub(crate) tombstone: bool,
    pub(crate) source_bytes: u64,
}

#[derive(Clone, Copy, Debug)]
pub(crate) enum LocalEventSendDifference<'a> {
    Exact(&'a [EventTransferId]),
    Blind,
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub(crate) struct EventPageSchedulePosition {
    pub(crate) acceptance_order: u64,
    pub(crate) id: EventTransferId,
}

impl From<AuthenticatedEventMetadata> for EventPageSchedulePosition {
    fn from(metadata: AuthenticatedEventMetadata) -> Self {
        Self {
            acceptance_order: metadata.acceptance_order,
            id: metadata.id,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct BuiltLocalEventSendPlan {
    pub(crate) plan: EventTurnPlanV1,
    pub(crate) scheduled: Vec<EventTransferId>,
    pub(crate) scheduled_metadata: Vec<AuthenticatedEventMetadata>,
    pub(crate) last_attempted_by_priority: [Option<EventPageSchedulePosition>; 4],
}

fn priority_schedule(
    metadata: &[AuthenticatedEventMetadata],
    schedule_capacity: usize,
    last_attempted_by_priority: [Option<EventPageSchedulePosition>; 4],
) -> (
    Vec<AuthenticatedEventMetadata>,
    [Option<EventPageSchedulePosition>; 4],
) {
    let mut scheduled = Vec::with_capacity(metadata.len().min(schedule_capacity));
    let mut advanced = [None; 4];
    for priority in [
        Priority::Flash,
        Priority::Immediate,
        Priority::Priority,
        Priority::Routine,
    ] {
        if scheduled.len() == schedule_capacity {
            break;
        }
        let mut tier = metadata
            .iter()
            .copied()
            .filter(|entry| entry.priority == priority)
            .collect::<Vec<_>>();
        tier.sort_unstable_by_key(|entry| EventPageSchedulePosition::from(*entry));
        if tier.is_empty() {
            continue;
        }
        let priority_index = priority as usize;
        let start = last_attempted_by_priority[priority_index].map_or(0, |last| {
            tier.partition_point(|entry| EventPageSchedulePosition::from(*entry) <= last)
                % tier.len()
        });
        let take = tier.len().min(schedule_capacity - scheduled.len());
        for offset in 0..take {
            scheduled.push(tier[(start + offset) % tier.len()]);
        }
        advanced[priority_index] = scheduled
            .last()
            .copied()
            .map(EventPageSchedulePosition::from);
    }
    (scheduled, advanced)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct EventPageScheduleLimits {
    pub(crate) item_capacity: usize,
    pub(crate) frame_capacity: usize,
    /// Aggregate uni-turn bytes, including every four-byte frame-length prefix.
    pub(crate) turn_bytes: usize,
    pub(crate) max_protected_frame_bytes: usize,
    /// Sender-local packing target. This is never a receiver rejection rule.
    pub(crate) page_target_entries: usize,
    /// Sender-local target for pages containing finite-TTL entries.
    pub(crate) finite_page_target_entries: usize,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct EventPagePackingState {
    pub(crate) codec_bytes: usize,
    pub(crate) entries: usize,
    pub(crate) contains_finite: bool,
}

impl EventPagePackingState {
    pub(crate) const fn empty() -> Self {
        Self {
            codec_bytes: CHANGE_PAGE_FIXED_BYTES,
            entries: 0,
            contains_finite: false,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct EventPagePackingDecision {
    pub(crate) starts_page: bool,
    pub(crate) state: EventPagePackingState,
    pub(crate) turn_byte_delta: usize,
}

pub(crate) fn pack_event_page_entry(
    current: EventPagePackingState,
    entry_bytes: usize,
    finite: bool,
    max_codec_bytes: usize,
    page_target_entries: usize,
    finite_page_target_entries: usize,
) -> Result<Option<EventPagePackingDecision>, EventPagesError> {
    if page_target_entries == 0 || finite_page_target_entries == 0 {
        return Err(EventPagesError::invalid(
            "Event page sender targets must be nonzero",
        ));
    }
    let effective_target = if finite || current.contains_finite {
        page_target_entries.min(finite_page_target_entries)
    } else {
        page_target_entries
    };
    let starts_page = current.entries == 0
        || current.entries >= effective_target
        || current
            .codec_bytes
            .checked_add(entry_bytes)
            .is_none_or(|bytes| bytes > max_codec_bytes);
    let (codec_bytes, entries) = if starts_page {
        let codec_bytes = CHANGE_PAGE_FIXED_BYTES
            .checked_add(entry_bytes)
            .ok_or_else(|| EventPagesError::invalid("Event page length overflows"))?;
        if codec_bytes > max_codec_bytes {
            return Ok(None);
        }
        (codec_bytes, 1)
    } else {
        (
            current
                .codec_bytes
                .checked_add(entry_bytes)
                .ok_or_else(|| EventPagesError::invalid("Event page length overflows"))?,
            current
                .entries
                .checked_add(1)
                .ok_or_else(|| EventPagesError::invalid("Event page entry count overflows"))?,
        )
    };
    let turn_byte_delta = if starts_page {
        framed_turn_bytes(codec_bytes)
            .ok_or_else(|| EventPagesError::invalid("Event page turn length overflows"))?
    } else {
        entry_bytes
    };
    Ok(Some(EventPagePackingDecision {
        starts_page,
        state: EventPagePackingState {
            codec_bytes,
            entries,
            contains_finite: finite || (!starts_page && current.contains_finite),
        },
        turn_byte_delta,
    }))
}

fn framed_turn_bytes(codec_bytes: usize) -> Option<usize> {
    UNI_FRAME_LENGTH_PREFIX_BYTES
        .checked_add(PROTECTED_FRAME_FIXED_BYTES)?
        .checked_add(codec_bytes)
}

fn attempted_positions(
    scheduled: &[AuthenticatedEventMetadata],
) -> [Option<EventPageSchedulePosition>; 4] {
    let mut advanced = [None; 4];
    for metadata in scheduled {
        advanced[metadata.priority as usize] = Some(EventPageSchedulePosition::from(*metadata));
    }
    advanced
}

pub(crate) fn plan_event_page_schedule(
    authenticated_metadata: &[AuthenticatedEventMetadata],
    limits: EventPageScheduleLimits,
    last_attempted_by_priority: [Option<EventPageSchedulePosition>; 4],
) -> Result<
    (
        Vec<AuthenticatedEventMetadata>,
        [Option<EventPageSchedulePosition>; 4],
    ),
    EventPagesError,
> {
    if limits.page_target_entries == 0 || limits.finite_page_target_entries == 0 {
        return Err(EventPagesError::invalid(
            "Event page sender targets must be nonzero",
        ));
    }
    let max_protected_frame_bytes = limits
        .max_protected_frame_bytes
        .min(MAX_CHANGE_PAGE_PROTECTED_BYTES);
    let Some(max_codec_bytes) = max_protected_frame_bytes.checked_sub(PROTECTED_FRAME_FIXED_BYTES)
    else {
        return Ok((Vec::new(), [None; 4]));
    };
    let item_capacity = limits.item_capacity.min(MAX_SCHEDULED_EVENT_IDS);
    let (ordered, _) = priority_schedule(
        authenticated_metadata,
        item_capacity,
        last_attempted_by_priority,
    );
    let Some(mut turn_bytes) =
        framed_turn_bytes(CHANGE_TURN_HEADER_FIXED_BYTES).and_then(|header| {
            framed_turn_bytes(CHANGE_TURN_FINISHED_FIXED_BYTES)
                .and_then(|terminal| header.checked_add(terminal))
        })
    else {
        return Err(EventPagesError::invalid("Event turn byte count overflows"));
    };
    let mut frame_count = 2usize;
    let mut header_codec_bytes = CHANGE_TURN_HEADER_FIXED_BYTES;
    let mut page = EventPagePackingState::empty();
    let page_target_entries = limits.page_target_entries.min(MAX_CHANGE_PAGE_ENTRIES);
    let finite_page_target_entries = limits
        .finite_page_target_entries
        .min(MAX_CHANGE_PAGE_ENTRIES);
    let mut scheduled = Vec::with_capacity(ordered.len());

    for metadata in ordered {
        if metadata.acceptance_order == 0 {
            return Err(EventPagesError::invalid(
                "Event scheduling metadata has zero acceptance order",
            ));
        }
        let entry_bytes = planned_change_page_entry_bytes(metadata)?;
        let next_header_codec_bytes = header_codec_bytes
            .checked_add(32)
            .ok_or_else(|| EventPagesError::invalid("Event turn header length overflows"))?;
        if next_header_codec_bytes > max_codec_bytes {
            break;
        }
        let Some(packing) = pack_event_page_entry(
            page,
            entry_bytes,
            metadata.ttl_ms.is_some() && !metadata.tombstone,
            max_codec_bytes,
            page_target_entries,
            finite_page_target_entries,
        )?
        else {
            break;
        };
        let Some(next_turn_bytes) = turn_bytes
            .checked_add(32)
            .and_then(|bytes| bytes.checked_add(packing.turn_byte_delta))
        else {
            return Err(EventPagesError::invalid("Event turn byte count overflows"));
        };
        let Some(next_frame_count) = frame_count.checked_add(usize::from(packing.starts_page))
        else {
            return Err(EventPagesError::invalid("Event turn frame count overflows"));
        };
        if next_turn_bytes > limits.turn_bytes || next_frame_count > limits.frame_capacity {
            break;
        }
        scheduled.push(metadata);
        turn_bytes = next_turn_bytes;
        frame_count = next_frame_count;
        header_codec_bytes = next_header_codec_bytes;
        page = packing.state;
    }
    let advanced = attempted_positions(&scheduled);
    Ok((scheduled, advanced))
}

/// Builds a sender-owned directional plan from authenticated source metadata.
///
/// `schedule_capacity` is a caller-computed, implementation-local contact
/// capacity. It is deliberately absent from every codec and is not a protocol
/// limit or receiver rejection rule.
#[allow(
    clippy::too_many_arguments,
    reason = "the explicit authenticated plan inputs keep sender-only limits separate from wire fields"
)]
pub(crate) fn build_local_event_send_plan(
    direction: EventDirection,
    transfer_profile_digest: [u8; 32],
    negotiated: &NegotiatedTransferProfiles,
    difference: LocalEventSendDifference<'_>,
    authenticated_metadata: &[AuthenticatedEventMetadata],
    outbound_suppressed: bool,
    schedule_capacity: usize,
    last_attempted_by_priority: [Option<EventPageSchedulePosition>; 4],
) -> Result<BuiltLocalEventSendPlan, EventPagesError> {
    build_local_event_send_plan_with_limits(
        direction,
        transfer_profile_digest,
        negotiated,
        difference,
        authenticated_metadata,
        outbound_suppressed,
        EventPageScheduleLimits {
            item_capacity: schedule_capacity,
            frame_capacity: usize::MAX,
            turn_bytes: usize::MAX,
            max_protected_frame_bytes: MAX_CHANGE_PAGE_PROTECTED_BYTES,
            page_target_entries: MAX_CHANGE_PAGE_ENTRIES,
            finite_page_target_entries: MAX_CHANGE_PAGE_ENTRIES,
        },
        last_attempted_by_priority,
    )
}

#[allow(
    clippy::too_many_arguments,
    reason = "the explicit authenticated plan inputs keep sender-only limits separate from wire fields"
)]
pub(crate) fn build_local_event_send_plan_with_limits(
    direction: EventDirection,
    transfer_profile_digest: [u8; 32],
    negotiated: &NegotiatedTransferProfiles,
    difference: LocalEventSendDifference<'_>,
    authenticated_metadata: &[AuthenticatedEventMetadata],
    outbound_suppressed: bool,
    schedule_limits: EventPageScheduleLimits,
    last_attempted_by_priority: [Option<EventPageSchedulePosition>; 4],
) -> Result<BuiltLocalEventSendPlan, EventPagesError> {
    if outbound_suppressed {
        return Ok(BuiltLocalEventSendPlan {
            plan: EventTurnPlanV1::Suppressed {
                direction,
                transfer_profile_digest,
            },
            scheduled: Vec::new(),
            scheduled_metadata: Vec::new(),
            last_attempted_by_priority: [None; 4],
        });
    }
    let selected_profile = negotiated
        .profile(LaneId::Event)
        .ok_or_else(|| EventPagesError::invalid("Event lane has no negotiated profile"))?;
    if matches!(difference, LocalEventSendDifference::Blind)
        && selected_profile != TransferProfileId::EventPagesV1
    {
        return Ok(BuiltLocalEventSendPlan {
            plan: EventTurnPlanV1::LegacyActive {
                direction,
                transfer_profile_digest,
                difference: LegacyDifference::Blind,
            },
            scheduled: Vec::new(),
            scheduled_metadata: Vec::new(),
            last_attempted_by_priority: [None; 4],
        });
    }
    let LocalEventSendDifference::Exact(difference) = difference else {
        let valid_metadata = authenticated_metadata.iter().all(|metadata| {
            usize::try_from(metadata.source_bytes)
                .ok()
                .is_some_and(|bytes| {
                    bytes > 0
                        && bytes <= MAX_EVENT_BYTES
                        && planned_change_page_entry_bytes(*metadata)
                            .ok()
                            .and_then(|entry| CHANGE_PAGE_FIXED_BYTES.checked_add(entry))
                            .is_some_and(|encoded| encoded <= MAX_CHANGE_PAGE_CODEC_BYTES)
                })
        }) && all_unique(
            authenticated_metadata
                .iter()
                .map(|metadata| metadata.id.as_bytes()),
        );
        if !valid_metadata {
            return Err(EventPagesError::invalid(
                "blind Event metadata is incomplete or exceeds page bounds",
            ));
        }
        let (scheduled_metadata, advanced) = plan_event_page_schedule(
            authenticated_metadata,
            schedule_limits,
            last_attempted_by_priority,
        )?;
        let scheduled = scheduled_metadata
            .iter()
            .map(|entry| entry.id)
            .collect::<Vec<_>>();
        let scheduled_count = scheduled.len();
        let unscheduled_count = authenticated_metadata.len() - scheduled_count;
        return Ok(BuiltLocalEventSendPlan {
            plan: EventTurnPlanV1::PageBlindActive {
                direction,
                transfer_profile_digest,
                scheduled_count: u32::try_from(scheduled_count)
                    .map_err(|_| EventPagesError::invalid("scheduled Event count overflows"))?,
                unscheduled_count: u32::try_from(unscheduled_count)
                    .map_err(|_| EventPagesError::invalid("unscheduled Event count overflows"))?,
            },
            scheduled,
            scheduled_metadata,
            last_attempted_by_priority: advanced,
        });
    };
    validate_strict_event_ids(difference)?;
    let set_commitment = event_difference_set_commitment(difference)?;
    if difference.is_empty() {
        return Ok(BuiltLocalEventSendPlan {
            plan: EventTurnPlanV1::Empty {
                direction,
                transfer_profile_digest,
                selected_profile,
                set_commitment,
            },
            scheduled: Vec::new(),
            scheduled_metadata: Vec::new(),
            last_attempted_by_priority: [None; 4],
        });
    }

    if selected_profile != TransferProfileId::EventPagesV1 {
        return Ok(BuiltLocalEventSendPlan {
            plan: EventTurnPlanV1::LegacyActive {
                direction,
                transfer_profile_digest,
                difference: LegacyDifference::Exact {
                    difference_count: u32::try_from(difference.len()).map_err(|_| {
                        EventPagesError::invalid("Event difference count overflows")
                    })?,
                    set_commitment,
                },
            },
            scheduled: Vec::new(),
            scheduled_metadata: Vec::new(),
            last_attempted_by_priority: [None; 4],
        });
    }

    let difference_ids = difference.iter().copied().collect::<BTreeSet<_>>();
    let mut seen_metadata = BTreeSet::new();
    let mut page_metadata = Vec::with_capacity(authenticated_metadata.len());
    for metadata in authenticated_metadata {
        if !difference_ids.contains(&metadata.id) || !seen_metadata.insert(metadata.id) {
            return Err(EventPagesError::invalid(
                "authenticated Event metadata differs from the exact difference",
            ));
        }
        let source_bytes = usize::try_from(metadata.source_bytes).ok();
        let page_eligible = source_bytes.is_some_and(|bytes| {
            bytes > 0
                && bytes <= MAX_EVENT_BYTES
                && planned_change_page_entry_bytes(*metadata)
                    .ok()
                    .and_then(|entry| CHANGE_PAGE_FIXED_BYTES.checked_add(entry))
                    .is_some_and(|encoded| encoded <= MAX_CHANGE_PAGE_CODEC_BYTES)
        });
        if page_eligible {
            page_metadata.push(*metadata);
        }
    }
    let (scheduled_metadata, advanced) =
        plan_event_page_schedule(&page_metadata, schedule_limits, last_attempted_by_priority)?;
    let scheduled = scheduled_metadata
        .iter()
        .map(|entry| entry.id)
        .collect::<Vec<_>>();
    let scheduled_count = scheduled.len();
    let unscheduled_count = difference.len() - scheduled_count;
    Ok(BuiltLocalEventSendPlan {
        plan: EventTurnPlanV1::PageActive {
            direction,
            transfer_profile_digest,
            difference_count: u32::try_from(difference.len())
                .map_err(|_| EventPagesError::invalid("Event difference count overflows"))?,
            set_commitment,
            scheduled_count: u32::try_from(scheduled_count)
                .map_err(|_| EventPagesError::invalid("scheduled Event count overflows"))?,
            unscheduled_count: u32::try_from(unscheduled_count)
                .map_err(|_| EventPagesError::invalid("unscheduled Event count overflows"))?,
        },
        scheduled,
        scheduled_metadata,
        last_attempted_by_priority: advanced,
    })
}

pub(crate) fn validate_remote_event_page_budget(
    plan: &EventTurnPlanV1,
    limits: EventPageScheduleLimits,
) -> Result<(), EventPagesError> {
    let scheduled_count = match plan {
        EventTurnPlanV1::PageActive {
            scheduled_count, ..
        }
        | EventTurnPlanV1::PageBlindActive {
            scheduled_count, ..
        } => *scheduled_count,
        _ => return Ok(()),
    };
    let scheduled_count = usize::try_from(scheduled_count)
        .map_err(|_| EventPagesError::invalid("scheduled Event count overflows"))?;
    if scheduled_count == 0 {
        return Ok(());
    }
    if scheduled_count > limits.item_capacity {
        return Err(EventPagesError::invalid(
            "remote Event schedule exceeds the local item budget",
        ));
    }
    let max_protected_frame_bytes = limits
        .max_protected_frame_bytes
        .min(MAX_CHANGE_PAGE_PROTECTED_BYTES);
    let max_codec_bytes = max_protected_frame_bytes
        .checked_sub(PROTECTED_FRAME_FIXED_BYTES)
        .ok_or_else(|| EventPagesError::invalid("carrier frame bound cannot hold Event pages"))?;
    let header_codec_bytes = CHANGE_TURN_HEADER_FIXED_BYTES
        .checked_add(
            scheduled_count
                .checked_mul(32)
                .ok_or_else(|| EventPagesError::invalid("Event schedule length overflows"))?,
        )
        .ok_or_else(|| EventPagesError::invalid("Event header length overflows"))?;
    if header_codec_bytes > max_codec_bytes || CHANGE_TURN_FINISHED_FIXED_BYTES > max_codec_bytes {
        return Err(EventPagesError::invalid(
            "remote Event schedule exceeds the carrier frame bound",
        ));
    }
    let entries_per_page = max_codec_bytes
        .checked_sub(CHANGE_PAGE_FIXED_BYTES)
        .map(|bytes| bytes / MINIMUM_CHANGE_PAGE_ENTRY_BYTES)
        .unwrap_or(0)
        .min(MAX_CHANGE_PAGE_ENTRIES);
    if entries_per_page == 0 {
        return Err(EventPagesError::invalid(
            "carrier frame bound cannot hold an Event page entry",
        ));
    }
    let page_count = scheduled_count
        .checked_add(entries_per_page - 1)
        .ok_or_else(|| EventPagesError::invalid("Event page count overflows"))?
        / entries_per_page;
    let frame_count = page_count
        .checked_add(2)
        .ok_or_else(|| EventPagesError::invalid("Event turn frame count overflows"))?;
    if frame_count > limits.frame_capacity {
        return Err(EventPagesError::invalid(
            "remote Event schedule exceeds the local frame budget",
        ));
    }
    let minimum_turn_bytes = framed_turn_bytes(header_codec_bytes)
        .and_then(|bytes| {
            framed_turn_bytes(CHANGE_TURN_FINISHED_FIXED_BYTES)
                .and_then(|terminal| bytes.checked_add(terminal))
        })
        .and_then(|bytes| {
            framed_turn_bytes(CHANGE_PAGE_FIXED_BYTES).and_then(|page| {
                page.checked_mul(page_count)
                    .and_then(|pages| bytes.checked_add(pages))
            })
        })
        .and_then(|bytes| {
            MINIMUM_CHANGE_PAGE_ENTRY_BYTES
                .checked_mul(scheduled_count)
                .and_then(|entries| bytes.checked_add(entries))
        })
        .ok_or_else(|| EventPagesError::invalid("Event turn byte count overflows"))?;
    if minimum_turn_bytes > limits.turn_bytes {
        return Err(EventPagesError::invalid(
            "remote Event schedule exceeds the local byte budget",
        ));
    }
    Ok(())
}

pub(crate) fn validate_remote_event_send_plan(
    plan: &EventTurnPlanV1,
    expected_direction: EventDirection,
    expected_transfer_profile_digest: [u8; 32],
    negotiated: &NegotiatedTransferProfiles,
    missing: LocalEventSendDifference<'_>,
    expect_suppressed: bool,
) -> Result<(), EventPagesError> {
    let (direction, digest) = match plan {
        EventTurnPlanV1::PageActive {
            direction,
            transfer_profile_digest,
            ..
        }
        | EventTurnPlanV1::PageBlindActive {
            direction,
            transfer_profile_digest,
            ..
        }
        | EventTurnPlanV1::LegacyActive {
            direction,
            transfer_profile_digest,
            ..
        }
        | EventTurnPlanV1::Empty {
            direction,
            transfer_profile_digest,
            ..
        }
        | EventTurnPlanV1::Suppressed {
            direction,
            transfer_profile_digest,
        } => (*direction, *transfer_profile_digest),
    };
    if direction != expected_direction || digest != expected_transfer_profile_digest {
        return Err(EventPagesError::invalid(
            "Event turn plan context differs from the authenticated contact",
        ));
    }
    if expect_suppressed {
        return matches!(plan, EventTurnPlanV1::Suppressed { .. })
            .then_some(())
            .ok_or_else(|| {
                EventPagesError::invalid("outbound ReceiveOnly plan is not suppressed")
            });
    }
    if matches!(plan, EventTurnPlanV1::Suppressed { .. }) {
        return Err(EventPagesError::invalid(
            "unexpected suppressed Event turn plan",
        ));
    }
    let selected_profile = negotiated
        .profile(LaneId::Event)
        .ok_or_else(|| EventPagesError::invalid("Event lane has no negotiated profile"))?;
    let LocalEventSendDifference::Exact(missing) = missing else {
        return match (selected_profile, plan) {
            (TransferProfileId::EventPagesV1, EventTurnPlanV1::PageBlindActive { .. })
            | (
                TransferProfileId::LegacyV6,
                EventTurnPlanV1::LegacyActive {
                    difference: LegacyDifference::Blind,
                    ..
                },
            ) => Ok(()),
            _ => Err(EventPagesError::invalid(
                "blind Event direction differs from its negotiated profile",
            )),
        };
    };
    validate_strict_event_ids(missing)?;
    let count = u32::try_from(missing.len())
        .map_err(|_| EventPagesError::invalid("Event difference count overflows"))?;
    let commitment = event_difference_set_commitment(missing)?;
    match plan {
        EventTurnPlanV1::PageActive {
            difference_count,
            set_commitment,
            scheduled_count,
            unscheduled_count,
            ..
        } if selected_profile == TransferProfileId::EventPagesV1
            && !missing.is_empty()
            && *difference_count == count
            && *set_commitment == commitment
            && scheduled_count.checked_add(*unscheduled_count) == Some(count) =>
        {
            Ok(())
        }
        EventTurnPlanV1::LegacyActive {
            difference:
                LegacyDifference::Exact {
                    difference_count,
                    set_commitment,
                },
            ..
        } if selected_profile == TransferProfileId::LegacyV6
            && *difference_count == count
            && *set_commitment == commitment =>
        {
            Ok(())
        }
        EventTurnPlanV1::Empty {
            selected_profile: plan_profile,
            set_commitment,
            ..
        } if missing.is_empty()
            && *plan_profile == selected_profile
            && *set_commitment == commitment =>
        {
            Ok(())
        }
        _ => Err(EventPagesError::invalid(
            "Event turn plan differs from authenticated missing IDs or negotiated profile",
        )),
    }
}

pub(crate) fn schedule_digest(schedule: &[EventTransferId]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(b"ASTER/event-page-schedule/v1\0");
    hasher.update(
        u32::try_from(schedule.len())
            .expect("bounded Event schedule")
            .to_be_bytes(),
    );
    for id in schedule {
        hasher.update(id.as_bytes());
    }
    hasher.finalize().into()
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct ChangeTurnHeaderV1 {
    pub(crate) direction: EventDirection,
    pub(crate) transfer_profile_digest: [u8; 32],
    pub(crate) set_commitment: [u8; 32],
    pub(crate) scheduled: Vec<EventTransferId>,
    pub(crate) schedule_digest: [u8; 32],
}

impl ChangeTurnHeaderV1 {
    pub(crate) fn encode(&self) -> Result<Vec<u8>, EventPagesError> {
        if self.scheduled.len() > MAX_SCHEDULED_EVENT_IDS {
            return Err(EventPagesError::invalid(
                "Event schedule exceeds the frame-derived codec ceiling",
            ));
        }
        if !all_unique(self.scheduled.iter().map(EventTransferId::as_bytes)) {
            return Err(EventPagesError::invalid(
                "Event schedule contains duplicate IDs",
            ));
        }
        if self.schedule_digest != schedule_digest(&self.scheduled) {
            return Err(EventPagesError::invalid("Event schedule digest differs"));
        }
        let mut output = vec![1];
        encode_lane_profile_direction(&mut output, self.direction);
        output.extend_from_slice(&self.transfer_profile_digest);
        output.extend_from_slice(&self.set_commitment);
        output.extend_from_slice(
            &u32::try_from(self.scheduled.len())
                .map_err(|_| EventPagesError::invalid("Event schedule count overflows"))?
                .to_be_bytes(),
        );
        for id in &self.scheduled {
            output.extend_from_slice(id.as_bytes());
        }
        output.extend_from_slice(&self.schedule_digest);
        if output.len() > MAX_CHANGE_PAGE_CODEC_BYTES {
            return Err(EventPagesError::invalid(
                "change-turn header exceeds the frame-body ceiling",
            ));
        }
        Ok(output)
    }

    pub(crate) fn decode(bytes: &[u8]) -> Result<Self, EventPagesError> {
        if bytes.len() > MAX_CHANGE_PAGE_CODEC_BYTES {
            return Err(EventPagesError::invalid(
                "change-turn header exceeds the frame-body ceiling",
            ));
        }
        let mut cursor = Cursor::new(bytes);
        require_version(cursor.u8()?, 1, "change-turn header")?;
        let direction = decode_lane_profile_direction(&mut cursor)?;
        let transfer_profile_digest = cursor.array_32()?;
        let set_commitment = cursor.array_32()?;
        let count = usize::try_from(cursor.u32()?)
            .map_err(|_| EventPagesError::invalid("Event schedule count overflows"))?;
        if count > MAX_SCHEDULED_EVENT_IDS {
            return Err(EventPagesError::invalid(
                "Event schedule exceeds the frame-derived codec ceiling",
            ));
        }
        let mut scheduled = Vec::with_capacity(count);
        for _ in 0..count {
            scheduled.push(EventTransferId::new(cursor.array_32()?));
        }
        let encoded_digest = cursor.array_32()?;
        cursor.finish()?;
        if !all_unique(scheduled.iter().map(EventTransferId::as_bytes)) {
            return Err(EventPagesError::invalid(
                "Event schedule contains duplicate IDs",
            ));
        }
        if encoded_digest != schedule_digest(&scheduled) {
            return Err(EventPagesError::invalid("Event schedule digest differs"));
        }
        Ok(Self {
            direction,
            transfer_profile_digest,
            set_commitment,
            scheduled,
            schedule_digest: encoded_digest,
        })
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct ChangePageCustody {
    pub(crate) exchange_id: u64,
    pub(crate) wrapper: Vec<u8>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct ChangePageEntry {
    pub(crate) id: EventTransferId,
    pub(crate) custody: Option<ChangePageCustody>,
    pub(crate) source_event: Vec<u8>,
}

impl ChangePageEntry {
    pub(crate) fn encoded_len(&self) -> Result<usize, EventPagesError> {
        let custody_bytes = match &self.custody {
            Some(custody)
                if !custody.wrapper.is_empty()
                    && custody.wrapper.len() <= MAX_CUSTODY_WRAPPER_BYTES =>
            {
                8usize
                    .checked_add(2)
                    .and_then(|bytes| bytes.checked_add(custody.wrapper.len()))
                    .ok_or_else(|| EventPagesError::invalid("custody wrapper size overflows"))?
            }
            Some(_) => return Err(EventPagesError::invalid("custody wrapper size is invalid")),
            None => 0,
        };
        CHANGE_PAGE_ENTRY_FIXED_BYTES
            .checked_add(custody_bytes)
            .and_then(|bytes| bytes.checked_add(self.source_event.len()))
            .ok_or_else(|| EventPagesError::invalid("change page entry size overflows"))
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct ChangePageV7 {
    pub(crate) direction: EventDirection,
    pub(crate) transfer_profile_digest: [u8; 32],
    pub(crate) schedule_digest: [u8; 32],
    pub(crate) page_number: u32,
    pub(crate) entries: Vec<ChangePageEntry>,
    pub(crate) remaining: u32,
}

impl ChangePageV7 {
    pub(crate) fn encode(&self) -> Result<Vec<u8>, EventPagesError> {
        validate_page_progress(self.page_number, self.entries.len(), self.remaining)?;
        if self.entries.is_empty() || self.entries.len() > MAX_CHANGE_PAGE_ENTRIES {
            return Err(EventPagesError::invalid(
                "change page entry count is invalid",
            ));
        }
        if !all_unique(self.entries.iter().map(|entry| entry.id.as_bytes())) {
            return Err(EventPagesError::invalid(
                "change page contains duplicate IDs",
            ));
        }
        let mut output = vec![1];
        encode_lane_profile_direction(&mut output, self.direction);
        output.extend_from_slice(&self.transfer_profile_digest);
        output.extend_from_slice(&self.schedule_digest);
        output.extend_from_slice(&self.page_number.to_be_bytes());
        output.extend_from_slice(
            &u16::try_from(self.entries.len())
                .map_err(|_| EventPagesError::invalid("change page count overflows"))?
                .to_be_bytes(),
        );
        for entry in &self.entries {
            if entry.source_event.is_empty() || entry.source_event.len() > MAX_EVENT_BYTES {
                return Err(EventPagesError::invalid("source Event size is invalid"));
            }
            output.extend_from_slice(entry.id.as_bytes());
            match &entry.custody {
                Some(custody) => {
                    if custody.wrapper.is_empty()
                        || custody.wrapper.len() > MAX_CUSTODY_WRAPPER_BYTES
                    {
                        return Err(EventPagesError::invalid("custody wrapper size is invalid"));
                    }
                    output.push(1);
                    output.extend_from_slice(&custody.exchange_id.to_be_bytes());
                    output.extend_from_slice(
                        &u16::try_from(custody.wrapper.len())
                            .map_err(|_| {
                                EventPagesError::invalid("custody wrapper size overflows")
                            })?
                            .to_be_bytes(),
                    );
                    output.extend_from_slice(&custody.wrapper);
                }
                None => output.push(0),
            }
            output.extend_from_slice(
                &u32::try_from(entry.source_event.len())
                    .map_err(|_| EventPagesError::invalid("source Event size overflows"))?
                    .to_be_bytes(),
            );
            output.extend_from_slice(&entry.source_event);
            if output.len() > MAX_CHANGE_PAGE_CODEC_BYTES {
                return Err(EventPagesError::invalid(
                    "change page exceeds protected-page bound",
                ));
            }
        }
        output.extend_from_slice(&self.remaining.to_be_bytes());
        if output.len() > MAX_CHANGE_PAGE_CODEC_BYTES {
            return Err(EventPagesError::invalid(
                "change page exceeds protected-page bound",
            ));
        }
        Ok(output)
    }

    pub(crate) fn decode(bytes: &[u8]) -> Result<Self, EventPagesError> {
        if bytes.len() > MAX_CHANGE_PAGE_CODEC_BYTES {
            return Err(EventPagesError::invalid(
                "change page exceeds protected-page bound",
            ));
        }
        let mut cursor = Cursor::new(bytes);
        require_version(cursor.u8()?, 1, "change page")?;
        let direction = decode_lane_profile_direction(&mut cursor)?;
        let transfer_profile_digest = cursor.array_32()?;
        let schedule_digest = cursor.array_32()?;
        let page_number = cursor.u32()?;
        let count = usize::from(cursor.u16()?);
        if count == 0 || count > MAX_CHANGE_PAGE_ENTRIES {
            return Err(EventPagesError::invalid(
                "change page entry count is invalid",
            ));
        }
        let mut entries = Vec::with_capacity(count);
        for _ in 0..count {
            let id = EventTransferId::new(cursor.array_32()?);
            let custody = match cursor.u8()? {
                0 => None,
                1 => {
                    let exchange_id = cursor.u64()?;
                    let size = usize::from(cursor.u16()?);
                    if size == 0 || size > MAX_CUSTODY_WRAPPER_BYTES {
                        return Err(EventPagesError::invalid("custody wrapper size is invalid"));
                    }
                    Some(ChangePageCustody {
                        exchange_id,
                        wrapper: cursor.bytes(size)?.to_vec(),
                    })
                }
                _ => return Err(EventPagesError::invalid("invalid custody evidence mode")),
            };
            let size = usize::try_from(cursor.u32()?)
                .map_err(|_| EventPagesError::invalid("source Event size overflows"))?;
            if size == 0 || size > MAX_EVENT_BYTES {
                return Err(EventPagesError::invalid("source Event size is invalid"));
            }
            entries.push(ChangePageEntry {
                id,
                custody,
                source_event: cursor.bytes(size)?.to_vec(),
            });
        }
        let remaining = cursor.u32()?;
        cursor.finish()?;
        validate_page_progress(page_number, entries.len(), remaining)?;
        if !all_unique(entries.iter().map(|entry| entry.id.as_bytes())) {
            return Err(EventPagesError::invalid(
                "change page contains duplicate IDs",
            ));
        }
        Ok(Self {
            direction,
            transfer_profile_digest,
            schedule_digest,
            page_number,
            entries,
            remaining,
        })
    }
}

fn validate_page_progress(
    page_number: u32,
    entry_count: usize,
    remaining: u32,
) -> Result<(), EventPagesError> {
    let page_number = usize::try_from(page_number)
        .map_err(|_| EventPagesError::invalid("change page number overflows"))?;
    let remaining = usize::try_from(remaining)
        .map_err(|_| EventPagesError::invalid("remaining Event count overflows"))?;
    if page_number >= MAX_SCHEDULED_EVENT_IDS
        || remaining > MAX_SCHEDULED_EVENT_IDS
        || entry_count
            .checked_add(remaining)
            .is_none_or(|total| total > MAX_SCHEDULED_EVENT_IDS)
    {
        return Err(EventPagesError::invalid(
            "change page progress exceeds the frame-derived schedule ceiling",
        ));
    }
    Ok(())
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct ChangeTurnFinishedV1 {
    pub(crate) direction: EventDirection,
    pub(crate) transfer_profile_digest: [u8; 32],
    pub(crate) set_commitment: [u8; 32],
    pub(crate) schedule_digest: [u8; 32],
    pub(crate) final_page_count: u32,
}

impl ChangeTurnFinishedV1 {
    pub(crate) fn encode(&self) -> Result<Vec<u8>, EventPagesError> {
        validate_final_page_count(self.final_page_count)?;
        let mut output = vec![1];
        encode_lane_profile_direction(&mut output, self.direction);
        output.extend_from_slice(&self.transfer_profile_digest);
        output.extend_from_slice(&self.set_commitment);
        output.extend_from_slice(&self.schedule_digest);
        output.extend_from_slice(&self.final_page_count.to_be_bytes());
        output.extend_from_slice(&0u32.to_be_bytes());
        Ok(output)
    }

    pub(crate) fn decode(bytes: &[u8]) -> Result<Self, EventPagesError> {
        let mut cursor = Cursor::new(bytes);
        require_version(cursor.u8()?, 1, "change-turn terminal")?;
        let direction = decode_lane_profile_direction(&mut cursor)?;
        let transfer_profile_digest = cursor.array_32()?;
        let set_commitment = cursor.array_32()?;
        let schedule_digest = cursor.array_32()?;
        let final_page_count = cursor.u32()?;
        validate_final_page_count(final_page_count)?;
        if cursor.u32()? != 0 {
            return Err(EventPagesError::invalid(
                "change-turn terminal remaining count must be zero",
            ));
        }
        cursor.finish()?;
        Ok(Self {
            direction,
            transfer_profile_digest,
            set_commitment,
            schedule_digest,
            final_page_count,
        })
    }
}

fn validate_final_page_count(final_page_count: u32) -> Result<(), EventPagesError> {
    if usize::try_from(final_page_count)
        .map_err(|_| EventPagesError::invalid("final Event page count overflows"))?
        > MAX_SCHEDULED_EVENT_IDS
    {
        return Err(EventPagesError::invalid(
            "final Event page count exceeds the frame-derived schedule ceiling",
        ));
    }
    Ok(())
}

fn encode_lane_profile_direction(output: &mut Vec<u8>, direction: EventDirection) {
    output.extend_from_slice(&(LaneId::Event as u16).to_be_bytes());
    output.extend_from_slice(&(TransferProfileId::EventPagesV1 as u16).to_be_bytes());
    output.push(encode_event_direction(direction));
}

fn decode_lane_profile_direction(
    cursor: &mut Cursor<'_>,
) -> Result<EventDirection, EventPagesError> {
    if cursor.u16()? != LaneId::Event as u16 {
        return Err(EventPagesError::invalid("change frame has the wrong lane"));
    }
    if cursor.u16()? != TransferProfileId::EventPagesV1 as u16 {
        return Err(EventPagesError::invalid(
            "change frame has the wrong profile",
        ));
    }
    decode_event_direction(cursor.u8()?)
}

fn all_unique<'a>(mut values: impl Iterator<Item = &'a [u8; 32]>) -> bool {
    let mut seen = BTreeSet::new();
    values.all(|value| seen.insert(*value))
}

fn require_version(actual: u8, expected: u8, label: &str) -> Result<(), EventPagesError> {
    if actual != expected {
        return Err(EventPagesError::invalid(format!(
            "unsupported {label} codec version"
        )));
    }
    Ok(())
}

struct Cursor<'a> {
    bytes: &'a [u8],
    offset: usize,
}

impl<'a> Cursor<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, offset: 0 }
    }
    fn bytes(&mut self, count: usize) -> Result<&'a [u8], EventPagesError> {
        let end = self
            .offset
            .checked_add(count)
            .ok_or_else(|| EventPagesError::invalid("codec offset overflows"))?;
        let value = self
            .bytes
            .get(self.offset..end)
            .ok_or_else(|| EventPagesError::invalid("canonical payload is truncated"))?;
        self.offset = end;
        Ok(value)
    }
    fn u8(&mut self) -> Result<u8, EventPagesError> {
        Ok(self.bytes(1)?[0])
    }
    fn u16(&mut self) -> Result<u16, EventPagesError> {
        Ok(u16::from_be_bytes(self.bytes(2)?.try_into().map_err(
            |_| EventPagesError::invalid("u16 is truncated"),
        )?))
    }
    fn u32(&mut self) -> Result<u32, EventPagesError> {
        Ok(u32::from_be_bytes(self.bytes(4)?.try_into().map_err(
            |_| EventPagesError::invalid("u32 is truncated"),
        )?))
    }
    fn u64(&mut self) -> Result<u64, EventPagesError> {
        Ok(u64::from_be_bytes(self.bytes(8)?.try_into().map_err(
            |_| EventPagesError::invalid("u64 is truncated"),
        )?))
    }
    fn array_32(&mut self) -> Result<[u8; 32], EventPagesError> {
        self.bytes(32)?
            .try_into()
            .map_err(|_| EventPagesError::invalid("32-byte field is truncated"))
    }
    fn finish(self) -> Result<(), EventPagesError> {
        if self.offset != self.bytes.len() {
            return Err(EventPagesError::invalid(
                "canonical payload contains trailing bytes",
            ));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn blob_stream_profile_is_version_neutral_and_fails_closed() {
        let v7 = TransferProfileOfferV1::for_semantic_version(SEMANTIC_PROTOCOL_V7)
            .expect("v7 transfer-profile offer");
        let v8 =
            TransferProfileOfferV1::for_semantic_version(8).expect("v8 transfer-profile offer");

        assert_eq!(v7, TransferProfileOfferV1::current());
        assert_eq!(v8, v7);
        assert_eq!(
            v7.encode().expect("v7 canonical offer"),
            vec![
                1, 5, // codec version and lane count
                0, 5, 1, 0, 1, // EventBridge: LegacyV6
                0, 4, 1, 0, 4, // Blob: BlobRangesStreamV1
                0, 3, 1, 0, 1, // Record: LegacyV6
                0, 2, 1, 0, 1, // State: LegacyV6
                0, 1, 2, 0, 2, 0, 1, // Event: EventPagesV1, LegacyV6
            ],
            "semantic-v7/v8 stream offer encoding is an immutable compatibility vector"
        );
        for semantic_version in [SEMANTIC_PROTOCOL_V7, 8] {
            assert_eq!(
                negotiate_transfer_profiles_for_semantic_version(semantic_version, &v7, &v8)
                    .expect("version-scoped stream negotiation")
                    .profile(LaneId::Blob),
                Some(TransferProfileId::BlobRangesStreamV1)
            );
        }

        let stream_on_event = TransferProfileOfferV1::from_lanes(vec![
            (LaneId::EventBridge, vec![TransferProfileId::LegacyV6]),
            (LaneId::Blob, vec![TransferProfileId::BlobRangesStreamV1]),
            (LaneId::Record, vec![TransferProfileId::LegacyV6]),
            (LaneId::State, vec![TransferProfileId::LegacyV6]),
            (
                LaneId::Event,
                vec![
                    TransferProfileId::BlobRangesStreamV1,
                    TransferProfileId::EventPagesV1,
                    TransferProfileId::LegacyV6,
                ],
            ),
        ]);
        assert!(stream_on_event.encode().is_err());

        let legacy = TransferProfileOfferV1::legacy_only();
        assert!(negotiate_transfer_profiles(&v8, &legacy).is_err());

        let duplicate_stream = TransferProfileOfferV1::from_lanes(vec![
            (LaneId::EventBridge, vec![TransferProfileId::LegacyV6]),
            (
                LaneId::Blob,
                vec![
                    TransferProfileId::BlobRangesStreamV1,
                    TransferProfileId::BlobRangesStreamV1,
                ],
            ),
            (LaneId::Record, vec![TransferProfileId::LegacyV6]),
            (LaneId::State, vec![TransferProfileId::LegacyV6]),
            (LaneId::Event, vec![TransferProfileId::LegacyV6]),
        ]);
        assert!(duplicate_stream.encode().is_err());
    }

    #[test]
    fn canonical_offer_and_intersection_cover_every_lane_without_disabling_legacy() {
        let offer = TransferProfileOfferV1::current();
        assert_eq!(
            offer.known_lanes(),
            vec![
                (LaneId::EventBridge, vec![TransferProfileId::LegacyV6]),
                (LaneId::Blob, vec![TransferProfileId::BlobRangesStreamV1]),
                (LaneId::Record, vec![TransferProfileId::LegacyV6]),
                (LaneId::State, vec![TransferProfileId::LegacyV6]),
                (
                    LaneId::Event,
                    vec![TransferProfileId::EventPagesV1, TransferProfileId::LegacyV6]
                ),
            ]
        );
        let encoded = offer.encode().expect("canonical offer");
        assert_eq!(TransferProfileOfferV1::decode(&encoded).unwrap(), offer);
        let negotiated = negotiate_transfer_profiles(&offer, &offer).unwrap();
        assert_eq!(
            negotiated.profile(LaneId::Event),
            Some(TransferProfileId::EventPagesV1)
        );
        assert_eq!(
            negotiated.profile(LaneId::State),
            Some(TransferProfileId::LegacyV6)
        );
        assert!(negotiated.contains(LaneId::Event, TransferProfileId::LegacyV6));
        assert_eq!(
            transfer_profile_digest(&offer, &offer, &negotiated),
            transfer_profile_digest(&offer, &offer, &negotiated)
        );
    }

    #[test]
    fn malformed_offers_fail_and_unknown_noncritical_profiles_are_transcript_bound() {
        let missing_legacy = TransferProfileOfferV1::from_lanes(vec![
            (LaneId::EventBridge, vec![TransferProfileId::LegacyV6]),
            (LaneId::Blob, vec![TransferProfileId::LegacyV6]),
            (LaneId::Record, vec![TransferProfileId::LegacyV6]),
            (LaneId::State, vec![TransferProfileId::LegacyV6]),
            (LaneId::Event, vec![TransferProfileId::EventPagesV1]),
        ]);
        assert!(missing_legacy.encode().is_err());

        let mut with_unknown = TransferProfileOfferV1::current().encode().unwrap();
        let event_profile_count_offset = with_unknown.len() - 5;
        with_unknown[event_profile_count_offset] = 3;
        with_unknown.splice(
            event_profile_count_offset + 1..event_profile_count_offset + 1,
            7u16.to_be_bytes(),
        );
        let decoded = TransferProfileOfferV1::decode(&with_unknown).unwrap();
        assert_eq!(decoded.encode().unwrap(), with_unknown);
        assert_ne!(decoded, TransferProfileOfferV1::current());
        let negotiated =
            negotiate_transfer_profiles(&decoded, &TransferProfileOfferV1::current()).unwrap();
        assert_eq!(
            negotiated.profile(LaneId::Event),
            Some(TransferProfileId::EventPagesV1)
        );

        let mut critical = with_unknown;
        critical[event_profile_count_offset + 1..event_profile_count_offset + 3]
            .copy_from_slice(&0x8007u16.to_be_bytes());
        assert!(TransferProfileOfferV1::decode(&critical).is_err());
    }

    #[test]
    fn unknown_noncritical_lanes_are_transcript_bound_but_not_selected() {
        let current = TransferProfileOfferV1::current();
        let mut with_unknown = current.encode().unwrap();
        with_unknown[1] += 1;
        with_unknown.splice(2..2, [0, 7, 1, 0, 7]);

        let decoded = TransferProfileOfferV1::decode(&with_unknown).unwrap();
        assert_eq!(decoded.encode().unwrap(), with_unknown);
        let negotiated = negotiate_transfer_profiles(&decoded, &current).unwrap();
        assert_eq!(
            negotiated.profile(LaneId::Event),
            Some(TransferProfileId::EventPagesV1)
        );
        assert_ne!(
            transfer_profile_digest(&decoded, &current, &negotiated),
            transfer_profile_digest(&current, &current, &negotiated)
        );

        let mut critical = with_unknown;
        critical[2..4].copy_from_slice(&0x8007u16.to_be_bytes());
        assert!(TransferProfileOfferV1::decode(&critical).is_err());
    }

    #[test]
    fn codecs_reject_truncation_and_trailing_bytes() {
        let offer = TransferProfileOfferV1::current().encode().unwrap();
        assert!(TransferProfileOfferV1::decode(&offer[..offer.len() - 1]).is_err());
        let mut trailing = offer;
        trailing.push(0);
        assert!(TransferProfileOfferV1::decode(&trailing).is_err());
    }

    fn id(byte: u8) -> aster_redb_store::EventTransferId {
        aster_redb_store::EventTransferId::new([byte; 32])
    }

    #[test]
    fn turn_plan_variants_round_trip_and_reject_inconsistent_counts() {
        let plan = EventTurnPlanV1::PageActive {
            direction: EventDirection::ToSessionResponder,
            transfer_profile_digest: [3; 32],
            difference_count: 3,
            set_commitment: [4; 32],
            scheduled_count: 2,
            unscheduled_count: 1,
        };
        assert_eq!(
            EventTurnPlanV1::decode(&plan.encode().unwrap()).unwrap(),
            plan
        );

        let invalid = EventTurnPlanV1::PageActive {
            direction: EventDirection::ToSessionResponder,
            transfer_profile_digest: [3; 32],
            difference_count: 4,
            set_commitment: [4; 32],
            scheduled_count: 2,
            unscheduled_count: 1,
        };
        assert!(invalid.encode().is_err());

        let blind = EventTurnPlanV1::LegacyActive {
            direction: EventDirection::ToSessionInitiator,
            transfer_profile_digest: [5; 32],
            difference: LegacyDifference::Blind,
        };
        assert_eq!(
            EventTurnPlanV1::decode(&blind.encode().unwrap()).unwrap(),
            blind
        );

        let empty = EventTurnPlanV1::Empty {
            direction: EventDirection::ToSessionResponder,
            transfer_profile_digest: [6; 32],
            selected_profile: TransferProfileId::EventPagesV1,
            set_commitment: empty_set_commitment(),
        };
        assert_eq!(
            EventTurnPlanV1::decode(&empty.encode().unwrap()).unwrap(),
            empty
        );
    }

    #[test]
    fn codec_ceilings_are_derived_from_authoritative_byte_bounds() {
        const CHANGE_PAGE_FIXED_BYTES: usize = 1 + 2 + 2 + 1 + 32 + 32 + 4 + 2 + 4;
        const MINIMUM_ENTRY_BYTES: usize = 32 + 1 + 4 + 1;
        let byte_derived_entries =
            (MAX_CHANGE_PAGE_CODEC_BYTES - CHANGE_PAGE_FIXED_BYTES) / MINIMUM_ENTRY_BYTES;

        assert_eq!(
            MAX_CHANGE_PAGE_PROTECTED_BYTES,
            aster_iroh::DEFAULT_MAX_EXCHANGE_BYTES
        );
        assert_eq!(MAX_EVENT_BYTES, crate::frame::MAX_OBJECT_BYTES);
        assert_eq!(MAX_CHANGE_PAGE_ENTRIES, byte_derived_entries);

        let empty_header = ChangeTurnHeaderV1 {
            direction: EventDirection::ToSessionResponder,
            transfer_profile_digest: [1; 32],
            set_commitment: [2; 32],
            scheduled: Vec::new(),
            schedule_digest: schedule_digest(&[]),
        };
        assert_eq!(
            empty_header.encode().unwrap().len(),
            CHANGE_TURN_HEADER_FIXED_BYTES
        );

        let minimum_page = ChangePageV7 {
            direction: EventDirection::ToSessionResponder,
            transfer_profile_digest: [1; 32],
            schedule_digest: [2; 32],
            page_number: 0,
            entries: vec![ChangePageEntry {
                id: id(3),
                custody: None,
                source_event: vec![4],
            }],
            remaining: 0,
        };
        assert_eq!(
            minimum_page.encode().unwrap().len(),
            CHANGE_PAGE_FIXED_BYTES + MINIMUM_CHANGE_PAGE_ENTRY_BYTES
        );
    }

    #[test]
    fn page_body_budget_reserves_mechanics_and_protection_overhead() {
        assert_eq!(
            MAX_CHANGE_PAGE_CODEC_BYTES
                + MECHANICS_FRAME_OVERHEAD_BYTES
                + aster_mesh::REFERENCE_SESSION_FRAME_OVERHEAD_BYTES,
            MAX_CHANGE_PAGE_PROTECTED_BYTES
        );
    }

    #[test]
    fn codec_bounds_are_protocol_resources_not_the_current_contact_budget() {
        let above_current_contact_budget = EventTurnPlanV1::PageActive {
            direction: EventDirection::ToSessionResponder,
            transfer_profile_digest: [1; 32],
            difference_count: 3_501,
            set_commitment: [2; 32],
            scheduled_count: 3_501,
            unscheduled_count: 0,
        };
        assert!(above_current_contact_budget.encode().is_ok());

        let maximum_fixed_width_difference = EventTurnPlanV1::PageActive {
            direction: EventDirection::ToSessionResponder,
            transfer_profile_digest: [1; 32],
            difference_count: u32::MAX,
            set_commitment: [2; 32],
            scheduled_count: 0,
            unscheduled_count: u32::MAX,
        };
        assert!(maximum_fixed_width_difference.encode().is_ok());

        let oversized_schedule = EventTurnPlanV1::PageActive {
            direction: EventDirection::ToSessionResponder,
            transfer_profile_digest: [1; 32],
            difference_count: (MAX_SCHEDULED_EVENT_IDS + 1) as u32,
            set_commitment: [2; 32],
            scheduled_count: (MAX_SCHEDULED_EVENT_IDS + 1) as u32,
            unscheduled_count: 0,
        };
        assert!(oversized_schedule.encode().is_err());

        let oversized_page = ChangePageV7 {
            direction: EventDirection::ToSessionResponder,
            transfer_profile_digest: [1; 32],
            schedule_digest: [2; 32],
            page_number: MAX_SCHEDULED_EVENT_IDS as u32,
            entries: vec![ChangePageEntry {
                id: id(1),
                custody: None,
                source_event: vec![3],
            }],
            remaining: (MAX_SCHEDULED_EVENT_IDS + 1) as u32,
        };
        assert!(oversized_page.encode().is_err());

        let oversized_terminal = ChangeTurnFinishedV1 {
            direction: EventDirection::ToSessionResponder,
            transfer_profile_digest: [1; 32],
            set_commitment: [2; 32],
            schedule_digest: [3; 32],
            final_page_count: (MAX_SCHEDULED_EVENT_IDS + 1) as u32,
        };
        assert!(oversized_terminal.encode().is_err());
    }

    #[test]
    fn header_page_and_terminal_are_canonical_and_bounded() {
        let scheduled = vec![id(1), id(2)];
        let header = ChangeTurnHeaderV1 {
            direction: EventDirection::ToSessionResponder,
            transfer_profile_digest: [7; 32],
            set_commitment: [8; 32],
            schedule_digest: schedule_digest(&scheduled),
            scheduled,
        };
        assert_eq!(
            ChangeTurnHeaderV1::decode(&header.encode().unwrap()).unwrap(),
            header
        );

        let page = ChangePageV7 {
            direction: EventDirection::ToSessionResponder,
            transfer_profile_digest: [7; 32],
            schedule_digest: header.schedule_digest,
            page_number: 0,
            entries: vec![ChangePageEntry {
                id: id(1),
                custody: None,
                source_event: vec![9; 64],
            }],
            remaining: 1,
        };
        assert_eq!(ChangePageV7::decode(&page.encode().unwrap()).unwrap(), page);

        let finite_page = ChangePageV7 {
            entries: vec![ChangePageEntry {
                id: id(2),
                custody: Some(ChangePageCustody {
                    exchange_id: 9,
                    wrapper: vec![0xaa, 0xbb, 0xcc],
                }),
                source_event: vec![7; 32],
            }],
            ..page.clone()
        };
        let finite_bytes = finite_page.encode().unwrap();
        assert_eq!(ChangePageV7::decode(&finite_bytes).unwrap(), finite_page);
        let mut invalid_mode = finite_bytes;
        invalid_mode[CHANGE_PAGE_FIXED_BYTES - 4 + 32] = 2;
        assert!(ChangePageV7::decode(&invalid_mode).is_err());

        let empty_custody = ChangePageV7 {
            entries: vec![ChangePageEntry {
                id: id(2),
                custody: Some(ChangePageCustody {
                    exchange_id: 9,
                    wrapper: Vec::new(),
                }),
                source_event: vec![7],
            }],
            ..page.clone()
        };
        assert!(empty_custody.encode().is_err());

        let finished = ChangeTurnFinishedV1 {
            direction: EventDirection::ToSessionResponder,
            transfer_profile_digest: [7; 32],
            set_commitment: [8; 32],
            schedule_digest: header.schedule_digest,
            final_page_count: 1,
        };
        assert_eq!(
            ChangeTurnFinishedV1::decode(&finished.encode().unwrap()).unwrap(),
            finished
        );

        let duplicate = ChangeTurnHeaderV1 {
            scheduled: vec![id(1), id(1)],
            schedule_digest: schedule_digest(&[id(1), id(1)]),
            ..header
        };
        assert!(duplicate.encode().is_err());

        let oversized = ChangePageV7 {
            entries: vec![ChangePageEntry {
                id: id(3),
                custody: None,
                source_event: vec![0; MAX_EVENT_BYTES + 1],
            }],
            ..page
        };
        assert!(oversized.encode().is_err());
    }

    #[test]
    fn blob_stream_only_offer_matches_versioned_vector() {
        let encoded = TransferProfileOfferV1::current().encode().unwrap();
        assert_eq!(
            format!(
                "# aster-blob-ranges-stream-vectors/v1\tsemantic=7,8\toracle=python-stdlib\nACCEPT\toffer-blob-stream-only-v1\t{}\n",
                vector_hex(&encoded)
            ),
            include_str!("../../../conformance/vectors/blob-ranges-stream-v1.tsv")
        );
        for semantic_version in [SEMANTIC_PROTOCOL_V7, SEMANTIC_PROTOCOL_V8] {
            assert_eq!(
                TransferProfileOfferV1::decode(&encoded).unwrap(),
                TransferProfileOfferV1::for_semantic_version(semantic_version)
                    .expect("versioned Blob stream offer")
            );
        }
    }

    #[test]
    fn blob_ranges_stream_rejects_unsupported_peer_without_fallback() {
        let current = TransferProfileOfferV1::current();
        let legacy = legacy_only_offer();
        let selected = negotiate_transfer_profiles(&current, &current).unwrap();
        assert_eq!(selected.profile(LaneId::Blob).unwrap() as u16, 4);
        assert_eq!(TransferProfileId::decode(3), None);
        let mut reserved = current.encode().unwrap();
        reserved[9] = 2;
        reserved[10..12].copy_from_slice(&3u16.to_be_bytes());
        reserved.splice(12..12, 1u16.to_be_bytes());
        let reserved = TransferProfileOfferV1::decode(&reserved).unwrap();
        assert!(negotiate_transfer_profiles(&current, &reserved).is_err());
        assert!(negotiate_transfer_profiles(&reserved, &current).is_err());
        for (left, right) in [(&current, &legacy), (&legacy, &current)] {
            let error = negotiate_transfer_profiles(left, right).unwrap_err();
            assert!(
                error
                    .to_string()
                    .contains("no common transfer profile for lane 4")
            );
        }
    }

    fn legacy_only_offer() -> TransferProfileOfferV1 {
        TransferProfileOfferV1::from_lanes(vec![
            (LaneId::EventBridge, vec![TransferProfileId::LegacyV6]),
            (LaneId::Blob, vec![TransferProfileId::LegacyV6]),
            (LaneId::Record, vec![TransferProfileId::LegacyV6]),
            (LaneId::State, vec![TransferProfileId::LegacyV6]),
            (LaneId::Event, vec![TransferProfileId::LegacyV6]),
        ])
    }

    fn legacy_event_offer() -> TransferProfileOfferV1 {
        TransferProfileOfferV1::from_lanes(vec![
            (LaneId::EventBridge, vec![TransferProfileId::LegacyV6]),
            (LaneId::Blob, vec![TransferProfileId::BlobRangesStreamV1]),
            (LaneId::Record, vec![TransferProfileId::LegacyV6]),
            (LaneId::State, vec![TransferProfileId::LegacyV6]),
            (LaneId::Event, vec![TransferProfileId::LegacyV6]),
        ])
    }

    fn vector_hex(bytes: &[u8]) -> String {
        const DIGITS: &[u8; 16] = b"0123456789abcdef";
        let mut output = String::with_capacity(bytes.len() * 2);
        for byte in bytes {
            output.push(char::from(DIGITS[usize::from(byte >> 4)]));
            output.push(char::from(DIGITS[usize::from(byte & 0x0f)]));
        }
        output
    }

    fn canonical_event_page_vectors() -> Vec<(&'static str, Vec<u8>)> {
        // Historical vectors bind the original explicit offers, not new defaults.
        let current = TransferProfileOfferV1::from_lanes(vec![
            (LaneId::EventBridge, vec![TransferProfileId::LegacyV6]),
            (LaneId::Blob, vec![TransferProfileId::LegacyV6]),
            (LaneId::Record, vec![TransferProfileId::LegacyV6]),
            (LaneId::State, vec![TransferProfileId::LegacyV6]),
            (
                LaneId::Event,
                vec![TransferProfileId::EventPagesV1, TransferProfileId::LegacyV6],
            ),
        ]);
        let legacy = legacy_only_offer();
        let current_profiles = negotiate_transfer_profiles(&current, &current).unwrap();
        let fallback_profiles = negotiate_transfer_profiles(&current, &legacy).unwrap();
        let current_digest = transfer_profile_digest(&current, &current, &current_profiles);
        let fallback_digest = transfer_profile_digest(&current, &legacy, &fallback_profiles);
        let scheduled = vec![id(0x11), id(0x22)];
        let set_commitment = event_difference_set_commitment(&scheduled).unwrap();
        let schedule_digest = schedule_digest(&scheduled);

        vec![
            ("offer-current", current.encode().unwrap()),
            ("offer-legacy", legacy.encode().unwrap()),
            ("intersection-current", current_profiles.encode()),
            ("profile-digest-current", current_digest.to_vec()),
            ("intersection-fallback", fallback_profiles.encode()),
            ("profile-digest-fallback", fallback_digest.to_vec()),
            (
                "plan-page-active",
                EventTurnPlanV1::PageActive {
                    direction: EventDirection::ToSessionResponder,
                    transfer_profile_digest: current_digest,
                    difference_count: 2,
                    set_commitment,
                    scheduled_count: 2,
                    unscheduled_count: 0,
                }
                .encode()
                .unwrap(),
            ),
            (
                "plan-legacy-exact",
                EventTurnPlanV1::LegacyActive {
                    direction: EventDirection::ToSessionResponder,
                    transfer_profile_digest: current_digest,
                    difference: LegacyDifference::Exact {
                        difference_count: 2,
                        set_commitment,
                    },
                }
                .encode()
                .unwrap(),
            ),
            (
                "plan-page-blind",
                EventTurnPlanV1::PageBlindActive {
                    direction: EventDirection::ToSessionInitiator,
                    transfer_profile_digest: current_digest,
                    scheduled_count: 2,
                    unscheduled_count: 3,
                }
                .encode()
                .unwrap(),
            ),
            (
                "plan-legacy-blind",
                EventTurnPlanV1::LegacyActive {
                    direction: EventDirection::ToSessionInitiator,
                    transfer_profile_digest: current_digest,
                    difference: LegacyDifference::Blind,
                }
                .encode()
                .unwrap(),
            ),
            (
                "plan-empty-event-pages",
                EventTurnPlanV1::Empty {
                    direction: EventDirection::ToSessionResponder,
                    transfer_profile_digest: current_digest,
                    selected_profile: TransferProfileId::EventPagesV1,
                    set_commitment: empty_set_commitment(),
                }
                .encode()
                .unwrap(),
            ),
            (
                "plan-suppressed",
                EventTurnPlanV1::Suppressed {
                    direction: EventDirection::ToSessionInitiator,
                    transfer_profile_digest: current_digest,
                }
                .encode()
                .unwrap(),
            ),
            (
                "fallback-plan-legacy-exact",
                EventTurnPlanV1::LegacyActive {
                    direction: EventDirection::ToSessionResponder,
                    transfer_profile_digest: fallback_digest,
                    difference: LegacyDifference::Exact {
                        difference_count: 2,
                        set_commitment,
                    },
                }
                .encode()
                .unwrap(),
            ),
            (
                "change-turn-header",
                ChangeTurnHeaderV1 {
                    direction: EventDirection::ToSessionResponder,
                    transfer_profile_digest: current_digest,
                    set_commitment,
                    scheduled: scheduled.clone(),
                    schedule_digest,
                }
                .encode()
                .unwrap(),
            ),
            (
                "change-page-single",
                ChangePageV7 {
                    direction: EventDirection::ToSessionResponder,
                    transfer_profile_digest: current_digest,
                    schedule_digest,
                    page_number: 0,
                    entries: vec![ChangePageEntry {
                        id: scheduled[0],
                        custody: None,
                        source_event: vec![0xaa, 0xbb, 0xcc],
                    }],
                    remaining: 1,
                }
                .encode()
                .unwrap(),
            ),
            (
                "change-page-multi",
                ChangePageV7 {
                    direction: EventDirection::ToSessionResponder,
                    transfer_profile_digest: current_digest,
                    schedule_digest,
                    page_number: 0,
                    entries: vec![
                        ChangePageEntry {
                            id: scheduled[0],
                            custody: None,
                            source_event: vec![0xaa],
                        },
                        ChangePageEntry {
                            id: scheduled[1],
                            custody: None,
                            source_event: vec![0xbb, 0xcc],
                        },
                    ],
                    remaining: 0,
                }
                .encode()
                .unwrap(),
            ),
            (
                "change-page-finite-evidence",
                ChangePageV7 {
                    direction: EventDirection::ToSessionResponder,
                    transfer_profile_digest: current_digest,
                    schedule_digest,
                    page_number: 1,
                    entries: vec![ChangePageEntry {
                        id: scheduled[1],
                        custody: Some(ChangePageCustody {
                            exchange_id: 7,
                            wrapper: vec![0x44, 0x55, 0x66],
                        }),
                        source_event: vec![0xdd, 0xee],
                    }],
                    remaining: 0,
                }
                .encode()
                .unwrap(),
            ),
            (
                "change-turn-finished",
                ChangeTurnFinishedV1 {
                    direction: EventDirection::ToSessionResponder,
                    transfer_profile_digest: current_digest,
                    set_commitment,
                    schedule_digest,
                    final_page_count: 2,
                }
                .encode()
                .unwrap(),
            ),
        ]
    }

    fn malformed_event_page_vectors() -> Vec<(&'static str, Vec<u8>)> {
        let canonical = canonical_event_page_vectors();
        let named = |name: &str| {
            canonical
                .iter()
                .find(|(candidate, _)| *candidate == name)
                .unwrap()
                .1
                .clone()
        };

        let mut offer_truncated = named("offer-current");
        offer_truncated.pop();
        let mut offer_critical_profile = named("offer-current");
        offer_critical_profile[25..27].copy_from_slice(&0x8002u16.to_be_bytes());
        let mut plan_inconsistent_counts = named("plan-page-active");
        let plan_len = plan_inconsistent_counts.len();
        plan_inconsistent_counts[plan_len - 4..].copy_from_slice(&1u32.to_be_bytes());
        let mut header_bad_schedule_digest = named("change-turn-header");
        *header_bad_schedule_digest.last_mut().unwrap() ^= 1;
        let mut page_zero_entries = named("change-page-single");
        page_zero_entries[74..76].copy_from_slice(&0u16.to_be_bytes());
        let mut terminal_nonzero_remaining = named("change-turn-finished");
        *terminal_nonzero_remaining.last_mut().unwrap() = 1;

        vec![
            ("offer-truncated", offer_truncated),
            ("offer-critical-profile", offer_critical_profile),
            ("plan-inconsistent-counts", plan_inconsistent_counts),
            ("header-bad-schedule-digest", header_bad_schedule_digest),
            ("page-zero-entries", page_zero_entries),
            ("terminal-nonzero-remaining", terminal_nonzero_remaining),
        ]
    }

    fn event_page_vector_document() -> String {
        let mut document =
            String::from("# aster-event-pages-vectors/v1\tsemantic=7\toracle=self\n");
        for (name, bytes) in canonical_event_page_vectors() {
            document.push_str(&format!("ACCEPT\t{name}\t{}\n", vector_hex(&bytes)));
        }
        for (name, bytes) in malformed_event_page_vectors() {
            document.push_str(&format!("REJECT\t{name}\t{}\n", vector_hex(&bytes)));
        }
        document
    }

    #[test]
    fn checked_in_event_page_vectors_match_current_encoder() {
        assert_eq!(
            event_page_vector_document(),
            include_str!("../../../conformance/vectors/event-pages-v7.tsv")
        );
    }

    #[test]
    fn malformed_event_page_vectors_are_rejected_by_their_reference_codec() {
        for (name, bytes) in malformed_event_page_vectors() {
            let rejected = if name.starts_with("offer-") {
                TransferProfileOfferV1::decode(&bytes).is_err()
            } else if name.starts_with("plan-") {
                EventTurnPlanV1::decode(&bytes).is_err()
            } else if name.starts_with("header-") {
                ChangeTurnHeaderV1::decode(&bytes).is_err()
            } else if name.starts_with("page-") {
                ChangePageV7::decode(&bytes).is_err()
            } else if name.starts_with("terminal-") {
                ChangeTurnFinishedV1::decode(&bytes).is_err()
            } else {
                panic!("unrouted malformed vector {name}");
            };
            assert!(rejected, "malformed vector {name} was accepted");
        }
    }

    fn metadata(
        id: EventTransferId,
        ttl_ms: Option<u64>,
        tombstone: bool,
    ) -> AuthenticatedEventMetadata {
        AuthenticatedEventMetadata {
            id,
            acceptance_order: u64::from(id.as_bytes()[0]) + 1,
            priority: Priority::Routine,
            ttl_ms,
            tombstone,
            source_bytes: 1,
        }
    }

    #[test]
    fn local_event_plan_classifies_durable_tombstone_finite_ttl_and_empty() {
        let current = TransferProfileOfferV1::current();
        let profiles = negotiate_transfer_profiles(&current, &current).unwrap();
        let digest = transfer_profile_digest(&current, &current, &profiles);
        let difference = vec![id(1), id(2), id(3)];

        let durable = build_local_event_send_plan(
            EventDirection::ToSessionResponder,
            digest,
            &profiles,
            LocalEventSendDifference::Exact(&difference),
            &[
                metadata(id(1), None, false),
                metadata(id(2), Some(5), true),
                metadata(id(3), None, false),
            ],
            false,
            2,
            [None; 4],
        )
        .unwrap();
        assert_eq!(durable.scheduled, vec![id(1), id(2)]);
        assert_eq!(
            durable.plan,
            EventTurnPlanV1::PageActive {
                direction: EventDirection::ToSessionResponder,
                transfer_profile_digest: digest,
                difference_count: 3,
                set_commitment: event_difference_set_commitment(&difference).unwrap(),
                scheduled_count: 2,
                unscheduled_count: 1,
            }
        );

        let finite = build_local_event_send_plan(
            EventDirection::ToSessionResponder,
            digest,
            &profiles,
            LocalEventSendDifference::Exact(&difference),
            &[
                metadata(id(1), None, false),
                metadata(id(2), Some(5), false),
                metadata(id(3), None, false),
            ],
            false,
            difference.len(),
            [None; 4],
        )
        .unwrap();
        assert_eq!(finite.scheduled, difference.clone());
        assert_eq!(
            finite.plan,
            EventTurnPlanV1::PageActive {
                direction: EventDirection::ToSessionResponder,
                transfer_profile_digest: digest,
                difference_count: 3,
                set_commitment: event_difference_set_commitment(&difference).unwrap(),
                scheduled_count: 3,
                unscheduled_count: 0,
            }
        );

        let empty = build_local_event_send_plan(
            EventDirection::ToSessionResponder,
            digest,
            &profiles,
            LocalEventSendDifference::Exact(&[]),
            &[],
            false,
            0,
            [None; 4],
        )
        .unwrap();
        assert!(matches!(empty.plan, EventTurnPlanV1::Empty { .. }));
    }

    #[test]
    fn local_event_plan_suppresses_outbound_and_pages_blind_inbound() {
        let current = TransferProfileOfferV1::current();
        let profiles = negotiate_transfer_profiles(&current, &current).unwrap();
        let digest = transfer_profile_digest(&current, &current, &profiles);

        let suppressed = build_local_event_send_plan(
            EventDirection::ToSessionResponder,
            digest,
            &profiles,
            LocalEventSendDifference::Exact(&[id(1)]),
            &[],
            true,
            1,
            [None; 4],
        )
        .unwrap();
        assert_eq!(
            suppressed.plan,
            EventTurnPlanV1::Suppressed {
                direction: EventDirection::ToSessionResponder,
                transfer_profile_digest: digest,
            }
        );

        let blind = build_local_event_send_plan(
            EventDirection::ToSessionInitiator,
            digest,
            &profiles,
            LocalEventSendDifference::Blind,
            &[],
            false,
            1,
            [None; 4],
        )
        .unwrap();
        assert_eq!(
            blind.plan,
            EventTurnPlanV1::PageBlindActive {
                direction: EventDirection::ToSessionInitiator,
                transfer_profile_digest: digest,
                scheduled_count: 0,
                unscheduled_count: 0,
            }
        );

        let legacy = legacy_event_offer();
        let fallback_profiles = negotiate_transfer_profiles(&current, &legacy).unwrap();
        let fallback_digest = transfer_profile_digest(&current, &legacy, &fallback_profiles);
        let fallback = build_local_event_send_plan(
            EventDirection::ToSessionInitiator,
            fallback_digest,
            &fallback_profiles,
            LocalEventSendDifference::Blind,
            &[],
            false,
            1,
            [None; 4],
        )
        .unwrap();
        assert_eq!(
            fallback.plan,
            EventTurnPlanV1::LegacyActive {
                direction: EventDirection::ToSessionInitiator,
                transfer_profile_digest: fallback_digest,
                difference: LegacyDifference::Blind,
            }
        );
    }

    #[test]
    fn asymmetric_page_support_falls_back_to_complete_legacy_direction() {
        let current = TransferProfileOfferV1::current();
        let legacy = legacy_event_offer();
        let profiles = negotiate_transfer_profiles(&current, &legacy).unwrap();
        let digest = transfer_profile_digest(&current, &legacy, &profiles);
        let difference = vec![id(1), id(2)];
        let built = build_local_event_send_plan(
            EventDirection::ToSessionResponder,
            digest,
            &profiles,
            LocalEventSendDifference::Exact(&difference),
            &[metadata(id(1), None, false), metadata(id(2), None, false)],
            false,
            difference.len(),
            [None; 4],
        )
        .unwrap();
        assert!(matches!(
            built.plan,
            EventTurnPlanV1::LegacyActive {
                difference: LegacyDifference::Exact { .. },
                ..
            }
        ));
        assert!(built.scheduled.is_empty());
    }

    #[test]
    fn event_pages_v1_schedules_available_metadata_without_legacy_substitution() {
        let current = TransferProfileOfferV1::current();
        let profiles = negotiate_transfer_profiles(&current, &current).unwrap();
        let digest = transfer_profile_digest(&current, &current, &profiles);
        let difference = vec![id(1), id(2), id(3), id(4)];
        let mut invalid_metadata = metadata(id(2), None, false);
        invalid_metadata.source_bytes = 0;

        let built = build_local_event_send_plan(
            EventDirection::ToSessionResponder,
            digest,
            &profiles,
            LocalEventSendDifference::Exact(&difference),
            &[
                metadata(id(1), None, false),
                invalid_metadata,
                metadata(id(3), None, false),
            ],
            false,
            difference.len(),
            [None; 4],
        )
        .unwrap();

        assert_eq!(built.scheduled, vec![id(1), id(3)]);
        assert_eq!(built.scheduled_metadata.len(), 2);
        assert_eq!(
            built.plan,
            EventTurnPlanV1::PageActive {
                direction: EventDirection::ToSessionResponder,
                transfer_profile_digest: digest,
                difference_count: 4,
                set_commitment: event_difference_set_commitment(&difference).unwrap(),
                scheduled_count: 2,
                unscheduled_count: 2,
            }
        );
    }

    #[test]
    fn local_event_plan_prioritizes_tiers_and_rotates_only_within_equal_priority() {
        let current = TransferProfileOfferV1::current();
        let profiles = negotiate_transfer_profiles(&current, &current).unwrap();
        let digest = transfer_profile_digest(&current, &current, &profiles);
        let difference = vec![id(1), id(2), id(3), id(4), id(5)];
        let mut metadata = difference
            .iter()
            .copied()
            .map(|id| metadata(id, None, false))
            .collect::<Vec<_>>();
        metadata[1].priority = Priority::Flash;
        metadata[3].priority = Priority::Flash;
        metadata[4].priority = Priority::Immediate;

        let built = build_local_event_send_plan(
            EventDirection::ToSessionResponder,
            digest,
            &profiles,
            LocalEventSendDifference::Exact(&difference),
            &metadata,
            false,
            3,
            [
                None,
                None,
                None,
                Some(EventPageSchedulePosition {
                    acceptance_order: 3,
                    id: id(2),
                }),
            ],
        )
        .unwrap();

        assert_eq!(built.scheduled, vec![id(4), id(2), id(5)]);
        assert_eq!(
            built.last_attempted_by_priority,
            [
                None,
                None,
                Some(EventPageSchedulePosition {
                    acceptance_order: 6,
                    id: id(5),
                }),
                Some(EventPageSchedulePosition {
                    acceptance_order: 3,
                    id: id(2),
                }),
            ]
        );
    }

    #[test]
    fn equal_priority_schedule_uses_acceptance_fifo_and_resumes_after_removed_cursor() {
        let current = TransferProfileOfferV1::current();
        let profiles = negotiate_transfer_profiles(&current, &current).unwrap();
        let digest = transfer_profile_digest(&current, &current, &profiles);
        let difference = vec![id(1), id(2), id(3)];
        let mut candidates = [
            metadata(id(1), None, false),
            metadata(id(2), None, false),
            metadata(id(3), None, false),
        ];
        candidates[0].acceptance_order = 30;
        candidates[1].acceptance_order = 10;
        candidates[2].acceptance_order = 20;

        let built = build_local_event_send_plan(
            EventDirection::ToSessionResponder,
            digest,
            &profiles,
            LocalEventSendDifference::Exact(&difference),
            &candidates,
            false,
            2,
            [
                Some(EventPageSchedulePosition {
                    acceptance_order: 15,
                    id: id(4),
                }),
                None,
                None,
                None,
            ],
        )
        .unwrap();

        assert_eq!(built.scheduled, vec![id(3), id(1)]);
        assert_eq!(
            built.last_attempted_by_priority[Priority::Routine as usize],
            Some(EventPageSchedulePosition {
                acceptance_order: 30,
                id: id(1),
            })
        );
    }

    #[test]
    fn page_schedule_respects_item_frame_byte_and_lower_carrier_budgets() {
        let mut candidates = [
            metadata(id(1), None, false),
            metadata(id(2), None, false),
            metadata(id(3), None, false),
        ];
        for candidate in &mut candidates {
            candidate.source_bytes = 100;
        }
        let one_entry_turn_bytes = (4 + 57 + CHANGE_TURN_HEADER_FIXED_BYTES + 32)
            + (4 + 57 + CHANGE_PAGE_FIXED_BYTES + CHANGE_PAGE_ENTRY_FIXED_BYTES + 100)
            + (4 + 57 + CHANGE_TURN_FINISHED_FIXED_BYTES);
        let limits = EventPageScheduleLimits {
            item_capacity: 3,
            frame_capacity: 3,
            turn_bytes: one_entry_turn_bytes,
            max_protected_frame_bytes: 57
                + CHANGE_PAGE_FIXED_BYTES
                + CHANGE_PAGE_ENTRY_FIXED_BYTES
                + 100,
            page_target_entries: 256,
            finite_page_target_entries: 16,
        };

        let (scheduled, advanced) =
            plan_event_page_schedule(&candidates, limits, [None; 4]).unwrap();
        assert_eq!(
            scheduled.iter().map(|entry| entry.id).collect::<Vec<_>>(),
            vec![id(1)]
        );
        assert_eq!(
            advanced[Priority::Routine as usize],
            Some(EventPageSchedulePosition {
                acceptance_order: 2,
                id: id(1),
            })
        );

        let two_page_turn_bytes = (4 + 57 + CHANGE_TURN_HEADER_FIXED_BYTES + 64)
            + 2 * (4 + 57 + CHANGE_PAGE_FIXED_BYTES + CHANGE_PAGE_ENTRY_FIXED_BYTES + 100)
            + (4 + 57 + CHANGE_TURN_FINISHED_FIXED_BYTES);
        let two_page_limits = EventPageScheduleLimits {
            item_capacity: 3,
            frame_capacity: 4,
            turn_bytes: two_page_turn_bytes,
            ..limits
        };
        let (two_pages, _) =
            plan_event_page_schedule(&candidates, two_page_limits, [None; 4]).unwrap();
        assert_eq!(
            two_pages.iter().map(|entry| entry.id).collect::<Vec<_>>(),
            vec![id(1), id(2)],
            "the lower carrier ceiling must split two eligible Events into two pages"
        );

        let no_progress = EventPageScheduleLimits {
            turn_bytes: one_entry_turn_bytes - 1,
            ..limits
        };
        assert!(
            plan_event_page_schedule(&candidates, no_progress, [None; 4])
                .unwrap()
                .0
                .is_empty()
        );

        let over_budget = EventTurnPlanV1::PageActive {
            direction: EventDirection::ToSessionResponder,
            transfer_profile_digest: [7; 32],
            difference_count: 4,
            set_commitment: [8; 32],
            scheduled_count: 4,
            unscheduled_count: 0,
        };
        assert!(validate_remote_event_page_budget(&over_budget, limits).is_err());
        let zero_schedule = EventTurnPlanV1::PageActive {
            direction: EventDirection::ToSessionResponder,
            transfer_profile_digest: [7; 32],
            difference_count: 4,
            set_commitment: [8; 32],
            scheduled_count: 0,
            unscheduled_count: 4,
        };
        validate_remote_event_page_budget(&zero_schedule, no_progress).unwrap();
    }

    #[test]
    fn page_schedule_accounts_for_mixed_finite_ttl_page_boundaries() {
        let mut candidates = (1..=17)
            .map(|index| metadata(id(index), Some(60_000), false))
            .collect::<Vec<_>>();
        candidates[0].ttl_ms = None;
        let single_page_turn_bytes =
            framed_turn_bytes(CHANGE_TURN_HEADER_FIXED_BYTES + 32 * candidates.len())
                .and_then(|header| {
                    candidates
                        .iter()
                        .map(|metadata| planned_change_page_entry_bytes(*metadata))
                        .try_fold(CHANGE_PAGE_FIXED_BYTES, |total, entry| {
                            total.checked_add(entry.ok()?)
                        })
                        .and_then(framed_turn_bytes)
                        .and_then(|page| header.checked_add(page))
                })
                .and_then(|bytes| {
                    framed_turn_bytes(CHANGE_TURN_FINISHED_FIXED_BYTES)
                        .and_then(|terminal| bytes.checked_add(terminal))
                })
                .expect("single-page turn bytes");

        let limits = EventPageScheduleLimits {
            item_capacity: candidates.len(),
            frame_capacity: 4,
            // This fits all entries in one page, but not the extra fixed frame
            // overhead required by the finite-TTL sender boundary.
            turn_bytes: single_page_turn_bytes,
            max_protected_frame_bytes: MAX_CHANGE_PAGE_PROTECTED_BYTES,
            page_target_entries: 256,
            finite_page_target_entries: 16,
        };

        let (scheduled, _) = plan_event_page_schedule(&candidates, limits, [None; 4]).unwrap();

        assert_eq!(
            scheduled.len(),
            16,
            "the planner must reserve the same mixed finite-TTL page boundary as the sender"
        );
    }

    #[test]
    fn remote_plan_validation_uses_only_authenticated_missing_ids_and_context() {
        let current = TransferProfileOfferV1::current();
        let profiles = negotiate_transfer_profiles(&current, &current).unwrap();
        let digest = transfer_profile_digest(&current, &current, &profiles);
        let missing = vec![id(1), id(2), id(3)];
        let built = build_local_event_send_plan(
            EventDirection::ToSessionResponder,
            digest,
            &profiles,
            LocalEventSendDifference::Exact(&missing),
            &[
                metadata(id(1), None, false),
                metadata(id(2), None, false),
                metadata(id(3), None, false),
            ],
            false,
            2,
            [None; 4],
        )
        .unwrap();

        validate_remote_event_send_plan(
            &built.plan,
            EventDirection::ToSessionResponder,
            digest,
            &profiles,
            LocalEventSendDifference::Exact(&missing),
            false,
        )
        .unwrap();
        let zero_schedule = EventTurnPlanV1::PageActive {
            direction: EventDirection::ToSessionResponder,
            transfer_profile_digest: digest,
            difference_count: 3,
            set_commitment: event_difference_set_commitment(&missing).unwrap(),
            scheduled_count: 0,
            unscheduled_count: 3,
        };
        validate_remote_event_send_plan(
            &zero_schedule,
            EventDirection::ToSessionResponder,
            digest,
            &profiles,
            LocalEventSendDifference::Exact(&missing),
            false,
        )
        .expect("a budget-deferred zero schedule must validate and open no stream");
        assert!(
            validate_remote_event_send_plan(
                &built.plan,
                EventDirection::ToSessionInitiator,
                digest,
                &profiles,
                LocalEventSendDifference::Exact(&missing),
                false,
            )
            .is_err()
        );
        let mut wrong_digest = digest;
        wrong_digest[0] ^= 1;
        assert!(
            validate_remote_event_send_plan(
                &built.plan,
                EventDirection::ToSessionResponder,
                wrong_digest,
                &profiles,
                LocalEventSendDifference::Exact(&missing),
                false,
            )
            .is_err()
        );
        assert!(
            validate_remote_event_send_plan(
                &built.plan,
                EventDirection::ToSessionResponder,
                digest,
                &profiles,
                LocalEventSendDifference::Exact(&[id(1), id(2)]),
                false,
            )
            .is_err()
        );

        let exact_legacy = EventTurnPlanV1::LegacyActive {
            direction: EventDirection::ToSessionResponder,
            transfer_profile_digest: digest,
            difference: LegacyDifference::Exact {
                difference_count: u32::try_from(missing.len()).unwrap(),
                set_commitment: event_difference_set_commitment(&missing).unwrap(),
            },
        };
        assert!(
            validate_remote_event_send_plan(
                &exact_legacy,
                EventDirection::ToSessionResponder,
                digest,
                &profiles,
                LocalEventSendDifference::Exact(&missing),
                false,
            )
            .is_err(),
            "EventPagesV1 must not accept an exact LegacyActive substitution"
        );

        let legacy = legacy_event_offer();
        let legacy_profiles = negotiate_transfer_profiles(&current, &legacy).unwrap();
        let legacy_digest = transfer_profile_digest(&current, &legacy, &legacy_profiles);
        let legacy_plan = EventTurnPlanV1::LegacyActive {
            direction: EventDirection::ToSessionResponder,
            transfer_profile_digest: legacy_digest,
            difference: LegacyDifference::Exact {
                difference_count: u32::try_from(missing.len()).unwrap(),
                set_commitment: event_difference_set_commitment(&missing).unwrap(),
            },
        };
        validate_remote_event_send_plan(
            &legacy_plan,
            EventDirection::ToSessionResponder,
            legacy_digest,
            &legacy_profiles,
            LocalEventSendDifference::Exact(&missing),
            false,
        )
        .expect("LegacyV6 must retain exact legacy scheduling");
    }
}
