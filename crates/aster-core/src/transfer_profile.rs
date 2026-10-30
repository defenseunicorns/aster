//! Canonical transfer-profile offers and their authenticated negotiation result.

use core::error::Error;
use core::fmt::{self, Display, Formatter};
use std::collections::BTreeSet;

use sha2::{Digest, Sha256};

const OFFER_CODEC_VERSION: u8 = 1;
const CRITICAL_ID_MASK: u16 = 0x8000;
const SEMANTIC_PROTOCOL_V7: u16 = 7;
const SEMANTIC_PROTOCOL_V8: u16 = 8;
const SEMANTIC_PROTOCOL_V9: u16 = 9;
/// Historical semantic-v7/v8 profile-4 publication ceiling. This remains
/// version-scoped even though v9/profile-5 can carry the full canonical Blob
/// ceiling.
pub const PROFILE4_MAX_CANONICAL_BLOB_BYTES: u64 = 64 * 1024 * 1024;
pub const PROFILE4_MAX_CANONICAL_BLOB_CHUNKS: u64 = 1_024;
pub const PROFILE5_MAX_CANONICAL_BLOB_BYTES: u64 = 8 * 1024 * 1024 * 1024;

/// Fixed application transfer lanes covered by profile negotiation.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
#[repr(u16)]
pub enum TransferLaneId {
    Event = 1,
    State = 2,
    Record = 3,
    Blob = 4,
    EventBridge = 5,
}

impl TransferLaneId {
    const DESCENDING: [Self; 5] = [
        Self::EventBridge,
        Self::Blob,
        Self::Record,
        Self::State,
        Self::Event,
    ];

    const fn decode(value: u16) -> Option<Self> {
        match value {
            1 => Some(Self::Event),
            2 => Some(Self::State),
            3 => Some(Self::Record),
            4 => Some(Self::Blob),
            5 => Some(Self::EventBridge),
            _ => None,
        }
    }
}

/// Closed transfer-profile identifier set.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
#[repr(u16)]
pub enum TransferProfileId {
    LegacyV6 = 1,
    EventPagesV1 = 2,
    // 3 remains reserved for the approved BlobCustodyV1 design.
    BlobRangesStreamV1 = 4,
    BlobStreamV1 = 5,
}

impl TransferProfileId {
    #[doc(hidden)]
    pub const fn decode(value: u16) -> Option<Self> {
        match value {
            1 => Some(Self::LegacyV6),
            2 => Some(Self::EventPagesV1),
            4 => Some(Self::BlobRangesStreamV1),
            5 => Some(Self::BlobStreamV1),
            _ => None,
        }
    }
}

/// Selects the Blob profile which can represent one exact canonical
/// publication for an already-authenticated semantic version.
///
/// This is sender inventory eligibility, not wire-format migration: a Blob
/// above the historical profile-4 bound is withheld from v7/v8 peers while
/// remaining eligible for v9/profile-5.
#[doc(hidden)]
pub fn blob_profile_for_canonical_shape(
    semantic_version: u16,
    total_len: u64,
    chunk_size: u32,
    chunk_count: u64,
) -> Option<TransferProfileId> {
    let selected_unit_bytes = match semantic_version {
        SEMANTIC_PROTOCOL_V7 | SEMANTIC_PROTOCOL_V8 => crate::MAX_BLOB_CHUNK_SIZE,
        SEMANTIC_PROTOCOL_V9 => crate::BLOB_STREAM_SEGMENT_BYTES as u32,
        _ => return None,
    };
    if chunk_size != selected_unit_bytes
        || chunk_count != total_len.div_ceil(u64::from(selected_unit_bytes))
        || chunk_count > crate::MAX_BLOB_CHUNKS
    {
        return None;
    }
    match semantic_version {
        SEMANTIC_PROTOCOL_V7 | SEMANTIC_PROTOCOL_V8
            if total_len > 0
                && total_len <= PROFILE4_MAX_CANONICAL_BLOB_BYTES
                && chunk_count <= PROFILE4_MAX_CANONICAL_BLOB_CHUNKS =>
        {
            Some(TransferProfileId::BlobRangesStreamV1)
        }
        SEMANTIC_PROTOCOL_V9 if total_len <= PROFILE5_MAX_CANONICAL_BLOB_BYTES => {
            Some(TransferProfileId::BlobStreamV1)
        }
        _ => None,
    }
}

/// Sanitized canonical profile-offer failure.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TransferProfileError(String);

impl TransferProfileError {
    pub fn invalid(message: impl Into<String>) -> Self {
        Self(message.into())
    }
}

impl Display for TransferProfileError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

impl Error for TransferProfileError {}

/// Canonical ordered offer for every fixed transfer lane.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TransferProfileOfferV1 {
    lanes: Vec<(u16, Vec<u16>)>,
}

impl TransferProfileOfferV1 {
    pub fn for_semantic_version(semantic_version: u16) -> Result<Self, TransferProfileError> {
        match semantic_version {
            SEMANTIC_PROTOCOL_V7 | SEMANTIC_PROTOCOL_V8 => Ok(Self::current()),
            SEMANTIC_PROTOCOL_V9 => Ok(Self::stream_v9()),
            _ => Err(TransferProfileError::invalid(
                "transfer-profile exchange requires semantic v7 or v8",
            )),
        }
    }

    /// Semantic-v7/v8 offer; Blob uses the receipt-free range stream.
    pub fn current() -> Self {
        Self {
            lanes: vec![
                (
                    TransferLaneId::EventBridge as u16,
                    vec![TransferProfileId::LegacyV6 as u16],
                ),
                (
                    TransferLaneId::Blob as u16,
                    vec![TransferProfileId::BlobRangesStreamV1 as u16],
                ),
                (
                    TransferLaneId::Record as u16,
                    vec![TransferProfileId::LegacyV6 as u16],
                ),
                (
                    TransferLaneId::State as u16,
                    vec![TransferProfileId::LegacyV6 as u16],
                ),
                (
                    TransferLaneId::Event as u16,
                    vec![
                        TransferProfileId::EventPagesV1 as u16,
                        TransferProfileId::LegacyV6 as u16,
                    ],
                ),
            ],
        }
    }

    /// Semantic-v9 offer; Blob uses the checkpointed data-mesh stream.
    pub fn stream_v9() -> Self {
        Self {
            lanes: vec![
                (
                    TransferLaneId::EventBridge as u16,
                    vec![TransferProfileId::LegacyV6 as u16],
                ),
                (
                    TransferLaneId::Blob as u16,
                    vec![TransferProfileId::BlobStreamV1 as u16],
                ),
                (
                    TransferLaneId::Record as u16,
                    vec![TransferProfileId::LegacyV6 as u16],
                ),
                (
                    TransferLaneId::State as u16,
                    vec![TransferProfileId::LegacyV6 as u16],
                ),
                (
                    TransferLaneId::Event as u16,
                    vec![
                        TransferProfileId::EventPagesV1 as u16,
                        TransferProfileId::LegacyV6 as u16,
                    ],
                ),
            ],
        }
    }

    /// Offer retaining only the mandatory LegacyV6 profile on every lane.
    pub fn legacy_only() -> Self {
        Self {
            lanes: TransferLaneId::DESCENDING
                .into_iter()
                .map(|lane| (lane as u16, vec![TransferProfileId::LegacyV6 as u16]))
                .collect(),
        }
    }

    /// Builds a test/conformance offer; encoding still validates all invariants.
    #[doc(hidden)]
    pub fn from_lanes(lanes: Vec<(TransferLaneId, Vec<TransferProfileId>)>) -> Self {
        Self {
            lanes: lanes
                .into_iter()
                .map(|(lane, profiles)| {
                    (
                        lane as u16,
                        profiles.into_iter().map(|profile| profile as u16).collect(),
                    )
                })
                .collect(),
        }
    }

    #[doc(hidden)]
    pub fn known_lanes(&self) -> Vec<(TransferLaneId, Vec<TransferProfileId>)> {
        self.lanes
            .iter()
            .filter_map(|(raw_lane, raw_profiles)| {
                TransferLaneId::decode(*raw_lane).map(|lane| {
                    (
                        lane,
                        raw_profiles
                            .iter()
                            .filter_map(|profile| TransferProfileId::decode(*profile))
                            .collect(),
                    )
                })
            })
            .collect()
    }

    fn validate(&self) -> Result<(), TransferProfileError> {
        if self.lanes.is_empty() || self.lanes.len() > u8::MAX as usize {
            return Err(TransferProfileError::invalid(
                "transfer-profile lane count is invalid",
            ));
        }
        let mut last_lane = None;
        let mut known_lanes = BTreeSet::new();
        for (raw_lane, profiles) in &self.lanes {
            if last_lane.is_some_and(|previous| *raw_lane >= previous) {
                return Err(TransferProfileError::invalid(
                    "transfer-profile lanes are duplicate or noncanonical",
                ));
            }
            last_lane = Some(*raw_lane);
            if profiles.is_empty() || profiles.len() > u8::MAX as usize {
                return Err(TransferProfileError::invalid(
                    "profile list count is invalid",
                ));
            }
            if !profiles.windows(2).all(|pair| pair[0] > pair[1]) {
                return Err(TransferProfileError::invalid(
                    "profile IDs are duplicate or noncanonical",
                ));
            }
            for raw_profile in profiles {
                if TransferProfileId::decode(*raw_profile).is_none()
                    && raw_profile & CRITICAL_ID_MASK != 0
                {
                    return Err(TransferProfileError::invalid(
                        "unknown critical transfer-profile ID",
                    ));
                }
            }
            let Some(lane) = TransferLaneId::decode(*raw_lane) else {
                if raw_lane & CRITICAL_ID_MASK != 0 {
                    return Err(TransferProfileError::invalid("unknown critical lane ID"));
                }
                continue;
            };
            known_lanes.insert(lane);
            if !profiles.contains(&(TransferProfileId::LegacyV6 as u16))
                && !(lane == TransferLaneId::Blob
                    && (profiles.contains(&(TransferProfileId::BlobRangesStreamV1 as u16))
                        || profiles.contains(&(TransferProfileId::BlobStreamV1 as u16))))
            {
                return Err(TransferProfileError::invalid(
                    "every fixed lane must offer LegacyV6",
                ));
            }
            if lane != TransferLaneId::Event
                && profiles.contains(&(TransferProfileId::EventPagesV1 as u16))
            {
                return Err(TransferProfileError::invalid(
                    "EventPagesV1 is valid only for the Event lane",
                ));
            }
            if lane != TransferLaneId::Blob
                && profiles.contains(&(TransferProfileId::BlobRangesStreamV1 as u16))
            {
                return Err(TransferProfileError::invalid(
                    "BlobRangesStreamV1 is valid only for the Blob lane",
                ));
            }
            if lane != TransferLaneId::Blob
                && profiles.contains(&(TransferProfileId::BlobStreamV1 as u16))
            {
                return Err(TransferProfileError::invalid(
                    "BlobStreamV1 is valid only for the Blob lane",
                ));
            }
        }
        if known_lanes.len() != TransferLaneId::DESCENDING.len() {
            return Err(TransferProfileError::invalid(
                "transfer-profile offer must contain every fixed lane",
            ));
        }
        Ok(())
    }

    pub fn encode(&self) -> Result<Vec<u8>, TransferProfileError> {
        self.validate()?;
        let mut output = Vec::with_capacity(4 + self.lanes.len() * 6);
        output.push(OFFER_CODEC_VERSION);
        output.push(
            u8::try_from(self.lanes.len())
                .map_err(|_| TransferProfileError::invalid("lane count overflows"))?,
        );
        for (lane, profiles) in &self.lanes {
            output.extend_from_slice(&lane.to_be_bytes());
            output.push(
                u8::try_from(profiles.len())
                    .map_err(|_| TransferProfileError::invalid("profile count overflows"))?,
            );
            for profile in profiles {
                output.extend_from_slice(&profile.to_be_bytes());
            }
        }
        Ok(output)
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, TransferProfileError> {
        let mut cursor = OfferReader::new(bytes);
        if cursor.u8()? != OFFER_CODEC_VERSION {
            return Err(TransferProfileError::invalid(
                "unsupported transfer-profile offer codec version",
            ));
        }
        let lane_count = usize::from(cursor.u8()?);
        let mut lanes = Vec::with_capacity(lane_count.min(TransferLaneId::DESCENDING.len()));
        for _ in 0..lane_count {
            let raw_lane = cursor.u16()?;
            let profile_count = usize::from(cursor.u8()?);
            let mut profiles = Vec::with_capacity(profile_count);
            for _ in 0..profile_count {
                profiles.push(cursor.u16()?);
            }
            lanes.push((raw_lane, profiles));
        }
        cursor.finish()?;
        let offer = Self { lanes };
        offer.validate()?;
        Ok(offer)
    }
}

/// Canonical intersection of the authenticated initiator and responder offers.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NegotiatedTransferProfiles {
    lanes: Vec<(TransferLaneId, Vec<TransferProfileId>)>,
}

impl NegotiatedTransferProfiles {
    pub fn profile(&self, lane: TransferLaneId) -> Option<TransferProfileId> {
        self.lanes
            .iter()
            .find(|(candidate, _)| *candidate == lane)
            .and_then(|(_, profiles)| profiles.first().copied())
    }

    pub fn contains(&self, lane: TransferLaneId, profile: TransferProfileId) -> bool {
        self.lanes
            .iter()
            .find(|(candidate, _)| *candidate == lane)
            .is_some_and(|(_, profiles)| profiles.contains(&profile))
    }

    #[doc(hidden)]
    pub fn encode(&self) -> Vec<u8> {
        let mut output = Vec::new();
        output.push(u8::try_from(self.lanes.len()).expect("fixed lane count fits u8"));
        for (lane, profiles) in &self.lanes {
            output.extend_from_slice(&(*lane as u16).to_be_bytes());
            output.push(u8::try_from(profiles.len()).expect("bounded profile count fits u8"));
            for profile in profiles {
                output.extend_from_slice(&(*profile as u16).to_be_bytes());
            }
        }
        output
    }
}

pub fn negotiate_transfer_profiles(
    initiator: &TransferProfileOfferV1,
    responder: &TransferProfileOfferV1,
) -> Result<NegotiatedTransferProfiles, TransferProfileError> {
    initiator.validate()?;
    responder.validate()?;
    let mut lanes = Vec::with_capacity(TransferLaneId::DESCENDING.len());
    for lane in TransferLaneId::DESCENDING {
        let left = profiles_for(initiator, lane)?;
        let right = profiles_for(responder, lane)?;
        let common: Vec<_> = left
            .iter()
            .copied()
            .filter(|profile| right.contains(profile))
            .collect();
        if common.is_empty() {
            return Err(TransferProfileError::invalid(format!(
                "no common transfer profile for lane {}",
                lane as u16
            )));
        }
        lanes.push((lane, common));
    }
    Ok(NegotiatedTransferProfiles { lanes })
}

pub fn negotiate_transfer_profiles_for_semantic_version(
    semantic_version: u16,
    initiator: &TransferProfileOfferV1,
    responder: &TransferProfileOfferV1,
) -> Result<NegotiatedTransferProfiles, TransferProfileError> {
    if !matches!(
        semantic_version,
        SEMANTIC_PROTOCOL_V7 | SEMANTIC_PROTOCOL_V8 | SEMANTIC_PROTOCOL_V9
    ) {
        return Err(TransferProfileError::invalid(
            "transfer-profile exchange requires semantic v7 or v8",
        ));
    }
    negotiate_transfer_profiles(initiator, responder)
}

fn profiles_for(
    offer: &TransferProfileOfferV1,
    lane: TransferLaneId,
) -> Result<Vec<TransferProfileId>, TransferProfileError> {
    offer
        .lanes
        .iter()
        .find(|(candidate, _)| *candidate == lane as u16)
        .map(|(_, profiles)| {
            profiles
                .iter()
                .filter_map(|profile| TransferProfileId::decode(*profile))
                .collect()
        })
        .ok_or_else(|| TransferProfileError::invalid("fixed lane is missing from profile offer"))
}

pub fn transfer_profile_digest(
    initiator: &TransferProfileOfferV1,
    responder: &TransferProfileOfferV1,
    negotiated: &NegotiatedTransferProfiles,
) -> [u8; 32] {
    let initiator = initiator.encode().expect("validated initiator offer");
    let responder = responder.encode().expect("validated responder offer");
    let intersections = negotiated.encode();
    let mut hasher = Sha256::new();
    hasher.update(b"ASTER/transfer-profile-digest/v1\0");
    hash_field(&mut hasher, &initiator);
    hash_field(&mut hasher, &responder);
    hash_field(&mut hasher, &intersections);
    hasher.finalize().into()
}

fn hash_field(hasher: &mut Sha256, bytes: &[u8]) {
    hasher.update(
        u32::try_from(bytes.len())
            .expect("bounded profile bytes")
            .to_be_bytes(),
    );
    hasher.update(bytes);
}

struct OfferReader<'a> {
    bytes: &'a [u8],
    offset: usize,
}

impl<'a> OfferReader<'a> {
    const fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, offset: 0 }
    }

    fn take<const N: usize>(&mut self) -> Result<[u8; N], TransferProfileError> {
        let end = self
            .offset
            .checked_add(N)
            .ok_or_else(|| TransferProfileError::invalid("transfer-profile offer overflows"))?;
        let bytes = self
            .bytes
            .get(self.offset..end)
            .ok_or_else(|| TransferProfileError::invalid("transfer-profile offer is truncated"))?;
        self.offset = end;
        bytes
            .try_into()
            .map_err(|_| TransferProfileError::invalid("transfer-profile field length differs"))
    }

    fn u8(&mut self) -> Result<u8, TransferProfileError> {
        Ok(self.take::<1>()?[0])
    }

    fn u16(&mut self) -> Result<u16, TransferProfileError> {
        Ok(u16::from_be_bytes(self.take()?))
    }

    fn finish(self) -> Result<(), TransferProfileError> {
        if self.offset == self.bytes.len() {
            Ok(())
        } else {
            Err(TransferProfileError::invalid(
                "transfer-profile offer has trailing bytes",
            ))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn native_profile5_blob_is_sender_eligible() {
        // Mutation caught: reusing profile-4's 64-KiB chunk shape would reject
        // the native one-MiB profile-5 pack selected by semantic v9.
        assert_eq!(
            blob_profile_for_canonical_shape(
                9,
                1024 * 1024,
                crate::BLOB_STREAM_SEGMENT_BYTES as u32,
                1,
            ),
            Some(TransferProfileId::BlobStreamV1)
        );
    }

    #[test]
    fn profile4_and_native_profile5_shapes_are_version_scoped() {
        let total_len = 64 * 1024 * 1024;
        let profile4_chunks = total_len / (64 * 1024);
        let profile5_segments = total_len / crate::BLOB_STREAM_SEGMENT_BYTES as u64;
        assert_eq!(
            blob_profile_for_canonical_shape(8, total_len, 64 * 1024, profile4_chunks),
            Some(TransferProfileId::BlobRangesStreamV1)
        );
        assert_eq!(
            blob_profile_for_canonical_shape(
                9,
                total_len,
                crate::BLOB_STREAM_SEGMENT_BYTES as u32,
                profile5_segments,
            ),
            Some(TransferProfileId::BlobStreamV1)
        );
        assert_eq!(
            blob_profile_for_canonical_shape(9, total_len, 64 * 1024, profile4_chunks),
            None
        );
    }

    #[test]
    fn profile4_and_profile5_size_boundaries_are_version_scoped() {
        let profile4_max = 64 * 1024 * 1024_u64;
        let profile5_max = 8 * 1024 * 1024 * 1024_u64;
        assert_eq!(
            blob_profile_for_canonical_shape(
                8,
                profile4_max + 1,
                64 * 1024,
                (profile4_max + 1).div_ceil(64 * 1024),
            ),
            None
        );
        assert_eq!(
            blob_profile_for_canonical_shape(
                9,
                profile4_max + 1,
                crate::BLOB_STREAM_SEGMENT_BYTES as u32,
                (profile4_max + 1).div_ceil(crate::BLOB_STREAM_SEGMENT_BYTES as u64),
            ),
            Some(TransferProfileId::BlobStreamV1)
        );
        assert_eq!(
            blob_profile_for_canonical_shape(
                9,
                profile5_max,
                crate::BLOB_STREAM_SEGMENT_BYTES as u32,
                profile5_max / crate::BLOB_STREAM_SEGMENT_BYTES as u64,
            ),
            Some(TransferProfileId::BlobStreamV1)
        );
        assert_eq!(
            blob_profile_for_canonical_shape(8, profile5_max, 64 * 1024, 131_072,),
            None
        );
        assert_eq!(
            blob_profile_for_canonical_shape(
                9,
                profile5_max + 1,
                crate::BLOB_STREAM_SEGMENT_BYTES as u32,
                (profile5_max + 1).div_ceil(crate::BLOB_STREAM_SEGMENT_BYTES as u64),
            ),
            None
        );
    }

    #[test]
    fn empty_canonical_blob_is_profile5_only() {
        assert_eq!(
            blob_profile_for_canonical_shape(
                SEMANTIC_PROTOCOL_V9,
                0,
                crate::BLOB_STREAM_SEGMENT_BYTES as u32,
                0,
            ),
            Some(TransferProfileId::BlobStreamV1)
        );
        assert_eq!(
            blob_profile_for_canonical_shape(
                SEMANTIC_PROTOCOL_V8,
                0,
                crate::BLOB_STREAM_SEGMENT_BYTES as u32,
                0,
            ),
            None
        );
        assert_eq!(
            blob_profile_for_canonical_shape(
                SEMANTIC_PROTOCOL_V9,
                0,
                crate::MAX_BLOB_CHUNK_SIZE,
                1,
            ),
            None
        );
    }

    #[test]
    fn semantic_v9_blob_selection_requires_profile5() {
        let offer = TransferProfileOfferV1::for_semantic_version(9).expect("v9 offer");
        let blob = offer
            .known_lanes()
            .into_iter()
            .find(|(lane, _)| *lane == TransferLaneId::Blob)
            .expect("Blob lane")
            .1;
        assert_eq!(blob, vec![TransferProfileId::BlobStreamV1]);
        let selected = negotiate_transfer_profiles_for_semantic_version(9, &offer, &offer)
            .expect("v9 selection");
        assert_eq!(
            selected.profile(TransferLaneId::Blob),
            Some(TransferProfileId::BlobStreamV1)
        );
        assert!(!selected.contains(TransferLaneId::Blob, TransferProfileId::BlobRangesStreamV1));
    }

    #[test]
    fn semantic_blob_profile_four_is_resolved_by_authenticated_version() {
        let v7 = TransferProfileOfferV1::for_semantic_version(SEMANTIC_PROTOCOL_V7)
            .expect("semantic-v7 offer");
        let v8 = TransferProfileOfferV1::for_semantic_version(SEMANTIC_PROTOCOL_V8)
            .expect("semantic-v8 offer");

        for (semantic_version, offer) in [(SEMANTIC_PROTOCOL_V7, v7), (SEMANTIC_PROTOCOL_V8, v8)] {
            assert_eq!(
                offer
                    .known_lanes()
                    .into_iter()
                    .find(|(lane, _)| *lane == TransferLaneId::Blob),
                Some((
                    TransferLaneId::Blob,
                    vec![TransferProfileId::BlobRangesStreamV1],
                )),
                "semantic v{semantic_version} must select the same stream mechanics"
            );
            assert_eq!(
                negotiate_transfer_profiles_for_semantic_version(semantic_version, &offer, &offer,)
                    .expect("matching stream profiles")
                    .profile(TransferLaneId::Blob),
                Some(TransferProfileId::BlobRangesStreamV1),
            );
        }
    }

    #[test]
    fn semantic_v7_does_not_fall_back_to_removed_blob_carrier() {
        let current = TransferProfileOfferV1::for_semantic_version(SEMANTIC_PROTOCOL_V7)
            .expect("semantic-v7 offer");
        let historical = TransferProfileOfferV1::legacy_only();

        assert!(
            negotiate_transfer_profiles_for_semantic_version(
                SEMANTIC_PROTOCOL_V7,
                &current,
                &historical,
            )
            .is_err(),
            "profile negotiation must fail before Blob carrier I/O"
        );
    }
}
