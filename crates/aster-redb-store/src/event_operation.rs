use crate::{CustodyRetirementReason, EventTransferId, MAX_EVENT_OPERATION_KEY_BYTES, StoreError};
use redb::TableDefinition;
use sha2::{Digest, Sha256};

#[allow(dead_code)] // Used by the ledger authority introduced in the following lifecycle slice.
pub(crate) const EVENT_OPERATION_LEDGER_V3: TableDefinition<&[u8], &[u8]> =
    TableDefinition::new("aster.event-operation-ledger.v3");
#[allow(dead_code)] // Used by the ledger authority introduced in the following lifecycle slice.
pub(crate) const ACTIVE_OPERATION_BY_EVENT_V1: TableDefinition<&[u8], &[u8]> =
    TableDefinition::new("aster.active-operation-by-event.v1");

pub(crate) const EVENT_OPERATION_ACTIVE_LOGICAL_BYTES: u64 = 98;
#[allow(dead_code)] // Used by checked ledger accounting in the following lifecycle slice.
pub(crate) const EVENT_OPERATION_RETIRED_LOGICAL_BYTES: u64 = 67;
pub(crate) const ACTIVE_OPERATION_BY_EVENT_LOGICAL_BYTES: u64 = 64;
const EVENT_OPERATION_EMERGENCY_RECORD_LOGICAL_BYTES: u64 =
    EVENT_OPERATION_ACTIVE_LOGICAL_BYTES + ACTIVE_OPERATION_BY_EVENT_LOGICAL_BYTES;
const EVENT_OPERATION_LEDGER_VERSION: u8 = 1;
const EVENT_OPERATION_LEDGER_ACTIVE: u8 = 1;
const EVENT_OPERATION_LEDGER_RETIRED: u8 = 2;
const EVENT_OPERATION_KEY_DOMAIN: &[u8] = b"aster/event-operation-key/v1";

/// A bounded, application-defined idempotency key for one local Event operation.
///
/// The key is durable and maps to exactly one accepted source Event. A caller
/// should namespace the bytes by application and operation kind. Reactive work
/// can append the authenticated predecessor's semantic item identifier.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct EventOperationKey(Vec<u8>);

impl EventOperationKey {
    /// Validates a nonempty bounded operation key.
    pub fn new(bytes: impl Into<Vec<u8>>) -> Result<Self, StoreError> {
        let bytes = bytes.into();
        if bytes.is_empty() || bytes.len() > MAX_EVENT_OPERATION_KEY_BYTES {
            return Err(StoreError::InvalidEventOperationKey {
                length: bytes.len(),
            });
        }
        Ok(Self(bytes))
    }

    /// Returns the exact durable key bytes.
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct EventOperationLimits {
    max_records: u64,
    max_logical_bytes: u64,
    emergency_reserve: u64,
}

impl EventOperationLimits {
    pub const DEFAULT: Self = Self {
        max_records: 1_000_000,
        max_logical_bytes: 201_326_592,
        emergency_reserve: 10_000,
    };

    pub fn new(
        max_records: u64,
        max_logical_bytes: u64,
        emergency_reserve: u64,
    ) -> Result<Self, StoreError> {
        if max_records == 0 || max_logical_bytes == 0 || emergency_reserve == 0 {
            return Err(StoreError::SemanticInvariant(
                "Event operation limits must be nonzero",
            ));
        }
        if emergency_reserve >= max_records {
            return Err(StoreError::SemanticInvariant(
                "Event operation emergency reserve must be below the record limit",
            ));
        }
        let required_emergency_bytes = emergency_reserve
            .checked_mul(EVENT_OPERATION_EMERGENCY_RECORD_LOGICAL_BYTES)
            .ok_or(StoreError::PayloadByteAccountingOverflow)?;
        if max_logical_bytes < required_emergency_bytes {
            return Err(StoreError::SemanticInvariant(
                "Event operation byte limit cannot retain the emergency reserve",
            ));
        }
        Ok(Self {
            max_records,
            max_logical_bytes,
            emergency_reserve,
        })
    }

    pub const fn max_records(self) -> u64 {
        self.max_records
    }

    pub const fn max_logical_bytes(self) -> u64 {
        self.max_logical_bytes
    }

    pub const fn emergency_reserve(self) -> u64 {
        self.emergency_reserve
    }

    pub const fn ordinary_record_limit(self) -> u64 {
        self.max_records - self.emergency_reserve
    }

    pub const fn emergency_byte_reserve(self) -> u64 {
        self.emergency_reserve * EVENT_OPERATION_EMERGENCY_RECORD_LOGICAL_BYTES
    }
}

pub(crate) type EventOperationFingerprint = [u8; 32];

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum EventOperationLedgerRecord {
    Active {
        intent_digest: [u8; 32],
        transfer_id: EventTransferId,
    },
    Retired {
        intent_digest: [u8; 32],
        reason: CustodyRetirementReason,
    },
}

pub(crate) fn event_operation_fingerprint(
    mission_authority: &[u8; 32],
    operation: &EventOperationKey,
) -> EventOperationFingerprint {
    let mut digest = Sha256::new();
    digest.update(EVENT_OPERATION_KEY_DOMAIN);
    digest.update(mission_authority);
    digest.update(
        u16::try_from(operation.as_bytes().len())
            .expect("EventOperationKey is bounded to u16 length")
            .to_be_bytes(),
    );
    digest.update(operation.as_bytes());
    digest.finalize().into()
}

pub(crate) fn encode_event_operation_ledger_record(record: EventOperationLedgerRecord) -> Vec<u8> {
    match record {
        EventOperationLedgerRecord::Active {
            intent_digest,
            transfer_id,
        } => {
            let mut encoded = Vec::with_capacity(66);
            encoded.extend_from_slice(&[
                EVENT_OPERATION_LEDGER_VERSION,
                EVENT_OPERATION_LEDGER_ACTIVE,
            ]);
            encoded.extend_from_slice(&intent_digest);
            encoded.extend_from_slice(transfer_id.as_bytes());
            encoded
        }
        EventOperationLedgerRecord::Retired {
            intent_digest,
            reason,
        } => {
            let mut encoded = Vec::with_capacity(35);
            encoded.extend_from_slice(&[
                EVENT_OPERATION_LEDGER_VERSION,
                EVENT_OPERATION_LEDGER_RETIRED,
            ]);
            encoded.extend_from_slice(&intent_digest);
            encoded.push(reason as u8);
            encoded
        }
    }
}

pub(crate) fn decode_event_operation_ledger_record(
    bytes: &[u8],
) -> Result<EventOperationLedgerRecord, StoreError> {
    let Some((&version, rest)) = bytes.split_first() else {
        return Err(StoreError::SemanticInvariant(
            "missing Event operation ledger version",
        ));
    };
    if version != EVENT_OPERATION_LEDGER_VERSION {
        return Err(StoreError::SemanticInvariant(
            "unknown Event operation ledger version",
        ));
    }
    let Some((&state, _)) = rest.split_first() else {
        return Err(StoreError::SemanticInvariant(
            "missing Event operation ledger state",
        ));
    };
    match state {
        EVENT_OPERATION_LEDGER_ACTIVE => {
            let encoded: &[u8; 66] = bytes.try_into().map_err(|_| {
                StoreError::SemanticInvariant("invalid active Event operation ledger length")
            })?;
            Ok(EventOperationLedgerRecord::Active {
                intent_digest: encoded[2..34]
                    .try_into()
                    .expect("fixed active Event operation intent slice"),
                transfer_id: EventTransferId::new(
                    encoded[34..66]
                        .try_into()
                        .expect("fixed active Event operation transfer slice"),
                ),
            })
        }
        EVENT_OPERATION_LEDGER_RETIRED => {
            let encoded: &[u8; 35] = bytes.try_into().map_err(|_| {
                StoreError::SemanticInvariant("invalid retired Event operation ledger length")
            })?;
            let reason = match encoded[34] {
                1 => CustodyRetirementReason::Expired,
                2 => CustodyRetirementReason::QuotaPressure,
                _ => {
                    return Err(StoreError::SemanticInvariant(
                        "unknown Event operation retirement reason",
                    ));
                }
            };
            Ok(EventOperationLedgerRecord::Retired {
                intent_digest: encoded[2..34]
                    .try_into()
                    .expect("fixed retired Event operation intent slice"),
                reason,
            })
        }
        _ => Err(StoreError::SemanticInvariant(
            "unknown Event operation ledger state",
        )),
    }
}

pub(crate) fn encode_active_operation_by_event_key(
    transfer_id: EventTransferId,
    fingerprint: EventOperationFingerprint,
) -> [u8; 64] {
    let mut encoded = [0u8; 64];
    encoded[..32].copy_from_slice(transfer_id.as_bytes());
    encoded[32..].copy_from_slice(&fingerprint);
    encoded
}

pub(crate) fn decode_active_operation_by_event_key(
    bytes: &[u8],
) -> Result<(EventTransferId, EventOperationFingerprint), StoreError> {
    let encoded: &[u8; 64] = bytes.try_into().map_err(|_| {
        StoreError::SemanticInvariant("invalid active Event operation reverse key length")
    })?;
    Ok((
        EventTransferId::new(
            encoded[..32]
                .try_into()
                .expect("fixed reverse Event operation transfer slice"),
        ),
        encoded[32..]
            .try_into()
            .expect("fixed reverse Event operation fingerprint slice"),
    ))
}

pub(crate) fn checked_event_operation_logical_bytes(
    active_records: u64,
    retired_records: u64,
    reverse_rows: u64,
) -> Result<u64, StoreError> {
    active_records
        .checked_mul(EVENT_OPERATION_ACTIVE_LOGICAL_BYTES)
        .and_then(|bytes| {
            retired_records
                .checked_mul(EVENT_OPERATION_RETIRED_LOGICAL_BYTES)
                .and_then(|retired_bytes| bytes.checked_add(retired_bytes))
        })
        .and_then(|bytes| {
            reverse_rows
                .checked_mul(ACTIVE_OPERATION_BY_EVENT_LOGICAL_BYTES)
                .and_then(|reverse_bytes| bytes.checked_add(reverse_bytes))
        })
        .ok_or(StoreError::PayloadByteAccountingOverflow)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{CustodyRetirementReason, EventTransferId};

    const MISSION_A: [u8; 32] = [
        0xa0, 0xa1, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7, 0xa8, 0xa9, 0xaa, 0xab, 0xac, 0xad, 0xae,
        0xaf, 0xb0, 0xb1, 0xb2, 0xb3, 0xb4, 0xb5, 0xb6, 0xb7, 0xb8, 0xb9, 0xba, 0xbb, 0xbc, 0xbd,
        0xbe, 0xbf,
    ];
    const MISSION_B: [u8; 32] = [
        0xc0, 0xc1, 0xc2, 0xc3, 0xc4, 0xc5, 0xc6, 0xc7, 0xc8, 0xc9, 0xca, 0xcb, 0xcc, 0xcd, 0xce,
        0xcf, 0xd0, 0xd1, 0xd2, 0xd3, 0xd4, 0xd5, 0xd6, 0xd7, 0xd8, 0xd9, 0xda, 0xdb, 0xdc, 0xdd,
        0xde, 0xdf,
    ];

    fn operation_key(bytes: &[u8]) -> EventOperationKey {
        EventOperationKey::new(bytes).expect("valid operation key")
    }

    #[test]
    fn fingerprint_uses_the_exact_domain_mission_length_and_raw_key() {
        let fingerprint =
            event_operation_fingerprint(&MISSION_A, &operation_key(&[0x01, 0x02, 0x03]));

        assert_eq!(
            fingerprint,
            [
                0xa0, 0x55, 0x15, 0x40, 0x96, 0x38, 0x73, 0x1f, 0x96, 0x7f, 0x03, 0x1f, 0x4f, 0x18,
                0xaf, 0x62, 0xf5, 0x65, 0x67, 0xa8, 0x36, 0x6a, 0xad, 0xe4, 0xa6, 0x31, 0x41, 0xdd,
                0x2f, 0xcd, 0xd4, 0x80,
            ]
        );
    }

    #[test]
    fn fingerprint_separates_operation_key_lengths() {
        let short = event_operation_fingerprint(&MISSION_A, &operation_key(&[0x01]));
        let long = event_operation_fingerprint(&MISSION_A, &operation_key(&[0x01, 0x00]));

        assert_eq!(
            short,
            [
                0xe0, 0xf2, 0x51, 0xa6, 0xeb, 0xd3, 0x67, 0x0d, 0xaa, 0x5a, 0xf5, 0xeb, 0x0a, 0x59,
                0x0a, 0xd4, 0xca, 0x3c, 0x59, 0xae, 0x75, 0xb8, 0xd5, 0xe7, 0x01, 0x54, 0xb0, 0x5e,
                0xa5, 0x61, 0xe1, 0xc6,
            ]
        );
        assert_eq!(
            long,
            [
                0x3e, 0xb1, 0x2c, 0x7d, 0x93, 0x78, 0x81, 0x90, 0x43, 0xba, 0xa0, 0x03, 0x6d, 0x20,
                0x9a, 0x5e, 0xf8, 0x55, 0x3f, 0x7e, 0x81, 0x7d, 0xdf, 0xb7, 0x05, 0x37, 0x32, 0x63,
                0x49, 0xea, 0xa1, 0x47,
            ]
        );
    }

    #[test]
    fn fingerprint_separates_missions() {
        let first = event_operation_fingerprint(&MISSION_A, &operation_key(&[0x01, 0x02, 0x03]));
        let second = event_operation_fingerprint(&MISSION_B, &operation_key(&[0x01, 0x02, 0x03]));

        assert_eq!(
            first,
            [
                0xa0, 0x55, 0x15, 0x40, 0x96, 0x38, 0x73, 0x1f, 0x96, 0x7f, 0x03, 0x1f, 0x4f, 0x18,
                0xaf, 0x62, 0xf5, 0x65, 0x67, 0xa8, 0x36, 0x6a, 0xad, 0xe4, 0xa6, 0x31, 0x41, 0xdd,
                0x2f, 0xcd, 0xd4, 0x80,
            ]
        );
        assert_eq!(
            second,
            [
                0xbd, 0x1b, 0xa9, 0x07, 0x08, 0x2d, 0xa9, 0xa6, 0x2c, 0xcb, 0x53, 0x67, 0x53, 0xd3,
                0xba, 0x0f, 0xd1, 0xb2, 0xfd, 0x75, 0xae, 0x82, 0xa2, 0xc4, 0xb3, 0x94, 0xbf, 0x6d,
                0x37, 0x66, 0x05, 0xab,
            ]
        );
    }

    #[test]
    fn active_record_round_trips_to_its_canonical_bytes() {
        let record = EventOperationLedgerRecord::Active {
            intent_digest: [0x11; 32],
            transfer_id: EventTransferId::new([0x22; 32]),
        };

        assert_eq!(
            encode_event_operation_ledger_record(record).as_slice(),
            [
                1, 1, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11,
                0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11,
                0x11, 0x11, 0x11, 0x11, 0x11, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22,
                0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22,
                0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22,
            ]
        );
        assert_eq!(
            decode_event_operation_ledger_record(&encode_event_operation_ledger_record(record))
                .expect("canonical active record"),
            record
        );
    }

    #[test]
    fn retired_record_round_trips_to_its_canonical_bytes() {
        let record = EventOperationLedgerRecord::Retired {
            intent_digest: [0x33; 32],
            reason: CustodyRetirementReason::QuotaPressure,
        };

        assert_eq!(
            encode_event_operation_ledger_record(record).as_slice(),
            [
                1, 2, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33,
                0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33,
                0x33, 0x33, 0x33, 0x33, 0x33, 2,
            ]
        );
        assert_eq!(
            decode_event_operation_ledger_record(&encode_event_operation_ledger_record(record))
                .expect("canonical retired record"),
            record
        );
    }

    #[test]
    fn ledger_decoder_rejects_each_malformed_version_state_length_and_reason() {
        assert!(decode_event_operation_ledger_record(&[9, 1]).is_err());
        assert!(decode_event_operation_ledger_record(&[1, 9]).is_err());
        assert!(decode_event_operation_ledger_record(&[1, 1]).is_err());
        assert!(decode_event_operation_ledger_record(&[1, 2]).is_err());
        let mut unknown_reason = [0u8; 35];
        unknown_reason[0] = 1;
        unknown_reason[1] = 2;
        unknown_reason[34] = 9;
        assert!(decode_event_operation_ledger_record(&unknown_reason).is_err());
    }

    #[test]
    fn reverse_key_round_trips_to_the_transfer_then_fingerprint_bytes() {
        let transfer_id = EventTransferId::new([0x44; 32]);
        let fingerprint = [0x55; 32];

        assert_eq!(
            encode_active_operation_by_event_key(transfer_id, fingerprint),
            [
                0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44,
                0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44,
                0x44, 0x44, 0x44, 0x44, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55,
                0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55,
                0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55,
            ]
        );
        assert_eq!(
            decode_active_operation_by_event_key(&encode_active_operation_by_event_key(
                transfer_id,
                fingerprint,
            ))
            .expect("canonical reverse key"),
            (transfer_id, fingerprint)
        );
        assert!(decode_active_operation_by_event_key(&[0; 63]).is_err());
    }

    #[test]
    fn limits_validate_reserve_and_derive_ordinary_capacity() {
        assert!(EventOperationLimits::new(0, 162, 1).is_err());
        assert!(EventOperationLimits::new(10, 1_620, 10).is_err());
        assert!(EventOperationLimits::new(11, 1_619, 10).is_err());

        let limits = EventOperationLimits::new(100, 20_000, 10).expect("valid limits");
        assert_eq!(limits.max_records(), 100);
        assert_eq!(limits.max_logical_bytes(), 20_000);
        assert_eq!(limits.emergency_reserve(), 10);
        assert_eq!(limits.ordinary_record_limit(), 90);
        assert_eq!(limits.emergency_byte_reserve(), 1_620);
    }

    #[test]
    fn logical_byte_accounting_uses_fixed_rows_and_rejects_overflow() {
        assert_eq!(
            checked_event_operation_logical_bytes(1, 2, 3).expect("finite logical usage"),
            424
        );
        assert!(checked_event_operation_logical_bytes(u64::MAX, 1, 1).is_err());
    }
}
