use crate::StoreError;
use redb::TableDefinition;

pub(crate) const EVENT_OPERATION_LEDGER_V3: TableDefinition<&[u8], &[u8]> =
    TableDefinition::new("aster.event-operation-ledger.v3");
pub(crate) const ACTIVE_OPERATION_BY_EVENT_V1: TableDefinition<&[u8], &[u8]> =
    TableDefinition::new("aster.active-operation-by-event.v1");

// Logical byte reserve per numbered emergency result.
const EVENT_OPERATION_EMERGENCY_RECORD_LOGICAL_BYTES: u64 = 162;

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

#[cfg(test)]
thread_local! {
    pub(crate) static RETIREMENT_TEST_FAULT: std::cell::Cell<u8> = const { std::cell::Cell::new(0) };
}

#[cfg(test)]
pub(crate) fn retirement_test_fault(point: u8) -> Result<(), StoreError> {
    if RETIREMENT_TEST_FAULT.get() == point {
        return Err(StoreError::SemanticInvariant(
            "injected Event operation retirement failure",
        ));
    }
    Ok(())
}
