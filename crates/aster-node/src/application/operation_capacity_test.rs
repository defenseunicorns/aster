use super::*;
use aster_redb_store::{EventOperationLimits, EventOperationStats};

#[test]
fn numbered_capacity_reports_conservative_emergency_byte_headroom() {
    let limits = EventOperationLimits::new(110, 2_000, 10).unwrap();
    let stats = NumberedEventOperationStats {
        clients: 1,
        outstanding_results: 1,
        reverse_edges: 1,
        logical_bytes: 300,
    };
    let capacity =
        EventOperationCapacity::for_ledgers(EventOperationStats::default(), stats, limits);
    assert_eq!(capacity.mode, EventOperationLedgerMode::Numbered);
    assert_eq!(capacity.ordinary_remaining, 0);
    // Total bytes permit five conservative 292-byte results, fewer than ten reserved records.
    assert_eq!(capacity.emergency_remaining, 5);
    assert_eq!(capacity.warning, EventOperationCapacityWarning::Exhausted);
}

#[test]
fn operation_capacity_uses_record_and_byte_headroom_and_exact_thresholds() {
    use EventOperationCapacityWarning::{Critical, Exhausted, Ok, Warning};
    // Hand-derived headroom includes 162 bytes per active record, 67 per retired
    // fence, and preserves the configured emergency record AND byte reserve.
    for (active, retired, records, bytes, reserve, ordinary, emergency, warning) in [
        (0, 0, 110, 17_820, 10, 100, 10, Ok),
        (20, 50, 110, 17_820, 10, 30, 10, Warning),
        (69, 0, 110, 17_820, 10, 31, 10, Ok),
        (70, 0, 110, 17_820, 10, 30, 10, Warning),
        (89, 0, 110, 17_820, 10, 11, 10, Warning),
        (90, 0, 110, 17_820, 10, 10, 10, Critical),
        (100, 0, 110, 17_820, 10, 0, 10, Exhausted),
        (110, 0, 110, 17_820, 10, 0, 0, Exhausted),
        (111, 0, 110, 17_820, 10, 0, 0, Exhausted),
        (69, 0, 1_100, 32_400, 100, 31, 100, Ok),
        (70, 0, 1_100, 32_400, 100, 30, 100, Warning),
        (90, 0, 1_100, 32_400, 100, 10, 100, Critical),
        (0, 0, 110, 1_620, 10, 0, 10, Exhausted),
    ] {
        let stats = EventOperationStats {
            records_total: active + retired,
            records_active: active,
            records_retired: retired,
            reverse_rows: active,
            logical_bytes: active * 162 + retired * 67,
        };
        let limits = EventOperationLimits::new(records, bytes, reserve).unwrap();
        let capacity = EventOperationCapacity::from_legacy_inspection(stats, limits);
        assert_eq!(capacity.stats, stats);
        assert_eq!(capacity.limits, limits);
        assert_eq!(
            (
                capacity.ordinary_remaining,
                capacity.emergency_remaining,
                capacity.warning
            ),
            (ordinary, emergency, warning),
            "active={active} retired={retired} records={records} bytes={bytes}"
        );
    }
}

#[test]
fn operation_capacity_threshold_comparison_does_not_overflow_u64() {
    let limits = EventOperationLimits::new(u64::MAX, u64::MAX, 1).unwrap();
    let active = 100_000_000_000_000_000;
    let stats = EventOperationStats {
        records_total: active,
        records_active: active,
        reverse_rows: active,
        logical_bytes: 16_200_000_000_000_000_000,
        ..Default::default()
    };
    assert_eq!(
        EventOperationCapacity::from_legacy_inspection(stats, limits).warning,
        EventOperationCapacityWarning::Warning
    );
}
