use super::*;

#[test]
fn numbered_capacity_reports_conservative_emergency_byte_headroom() {
    let limits = EventOperationLimits::new(110, 2_000, 10).unwrap();
    let stats = NumberedEventOperationStats {
        clients: 1,
        outstanding_results: 1,
        reverse_edges: 1,
        logical_bytes: 300,
    };
    let capacity = EventOperationCapacity::for_ledgers(stats, limits);
    assert_eq!(capacity.ordinary_remaining, 0);
    // Total bytes permit five conservative 292-byte results, fewer than ten reserved records.
    assert_eq!(capacity.emergency_remaining, 5);
    assert_eq!(capacity.warning, EventOperationCapacityWarning::Exhausted);
}

#[test]
fn operation_capacity_uses_record_and_byte_headroom_and_exact_thresholds() {
    use EventOperationCapacityWarning::{Critical, Exhausted, Ok, Warning};
    // Both client and result rows count. Headroom budgets 292 bytes per result,
    // preserving the configured emergency record and byte reserve independently.
    for (clients, results, used_bytes, records, bytes, reserve, ordinary, emergency, warning) in [
        (0, 0, 0, 110, 40_000, 10, 100, 10, Ok),
        (20, 50, 2_000, 110, 40_000, 10, 30, 10, Warning),
        (1, 68, 20_148, 110, 40_000, 10, 31, 10, Ok),
        (1, 69, 20_440, 110, 40_000, 10, 30, 10, Warning),
        (1, 88, 25_988, 110, 40_000, 10, 11, 10, Warning),
        (1, 89, 26_280, 110, 40_000, 10, 10, 10, Critical),
        (1, 99, 29_200, 110, 40_000, 10, 0, 10, Exhausted),
        (1, 109, 32_120, 110, 40_000, 10, 0, 0, Exhausted),
        (1, 110, 32_412, 110, 40_000, 10, 0, 0, Exhausted),
        (1, 1, 20_148, 1_100, 45_400, 100, 31, 55, Ok),
        (1, 1, 20_440, 1_100, 45_400, 100, 30, 55, Warning),
        (1, 1, 26_280, 1_100, 45_400, 100, 10, 55, Critical),
        (0, 0, 0, 110, 1_620, 10, 0, 5, Exhausted),
    ] {
        let stats = NumberedEventOperationStats {
            clients,
            outstanding_results: results,
            reverse_edges: results,
            logical_bytes: used_bytes,
        };
        let limits = EventOperationLimits::new(records, bytes, reserve).unwrap();
        let capacity = EventOperationCapacity::for_ledgers(stats, limits);
        assert_eq!(capacity.numbered_stats, stats);
        assert_eq!(capacity.limits, limits);
        assert_eq!(capacity.rows, clients + results);
        assert_eq!(capacity.logical_bytes, used_bytes);
        assert_eq!(
            (
                capacity.ordinary_remaining,
                capacity.emergency_remaining,
                capacity.warning
            ),
            (ordinary, emergency, warning),
            "clients={clients} results={results} records={records} bytes={bytes}"
        );
    }
}

#[test]
fn operation_capacity_threshold_comparison_does_not_overflow_u64() {
    let limits = EventOperationLimits::new(u64::MAX, u64::MAX, 1).unwrap();
    let stats = NumberedEventOperationStats {
        clients: 1,
        outstanding_results: 100_000_000_000_000_000,
        reverse_edges: 100_000_000_000_000_000,
        logical_bytes: 16_200_000_000_000_000_000,
    };
    assert_eq!(
        EventOperationCapacity::for_ledgers(stats, limits).warning,
        EventOperationCapacityWarning::Warning
    );
}
