use std::time::Duration;

use focus_linux::{ProcessGuardMetrics, ProductionProcessGuard};

#[test]
fn new_production_guard_exposes_zeroed_performance_metrics() {
    let guard = ProductionProcessGuard::for_uid(1000);

    let metrics = guard.metrics();

    assert_eq!(metrics, ProcessGuardMetrics::default());
    assert_eq!(metrics.permission_decisions(), 0);
    assert_eq!(metrics.total_decision_latency(), Duration::ZERO);
    assert_eq!(metrics.max_decision_latency(), Duration::ZERO);
    assert_eq!(metrics.average_decision_latency(), None);
    assert_eq!(metrics.watchdog_wakeups(), 0);
}
