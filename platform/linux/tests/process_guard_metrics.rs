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

#[test]
fn isolated_mount_guard_can_bind_the_protected_uid() {
    let guard = ProductionProcessGuard::for_mounts_and_uid(["/tmp/focus-guard-fixture"], 60_000);

    assert_eq!(guard.enforced_uid(), Some(60_000));
    assert_eq!(guard.metrics(), ProcessGuardMetrics::default());
}
