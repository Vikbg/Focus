use focus_core::{
    BootId, EMERGENCY_DELAY_SECONDS, EmergencyClockEvent, EmergencyClockSample, EmergencyDecision,
    EmergencyError, EmergencyRequest, RecoveryCodeHash,
};

const CODE: &str = "FG7K-P29M-4TXQ-R8VN";
const BOOT_A: BootId = BootId(0xaaaa);
const BOOT_B: BootId = BootId(0xbbbb);

const fn sample(
    boot_id: BootId,
    monotonic_seconds: u64,
    unix_seconds: u64,
) -> EmergencyClockSample {
    EmergencyClockSample::new(boot_id, monotonic_seconds, unix_seconds)
}

#[test]
fn emergency_reason_is_mandatory() {
    assert_eq!(
        EmergencyRequest::new("   ", sample(BOOT_A, 100, 1_000), CODE),
        Err(EmergencyError::EmptyReason)
    );
}

#[test]
fn emergency_recovery_code_is_mandatory() {
    assert_eq!(
        EmergencyRequest::new(
            "Need to leave for a real emergency",
            sample(BOOT_A, 100, 1_000),
            "   ",
        ),
        Err(EmergencyError::EmptyRecoveryCode)
    );
}

#[test]
fn forward_wall_clock_jump_does_not_advance_emergency_delay() {
    let mut request = EmergencyRequest::new(
        "Need to leave for a real emergency",
        sample(BOOT_A, 100, 1_000),
        CODE,
    )
    .unwrap();

    let evaluation = request.evaluate(sample(BOOT_A, 160, 1_600), CODE);

    assert_eq!(
        evaluation.decision(),
        EmergencyDecision::Waiting {
            remaining_seconds: EMERGENCY_DELAY_SECONDS - 60,
        }
    );
    assert_eq!(
        evaluation.clock_event(),
        EmergencyClockEvent::WallClockAnomaly
    );
}

#[test]
fn backward_wall_clock_jump_does_not_reset_or_advance_emergency_delay() {
    let mut request = EmergencyRequest::new(
        "Need to leave for a real emergency",
        sample(BOOT_A, 100, 1_000),
        CODE,
    )
    .unwrap();

    let evaluation = request.evaluate(sample(BOOT_A, 160, 900), CODE);

    assert_eq!(
        evaluation.decision(),
        EmergencyDecision::Waiting {
            remaining_seconds: EMERGENCY_DELAY_SECONDS - 60,
        }
    );
    assert_eq!(
        evaluation.clock_event(),
        EmergencyClockEvent::WallClockAnomaly
    );
}

#[test]
fn correct_code_at_599_monotonic_seconds_is_denied() {
    let mut request = EmergencyRequest::new(
        "Need to leave for a real emergency",
        sample(BOOT_A, 100, 1_000),
        CODE,
    )
    .unwrap();

    let evaluation = request.evaluate(sample(BOOT_A, 699, 1_599), CODE);

    assert_eq!(
        evaluation.decision(),
        EmergencyDecision::Waiting {
            remaining_seconds: 1,
        }
    );
    assert_eq!(evaluation.clock_event(), EmergencyClockEvent::None);
}

#[test]
fn correct_code_at_600_monotonic_seconds_is_authorized() {
    let mut request = EmergencyRequest::new(
        "Need to leave for a real emergency",
        sample(BOOT_A, 100, 1_000),
        CODE,
    )
    .unwrap();

    let evaluation = request.evaluate(sample(BOOT_A, 700, 1_600), CODE);

    assert_eq!(evaluation.decision(), EmergencyDecision::Authorized);
    assert_eq!(evaluation.clock_event(), EmergencyClockEvent::None);
}

#[test]
fn wrong_code_remains_denied_after_verified_monotonic_delay() {
    let mut request = EmergencyRequest::new(
        "Need to leave for a real emergency",
        sample(BOOT_A, 100, 1_000),
        CODE,
    )
    .unwrap();

    let evaluation = request.evaluate(sample(BOOT_A, 700, 1_600), "WRONG-CODE");

    assert_eq!(evaluation.decision(), EmergencyDecision::InvalidCode);
}

#[test]
fn daemon_restart_on_same_boot_keeps_monotonic_progress() {
    let original = EmergencyRequest::new(
        "Power outage requires shutdown",
        sample(BOOT_A, 100, 2_000),
        CODE,
    )
    .unwrap();
    let mut restored = EmergencyRequest::restore(
        original.reason().to_owned(),
        original.requested_at(),
        original.code_hash(),
        original.timing_state(),
    )
    .unwrap();

    let evaluation = restored.evaluate(sample(BOOT_A, 700, 2_600), CODE);

    assert_eq!(evaluation.decision(), EmergencyDecision::Authorized);
    assert_eq!(evaluation.clock_event(), EmergencyClockEvent::None);
    assert_eq!(restored.code_hash(), RecoveryCodeHash::from_code(CODE));
}

#[test]
fn reboot_preserves_only_progress_verified_before_reboot() {
    let mut original = EmergencyRequest::new(
        "Power outage requires shutdown",
        sample(BOOT_A, 100, 2_000),
        CODE,
    )
    .unwrap();
    let before_reboot = original.evaluate(sample(BOOT_A, 400, 2_300), CODE);
    assert_eq!(
        before_reboot.decision(),
        EmergencyDecision::Waiting {
            remaining_seconds: 300,
        }
    );

    let mut restored = EmergencyRequest::restore(
        original.reason().to_owned(),
        original.requested_at(),
        original.code_hash(),
        original.timing_state(),
    )
    .unwrap();

    let after_reboot = restored.evaluate(sample(BOOT_B, 10, 50_000), CODE);
    assert_eq!(
        after_reboot.decision(),
        EmergencyDecision::Waiting {
            remaining_seconds: 300,
        }
    );
    assert_eq!(
        after_reboot.clock_event(),
        EmergencyClockEvent::RebootDetected
    );

    let completed = restored.evaluate(sample(BOOT_B, 310, 50_300), CODE);
    assert_eq!(completed.decision(), EmergencyDecision::Authorized);
}

#[test]
fn reboot_without_checkpoint_gets_no_unverified_offline_credit() {
    let original = EmergencyRequest::new(
        "Power outage requires shutdown",
        sample(BOOT_A, 100, 2_000),
        CODE,
    )
    .unwrap();
    let mut restored = EmergencyRequest::restore(
        original.reason().to_owned(),
        original.requested_at(),
        original.code_hash(),
        original.timing_state(),
    )
    .unwrap();

    let evaluation = restored.evaluate(sample(BOOT_B, 10, 50_000), CODE);

    assert_eq!(
        evaluation.decision(),
        EmergencyDecision::Waiting {
            remaining_seconds: EMERGENCY_DELAY_SECONDS,
        }
    );
    assert_eq!(
        evaluation.clock_event(),
        EmergencyClockEvent::RebootDetected
    );
}

#[test]
fn monotonic_regression_fails_closed() {
    let mut request = EmergencyRequest::new(
        "Need to leave for a real emergency",
        sample(BOOT_A, 100, 1_000),
        CODE,
    )
    .unwrap();

    let evaluation = request.evaluate(sample(BOOT_A, 99, 1_001), CODE);

    assert_eq!(
        evaluation.decision(),
        EmergencyDecision::ClockIntegrityFailure
    );
    assert_eq!(
        evaluation.clock_event(),
        EmergencyClockEvent::MonotonicRegression
    );
}
