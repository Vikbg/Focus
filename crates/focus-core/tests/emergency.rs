use focus_core::{
    EMERGENCY_DELAY_SECONDS, EmergencyDecision, EmergencyError, EmergencyRequest, RecoveryCodeHash,
};

const CODE: &str = "FG7K-P29M-4TXQ-R8VN";

#[test]
fn emergency_reason_is_mandatory() {
    assert_eq!(
        EmergencyRequest::new("   ", 1_000, CODE),
        Err(EmergencyError::EmptyReason)
    );
}

#[test]
fn emergency_recovery_code_is_mandatory() {
    assert_eq!(
        EmergencyRequest::new("Need to leave for a real emergency", 1_000, "   "),
        Err(EmergencyError::EmptyRecoveryCode)
    );
}

#[test]
fn correct_code_at_nine_minutes_fifty_nine_seconds_is_denied() {
    let request = EmergencyRequest::new("Need to leave for a real emergency", 1_000, CODE).unwrap();

    assert_eq!(
        request.evaluate(1_000 + EMERGENCY_DELAY_SECONDS - 1, CODE),
        EmergencyDecision::Waiting {
            remaining_seconds: 1
        }
    );
}

#[test]
fn correct_code_at_ten_minutes_is_authorized() {
    let request = EmergencyRequest::new("Need to leave for a real emergency", 1_000, CODE).unwrap();

    assert_eq!(
        request.evaluate(1_000 + EMERGENCY_DELAY_SECONDS, CODE),
        EmergencyDecision::Authorized
    );
}

#[test]
fn wrong_code_remains_denied_after_delay() {
    let request = EmergencyRequest::new("Need to leave for a real emergency", 1_000, CODE).unwrap();

    assert_eq!(
        request.evaluate(1_000 + EMERGENCY_DELAY_SECONDS, "WRONG-CODE"),
        EmergencyDecision::InvalidCode
    );
}

#[test]
fn restored_request_keeps_original_deadline_after_reboot() {
    let original = EmergencyRequest::new("Power outage requires shutdown", 2_000, CODE).unwrap();
    let restored = EmergencyRequest::restore(
        original.reason().to_owned(),
        original.requested_at(),
        original.code_hash(),
    )
    .unwrap();

    assert_eq!(
        restored.evaluate(2_000 + 300, CODE),
        EmergencyDecision::Waiting {
            remaining_seconds: 300
        }
    );
    assert_eq!(
        restored.evaluate(2_000 + EMERGENCY_DELAY_SECONDS, CODE),
        EmergencyDecision::Authorized
    );
    assert_eq!(restored.code_hash(), RecoveryCodeHash::from_code(CODE));
}
