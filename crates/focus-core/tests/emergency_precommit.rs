use focus_core::{
    BootId, EmergencyClockSample, EmergencyDecision, EmergencyRequest, RecoveryCodeHash, SessionId,
};

const CODE: &str = "FG7K-P29M-4TXQ-R8VN";
const BOOT: BootId = BootId(0x1111);

const fn sample(monotonic_seconds: u64, unix_seconds: u64) -> EmergencyClockSample {
    EmergencyClockSample::new(BOOT, monotonic_seconds, unix_seconds)
}

#[test]
fn emergency_request_is_bound_to_session_without_accepting_a_new_code() {
    let request = EmergencyRequest::new(
        SessionId(44),
        "Need to leave for a real emergency",
        sample(100, 1_000),
    )
    .unwrap();

    assert_eq!(request.session_id(), SessionId(44));
}

#[test]
fn emergency_evaluation_uses_the_precommitted_hash_supplied_by_the_active_session() {
    let mut request = EmergencyRequest::new(
        SessionId(45),
        "Need to leave for a real emergency",
        sample(100, 1_000),
    )
    .unwrap();
    let precommitted = RecoveryCodeHash::from_code(CODE);

    let authorized = request.evaluate(sample(700, 1_600), precommitted, CODE);
    assert_eq!(authorized.decision(), EmergencyDecision::Authorized);
}

#[test]
fn a_different_candidate_cannot_replace_the_precommitted_hash() {
    let mut request = EmergencyRequest::new(
        SessionId(46),
        "Need to leave for a real emergency",
        sample(100, 1_000),
    )
    .unwrap();
    let precommitted = RecoveryCodeHash::from_code(CODE);

    let denied = request.evaluate(sample(700, 1_600), precommitted, "NEW-KNOWN-CODE");
    assert_eq!(denied.decision(), EmergencyDecision::InvalidCode);
}
