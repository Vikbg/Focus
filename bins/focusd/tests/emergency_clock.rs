use focus_core::{
    BootId, EmergencyClockEvent, EmergencyClockSample, EmergencyDecision, EmergencyRequest,
    SessionId, SessionState,
};
use focus_storage::{FocusStore, SqliteStore};
use focusd::evaluate_emergency_unlock;

const CODE: &str = "FG7K-P29M-4TXQ-R8VN";
const BOOT_A: BootId = BootId(0xaaaa);

const fn sample(monotonic_seconds: u64, unix_seconds: u64) -> EmergencyClockSample {
    EmergencyClockSample::new(BOOT_A, monotonic_seconds, unix_seconds)
}

#[test]
fn wall_clock_anomaly_is_journaled_and_timing_progress_is_persisted() {
    let mut store = SqliteStore::open_in_memory().unwrap();
    let mut request =
        EmergencyRequest::new("Need a real emergency exit", sample(100, 1_000), CODE).unwrap();
    store.persist_emergency_request(&request).unwrap();

    let evaluation =
        evaluate_emergency_unlock(&mut store, &mut request, sample(160, 1_600), CODE).unwrap();

    assert_eq!(
        evaluation.decision(),
        EmergencyDecision::Waiting {
            remaining_seconds: 540,
        }
    );
    assert_eq!(
        evaluation.clock_event(),
        EmergencyClockEvent::WallClockAnomaly
    );
    assert_eq!(store.security_event_count().unwrap(), 1);
    assert_eq!(
        store
            .emergency_request()
            .unwrap()
            .unwrap()
            .timing_state()
            .verified_elapsed_seconds(),
        60
    );
}

#[test]
fn monotonic_regression_moves_active_session_to_protection_failure() {
    let mut store = SqliteStore::open_in_memory().unwrap();
    let session_id = SessionId(7);
    store
        .set_active_session(session_id, SessionState::EmergencyPending)
        .unwrap();
    let mut request =
        EmergencyRequest::new("Need a real emergency exit", sample(100, 1_000), CODE).unwrap();
    store.persist_emergency_request(&request).unwrap();

    let evaluation =
        evaluate_emergency_unlock(&mut store, &mut request, sample(99, 1_001), CODE).unwrap();

    assert_eq!(
        evaluation.decision(),
        EmergencyDecision::ClockIntegrityFailure
    );
    assert_eq!(
        evaluation.clock_event(),
        EmergencyClockEvent::MonotonicRegression
    );
    assert_eq!(store.security_event_count().unwrap(), 1);
    assert_eq!(
        store.active_session().unwrap().unwrap().state(),
        SessionState::ProtectionFailure
    );
}
