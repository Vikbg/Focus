use std::{
    future::Future,
    pin::pin,
    task::{Context, Poll, Waker},
};

use focus_core::{
    Decision, PolicySet, PolicyVersion, Profile, ProfileId, RecoveryCodeHash, SessionId,
    SessionState,
};
use focus_platform::{FakeBackend, GuardKind};
use focus_storage::{FocusStore, SqliteStore, StoredActiveSession};
use focusd::{ArmingCoordinator, arm_session, recover_session};

const CODE: &str = "FG7K-P29M-4TXQ-R8VN";
const GUARDS: [GuardKind; 4] = [
    GuardKind::Process,
    GuardKind::Network,
    GuardKind::Browser,
    GuardKind::Privilege,
];

fn block_on_ready<F: Future>(future: F) -> F::Output {
    let waker = Waker::noop();
    let mut context = Context::from_waker(waker);
    let mut future = pin!(future);

    match future.as_mut().poll(&mut context) {
        Poll::Ready(output) => output,
        Poll::Pending => panic!("fake backend futures must resolve immediately"),
    }
}

fn session(id: u128) -> StoredActiveSession {
    StoredActiveSession::new(
        SessionId(id),
        SessionState::Arming,
        Profile::new(
            ProfileId(7),
            PolicyVersion(3),
            PolicySet::new(Decision::Allow),
        )
        .snapshot(),
        1_000,
        2_000,
        RecoveryCodeHash::from_code(CODE),
    )
}

#[test]
fn every_arm_stage_failure_compensates_exactly_the_applied_prefix() {
    for (index, failing_guard) in GUARDS.into_iter().enumerate() {
        let mut store = SqliteStore::open_in_memory().unwrap();
        let mut backend = FakeBackend::default();
        backend.fail_guard(failing_guard);
        let session = session(500 + index as u128);

        let result = block_on_ready(arm_session(&mut store, &mut backend, &session));

        assert!(result.is_err());
        let expected_armed = &GUARDS[..index];
        let expected_disarmed = expected_armed.iter().rev().copied().collect::<Vec<_>>();
        assert_eq!(backend.armed(), expected_armed);
        assert_eq!(backend.disarmed(), expected_disarmed.as_slice());
        assert_eq!(
            store.active_session().unwrap().unwrap().state(),
            SessionState::ProtectionFailure
        );
    }
}

#[test]
fn every_verification_failure_compensates_all_armed_guards_in_reverse_order() {
    let expected_disarmed = GUARDS.iter().rev().copied().collect::<Vec<_>>();

    for (index, failing_guard) in GUARDS.into_iter().enumerate() {
        let mut store = SqliteStore::open_in_memory().unwrap();
        let mut backend = FakeBackend::default();
        backend.fail_verification(failing_guard);
        let session = session(510 + index as u128);

        let result = block_on_ready(arm_session(&mut store, &mut backend, &session));

        assert!(result.is_err());
        assert_eq!(backend.armed(), GUARDS.as_slice());
        assert_eq!(backend.disarmed(), expected_disarmed.as_slice());
        assert_eq!(
            store.active_session().unwrap().unwrap().state(),
            SessionState::ProtectionFailure
        );
    }
}

#[test]
fn compensation_is_idempotent_and_never_double_disarms_successful_steps() {
    let mut backend = FakeBackend::default();

    {
        let mut coordinator = ArmingCoordinator::new(&mut backend);
        block_on_ready(coordinator.arm_guard(GuardKind::Process)).unwrap();
        block_on_ready(coordinator.arm_guard(GuardKind::Network)).unwrap();

        let first = block_on_ready(coordinator.compensate());
        assert!(first.remaining_guards().is_empty());
        let second = block_on_ready(coordinator.compensate());
        assert!(second.remaining_guards().is_empty());
    }

    assert_eq!(
        backend.disarmed(),
        &[GuardKind::Network, GuardKind::Process]
    );
}

#[test]
fn compensation_failure_still_persists_protection_failure_and_reports_remaining_effects() {
    let mut store = SqliteStore::open_in_memory().unwrap();
    let mut backend = FakeBackend::default();
    backend.fail_verification(GuardKind::Browser);
    backend.fail_disarm(GuardKind::Network);
    let session = session(520);

    let result = block_on_ready(arm_session(&mut store, &mut backend, &session));

    assert!(result.is_err());
    assert_eq!(
        store.active_session().unwrap().unwrap().state(),
        SessionState::ProtectionFailure
    );
    assert!(backend.guard_is_armed(GuardKind::Network));
    assert_eq!(
        backend.disarmed(),
        &[
            GuardKind::Privilege,
            GuardKind::Browser,
            GuardKind::Network,
            GuardKind::Process,
        ]
    );
}

#[test]
fn close_blocked_apps_failure_persists_protection_failure_without_disarming_guards() {
    let mut store = SqliteStore::open_in_memory().unwrap();
    let mut backend = FakeBackend::default();
    backend.fail_close_blocked_apps();
    let session = session(521);

    let result = block_on_ready(arm_session(&mut store, &mut backend, &session));

    assert!(result.is_err());
    assert!(backend.armed().is_empty());
    assert!(backend.disarmed().is_empty());
    assert_eq!(
        store.active_session().unwrap().unwrap().state(),
        SessionState::ProtectionFailure
    );
}

#[test]
fn crash_after_state_write_before_platform_effects_recovers_by_reapplying_every_guard() {
    let mut store = SqliteStore::open_in_memory().unwrap();
    let active = session(530);
    store.set_active_session(&active).unwrap();
    let mut backend = FakeBackend::default();

    let state = block_on_ready(recover_session(&mut store, &mut backend)).unwrap();

    assert_eq!(state, SessionState::Locked);
    assert_eq!(backend.armed(), GUARDS.as_slice());
    for guard in GUARDS {
        assert!(backend.guard_is_armed(guard));
    }
}

#[test]
fn crash_after_platform_effect_before_followup_state_write_is_reconciled_idempotently() {
    let mut store = SqliteStore::open_in_memory().unwrap();
    let active = session(531);
    store.set_active_session(&active).unwrap();
    let mut backend = FakeBackend::default();
    backend.prearm_guard(GuardKind::Process);

    let state = block_on_ready(recover_session(&mut store, &mut backend)).unwrap();

    assert_eq!(state, SessionState::Locked);
    assert_eq!(
        backend.armed(),
        &[GuardKind::Network, GuardKind::Browser, GuardKind::Privilege]
    );
    for guard in GUARDS {
        assert!(backend.guard_is_armed(guard));
    }
}
