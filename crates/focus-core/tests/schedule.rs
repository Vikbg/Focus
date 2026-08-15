use focus_core::{Schedule, ScheduleId, ScheduleStatus, SchedulerOutcome};

#[test]
fn one_time_schedule_starts_when_due_and_idle() {
    let mut schedule = Schedule::one_time(ScheduleId(1), 1_000);

    assert_eq!(
        schedule.evaluate(1_000, false),
        SchedulerOutcome::Start(ScheduleId(1))
    );
    assert_eq!(schedule.status(), ScheduleStatus::Completed);
}

#[test]
fn recurring_schedule_advances_after_due_occurrence() {
    let mut schedule = Schedule::recurring(ScheduleId(2), 1_000, 300).unwrap();

    assert_eq!(
        schedule.evaluate(1_000, false),
        SchedulerOutcome::Start(ScheduleId(2))
    );
    assert_eq!(schedule.next_due_at(), Some(1_300));
    assert_eq!(schedule.status(), ScheduleStatus::Pending);
}

#[test]
fn due_schedule_is_marked_missed_when_another_session_is_active() {
    let mut schedule = Schedule::one_time(ScheduleId(3), 1_000);

    assert_eq!(
        schedule.evaluate(1_000, true),
        SchedulerOutcome::MissedDueToActiveSession(ScheduleId(3))
    );
    assert_eq!(schedule.status(), ScheduleStatus::MissedDueToActiveSession);
}

#[test]
fn recurring_schedule_skips_past_collisions_instead_of_bursting_late_sessions() {
    let mut schedule = Schedule::recurring(ScheduleId(4), 1_000, 300).unwrap();

    assert_eq!(
        schedule.evaluate(1_950, true),
        SchedulerOutcome::MissedDueToActiveSession(ScheduleId(4))
    );
    assert_eq!(schedule.next_due_at(), Some(2_200));
    assert_eq!(schedule.status(), ScheduleStatus::Pending);
}
