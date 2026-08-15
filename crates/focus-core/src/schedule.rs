//! Focus session scheduling domain types.

/// Source that initiated a Focus session.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ScheduleSource {
    Manual,
    OneTime,
    Recurring,
}

/// Stable schedule identifier.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ScheduleId(pub u128);

/// Persistent lifecycle state of a schedule.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ScheduleStatus {
    Pending,
    Completed,
    MissedDueToActiveSession,
}

/// Result of evaluating one schedule against the current time and session state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SchedulerOutcome {
    NotDue,
    Start(ScheduleId),
    MissedDueToActiveSession(ScheduleId),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ScheduleKind {
    OneTime,
    Recurring { interval_seconds: u64 },
}

/// One-time or recurring Focus session schedule.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Schedule {
    id: ScheduleId,
    next_due_at: Option<u64>,
    kind: ScheduleKind,
    status: ScheduleStatus,
}

impl Schedule {
    /// Creates a one-time schedule using an absolute Unix timestamp in seconds.
    #[must_use]
    pub const fn one_time(id: ScheduleId, starts_at: u64) -> Self {
        Self {
            id,
            next_due_at: Some(starts_at),
            kind: ScheduleKind::OneTime,
            status: ScheduleStatus::Pending,
        }
    }

    /// Creates a recurring schedule.
    ///
    /// Returns `None` when `interval_seconds` is zero.
    #[must_use]
    pub const fn recurring(id: ScheduleId, first_at: u64, interval_seconds: u64) -> Option<Self> {
        if interval_seconds == 0 {
            return None;
        }

        Some(Self {
            id,
            next_due_at: Some(first_at),
            kind: ScheduleKind::Recurring { interval_seconds },
            status: ScheduleStatus::Pending,
        })
    }

    /// Returns the current persistent schedule status.
    #[must_use]
    pub const fn status(self) -> ScheduleStatus {
        self.status
    }

    /// Returns the next absolute due timestamp, if this schedule still has one.
    #[must_use]
    pub const fn next_due_at(self) -> Option<u64> {
        self.next_due_at
    }

    /// Evaluates the schedule against the current absolute Unix timestamp.
    ///
    /// A due one-time occurrence is consumed immediately. A recurring occurrence
    /// advances to the first future slot strictly after `now`, preventing a burst
    /// of catch-up sessions after sleep, reboot, or a long active session.
    pub fn evaluate(&mut self, now: u64, session_active: bool) -> SchedulerOutcome {
        let Some(due_at) = self.next_due_at else {
            return SchedulerOutcome::NotDue;
        };

        if now < due_at {
            return SchedulerOutcome::NotDue;
        }

        let outcome = if session_active {
            SchedulerOutcome::MissedDueToActiveSession(self.id)
        } else {
            SchedulerOutcome::Start(self.id)
        };

        match self.kind {
            ScheduleKind::OneTime => {
                self.next_due_at = None;
                self.status = if session_active {
                    ScheduleStatus::MissedDueToActiveSession
                } else {
                    ScheduleStatus::Completed
                };
            }
            ScheduleKind::Recurring { interval_seconds } => {
                let elapsed = now - due_at;
                let skipped_intervals = elapsed / interval_seconds;
                let advance = skipped_intervals.saturating_add(1);
                self.next_due_at =
                    Some(due_at.saturating_add(advance.saturating_mul(interval_seconds)));
                self.status = ScheduleStatus::Pending;
            }
        }

        outcome
    }
}
