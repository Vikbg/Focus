//! Focus session scheduling domain types.

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ScheduleSource {
    Manual,
    OneTime,
    Recurring,
}
