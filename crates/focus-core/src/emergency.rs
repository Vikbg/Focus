//! Emergency unlock domain state.

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EmergencyState {
    Inactive,
    Pending,
    Authorized,
}
