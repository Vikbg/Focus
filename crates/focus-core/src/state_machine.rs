//! Focus session lifecycle states.

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionState {
    Idle,
    Preflight,
    Arming,
    Locked,
    EmergencyPending,
    EmergencyAuthorized,
    Ending,
    Recovering,
    ProtectionFailure,
}
