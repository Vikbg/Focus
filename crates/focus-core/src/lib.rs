//! Platform-independent Focus domain logic.

mod decision;
mod emergency;
mod policy;
mod profile;
mod schedule;
mod session;
mod state_machine;
mod vpn;

pub use decision::{BlockReason, Decision};
pub use emergency::{
    EMERGENCY_DELAY_SECONDS, EmergencyDecision, EmergencyError, EmergencyRequest, EmergencyState,
    RecoveryCodeHash,
};
pub use policy::{DecisionContext, PolicyEngine, PolicySet};
pub use profile::{PolicyVersion, Profile, ProfileId, SessionPolicySnapshot};
pub use schedule::{Schedule, ScheduleId, ScheduleSource, ScheduleStatus, SchedulerOutcome};
pub use session::SessionId;
pub use state_machine::{SessionGuard, SessionState, TransitionError};
pub use vpn::VpnId;
