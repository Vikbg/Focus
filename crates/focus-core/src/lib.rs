//! Platform-independent Focus domain logic.

mod decision;
mod emergency;
mod policy;
mod process;
mod profile;
mod schedule;
mod session;
mod state_machine;
mod vpn;

pub use decision::{BlockReason, Decision};
pub use emergency::{
    BootId, EMERGENCY_DELAY_SECONDS, EmergencyClockEvent, EmergencyClockSample, EmergencyDecision,
    EmergencyError, EmergencyEvaluation, EmergencyRequest, EmergencyState, EmergencyTimingState,
    RecoveryCodeHash, WALL_CLOCK_DRIFT_TOLERANCE_SECONDS,
};
pub use policy::{DecisionContext, PolicyEngine, PolicySet};
pub use process::{
    ExecutableMatcher, ExecutionOrigin, ObservedExecutable, PackageIdentity, PackageKind,
    ProcessEnforcementPlan, ProcessPolicy, ProcessRule,
};
pub use profile::{
    PolicyVersion, Profile, ProfileId, SESSION_POLICY_SCHEMA_VERSION, SessionPolicySnapshot,
    SessionPolicySnapshotError,
};
pub use schedule::{Schedule, ScheduleId, ScheduleSource, ScheduleStatus, SchedulerOutcome};
pub use session::SessionId;
pub use state_machine::{
    SessionEvent, SessionMachine, SessionState, TransitionContext, TransitionError,
    ValidatedTransition,
};
pub use vpn::VpnId;
