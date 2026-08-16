use focus_core::{Decision, ObservedExecutable, ProcessEnforcementPlan};

/// Permission response for one executable-open permission event.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExecutionPermission {
    Allow,
    Deny,
}

/// Converts the frozen process-policy decision into a pre-exec permission response.
///
/// Only an explicit [`Decision::Allow`] can permit execution. Blocks, unresolved classification,
/// and fail-closed decisions are all denied before exec.
#[must_use]
pub fn decide_execution_permission(
    plan: &ProcessEnforcementPlan,
    executable: &ObservedExecutable,
) -> ExecutionPermission {
    match plan.decide(executable) {
        Decision::Allow => ExecutionPermission::Allow,
        Decision::Block(_) | Decision::Classify | Decision::FailClosed(_) => {
            ExecutionPermission::Deny
        }
    }
}
