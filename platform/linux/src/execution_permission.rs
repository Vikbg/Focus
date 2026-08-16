use std::io;

use focus_core::{Decision, ObservedExecutable, ProcessEnforcementPlan};

/// Permission response for one executable-open permission event.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExecutionPermission {
    Allow,
    Deny,
}

/// One execution attempt waiting for a pre-exec permission response.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ExecutionAttempt {
    Observed(ObservedExecutable),
    Unclassifiable,
}

/// Channel that owns the pending permission event until a response is written.
pub trait ExecutionPermissionChannel {
    /// Returns the next pending execution attempt, or `None` when no event is ready.
    ///
    /// When this returns `Some`, the implementation must retain the corresponding permission event
    /// until [`Self::respond`] is called exactly once.
    ///
    /// # Errors
    ///
    /// Returns an I/O error when the event source cannot be read safely.
    fn next_attempt(&mut self) -> io::Result<Option<ExecutionAttempt>>;

    /// Writes the permission response for the current pending event.
    ///
    /// # Errors
    ///
    /// Returns an I/O error when the response cannot be delivered to the enforcement source.
    fn respond(&mut self, permission: ExecutionPermission) -> io::Result<()>;
}

/// Result of processing one execution-permission channel step.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExecutionPermissionStep {
    Idle,
    Allowed,
    Denied,
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

/// Processes at most one pending execution permission event.
///
/// An unclassifiable event is denied. A step is reported as allowed or denied only after the
/// corresponding response has been written successfully.
///
/// # Errors
///
/// Returns an I/O error when the channel cannot read the next event or cannot write the required
/// permission response.
pub fn process_next_execution_permission<C: ExecutionPermissionChannel>(
    channel: &mut C,
    plan: &ProcessEnforcementPlan,
) -> io::Result<ExecutionPermissionStep> {
    let Some(attempt) = channel.next_attempt()? else {
        return Ok(ExecutionPermissionStep::Idle);
    };

    let permission = match attempt {
        ExecutionAttempt::Observed(executable) => decide_execution_permission(plan, &executable),
        ExecutionAttempt::Unclassifiable => ExecutionPermission::Deny,
    };
    channel.respond(permission)?;

    Ok(match permission {
        ExecutionPermission::Allow => ExecutionPermissionStep::Allowed,
        ExecutionPermission::Deny => ExecutionPermissionStep::Denied,
    })
}
