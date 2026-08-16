use std::{fs::File, io, os::fd::AsFd};

use focus_core::ExecutionOrigin;

use crate::{
    ExecutionAttempt, ExecutionContextClassifier, ExecutionPermission, ExecutionPermissionChannel,
    LinuxExecutionFactSource, enrich_execution_target_context, observe_open_executable,
};

/// One execution permission event with a kernel-opened target file and requester PID.
#[derive(Debug)]
pub struct FanotifyExecutionEvent {
    target: File,
    requester_pid: u32,
}

impl FanotifyExecutionEvent {
    /// Creates an execution event from the target file descriptor clone and requester PID.
    #[must_use]
    pub const fn new(target: File, requester_pid: u32) -> Self {
        Self {
            target,
            requester_pid,
        }
    }
}

/// Low-level permission source used by the fanotify execution channel.
///
/// Implementations must retain the original pending permission event until [`Self::respond`] is
/// called. The file in [`FanotifyExecutionEvent`] is an observation clone, not the response token.
pub trait FanotifyPermissionSource {
    /// Returns the next pending execution permission event.
    ///
    /// # Errors
    ///
    /// Returns an I/O error when the fanotify event queue cannot be read safely.
    fn next_event(&mut self) -> io::Result<Option<FanotifyExecutionEvent>>;

    /// Responds to the currently pending permission event.
    ///
    /// # Errors
    ///
    /// Returns an I/O error when the permission response cannot be delivered.
    fn respond(&mut self, permission: ExecutionPermission) -> io::Result<()>;
}

/// Health of the fanotify permission transport.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FanotifyChannelHealth {
    Healthy,
    Failed,
}

/// Converts fanotify permission events into policy-ready execution attempts.
pub struct FanotifyExecutionChannel<S, F> {
    source: S,
    facts: F,
    classifier: ExecutionContextClassifier,
    health: FanotifyChannelHealth,
    awaiting_response: bool,
}

impl<S, F> FanotifyExecutionChannel<S, F> {
    /// Creates a healthy channel around one permission source and requester fact source.
    #[must_use]
    pub const fn new(source: S, facts: F, classifier: ExecutionContextClassifier) -> Self {
        Self {
            source,
            facts,
            classifier,
            health: FanotifyChannelHealth::Healthy,
            awaiting_response: false,
        }
    }

    /// Returns whether the permission transport is still trustworthy.
    #[must_use]
    pub const fn health(&self) -> FanotifyChannelHealth {
        self.health
    }

    fn fail<T>(&mut self, error: io::Error) -> io::Result<T> {
        self.health = FanotifyChannelHealth::Failed;
        Err(error)
    }
}

impl<S, F> ExecutionPermissionChannel for FanotifyExecutionChannel<S, F>
where
    S: FanotifyPermissionSource,
    F: LinuxExecutionFactSource,
{
    fn next_attempt(&mut self) -> io::Result<Option<ExecutionAttempt>> {
        if self.health == FanotifyChannelHealth::Failed {
            return Err(io::Error::other("fanotify execution channel is unhealthy"));
        }
        if self.awaiting_response {
            return self.fail(io::Error::other(
                "fanotify permission event is still awaiting a response",
            ));
        }

        let event = match self.source.next_event() {
            Ok(Some(event)) => event,
            Ok(None) => return Ok(None),
            Err(error) => return self.fail(error),
        };
        self.awaiting_response = true;

        let observed = observe_open_executable(event.target.as_fd(), ExecutionOrigin::Direct)
            .ok()
            .and_then(|target| {
                enrich_execution_target_context(
                    &self.facts,
                    event.requester_pid,
                    target,
                    &self.classifier,
                )
                .ok()
            });

        Ok(Some(match observed {
            Some(executable) => ExecutionAttempt::Observed(executable),
            None => ExecutionAttempt::Unclassifiable,
        }))
    }

    fn respond(&mut self, permission: ExecutionPermission) -> io::Result<()> {
        if self.health == FanotifyChannelHealth::Failed {
            return Err(io::Error::other("fanotify execution channel is unhealthy"));
        }
        if !self.awaiting_response {
            return self.fail(io::Error::other(
                "fanotify response requested without a pending event",
            ));
        }

        match self.source.respond(permission) {
            Ok(()) => {
                self.awaiting_response = false;
                Ok(())
            }
            Err(error) => self.fail(error),
        }
    }
}
