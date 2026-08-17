use std::{
    fs::File,
    io,
    os::fd::{AsFd, BorrowedFd},
};

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
    enforced_uid: Option<u32>,
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
            enforced_uid: None,
        }
    }

    /// Creates a healthy channel that enforces policy only for one effective requester UID.
    #[must_use]
    pub const fn for_uid(
        source: S,
        facts: F,
        classifier: ExecutionContextClassifier,
        enforced_uid: u32,
    ) -> Self {
        Self {
            source,
            facts,
            classifier,
            health: FanotifyChannelHealth::Healthy,
            awaiting_response: false,
            enforced_uid: Some(enforced_uid),
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

impl<S, F> FanotifyExecutionChannel<S, F>
where
    S: AsFd,
{
    pub(crate) fn source_fd(&self) -> BorrowedFd<'_> {
        self.source.as_fd()
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

        loop {
            let event = match self.source.next_event() {
                Ok(Some(event)) => event,
                Ok(None) => return Ok(None),
                Err(error) => return self.fail(error),
            };
            self.awaiting_response = true;

            if let Some(enforced_uid) = self.enforced_uid {
                let requester_uid = self
                    .facts
                    .status_text(event.requester_pid)
                    .ok()
                    .and_then(|status| parse_effective_uid(&status));

                match requester_uid {
                    Some(requester_uid) if requester_uid != enforced_uid => {
                        match self.source.respond(ExecutionPermission::Allow) {
                            Ok(()) => {
                                self.awaiting_response = false;
                                continue;
                            }
                            Err(error) => return self.fail(error),
                        }
                    }
                    None => return Ok(Some(ExecutionAttempt::Unclassifiable)),
                    Some(_) => {}
                }
            }

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

            return Ok(Some(match observed {
                Some(executable) => ExecutionAttempt::Observed(executable),
                None => ExecutionAttempt::Unclassifiable,
            }));
        }
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

fn parse_effective_uid(status: &str) -> Option<u32> {
    status.lines().find_map(|line| {
        let values = line.strip_prefix("Uid:")?;
        values.split_whitespace().nth(1)?.parse::<u32>().ok()
    })
}
