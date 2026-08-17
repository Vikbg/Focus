use std::{fs, io};

use crate::{
    ExecutionContextClassifier, LinuxExecutionFactSource, ProcessCloseError, ProcessControl,
    ProcessLifetime, ProcfsExecutionFactSource, RunningProcess,
    execution_fact_collector::{collect_running_process, read_process_lifetime},
};

/// Linux process inventory source layered on top of execution-fact collection.
pub trait LinuxProcessInventorySource: LinuxExecutionFactSource {
    /// Returns every numeric process ID currently visible to the enforcement domain.
    ///
    /// # Errors
    ///
    /// Returns an error when the inventory cannot be enumerated completely.
    fn process_ids(&self) -> io::Result<Vec<u32>>;
}

impl LinuxProcessInventorySource for ProcfsExecutionFactSource {
    fn process_ids(&self) -> io::Result<Vec<u32>> {
        let mut process_ids = Vec::new();
        for entry in fs::read_dir("/proc")? {
            let entry = entry?;
            let name = entry.file_name();
            let Some(name) = name.to_str() else {
                continue;
            };
            let Ok(pid) = name.parse::<u32>() else {
                continue;
            };
            if pid != 0 {
                process_ids.push(pid);
            }
        }
        process_ids.sort_unstable();
        Ok(process_ids)
    }
}

/// Stable process-handle operations used by the Linux process-control adapter.
///
/// Production implementations should use a kernel handle such as a pidfd rather than sending a
/// signal to a numeric PID after observation.
pub trait ProcessHandleOps {
    type Handle;

    /// Opens a stable process handle for one numeric PID.
    ///
    /// # Errors
    ///
    /// Returns an error when a stable process handle cannot be acquired.
    fn open_process(&mut self, pid: u32) -> io::Result<Self::Handle>;

    /// Requests termination through the stable process handle.
    ///
    /// # Errors
    ///
    /// Returns an error when the termination request cannot be delivered safely.
    fn terminate_process(&mut self, handle: &Self::Handle) -> io::Result<()>;
}

/// Stable Linux handle paired with the process lifetime it was opened for.
pub struct LinuxProcessHandle<H> {
    lifetime: ProcessLifetime,
    inner: H,
}

/// Linux adapter that combines procfs observations with stable process handles.
pub struct LinuxProcessControl<S, O> {
    source: S,
    handle_ops: O,
    classifier: ExecutionContextClassifier,
    enforced_uid: Option<u32>,
}

impl<S, O> LinuxProcessControl<S, O> {
    /// Creates a Linux process-control adapter from explicit fact and handle sources.
    #[must_use]
    pub const fn new(source: S, handle_ops: O, classifier: ExecutionContextClassifier) -> Self {
        Self {
            source,
            handle_ops,
            classifier,
            enforced_uid: None,
        }
    }

    /// Creates a Linux process-control adapter scoped to one protected effective UID.
    #[must_use]
    pub const fn for_uid(
        source: S,
        handle_ops: O,
        classifier: ExecutionContextClassifier,
        enforced_uid: u32,
    ) -> Self {
        Self {
            source,
            handle_ops,
            classifier,
            enforced_uid: Some(enforced_uid),
        }
    }

    /// Returns the handle operations for inspection by deterministic tests.
    #[must_use]
    pub const fn handle_ops(&self) -> &O {
        &self.handle_ops
    }

    /// Returns the protected effective UID when this control is user-scoped.
    #[must_use]
    pub const fn enforced_uid(&self) -> Option<u32> {
        self.enforced_uid
    }
}

impl<S, O> ProcessControl for LinuxProcessControl<S, O>
where
    S: LinuxProcessInventorySource,
    O: ProcessHandleOps,
{
    type Handle = LinuxProcessHandle<O::Handle>;

    fn process_ids(&self) -> Result<Vec<u32>, ProcessCloseError> {
        let process_ids = self
            .source
            .process_ids()
            .map_err(|_| ProcessCloseError::InventoryFailed)?;
        let Some(enforced_uid) = self.enforced_uid else {
            return Ok(process_ids);
        };

        let mut scoped = Vec::new();
        for pid in process_ids {
            let status = match self.source.status_text(pid) {
                Ok(status) => status,
                Err(error) if error.kind() == io::ErrorKind::NotFound => continue,
                Err(_) => return Err(ProcessCloseError::InventoryFailed),
            };
            let effective_uid =
                parse_effective_uid(&status).ok_or(ProcessCloseError::InventoryFailed)?;
            if effective_uid == enforced_uid {
                scoped.push(pid);
            }
        }
        Ok(scoped)
    }

    fn observe_process(&self, pid: u32) -> Result<Option<RunningProcess>, ProcessCloseError> {
        match collect_running_process(&self.source, pid, &self.classifier) {
            Ok(process) => Ok(Some(process)),
            Err(error) if error.is_not_found() => Ok(None),
            Err(_) => Err(ProcessCloseError::ObservationFailed(pid)),
        }
    }

    fn open_process_handle(
        &mut self,
        lifetime: ProcessLifetime,
    ) -> Result<Self::Handle, ProcessCloseError> {
        let inner = self
            .handle_ops
            .open_process(lifetime.pid())
            .map_err(|_| ProcessCloseError::HandleOpenFailed(lifetime.pid()))?;
        Ok(LinuxProcessHandle { lifetime, inner })
    }

    fn revalidate_process_handle(
        &mut self,
        handle: &Self::Handle,
        expected: ProcessLifetime,
    ) -> Result<(), ProcessCloseError> {
        if handle.lifetime != expected {
            return Err(ProcessCloseError::LifetimeChanged(expected.pid()));
        }
        match read_process_lifetime(&self.source, expected.pid(), "revalidation stat") {
            Ok(current) if current == expected => Ok(()),
            Ok(_) => Err(ProcessCloseError::LifetimeChanged(expected.pid())),
            Err(error) if error.is_not_found() => {
                Err(ProcessCloseError::LifetimeChanged(expected.pid()))
            }
            Err(_) => Err(ProcessCloseError::ObservationFailed(expected.pid())),
        }
    }

    fn terminate_process(&mut self, handle: &Self::Handle) -> Result<(), ProcessCloseError> {
        self.handle_ops
            .terminate_process(&handle.inner)
            .map_err(|_| ProcessCloseError::TerminationFailed(handle.lifetime.pid()))
    }
}

fn parse_effective_uid(status: &str) -> Option<u32> {
    status.lines().find_map(|line| {
        let values = line.strip_prefix("Uid:")?;
        values.split_whitespace().nth(1)?.parse::<u32>().ok()
    })
}
