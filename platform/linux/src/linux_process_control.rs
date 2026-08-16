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
            let Some(name) = entry.file_name().to_str().map(str::to_owned) else {
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

/// Linux adapter that combines procfs observations with stable process handles.
pub struct LinuxProcessControl<S, O> {
    source: S,
    handle_ops: O,
    classifier: ExecutionContextClassifier,
}

impl<S, O> LinuxProcessControl<S, O> {
    /// Creates a Linux process-control adapter from explicit fact and handle sources.
    #[must_use]
    pub const fn new(source: S, handle_ops: O, classifier: ExecutionContextClassifier) -> Self {
        Self {
            source,
            handle_ops,
            classifier,
        }
    }

    /// Returns the handle operations for inspection by deterministic tests.
    #[must_use]
    pub const fn handle_ops(&self) -> &O {
        &self.handle_ops
    }
}

impl<S, O> ProcessControl for LinuxProcessControl<S, O>
where
    S: LinuxProcessInventorySource,
    O: ProcessHandleOps,
{
    type Handle = O::Handle;

    fn process_ids(&self) -> Result<Vec<u32>, ProcessCloseError> {
        self.source
            .process_ids()
            .map_err(|_| ProcessCloseError::InventoryFailed)
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
        self.handle_ops
            .open_process(lifetime.pid())
            .map_err(|_| ProcessCloseError::HandleOpenFailed(lifetime.pid()))
    }

    fn revalidate_process_handle(
        &mut self,
        _handle: &Self::Handle,
        expected: ProcessLifetime,
    ) -> Result<(), ProcessCloseError> {
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
            .terminate_process(handle)
            .map_err(|_| ProcessCloseError::TerminationFailed(handle_pid_unavailable()))
    }
}

const fn handle_pid_unavailable() -> u32 {
    0
}
