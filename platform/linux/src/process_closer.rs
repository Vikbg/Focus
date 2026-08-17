use focus_core::{Decision, ObservedExecutable, ProcessEnforcementPlan};

/// Stable lifetime identity for one Linux process instance.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ProcessLifetime {
    pid: u32,
    starttime: u64,
}

impl ProcessLifetime {
    /// Creates a process lifetime from its numeric PID and procfs start time.
    #[must_use]
    pub const fn new(pid: u32, starttime: u64) -> Self {
        Self { pid, starttime }
    }

    /// Returns the numeric Linux process ID.
    #[must_use]
    pub const fn pid(self) -> u32 {
        self.pid
    }

    /// Returns the procfs start-time tick value that identifies this PID lifetime.
    #[must_use]
    pub const fn starttime(self) -> u64 {
        self.starttime
    }
}

/// Process observation paired with the lifetime that was verified while collecting it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RunningProcess {
    lifetime: ProcessLifetime,
    executable: ObservedExecutable,
}

impl RunningProcess {
    /// Creates one process observation bound to a verified lifetime.
    #[must_use]
    pub const fn new(lifetime: ProcessLifetime, executable: ObservedExecutable) -> Self {
        Self {
            lifetime,
            executable,
        }
    }

    /// Returns the verified process lifetime.
    #[must_use]
    pub const fn lifetime(&self) -> ProcessLifetime {
        self.lifetime
    }

    /// Returns the stable executable observation used by the frozen policy.
    #[must_use]
    pub const fn executable(&self) -> &ObservedExecutable {
        &self.executable
    }
}

/// Failure while preparing or terminating processes before a protected session arms.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProcessCloseError {
    InventoryFailed,
    ObservationFailed(u32),
    PolicyUncertain(u32),
    HandleOpenFailed(u32),
    LifetimeChanged(u32),
    TerminationFailed(u32),
}

/// OS process-control operations required by the initial-close algorithm.
///
/// Implementations must return handles that remain bound to one process lifetime independently of
/// numeric PID reuse. `revalidate_process_handle` is still required after all handles are opened so
/// a process that changed during observation cannot be terminated under stale policy facts.
pub trait ProcessControl {
    type Handle;

    /// Returns the process IDs visible to the enforcement domain.
    ///
    /// # Errors
    ///
    /// Returns an error when the inventory cannot be enumerated completely.
    fn process_ids(&self) -> Result<Vec<u32>, ProcessCloseError>;

    /// Returns a stable observation for one PID, or `None` when it disappeared during enumeration.
    ///
    /// # Errors
    ///
    /// Returns an error when an existing process cannot be observed safely.
    fn observe_process(&self, pid: u32) -> Result<Option<RunningProcess>, ProcessCloseError>;

    /// Opens a process handle bound to the supplied lifetime.
    ///
    /// # Errors
    ///
    /// Returns an error when a stable handle cannot be acquired.
    fn open_process_handle(
        &mut self,
        lifetime: ProcessLifetime,
    ) -> Result<Self::Handle, ProcessCloseError>;

    /// Confirms that an opened handle still corresponds to the policy observation being acted on.
    ///
    /// # Errors
    ///
    /// Returns an error when the process lifetime changed or cannot be proven stable.
    fn revalidate_process_handle(
        &mut self,
        handle: &Self::Handle,
        expected: ProcessLifetime,
    ) -> Result<(), ProcessCloseError>;

    /// Terminates the process referred to by the stable handle.
    ///
    /// # Errors
    ///
    /// Returns an error when termination cannot be requested safely.
    fn terminate_process(&mut self, handle: &Self::Handle) -> Result<(), ProcessCloseError>;
}

/// Successful result of the initial blocked-process close pass.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProcessCloseReport {
    terminated_pids: Vec<u32>,
}

impl ProcessCloseReport {
    /// Returns PIDs whose stable handles received a successful termination request.
    #[must_use]
    pub fn terminated_pids(&self) -> &[u32] {
        &self.terminated_pids
    }
}

/// Closes already-running processes that are explicitly blocked by the frozen session policy.
///
/// The operation is deliberately phased. Every visible process is first observed and classified.
/// Any `Classify` or `FailClosed` decision aborts before handles are opened. Every blocked handle is
/// then opened and revalidated before the first termination request is sent. This prevents a stale
/// or ambiguous process from causing early partial termination side effects.
///
/// # Errors
///
/// Returns an error when the inventory is incomplete, observation is unsafe, policy classification
/// is uncertain, a stable handle cannot be opened or revalidated, or termination fails.
pub fn close_blocked_processes<C: ProcessControl>(
    control: &mut C,
    plan: &ProcessEnforcementPlan,
) -> Result<ProcessCloseReport, ProcessCloseError> {
    let process_ids = control.process_ids()?;
    let mut blocked = Vec::new();

    for pid in process_ids {
        let Some(process) = control.observe_process(pid)? else {
            continue;
        };
        match plan.decide(process.executable()) {
            Decision::Block(_) => blocked.push(process.lifetime()),
            Decision::Allow => {}
            Decision::Classify | Decision::FailClosed(_) => {
                return Err(ProcessCloseError::PolicyUncertain(pid));
            }
        }
    }

    let mut handles = Vec::with_capacity(blocked.len());
    for lifetime in blocked {
        let handle = control.open_process_handle(lifetime)?;
        handles.push((lifetime, handle));
    }

    for (lifetime, handle) in &handles {
        control.revalidate_process_handle(handle, *lifetime)?;
    }

    let mut terminated_pids = Vec::with_capacity(handles.len());
    for (lifetime, handle) in &handles {
        control.terminate_process(handle)?;
        terminated_pids.push(lifetime.pid());
    }

    Ok(ProcessCloseReport { terminated_pids })
}
