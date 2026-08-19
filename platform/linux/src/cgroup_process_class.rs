use std::{error::Error, fmt};

use focus_core::{ExecutableMatcher, ObservedExecutable};

/// Fixed Focus-owned process classes reserved for cgroup-aware network enforcement.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum FocusCgroupClass {
    Browser,
    Development,
    Vpn,
    System,
    Blocked,
}

impl FocusCgroupClass {
    /// Returns the fixed safe cgroup component owned by Focus for this class.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Browser => "browser",
            Self::Development => "development",
            Self::Vpn => "vpn",
            Self::System => "system",
            Self::Blocked => "blocked",
        }
    }
}

/// Classifies observed executables into the fixed Focus cgroup classes.
///
/// Browser, VPN, and system identities are matched directly against stable executable matchers.
/// Development children are recognized through the stable identity of their direct compiler or
/// build-tool parent. Unknown or ambiguous observations fail closed to the blocked class.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FocusCgroupClassClassifier {
    browser: Vec<ExecutableMatcher>,
    development_parents: Vec<ExecutableMatcher>,
    vpn: Vec<ExecutableMatcher>,
    system: Vec<ExecutableMatcher>,
}

impl FocusCgroupClassClassifier {
    /// Creates a classifier from stable identities for the four allow-capable classes.
    #[must_use]
    pub const fn new(
        browser_matchers: Vec<ExecutableMatcher>,
        development_parent_matchers: Vec<ExecutableMatcher>,
        vpn_matchers: Vec<ExecutableMatcher>,
        system_matchers: Vec<ExecutableMatcher>,
    ) -> Self {
        Self {
            browser: browser_matchers,
            development_parents: development_parent_matchers,
            vpn: vpn_matchers,
            system: system_matchers,
        }
    }

    /// Returns the fixed class for one observed executable.
    ///
    /// Multiple matching classes are treated as ambiguous and therefore blocked.
    #[must_use]
    pub fn classify(&self, executable: &ObservedExecutable) -> FocusCgroupClass {
        let browser = matches_any(&self.browser, executable);
        let development = executable
            .parent()
            .is_some_and(|parent| matches_any(&self.development_parents, parent));
        let vpn = matches_any(&self.vpn, executable);
        let system = matches_any(&self.system, executable);
        let match_count = usize::from(browser)
            + usize::from(development)
            + usize::from(vpn)
            + usize::from(system);

        if match_count != 1 {
            return FocusCgroupClass::Blocked;
        }
        if browser {
            FocusCgroupClass::Browser
        } else if development {
            FocusCgroupClass::Development
        } else if vpn {
            FocusCgroupClass::Vpn
        } else {
            FocusCgroupClass::System
        }
    }
}

/// Error returned while preparing or mutating Focus-owned cgroup classes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FocusCgroupError {
    InvalidPid,
    PreparationFailed,
    PlacementFailed,
    VerificationFailed,
}

impl fmt::Display for FocusCgroupError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidPid => {
                formatter.write_str("invalid process id for Focus cgroup placement")
            }
            Self::PreparationFailed => {
                formatter.write_str("Focus cgroup classes could not be prepared")
            }
            Self::PlacementFailed => {
                formatter.write_str("process could not be placed in its Focus cgroup class")
            }
            Self::VerificationFailed => {
                formatter.write_str("Focus cgroup process placement could not be verified")
            }
        }
    }
}

impl Error for FocusCgroupError {}

/// Narrow cgroup authority limited to the fixed Focus process classes.
pub trait FocusCgroupControl {
    /// Prepares the complete fixed set of Focus-owned cgroup classes.
    ///
    /// # Errors
    ///
    /// Returns an error when the classes cannot be prepared safely.
    fn prepare_classes(&mut self) -> Result<(), FocusCgroupError>;

    /// Places one nonzero process ID into a fixed Focus cgroup class.
    ///
    /// # Errors
    ///
    /// Returns an error when the process cannot be placed safely.
    fn place_pid(&mut self, class: FocusCgroupClass, pid: u32) -> Result<(), FocusCgroupError>;

    /// Verifies that one process ID belongs to the expected fixed Focus cgroup class.
    ///
    /// # Errors
    ///
    /// Returns an error when membership cannot be verified exactly.
    fn verify_pid(&mut self, class: FocusCgroupClass, pid: u32) -> Result<(), FocusCgroupError>;
}

/// Classifies a process, places it into the matching fixed Focus cgroup, and verifies membership.
///
/// Unknown or ambiguous executable identity is classified as [`FocusCgroupClass::Blocked`] before
/// any placement is requested. PID zero is rejected before any cgroup mutation.
///
/// # Errors
///
/// Returns the underlying cgroup control error when preparation, placement, or verification fails,
/// or [`FocusCgroupError::InvalidPid`] when `pid` is zero.
pub fn place_classified_process<C: FocusCgroupControl>(
    control: &mut C,
    classifier: &FocusCgroupClassClassifier,
    pid: u32,
    executable: &ObservedExecutable,
) -> Result<FocusCgroupClass, FocusCgroupError> {
    if pid == 0 {
        return Err(FocusCgroupError::InvalidPid);
    }

    let class = classifier.classify(executable);
    control.prepare_classes()?;
    control.place_pid(class, pid)?;
    control.verify_pid(class, pid)?;
    Ok(class)
}

fn matches_any(matchers: &[ExecutableMatcher], executable: &ObservedExecutable) -> bool {
    matchers.iter().any(|matcher| matcher.matches(executable))
}
