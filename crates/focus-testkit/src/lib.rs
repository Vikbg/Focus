//! Shared test fixtures and builders for Focus.

pub const CRATE_NAME: &str = "focus-testkit";

/// Linux lifecycle and privileged enforcement scenarios exercised in disposable virtual machines.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LinuxVmScenario {
    Boot,
    Reboot,
    SuspendResume,
    DaemonRestart,
    MultiUser,
    FanotifyPermission,
}

/// Metadata consumed by the disposable Linux VM harness.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LinuxVmFixture {
    scenario: LinuxVmScenario,
    slug: &'static str,
    requires_reboot: bool,
    requires_suspend_resume: bool,
    active_users: usize,
}

impl LinuxVmFixture {
    const fn new(
        scenario: LinuxVmScenario,
        slug: &'static str,
        requires_reboot: bool,
        requires_suspend_resume: bool,
        active_users: usize,
    ) -> Self {
        Self {
            scenario,
            slug,
            requires_reboot,
            requires_suspend_resume,
            active_users,
        }
    }

    /// Returns the lifecycle scenario represented by this fixture.
    #[must_use]
    pub const fn scenario(self) -> LinuxVmScenario {
        self.scenario
    }

    /// Returns the stable harness slug for this fixture.
    #[must_use]
    pub const fn slug(self) -> &'static str {
        self.slug
    }

    /// Returns whether the scenario requires a guest reboot before completion.
    #[must_use]
    pub const fn requires_reboot(self) -> bool {
        self.requires_reboot
    }

    /// Returns whether the scenario requires a guest suspend and resume cycle.
    #[must_use]
    pub const fn requires_suspend_resume(self) -> bool {
        self.requires_suspend_resume
    }

    /// Returns the expected number of active non-root users for the scenario.
    #[must_use]
    pub const fn active_users(self) -> usize {
        self.active_users
    }
}

/// Required Task 11 Linux VM lifecycle fixtures.
pub const REQUIRED_LINUX_VM_FIXTURES: [LinuxVmFixture; 5] = [
    LinuxVmFixture::new(LinuxVmScenario::Boot, "boot", false, false, 1),
    LinuxVmFixture::new(LinuxVmScenario::Reboot, "reboot", true, false, 1),
    LinuxVmFixture::new(
        LinuxVmScenario::SuspendResume,
        "suspend-resume",
        false,
        true,
        1,
    ),
    LinuxVmFixture::new(
        LinuxVmScenario::DaemonRestart,
        "daemon-restart",
        false,
        false,
        1,
    ),
    LinuxVmFixture::new(LinuxVmScenario::MultiUser, "multi-user", false, false, 2),
];

/// Task 12 privileged process-enforcement fixtures.
pub const PROCESS_ENFORCEMENT_VM_FIXTURES: [LinuxVmFixture; 1] = [LinuxVmFixture::new(
    LinuxVmScenario::FanotifyPermission,
    "fanotify-permission",
    false,
    false,
    1,
)];
