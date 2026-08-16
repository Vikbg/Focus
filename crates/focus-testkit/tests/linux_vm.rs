use focus_testkit::{LinuxVmScenario, REQUIRED_LINUX_VM_FIXTURES};

#[test]
fn required_linux_vm_fixtures_cover_every_task11_lifecycle() {
    let scenarios = REQUIRED_LINUX_VM_FIXTURES.map(|fixture| fixture.scenario());

    assert_eq!(
        scenarios,
        [
            LinuxVmScenario::Boot,
            LinuxVmScenario::Reboot,
            LinuxVmScenario::SuspendResume,
            LinuxVmScenario::DaemonRestart,
            LinuxVmScenario::MultiUser,
        ]
    );
}

#[test]
fn linux_vm_fixture_metadata_drives_disposable_harness_behavior() {
    let reboot = REQUIRED_LINUX_VM_FIXTURES[1];
    assert_eq!(reboot.slug(), "reboot");
    assert!(reboot.requires_reboot());
    assert!(!reboot.requires_suspend_resume());

    let suspend_resume = REQUIRED_LINUX_VM_FIXTURES[2];
    assert_eq!(suspend_resume.slug(), "suspend-resume");
    assert!(suspend_resume.requires_suspend_resume());

    let multi_user = REQUIRED_LINUX_VM_FIXTURES[4];
    assert_eq!(multi_user.slug(), "multi-user");
    assert_eq!(multi_user.active_users(), 2);
}
