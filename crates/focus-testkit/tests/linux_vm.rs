use focus_testkit::{
    LinuxVmFixture, LinuxVmScenario, PROCESS_ENFORCEMENT_VM_FIXTURES, REQUIRED_LINUX_VM_FIXTURES,
};

#[test]
fn required_linux_vm_fixtures_cover_every_task11_lifecycle() {
    let scenarios = REQUIRED_LINUX_VM_FIXTURES.map(LinuxVmFixture::scenario);

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

#[test]
fn task12_process_enforcement_requires_real_fanotify_permission_fixture() {
    assert_eq!(PROCESS_ENFORCEMENT_VM_FIXTURES.len(), 1);
    let fanotify = PROCESS_ENFORCEMENT_VM_FIXTURES[0];

    assert_eq!(fanotify.scenario(), LinuxVmScenario::FanotifyPermission);
    assert_eq!(fanotify.slug(), "fanotify-permission");
    assert!(!fanotify.requires_reboot());
    assert!(!fanotify.requires_suspend_resume());
    assert_eq!(fanotify.active_users(), 1);
}
