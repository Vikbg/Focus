use focus_linux::{
    Health, LinuxError, SystemProbe, evaluate_preflight, require_strict_preflight,
};

#[derive(Debug, Clone, Copy)]
struct Probe {
    systemd: bool,
    cgroup_v2: bool,
    fanotify: bool,
    nftables: bool,
    filesystem_permissions: bool,
    privilege_model: bool,
    active_users: usize,
}

impl Probe {
    const fn healthy() -> Self {
        Self {
            systemd: true,
            cgroup_v2: true,
            fanotify: true,
            nftables: true,
            filesystem_permissions: true,
            privilege_model: true,
            active_users: 1,
        }
    }
}

impl SystemProbe for Probe {
    fn systemd_available(&self) -> Result<bool, LinuxError> {
        Ok(self.systemd)
    }

    fn cgroup_v2_available(&self) -> Result<bool, LinuxError> {
        Ok(self.cgroup_v2)
    }

    fn fanotify_available(&self) -> Result<bool, LinuxError> {
        Ok(self.fanotify)
    }

    fn nftables_available(&self) -> Result<bool, LinuxError> {
        Ok(self.nftables)
    }

    fn filesystem_permissions_ready(&self) -> Result<bool, LinuxError> {
        Ok(self.filesystem_permissions)
    }

    fn privilege_model_ready(&self) -> Result<bool, LinuxError> {
        Ok(self.privilege_model)
    }

    fn active_user_count(&self) -> Result<usize, LinuxError> {
        Ok(self.active_users)
    }
}

#[test]
fn healthy_linux_host_satisfies_strict_preflight() {
    let report = evaluate_preflight(&Probe::healthy()).unwrap();

    assert_eq!(report.systemd, Health::Healthy);
    assert_eq!(report.cgroup_v2, Health::Healthy);
    assert_eq!(report.fanotify, Health::Healthy);
    assert_eq!(report.nftables, Health::Healthy);
    assert_eq!(report.filesystem_permissions, Health::Healthy);
    assert_eq!(report.privilege_model, Health::Healthy);
    assert_eq!(report.multi_user_state, Health::Healthy);
    assert_eq!(report.active_users, 1);
    assert!(report.is_strict_ready());
    require_strict_preflight(&report).unwrap();
}

#[test]
fn every_required_capability_fails_closed_when_missing() {
    for degraded in [
        Probe {
            systemd: false,
            ..Probe::healthy()
        },
        Probe {
            cgroup_v2: false,
            ..Probe::healthy()
        },
        Probe {
            fanotify: false,
            ..Probe::healthy()
        },
        Probe {
            nftables: false,
            ..Probe::healthy()
        },
        Probe {
            filesystem_permissions: false,
            ..Probe::healthy()
        },
        Probe {
            privilege_model: false,
            ..Probe::healthy()
        },
        Probe {
            active_users: 2,
            ..Probe::healthy()
        },
    ] {
        let report = evaluate_preflight(&degraded).unwrap();
        assert!(!report.is_strict_ready());
        assert!(require_strict_preflight(&report).is_err());
    }
}

#[test]
fn multi_user_state_reports_degraded_instead_of_hiding_active_users() {
    let report = evaluate_preflight(&Probe {
        active_users: 3,
        ..Probe::healthy()
    })
    .unwrap();

    assert_eq!(report.active_users, 3);
    assert_eq!(report.multi_user_state, Health::Degraded);
}
