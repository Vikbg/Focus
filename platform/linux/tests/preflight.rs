use focus_linux::{Health, LinuxError, SystemProbe, evaluate_preflight, require_strict_preflight};

#[derive(Debug, Clone, Copy)]
struct Probe {
    systemd: Health,
    cgroup_v2: Health,
    fanotify: Health,
    nftables: Health,
    filesystem_permissions: Health,
    privilege_model: Health,
    active_users: usize,
}

impl Probe {
    const fn healthy() -> Self {
        Self {
            systemd: Health::Healthy,
            cgroup_v2: Health::Healthy,
            fanotify: Health::Healthy,
            nftables: Health::Healthy,
            filesystem_permissions: Health::Healthy,
            privilege_model: Health::Healthy,
            active_users: 1,
        }
    }

    const fn available(health: Health) -> bool {
        matches!(health, Health::Healthy)
    }
}

impl SystemProbe for Probe {
    fn systemd_available(&self) -> Result<bool, LinuxError> {
        Ok(Self::available(self.systemd))
    }

    fn cgroup_v2_available(&self) -> Result<bool, LinuxError> {
        Ok(Self::available(self.cgroup_v2))
    }

    fn fanotify_available(&self) -> Result<bool, LinuxError> {
        Ok(Self::available(self.fanotify))
    }

    fn nftables_available(&self) -> Result<bool, LinuxError> {
        Ok(Self::available(self.nftables))
    }

    fn filesystem_permissions_ready(&self) -> Result<bool, LinuxError> {
        Ok(Self::available(self.filesystem_permissions))
    }

    fn privilege_model_ready(&self) -> Result<bool, LinuxError> {
        Ok(Self::available(self.privilege_model))
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
            systemd: Health::Unavailable,
            ..Probe::healthy()
        },
        Probe {
            cgroup_v2: Health::Unavailable,
            ..Probe::healthy()
        },
        Probe {
            fanotify: Health::Unavailable,
            ..Probe::healthy()
        },
        Probe {
            nftables: Health::Unavailable,
            ..Probe::healthy()
        },
        Probe {
            filesystem_permissions: Health::Unavailable,
            ..Probe::healthy()
        },
        Probe {
            privilege_model: Health::Unavailable,
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
