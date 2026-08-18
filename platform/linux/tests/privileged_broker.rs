use focus_linux::{
    DockerServiceControl, LinuxPrivilegeBroker, PrivilegeBrokerControl, PrivilegeBrokerError,
    ProductionPrivilegeBroker, VpnActionControl,
};
use focus_platform::PrivilegedAction;

#[derive(Debug, Default)]
struct RecordingDockerControl {
    trusted: bool,
    fail_stop: bool,
    starts: usize,
    stops: usize,
}

impl DockerServiceControl for RecordingDockerControl {
    fn executor_is_trusted(&self) -> Result<bool, PrivilegeBrokerError> {
        Ok(self.trusted)
    }

    fn start_docker(&mut self) -> Result<(), PrivilegeBrokerError> {
        self.starts += 1;
        Ok(())
    }

    fn stop_docker(&mut self) -> Result<(), PrivilegeBrokerError> {
        self.stops += 1;
        if self.fail_stop {
            Err(PrivilegeBrokerError::ActionFailed)
        } else {
            Ok(())
        }
    }
}

#[derive(Debug, Default)]
struct RecordingVpnControl {
    connects: Vec<u128>,
    disconnects: Vec<u128>,
    fail: bool,
}

impl VpnActionControl for RecordingVpnControl {
    fn connect_vpn(&mut self, id: u128) -> Result<(), PrivilegeBrokerError> {
        self.connects.push(id);
        if self.fail {
            Err(PrivilegeBrokerError::ActionFailed)
        } else {
            Ok(())
        }
    }

    fn disconnect_vpn(&mut self, id: u128) -> Result<(), PrivilegeBrokerError> {
        self.disconnects.push(id);
        if self.fail {
            Err(PrivilegeBrokerError::ActionFailed)
        } else {
            Ok(())
        }
    }
}

#[test]
fn vpn_actions_route_exact_typed_ids_to_the_vpn_control() {
    let docker = RecordingDockerControl::default();
    let vpn = RecordingVpnControl::default();
    let mut broker = LinuxPrivilegeBroker::with_controls(docker, vpn);

    assert_eq!(
        broker.execute(PrivilegedAction::VpnConnect { id: 41 }),
        Ok(())
    );
    assert_eq!(
        broker.execute(PrivilegedAction::VpnDisconnect { id: 42 }),
        Ok(())
    );
    assert_eq!(broker.vpn_control().connects, vec![41]);
    assert_eq!(broker.vpn_control().disconnects, vec![42]);
    assert_eq!(broker.control().starts, 0);
    assert_eq!(broker.control().stops, 0);
}

#[test]
fn vpn_action_failure_is_never_reported_as_success() {
    let docker = RecordingDockerControl::default();
    let vpn = RecordingVpnControl {
        fail: true,
        ..RecordingVpnControl::default()
    };
    let mut broker = LinuxPrivilegeBroker::with_controls(docker, vpn);

    assert_eq!(
        broker.execute(PrivilegedAction::VpnConnect { id: 7 }),
        Err(PrivilegeBrokerError::ActionFailed)
    );
    assert_eq!(broker.vpn_control().connects, vec![7]);
}

#[test]
fn production_vpn_actions_remain_fail_closed_until_p3_injects_a_manager() {
    let mut broker = ProductionPrivilegeBroker::default();

    assert_eq!(
        broker.execute(PrivilegedAction::VpnConnect { id: 9 }),
        Err(PrivilegeBrokerError::ActionNotApproved)
    );
    assert_eq!(
        broker.execute(PrivilegedAction::VpnDisconnect { id: 9 }),
        Err(PrivilegeBrokerError::ActionNotApproved)
    );
}

#[test]
fn docker_stop_routes_to_one_typed_docker_control_action() {
    let control = RecordingDockerControl {
        trusted: true,
        ..RecordingDockerControl::default()
    };
    let mut broker = LinuxPrivilegeBroker::new(control);

    assert_eq!(broker.execute(PrivilegedAction::DockerStop), Ok(()));
    assert_eq!(broker.control().stops, 1);
    assert_eq!(broker.control().starts, 0);
}

#[test]
fn rootful_docker_start_is_not_approved_by_the_task22_broker() {
    let control = RecordingDockerControl {
        trusted: true,
        ..RecordingDockerControl::default()
    };
    let mut broker = LinuxPrivilegeBroker::new(control);

    assert_eq!(
        broker.execute(PrivilegedAction::DockerStart),
        Err(PrivilegeBrokerError::ActionNotApproved)
    );
    assert_eq!(broker.control().starts, 0);
    assert_eq!(broker.control().stops, 0);
}

#[test]
fn untrusted_privilege_executor_fails_before_any_action() {
    let control = RecordingDockerControl::default();
    let mut broker = LinuxPrivilegeBroker::new(control);

    assert_eq!(
        broker.execute(PrivilegedAction::DockerStop),
        Err(PrivilegeBrokerError::UnsafeExecutor)
    );
    assert_eq!(broker.control().stops, 0);
}

#[test]
fn privileged_action_failure_is_never_reported_as_success() {
    let control = RecordingDockerControl {
        trusted: true,
        fail_stop: true,
        starts: 0,
        stops: 0,
    };
    let mut broker = LinuxPrivilegeBroker::new(control);

    assert_eq!(
        broker.execute(PrivilegedAction::DockerStop),
        Err(PrivilegeBrokerError::ActionFailed)
    );
    assert_eq!(broker.control().stops, 1);
}

#[test]
fn production_broker_is_a_concrete_typed_controller() {
    let _broker = ProductionPrivilegeBroker::default();
}
