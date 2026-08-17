use focus_linux::{
    DockerServiceControl, LinuxPrivilegeBroker, PrivilegeBrokerControl, PrivilegeBrokerError,
    ProductionPrivilegeBroker,
};
use focus_platform::PrivilegedAction;

#[derive(Debug, Default)]
struct RecordingDockerControl {
    trusted: bool,
    fail_start: bool,
    starts: usize,
}

impl DockerServiceControl for RecordingDockerControl {
    fn executor_is_trusted(&self) -> Result<bool, PrivilegeBrokerError> {
        Ok(self.trusted)
    }

    fn start_docker(&mut self) -> Result<(), PrivilegeBrokerError> {
        self.starts += 1;
        if self.fail_start {
            Err(PrivilegeBrokerError::ActionFailed)
        } else {
            Ok(())
        }
    }
}

#[test]
fn docker_start_routes_to_one_typed_docker_control_action() {
    let control = RecordingDockerControl {
        trusted: true,
        ..RecordingDockerControl::default()
    };
    let mut broker = LinuxPrivilegeBroker::new(control);

    assert_eq!(broker.execute(PrivilegedAction::DockerStart), Ok(()));
    assert_eq!(broker.control().starts, 1);
}

#[test]
fn untrusted_privilege_executor_fails_before_any_action() {
    let control = RecordingDockerControl::default();
    let mut broker = LinuxPrivilegeBroker::new(control);

    assert_eq!(
        broker.execute(PrivilegedAction::DockerStart),
        Err(PrivilegeBrokerError::UnsafeExecutor)
    );
    assert_eq!(broker.control().starts, 0);
}

#[test]
fn privileged_action_failure_is_never_reported_as_success() {
    let control = RecordingDockerControl {
        trusted: true,
        fail_start: true,
        starts: 0,
    };
    let mut broker = LinuxPrivilegeBroker::new(control);

    assert_eq!(
        broker.execute(PrivilegedAction::DockerStart),
        Err(PrivilegeBrokerError::ActionFailed)
    );
    assert_eq!(broker.control().starts, 1);
}

#[test]
fn production_broker_is_a_concrete_typed_controller() {
    let _broker = ProductionPrivilegeBroker::default();
}
