use focus_linux::{
    DockerServiceControl, LinuxPrivilegeBroker, PrivilegeBrokerControl, PrivilegeBrokerError,
    ProductionPrivilegeBroker,
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
fn rootful_docker_start_is_not_approved_by_the_task21_broker() {
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
