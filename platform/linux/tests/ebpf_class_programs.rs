use std::net::Ipv4Addr;

use focus_linux::{
    CgroupEgressPolicy, EgressClassProgramControl, EgressProgramError, EgressProtocol,
    FocusCgroupClass, Ipv4EgressRule, arm_cgroup_egress_programs,
};

#[derive(Debug, Default)]
struct RecordingPrograms {
    events: Vec<(FocusCgroupClass, &'static str, Vec<u64>)>,
    fail_attach: Option<FocusCgroupClass>,
}

impl EgressClassProgramControl for RecordingPrograms {
    fn replace_rules(
        &mut self,
        class: FocusCgroupClass,
        rules: &[Ipv4EgressRule],
    ) -> Result<(), EgressProgramError> {
        self.events.push((
            class,
            "replace",
            rules.iter().map(|rule| rule.map_key()).collect(),
        ));
        Ok(())
    }

    fn attach(&mut self, class: FocusCgroupClass) -> Result<(), EgressProgramError> {
        if self.fail_attach == Some(class) {
            return Err(EgressProgramError::AttachFailed);
        }
        self.events.push((class, "attach", Vec::new()));
        Ok(())
    }

    fn verify(
        &mut self,
        class: FocusCgroupClass,
        rules: &[Ipv4EgressRule],
    ) -> Result<(), EgressProgramError> {
        self.events.push((
            class,
            "verify",
            rules.iter().map(|rule| rule.map_key()).collect(),
        ));
        Ok(())
    }
}

fn tcp(port: u16) -> Ipv4EgressRule {
    Ipv4EgressRule::new(Ipv4Addr::LOCALHOST, port, EgressProtocol::Tcp).unwrap()
}

#[test]
fn all_five_classes_are_replaced_attached_and_verified() {
    let policy = CgroupEgressPolicy::new(
        vec![tcp(9100)],
        vec![tcp(9200)],
        vec![tcp(9300)],
        vec![tcp(9400)],
    );
    let mut control = RecordingPrograms::default();

    arm_cgroup_egress_programs(&mut control, &policy).unwrap();

    for class in [
        FocusCgroupClass::Browser,
        FocusCgroupClass::Development,
        FocusCgroupClass::Vpn,
        FocusCgroupClass::System,
        FocusCgroupClass::Blocked,
    ] {
        assert!(
            control
                .events
                .iter()
                .any(|event| { event.0 == class && event.1 == "replace" })
        );
        assert!(
            control
                .events
                .iter()
                .any(|event| { event.0 == class && event.1 == "attach" })
        );
        assert!(
            control
                .events
                .iter()
                .any(|event| { event.0 == class && event.1 == "verify" })
        );
    }
}

#[test]
fn blocked_class_is_structurally_default_deny() {
    let policy = CgroupEgressPolicy::new(
        vec![tcp(9100)],
        vec![tcp(9200)],
        vec![tcp(9300)],
        vec![tcp(9400)],
    );

    assert!(policy.rules_for(FocusCgroupClass::Blocked).is_empty());
    assert_eq!(policy.rules_for(FocusCgroupClass::Browser), &[tcp(9100)]);
}

#[test]
fn one_class_attach_failure_prevents_success() {
    let policy = CgroupEgressPolicy::new(Vec::new(), Vec::new(), Vec::new(), Vec::new());
    let mut control = RecordingPrograms {
        fail_attach: Some(FocusCgroupClass::Development),
        ..RecordingPrograms::default()
    };

    assert_eq!(
        arm_cgroup_egress_programs(&mut control, &policy),
        Err(EgressProgramError::AttachFailed)
    );
    assert!(
        !control
            .events
            .iter()
            .any(|event| { event.0 == FocusCgroupClass::Vpn && event.1 == "attach" })
    );
}
