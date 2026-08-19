use focus_core::{ExecutableMatcher, ObservedExecutable};
use focus_linux::{
    FocusCgroupClass, FocusCgroupClassClassifier, FocusCgroupControl, FocusCgroupError,
    ProcessLifetime, RunningProcess, place_classified_process,
};

#[derive(Debug, Default)]
struct RecordingControl {
    events: Vec<(FocusCgroupClass, ProcessLifetime)>,
    prepared: bool,
    verified: Vec<(FocusCgroupClass, ProcessLifetime)>,
    fail_place: bool,
}

impl FocusCgroupControl for RecordingControl {
    fn prepare_classes(&mut self) -> Result<(), FocusCgroupError> {
        self.prepared = true;
        Ok(())
    }

    fn place_process(
        &mut self,
        class: FocusCgroupClass,
        lifetime: ProcessLifetime,
    ) -> Result<(), FocusCgroupError> {
        if self.fail_place {
            return Err(FocusCgroupError::PlacementFailed);
        }
        self.events.push((class, lifetime));
        Ok(())
    }

    fn verify_process(
        &mut self,
        class: FocusCgroupClass,
        lifetime: ProcessLifetime,
    ) -> Result<(), FocusCgroupError> {
        self.verified.push((class, lifetime));
        Ok(())
    }
}

fn running(pid: u32, starttime: u64, executable: ObservedExecutable) -> RunningProcess {
    RunningProcess::new(ProcessLifetime::new(pid, starttime), executable)
}

#[test]
fn classified_browser_is_placed_and_verified_with_its_process_lifetime() {
    let digest = [0x51; 32];
    let classifier = FocusCgroupClassClassifier::new(
        vec![ExecutableMatcher::Digest(digest)],
        Vec::new(),
        Vec::new(),
        Vec::new(),
    );
    let process = running(
        4100,
        9001,
        ObservedExecutable::new("/usr/lib/firefox/firefox").with_digest(digest),
    );
    let mut control = RecordingControl::default();

    let class = place_classified_process(&mut control, &classifier, &process).unwrap();

    assert_eq!(class, FocusCgroupClass::Browser);
    assert!(control.prepared);
    assert_eq!(
        control.events,
        vec![(FocusCgroupClass::Browser, ProcessLifetime::new(4100, 9001))]
    );
    assert_eq!(control.verified, control.events);
}

#[test]
fn unknown_process_is_placed_in_blocked_class() {
    let classifier =
        FocusCgroupClassClassifier::new(Vec::new(), Vec::new(), Vec::new(), Vec::new());
    let process = running(
        4200,
        9002,
        ObservedExecutable::new("/opt/unknown").with_digest([0x52; 32]),
    );
    let mut control = RecordingControl::default();

    let class = place_classified_process(&mut control, &classifier, &process).unwrap();

    assert_eq!(class, FocusCgroupClass::Blocked);
    assert_eq!(
        control.events,
        vec![(FocusCgroupClass::Blocked, ProcessLifetime::new(4200, 9002))]
    );
    assert_eq!(control.verified, control.events);
}

#[test]
fn placement_failure_is_never_reported_as_success() {
    let classifier =
        FocusCgroupClassClassifier::new(Vec::new(), Vec::new(), Vec::new(), Vec::new());
    let process = running(
        4300,
        9003,
        ObservedExecutable::new("/opt/unknown").with_digest([0x53; 32]),
    );
    let mut control = RecordingControl {
        fail_place: true,
        ..RecordingControl::default()
    };

    assert_eq!(
        place_classified_process(&mut control, &classifier, &process),
        Err(FocusCgroupError::PlacementFailed)
    );
    assert!(control.verified.is_empty());
}
