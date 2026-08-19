use focus_core::{ExecutableMatcher, ObservedExecutable};
use focus_linux::{
    FocusCgroupClass, FocusCgroupClassClassifier, FocusCgroupControl, FocusCgroupError,
    place_classified_process,
};

#[derive(Debug, Default)]
struct RecordingControl {
    events: Vec<(FocusCgroupClass, u32)>,
    prepared: bool,
    verified: Vec<(FocusCgroupClass, u32)>,
    fail_place: bool,
}

impl FocusCgroupControl for RecordingControl {
    fn prepare_classes(&mut self) -> Result<(), FocusCgroupError> {
        self.prepared = true;
        Ok(())
    }

    fn place_pid(&mut self, class: FocusCgroupClass, pid: u32) -> Result<(), FocusCgroupError> {
        if self.fail_place {
            return Err(FocusCgroupError::PlacementFailed);
        }
        self.events.push((class, pid));
        Ok(())
    }

    fn verify_pid(&mut self, class: FocusCgroupClass, pid: u32) -> Result<(), FocusCgroupError> {
        self.verified.push((class, pid));
        Ok(())
    }
}

#[test]
fn classified_browser_is_placed_and_verified_in_browser_class() {
    let digest = [0x51; 32];
    let classifier = FocusCgroupClassClassifier::new(
        vec![ExecutableMatcher::Digest(digest)],
        Vec::new(),
        Vec::new(),
        Vec::new(),
    );
    let executable = ObservedExecutable::new("/usr/lib/firefox/firefox").with_digest(digest);
    let mut control = RecordingControl::default();

    let class = place_classified_process(&mut control, &classifier, 4100, &executable).unwrap();

    assert_eq!(class, FocusCgroupClass::Browser);
    assert!(control.prepared);
    assert_eq!(control.events, vec![(FocusCgroupClass::Browser, 4100)]);
    assert_eq!(control.verified, control.events);
}

#[test]
fn unknown_process_is_placed_in_blocked_class() {
    let classifier = FocusCgroupClassClassifier::new(
        Vec::new(),
        Vec::new(),
        Vec::new(),
        Vec::new(),
    );
    let executable = ObservedExecutable::new("/opt/unknown").with_digest([0x52; 32]);
    let mut control = RecordingControl::default();

    let class = place_classified_process(&mut control, &classifier, 4200, &executable).unwrap();

    assert_eq!(class, FocusCgroupClass::Blocked);
    assert_eq!(control.events, vec![(FocusCgroupClass::Blocked, 4200)]);
    assert_eq!(control.verified, control.events);
}

#[test]
fn placement_failure_is_never_reported_as_success() {
    let classifier = FocusCgroupClassClassifier::new(
        Vec::new(),
        Vec::new(),
        Vec::new(),
        Vec::new(),
    );
    let executable = ObservedExecutable::new("/opt/unknown").with_digest([0x53; 32]);
    let mut control = RecordingControl {
        fail_place: true,
        ..RecordingControl::default()
    };

    assert_eq!(
        place_classified_process(&mut control, &classifier, 4300, &executable),
        Err(FocusCgroupError::PlacementFailed)
    );
    assert!(control.verified.is_empty());
}
