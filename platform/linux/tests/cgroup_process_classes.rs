use focus_core::{ExecutableMatcher, ObservedExecutable};
use focus_linux::{FocusCgroupClass, FocusCgroupClassClassifier};

fn stable_executable(path: &str, digest_byte: u8) -> ObservedExecutable {
    ObservedExecutable::new(path).with_digest([digest_byte; 32])
}

#[test]
fn focus_cgroup_classes_have_fixed_safe_names() {
    let classes = [
        (FocusCgroupClass::Browser, "browser"),
        (FocusCgroupClass::Development, "development"),
        (FocusCgroupClass::Vpn, "vpn"),
        (FocusCgroupClass::System, "system"),
        (FocusCgroupClass::Blocked, "blocked"),
    ];

    for (class, expected_name) in classes {
        assert_eq!(class.as_str(), expected_name);
        assert!(!class.as_str().contains('/'));
        assert!(!class.as_str().contains(".."));
    }
}

#[test]
fn trusted_firefox_identity_enters_browser_class() {
    let firefox_digest = [0x11; 32];
    let classifier = FocusCgroupClassClassifier::new(
        vec![ExecutableMatcher::Digest(firefox_digest)],
        Vec::new(),
        Vec::new(),
        Vec::new(),
    );
    let firefox = ObservedExecutable::new("/usr/lib/firefox/firefox").with_digest(firefox_digest);

    assert_eq!(classifier.classify(&firefox), FocusCgroupClass::Browser);
}

#[test]
fn child_of_trusted_compiler_enters_development_class() {
    let compiler_digest = [0x22; 32];
    let classifier = FocusCgroupClassClassifier::new(
        Vec::new(),
        vec![ExecutableMatcher::Digest(compiler_digest)],
        Vec::new(),
        Vec::new(),
    );
    let compiler = ObservedExecutable::new("/usr/bin/clang").with_digest(compiler_digest);
    let compiled_child = stable_executable("/workspace/target/app", 0x23).with_parent(compiler);

    assert_eq!(
        classifier.classify(&compiled_child),
        FocusCgroupClass::Development
    );
}

#[test]
fn unknown_or_ambiguous_identity_fails_closed_to_blocked_class() {
    let shared_digest = [0x33; 32];
    let classifier = FocusCgroupClassClassifier::new(
        vec![ExecutableMatcher::Digest(shared_digest)],
        Vec::new(),
        vec![ExecutableMatcher::Digest(shared_digest)],
        Vec::new(),
    );

    assert_eq!(
        classifier.classify(&stable_executable("/opt/unknown", 0x44)),
        FocusCgroupClass::Blocked
    );
    assert_eq!(
        classifier.classify(&ObservedExecutable::new("/opt/ambiguous").with_digest(shared_digest)),
        FocusCgroupClass::Blocked
    );
}
