use focus_linux::{
    ExecutionContextClassifier, ProcfsExecutionFactSource, collect_execution_observation,
};

#[test]
fn live_procfs_observation_keeps_stable_executable_identity() {
    let source = ProcfsExecutionFactSource;
    let classifier = ExecutionContextClassifier::new(Vec::new());
    let observed = collect_execution_observation(&source, std::process::id(), &classifier).unwrap();

    assert!(observed.filesystem_identity().is_some());
    assert!(observed.digest().is_some());
    assert!(!observed.canonical_path().is_empty());
}
