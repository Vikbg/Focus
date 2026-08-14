use focus_core::{BlockReason, Decision, PolicySet, PolicyVersion, Profile, ProfileId};

#[test]
fn active_session_snapshot_keeps_original_profile_version_and_policy() {
    let profile = Profile::new(
        ProfileId(1),
        PolicyVersion(5),
        PolicySet::new(Decision::Allow),
    );
    let snapshot = profile.snapshot();

    let updated = profile.with_policy(
        PolicyVersion(6),
        PolicySet::new(Decision::Block(BlockReason::ExplicitBlock)),
    );

    assert_eq!(snapshot.profile_version(), PolicyVersion(5));
    assert_eq!(snapshot.policy().default_decision(), Decision::Allow);
    assert_eq!(updated.version(), PolicyVersion(6));
    assert_eq!(
        updated.policy().default_decision(),
        Decision::Block(BlockReason::ExplicitBlock)
    );
}
