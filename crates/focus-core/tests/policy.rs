use focus_core::{BlockReason, Decision, DecisionContext, PolicyEngine};

#[test]
fn ambiguous_policy_requests_classification() {
    let context = DecisionContext::classification_required();
    let decision = PolicyEngine.decide(&context);

    assert_eq!(decision, Decision::Classify);
}

#[test]
fn explicit_allow_cannot_override_security_invariant() {
    let context = DecisionContext::default()
        .with_security_invariant_violation()
        .with_explicit_allow();

    assert_eq!(
        PolicyEngine.decide(&context),
        Decision::Block(BlockReason::SecurityInvariant)
    );
}

#[test]
fn session_restriction_beats_explicit_allow() {
    let context = DecisionContext::default()
        .with_session_restriction()
        .with_explicit_allow();

    assert_eq!(
        PolicyEngine.decide(&context),
        Decision::Block(BlockReason::SessionRestriction)
    );
}

#[test]
fn explicit_block_beats_explicit_allow() {
    let context = DecisionContext::default()
        .with_explicit_block()
        .with_explicit_allow();

    assert_eq!(
        PolicyEngine.decide(&context),
        Decision::Block(BlockReason::ExplicitBlock)
    );
}

#[test]
fn explicit_allow_beats_classification() {
    let context = DecisionContext::classification_required().with_explicit_allow();

    assert_eq!(PolicyEngine.decide(&context), Decision::Allow);
}

#[test]
fn unknown_context_defaults_to_block() {
    assert_eq!(
        PolicyEngine.decide(&DecisionContext::default()),
        Decision::Block(BlockReason::Unknown)
    );
}
