use focus_core::{Decision, DecisionContext, PolicyEngine};

#[test]
fn ambiguous_policy_requests_classification() {
    let context = DecisionContext::classification_required();
    let decision = PolicyEngine::default().decide(&context);

    assert_eq!(decision, Decision::Classify);
}
