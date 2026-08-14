//! Platform-independent policy evaluation.

use crate::{BlockReason, Decision};

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct DecisionContext {
    security_invariant_violation: bool,
    session_restriction: bool,
    explicit_block: bool,
    explicit_allow: bool,
    classification_required: bool,
}

impl DecisionContext {
    #[must_use]
    pub const fn classification_required() -> Self {
        Self {
            classification_required: true,
            ..Self::new()
        }
    }

    #[must_use]
    pub const fn with_security_invariant_violation(mut self) -> Self {
        self.security_invariant_violation = true;
        self
    }

    #[must_use]
    pub const fn with_session_restriction(mut self) -> Self {
        self.session_restriction = true;
        self
    }

    #[must_use]
    pub const fn with_explicit_block(mut self) -> Self {
        self.explicit_block = true;
        self
    }

    #[must_use]
    pub const fn with_explicit_allow(mut self) -> Self {
        self.explicit_allow = true;
        self
    }

    const fn new() -> Self {
        Self {
            security_invariant_violation: false,
            session_restriction: false,
            explicit_block: false,
            explicit_allow: false,
            classification_required: false,
        }
    }
}

#[derive(Debug, Clone, Copy, Default)]
pub struct PolicyEngine;

impl PolicyEngine {
    #[must_use]
    pub const fn decide(self, context: &DecisionContext) -> Decision {
        if context.security_invariant_violation {
            return Decision::Block(BlockReason::SecurityInvariant);
        }

        if context.session_restriction {
            return Decision::Block(BlockReason::SessionRestriction);
        }

        if context.explicit_block {
            return Decision::Block(BlockReason::ExplicitBlock);
        }

        if context.explicit_allow {
            return Decision::Allow;
        }

        if context.classification_required {
            return Decision::Classify;
        }

        Decision::Block(BlockReason::Unknown)
    }
}
