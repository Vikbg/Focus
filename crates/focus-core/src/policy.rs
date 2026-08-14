//! Platform-independent policy evaluation.

use crate::{BlockReason, Decision};

const SECURITY_INVARIANT_VIOLATION: u8 = 1 << 0;
const SESSION_RESTRICTION: u8 = 1 << 1;
const EXPLICIT_BLOCK: u8 = 1 << 2;
const EXPLICIT_ALLOW: u8 = 1 << 3;
const CLASSIFICATION_REQUIRED: u8 = 1 << 4;

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct DecisionContext {
    facts: u8,
}

impl DecisionContext {
    #[must_use]
    pub const fn classification_required() -> Self {
        Self {
            facts: CLASSIFICATION_REQUIRED,
        }
    }

    #[must_use]
    pub const fn with_security_invariant_violation(mut self) -> Self {
        self.facts |= SECURITY_INVARIANT_VIOLATION;
        self
    }

    #[must_use]
    pub const fn with_session_restriction(mut self) -> Self {
        self.facts |= SESSION_RESTRICTION;
        self
    }

    #[must_use]
    pub const fn with_explicit_block(mut self) -> Self {
        self.facts |= EXPLICIT_BLOCK;
        self
    }

    #[must_use]
    pub const fn with_explicit_allow(mut self) -> Self {
        self.facts |= EXPLICIT_ALLOW;
        self
    }

    const fn contains(self, fact: u8) -> bool {
        self.facts & fact != 0
    }
}

#[derive(Debug, Clone, Copy, Default)]
pub struct PolicyEngine;

impl PolicyEngine {
    #[must_use]
    pub const fn decide(self, context: &DecisionContext) -> Decision {
        if context.contains(SECURITY_INVARIANT_VIOLATION) {
            return Decision::Block(BlockReason::SecurityInvariant);
        }

        if context.contains(SESSION_RESTRICTION) {
            return Decision::Block(BlockReason::SessionRestriction);
        }

        if context.contains(EXPLICIT_BLOCK) {
            return Decision::Block(BlockReason::ExplicitBlock);
        }

        if context.contains(EXPLICIT_ALLOW) {
            return Decision::Allow;
        }

        if context.contains(CLASSIFICATION_REQUIRED) {
            return Decision::Classify;
        }

        Decision::Block(BlockReason::Unknown)
    }
}
