//! Platform-independent policy evaluation.

use crate::{BlockReason, Decision};

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct DecisionContext {
    classification_required: bool,
}

impl DecisionContext {
    #[must_use]
    pub const fn classification_required() -> Self {
        Self {
            classification_required: true,
        }
    }
}

#[derive(Debug, Clone, Copy, Default)]
pub struct PolicyEngine;

impl PolicyEngine {
    #[must_use]
    pub const fn decide(self, context: &DecisionContext) -> Decision {
        if context.classification_required {
            Decision::Classify
        } else {
            Decision::Block(BlockReason::Unknown)
        }
    }
}
