//! Policy decision results.

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BlockReason {
    SecurityInvariant,
    SessionRestriction,
    ExplicitBlock,
    Unknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Decision {
    Allow,
    Block(BlockReason),
    Classify,
    FailClosed(BlockReason),
}
