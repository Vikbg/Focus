use std::{error::Error, fmt};

use crate::{
    cgroup_process_class::FocusCgroupClass,
    ebpf_egress_policy::Ipv4EgressRule,
};

/// Complete exact egress policy for the fixed Focus cgroup classes.
///
/// The blocked class intentionally has no configurable allow rules and is therefore always
/// structurally default-deny.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CgroupEgressPolicy {
    browser: Vec<Ipv4EgressRule>,
    development: Vec<Ipv4EgressRule>,
    vpn: Vec<Ipv4EgressRule>,
    system: Vec<Ipv4EgressRule>,
}

impl CgroupEgressPolicy {
    /// Creates the exact allow rules for each allow-capable Focus cgroup class.
    #[must_use]
    pub const fn new(
        browser: Vec<Ipv4EgressRule>,
        development: Vec<Ipv4EgressRule>,
        vpn: Vec<Ipv4EgressRule>,
        system: Vec<Ipv4EgressRule>,
    ) -> Self {
        Self {
            browser,
            development,
            vpn,
            system,
        }
    }

    /// Returns the exact rule set for one fixed Focus cgroup class.
    ///
    /// [`FocusCgroupClass::Blocked`] always returns an empty slice so callers cannot accidentally
    /// make the blocked class allow-capable through this policy surface.
    #[must_use]
    pub fn rules_for(&self, class: FocusCgroupClass) -> &[Ipv4EgressRule] {
        match class {
            FocusCgroupClass::Browser => &self.browser,
            FocusCgroupClass::Development => &self.development,
            FocusCgroupClass::Vpn => &self.vpn,
            FocusCgroupClass::System => &self.system,
            FocusCgroupClass::Blocked => &[],
        }
    }
}

/// Error returned while replacing, attaching, or verifying one class eBPF egress program.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EgressProgramError {
    RuleReplacementFailed,
    AttachFailed,
    VerificationFailed,
}

impl fmt::Display for EgressProgramError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::RuleReplacementFailed => {
                formatter.write_str("eBPF class egress rules could not be replaced")
            }
            Self::AttachFailed => formatter.write_str("eBPF class egress program attach failed"),
            Self::VerificationFailed => {
                formatter.write_str("eBPF class egress program verification failed")
            }
        }
    }
}

impl Error for EgressProgramError {}

/// Narrow authority over one eBPF egress program attached to each fixed Focus cgroup class.
pub trait EgressClassProgramControl {
    /// Replaces the complete exact allow-rule set for one class.
    ///
    /// # Errors
    ///
    /// Returns an error when the class map cannot be replaced safely.
    fn replace_rules(
        &mut self,
        class: FocusCgroupClass,
        rules: &[Ipv4EgressRule],
    ) -> Result<(), EgressProgramError>;

    /// Attaches the egress program to one fixed Focus cgroup class.
    ///
    /// # Errors
    ///
    /// Returns an error when the program cannot be attached safely.
    fn attach(&mut self, class: FocusCgroupClass) -> Result<(), EgressProgramError>;

    /// Verifies the attachment and exact rules for one fixed Focus cgroup class.
    ///
    /// # Errors
    ///
    /// Returns an error when attachment or rule state cannot be verified exactly.
    fn verify(
        &mut self,
        class: FocusCgroupClass,
        rules: &[Ipv4EgressRule],
    ) -> Result<(), EgressProgramError>;
}

/// Replaces, attaches, and verifies eBPF egress enforcement for every fixed Focus cgroup class.
///
/// Classes are armed in a stable order and the operation stops on the first failure. This avoids
/// claiming success for later classes after an earlier class could not be protected.
///
/// # Errors
///
/// Returns the first rule replacement, attachment, or verification error reported by the control.
pub fn arm_cgroup_egress_programs<C: EgressClassProgramControl>(
    control: &mut C,
    policy: &CgroupEgressPolicy,
) -> Result<(), EgressProgramError> {
    for class in [
        FocusCgroupClass::Browser,
        FocusCgroupClass::Development,
        FocusCgroupClass::Vpn,
        FocusCgroupClass::System,
        FocusCgroupClass::Blocked,
    ] {
        let rules = policy.rules_for(class);
        control.replace_rules(class, rules)?;
        control.attach(class)?;
        control.verify(class, rules)?;
    }

    Ok(())
}
