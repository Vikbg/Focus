//! Focus profile identity, versioning, and immutable session snapshots.

use sha2::{Digest, Sha256};

use crate::{
    BlockReason, Decision, ExecutableMatcher, PackageIdentity, PackageKind, PolicySet,
    ProcessEnforcementPlan, ProcessPolicy, ProcessRule,
};

const LEGACY_SESSION_POLICY_SCHEMA_VERSION: u32 = 1;
/// Current canonical encoding version for frozen session policy snapshots.
pub const SESSION_POLICY_SCHEMA_VERSION: u32 = 2;

const PROCESS_POLICY_NONE: u8 = 0;
const PROCESS_POLICY_STRICT: u8 = 1;
const MATCHER_DIGEST: u8 = 0;
const MATCHER_FILESYSTEM: u8 = 1;
const MATCHER_PACKAGE: u8 = 2;
const MATCHER_CANONICAL_PATH: u8 = 3;
const MAX_PROCESS_RULES: usize = 4_096;
const MAX_WORKSPACE_ROOTS: usize = 1_024;
const MAX_POLICY_STRING_BYTES: usize = 16 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ProfileId(pub u128);

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct PolicyVersion(pub u64);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionPolicySnapshotError {
    UnsupportedSchemaVersion(u32),
    MalformedPolicy,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Profile {
    id: ProfileId,
    version: PolicyVersion,
    policy: PolicySet,
    process_policy: Option<ProcessPolicy>,
}

impl Profile {
    #[must_use]
    pub const fn new(id: ProfileId, version: PolicyVersion, policy: PolicySet) -> Self {
        Self {
            id,
            version,
            policy,
            process_policy: None,
        }
    }

    #[must_use]
    pub const fn version(&self) -> PolicyVersion {
        self.version
    }

    #[must_use]
    pub const fn policy(&self) -> PolicySet {
        self.policy
    }

    /// Adds the process-policy inputs that must remain immutable for a session.
    #[must_use]
    pub fn with_process_policy(mut self, process_policy: ProcessPolicy) -> Self {
        self.process_policy = Some(process_policy);
        self
    }

    #[must_use]
    pub fn snapshot(&self) -> SessionPolicySnapshot {
        SessionPolicySnapshot {
            profile_id: self.id,
            profile_version: self.version,
            schema_version: SESSION_POLICY_SCHEMA_VERSION,
            policy: self.policy,
            process_policy: self.process_policy.clone(),
        }
    }

    #[must_use]
    pub const fn with_policy(mut self, version: PolicyVersion, policy: PolicySet) -> Self {
        self.version = version;
        self.policy = policy;
        self
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionPolicySnapshot {
    profile_id: ProfileId,
    profile_version: PolicyVersion,
    schema_version: u32,
    policy: PolicySet,
    process_policy: Option<ProcessPolicy>,
}

impl SessionPolicySnapshot {
    #[must_use]
    pub const fn profile_id(&self) -> ProfileId {
        self.profile_id
    }

    #[must_use]
    pub const fn profile_version(&self) -> PolicyVersion {
        self.profile_version
    }

    #[must_use]
    pub const fn policy(&self) -> PolicySet {
        self.policy
    }

    #[must_use]
    pub const fn schema_version(&self) -> u32 {
        self.schema_version
    }

    /// Returns a process enforcement plan reconstructed only from frozen snapshot data.
    #[must_use]
    pub fn process_enforcement_plan(&self) -> Option<ProcessEnforcementPlan> {
        self.process_policy
            .as_ref()
            .map(|policy| policy.compile(self.policy_sha256()))
    }

    /// Returns the deterministic payload persisted for this policy snapshot.
    #[must_use]
    pub fn policy_payload(&self) -> Vec<u8> {
        if self.schema_version == LEGACY_SESSION_POLICY_SCHEMA_VERSION {
            return vec![encode_decision(self.policy.default_decision())];
        }

        let mut payload = Vec::new();
        payload.push(encode_decision(self.policy.default_decision()));
        match &self.process_policy {
            None => payload.push(PROCESS_POLICY_NONE),
            Some(process_policy) => {
                payload.push(PROCESS_POLICY_STRICT);
                encode_process_policy(process_policy, &mut payload);
            }
        }
        payload
    }

    /// Returns a digest covering the profile identity, policy version, schema, and payload.
    #[must_use]
    pub fn policy_sha256(&self) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(self.profile_id.0.to_be_bytes());
        hasher.update(self.profile_version.0.to_be_bytes());
        hasher.update(self.schema_version.to_be_bytes());
        hasher.update(self.policy_payload());
        let digest = hasher.finalize();
        let mut bytes = [0_u8; 32];
        bytes.copy_from_slice(&digest);
        bytes
    }

    /// Restores one canonical frozen policy snapshot from protected storage.
    ///
    /// Schema v1 snapshots remain readable for recovery but contain no process policy. A caller
    /// that requires the P2 process guard must therefore fail closed when
    /// `process_enforcement_plan` returns `None`.
    ///
    /// # Errors
    ///
    /// Returns an error for an unsupported schema version or malformed policy payload.
    pub fn restore(
        profile_id: ProfileId,
        profile_version: PolicyVersion,
        schema_version: u32,
        payload: &[u8],
    ) -> Result<Self, SessionPolicySnapshotError> {
        match schema_version {
            LEGACY_SESSION_POLICY_SCHEMA_VERSION => {
                let [decision] = payload else {
                    return Err(SessionPolicySnapshotError::MalformedPolicy);
                };
                Ok(Self {
                    profile_id,
                    profile_version,
                    schema_version,
                    policy: PolicySet::new(decode_decision(*decision)?),
                    process_policy: None,
                })
            }
            SESSION_POLICY_SCHEMA_VERSION => restore_current(profile_id, profile_version, payload),
            other => Err(SessionPolicySnapshotError::UnsupportedSchemaVersion(other)),
        }
    }
}

fn restore_current(
    profile_id: ProfileId,
    profile_version: PolicyVersion,
    payload: &[u8],
) -> Result<SessionPolicySnapshot, SessionPolicySnapshotError> {
    let mut cursor = PayloadCursor::new(payload);
    let policy = PolicySet::new(decode_decision(cursor.read_u8()?)?);
    let process_policy = match cursor.read_u8()? {
        PROCESS_POLICY_NONE => None,
        PROCESS_POLICY_STRICT => Some(decode_process_policy(&mut cursor)?),
        _ => return Err(SessionPolicySnapshotError::MalformedPolicy),
    };
    if !cursor.is_finished() {
        return Err(SessionPolicySnapshotError::MalformedPolicy);
    }

    Ok(SessionPolicySnapshot {
        profile_id,
        profile_version,
        schema_version: SESSION_POLICY_SCHEMA_VERSION,
        policy,
        process_policy,
    })
}

fn encode_process_policy(policy: &ProcessPolicy, payload: &mut Vec<u8>) {
    push_u32(payload, policy.rules().len());
    for rule in policy.rules() {
        encode_matcher(rule.matcher(), payload);
    }
    push_u32(payload, policy.trusted_workspace_roots().len());
    for root in policy.trusted_workspace_roots() {
        push_string(payload, root);
    }
}

fn decode_process_policy(
    cursor: &mut PayloadCursor<'_>,
) -> Result<ProcessPolicy, SessionPolicySnapshotError> {
    let rule_count = cursor.read_count(MAX_PROCESS_RULES)?;
    let mut rules = Vec::with_capacity(rule_count);
    for _ in 0..rule_count {
        rules.push(ProcessRule::block(decode_matcher(cursor)?));
    }

    let workspace_count = cursor.read_count(MAX_WORKSPACE_ROOTS)?;
    let mut roots = Vec::with_capacity(workspace_count);
    for _ in 0..workspace_count {
        roots.push(cursor.read_string()?);
    }

    Ok(ProcessPolicy::strict(rules, roots))
}

fn encode_matcher(matcher: &ExecutableMatcher, payload: &mut Vec<u8>) {
    match matcher {
        ExecutableMatcher::Digest(digest) => {
            payload.push(MATCHER_DIGEST);
            payload.extend_from_slice(digest);
        }
        ExecutableMatcher::Filesystem { device, inode } => {
            payload.push(MATCHER_FILESYSTEM);
            payload.extend_from_slice(&device.to_be_bytes());
            payload.extend_from_slice(&inode.to_be_bytes());
        }
        ExecutableMatcher::Package(package) => {
            payload.push(MATCHER_PACKAGE);
            payload.push(encode_package_kind(package.kind()));
            push_string(payload, package.id());
        }
        ExecutableMatcher::CanonicalPath(path) => {
            payload.push(MATCHER_CANONICAL_PATH);
            push_string(payload, path);
        }
    }
}

fn decode_matcher(
    cursor: &mut PayloadCursor<'_>,
) -> Result<ExecutableMatcher, SessionPolicySnapshotError> {
    match cursor.read_u8()? {
        MATCHER_DIGEST => Ok(ExecutableMatcher::Digest(cursor.read_array_32()?)),
        MATCHER_FILESYSTEM => Ok(ExecutableMatcher::Filesystem {
            device: cursor.read_u64()?,
            inode: cursor.read_u64()?,
        }),
        MATCHER_PACKAGE => Ok(ExecutableMatcher::Package(PackageIdentity::new(
            decode_package_kind(cursor.read_u8()?)?,
            cursor.read_string()?,
        ))),
        MATCHER_CANONICAL_PATH => Ok(ExecutableMatcher::CanonicalPath(cursor.read_string()?)),
        _ => Err(SessionPolicySnapshotError::MalformedPolicy),
    }
}

fn push_u32(payload: &mut Vec<u8>, value: usize) {
    let value = u32::try_from(value).expect("bounded policy collection length must fit u32");
    payload.extend_from_slice(&value.to_be_bytes());
}

fn push_string(payload: &mut Vec<u8>, value: &str) {
    push_u32(payload, value.len());
    payload.extend_from_slice(value.as_bytes());
}

struct PayloadCursor<'a> {
    payload: &'a [u8],
    offset: usize,
}

impl<'a> PayloadCursor<'a> {
    const fn new(payload: &'a [u8]) -> Self {
        Self { payload, offset: 0 }
    }

    const fn is_finished(&self) -> bool {
        self.offset == self.payload.len()
    }

    fn read_exact(&mut self, length: usize) -> Result<&'a [u8], SessionPolicySnapshotError> {
        let end = self
            .offset
            .checked_add(length)
            .filter(|end| *end <= self.payload.len())
            .ok_or(SessionPolicySnapshotError::MalformedPolicy)?;
        let bytes = &self.payload[self.offset..end];
        self.offset = end;
        Ok(bytes)
    }

    fn read_u8(&mut self) -> Result<u8, SessionPolicySnapshotError> {
        Ok(self.read_exact(1)?[0])
    }

    fn read_u32(&mut self) -> Result<u32, SessionPolicySnapshotError> {
        let bytes: [u8; 4] = self
            .read_exact(4)?
            .try_into()
            .map_err(|_| SessionPolicySnapshotError::MalformedPolicy)?;
        Ok(u32::from_be_bytes(bytes))
    }

    fn read_u64(&mut self) -> Result<u64, SessionPolicySnapshotError> {
        let bytes: [u8; 8] = self
            .read_exact(8)?
            .try_into()
            .map_err(|_| SessionPolicySnapshotError::MalformedPolicy)?;
        Ok(u64::from_be_bytes(bytes))
    }

    fn read_array_32(&mut self) -> Result<[u8; 32], SessionPolicySnapshotError> {
        self.read_exact(32)?
            .try_into()
            .map_err(|_| SessionPolicySnapshotError::MalformedPolicy)
    }

    fn read_count(&mut self, maximum: usize) -> Result<usize, SessionPolicySnapshotError> {
        let count = usize::try_from(self.read_u32()?)
            .map_err(|_| SessionPolicySnapshotError::MalformedPolicy)?;
        if count > maximum {
            return Err(SessionPolicySnapshotError::MalformedPolicy);
        }
        Ok(count)
    }

    fn read_string(&mut self) -> Result<String, SessionPolicySnapshotError> {
        let length = usize::try_from(self.read_u32()?)
            .map_err(|_| SessionPolicySnapshotError::MalformedPolicy)?;
        if length > MAX_POLICY_STRING_BYTES {
            return Err(SessionPolicySnapshotError::MalformedPolicy);
        }
        let bytes = self.read_exact(length)?;
        std::str::from_utf8(bytes)
            .map(str::to_owned)
            .map_err(|_| SessionPolicySnapshotError::MalformedPolicy)
    }
}

const fn encode_package_kind(kind: PackageKind) -> u8 {
    match kind {
        PackageKind::Native => 0,
        PackageKind::Flatpak => 1,
        PackageKind::Snap => 2,
        PackageKind::AppImage => 3,
        PackageKind::Wine => 4,
    }
}

const fn decode_package_kind(value: u8) -> Result<PackageKind, SessionPolicySnapshotError> {
    match value {
        0 => Ok(PackageKind::Native),
        1 => Ok(PackageKind::Flatpak),
        2 => Ok(PackageKind::Snap),
        3 => Ok(PackageKind::AppImage),
        4 => Ok(PackageKind::Wine),
        _ => Err(SessionPolicySnapshotError::MalformedPolicy),
    }
}

const fn encode_decision(decision: Decision) -> u8 {
    match decision {
        Decision::Allow => 0,
        Decision::Block(BlockReason::SecurityInvariant) => 1,
        Decision::Block(BlockReason::SessionRestriction) => 2,
        Decision::Block(BlockReason::ExplicitBlock) => 3,
        Decision::Block(BlockReason::Unknown) => 4,
        Decision::Classify => 5,
        Decision::FailClosed(BlockReason::SecurityInvariant) => 6,
        Decision::FailClosed(BlockReason::SessionRestriction) => 7,
        Decision::FailClosed(BlockReason::ExplicitBlock) => 8,
        Decision::FailClosed(BlockReason::Unknown) => 9,
    }
}

const fn decode_decision(value: u8) -> Result<Decision, SessionPolicySnapshotError> {
    match value {
        0 => Ok(Decision::Allow),
        1 => Ok(Decision::Block(BlockReason::SecurityInvariant)),
        2 => Ok(Decision::Block(BlockReason::SessionRestriction)),
        3 => Ok(Decision::Block(BlockReason::ExplicitBlock)),
        4 => Ok(Decision::Block(BlockReason::Unknown)),
        5 => Ok(Decision::Classify),
        6 => Ok(Decision::FailClosed(BlockReason::SecurityInvariant)),
        7 => Ok(Decision::FailClosed(BlockReason::SessionRestriction)),
        8 => Ok(Decision::FailClosed(BlockReason::ExplicitBlock)),
        9 => Ok(Decision::FailClosed(BlockReason::Unknown)),
        _ => Err(SessionPolicySnapshotError::MalformedPolicy),
    }
}
