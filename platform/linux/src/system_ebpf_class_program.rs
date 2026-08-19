use std::{
    collections::BTreeSet,
    fs::{self, File},
    os::unix::fs::MetadataExt,
    path::{Path, PathBuf},
};

use aya::{
    Ebpf, EbpfLoader,
    maps::HashMap as AyaHashMap,
    programs::{
        CgroupAttachMode, CgroupSkb, CgroupSkbAttachType, links::LinkType, loaded_links,
    },
};

use crate::{
    EgressClassProgramControl, EgressProgramError, FOCUS_CGROUP_ROOT, FocusCgroupClass,
    Ipv4EgressRule,
};

/// Fixed production path for the Focus cgroup eBPF object installed by the package.
pub const FOCUS_EBPF_OBJECT_PATH: &str = "/usr/lib/focus/focus-egress-ebpf.o";

const FOCUS_EBPF_PROGRAM_NAME: &str = "focus_egress";
const FOCUS_EBPF_ALLOWED_MAP_NAME: &str = "ALLOWED_IPV4_ENDPOINTS";
const ALLOW_VALUE: u8 = 1;
const WRITEABLE_BY_NON_OWNER: u32 = 0o022;

struct LoadedClassProgram {
    ebpf: Ebpf,
    attached_program_id: Option<u32>,
}

impl LoadedClassProgram {
    fn new(ebpf: Ebpf) -> Self {
        Self {
            ebpf,
            attached_program_id: None,
        }
    }
}

/// Production eBPF authority limited to the five fixed Focus cgroup classes.
///
/// Each class owns a distinct [`Ebpf`] instance. This is deliberate: the eBPF object contains one
/// allow map, so sharing a single object instance across classes would also share policy state.
#[derive(Default)]
pub struct SystemEgressClassProgramControl {
    browser: Option<LoadedClassProgram>,
    development: Option<LoadedClassProgram>,
    vpn: Option<LoadedClassProgram>,
    system: Option<LoadedClassProgram>,
    blocked: Option<LoadedClassProgram>,
}

impl SystemEgressClassProgramControl {
    /// Returns the immutable production eBPF object path.
    #[must_use]
    pub fn object_path(&self) -> &'static Path {
        Path::new(FOCUS_EBPF_OBJECT_PATH)
    }

    /// Returns the fixed production cgroup path for one typed Focus class.
    #[must_use]
    pub fn class_path(&self, class: FocusCgroupClass) -> PathBuf {
        Path::new(FOCUS_CGROUP_ROOT).join(class.as_str())
    }

    fn slot_mut(&mut self, class: FocusCgroupClass) -> &mut Option<LoadedClassProgram> {
        match class {
            FocusCgroupClass::Browser => &mut self.browser,
            FocusCgroupClass::Development => &mut self.development,
            FocusCgroupClass::Vpn => &mut self.vpn,
            FocusCgroupClass::System => &mut self.system,
            FocusCgroupClass::Blocked => &mut self.blocked,
        }
    }

    fn ensure_loaded(
        &mut self,
        class: FocusCgroupClass,
        error: EgressProgramError,
    ) -> Result<&mut LoadedClassProgram, EgressProgramError> {
        let slot = self.slot_mut(class);
        if slot.is_none() {
            let ebpf = EbpfLoader::new()
                .load_file(FOCUS_EBPF_OBJECT_PATH)
                .map_err(|_| error)?;
            *slot = Some(LoadedClassProgram::new(ebpf));
        }
        slot.as_mut().ok_or(error)
    }

    fn open_safe_class_cgroup(class: FocusCgroupClass) -> Result<File, EgressProgramError> {
        let path = Path::new(FOCUS_CGROUP_ROOT).join(class.as_str());
        let metadata = fs::symlink_metadata(&path).map_err(|_| EgressProgramError::AttachFailed)?;
        let mode = metadata.mode() & 0o777;
        if !metadata.file_type().is_dir()
            || metadata.uid() != 0
            || mode & WRITEABLE_BY_NON_OWNER != 0
        {
            return Err(EgressProgramError::AttachFailed);
        }
        File::open(path).map_err(|_| EgressProgramError::AttachFailed)
    }

    fn expected_keys(rules: &[Ipv4EgressRule]) -> BTreeSet<u64> {
        rules.iter().copied().map(Ipv4EgressRule::map_key).collect()
    }

    fn replace_loaded_rules(
        loaded: &mut LoadedClassProgram,
        rules: &[Ipv4EgressRule],
    ) -> Result<(), EgressProgramError> {
        let map = loaded
            .ebpf
            .map_mut(FOCUS_EBPF_ALLOWED_MAP_NAME)
            .ok_or(EgressProgramError::RuleReplacementFailed)?;
        let mut map = AyaHashMap::<_, u64, u8>::try_from(map)
            .map_err(|_| EgressProgramError::RuleReplacementFailed)?;

        let existing = map
            .keys()
            .collect::<Result<Vec<_>, _>>()
            .map_err(|_| EgressProgramError::RuleReplacementFailed)?;
        for key in existing {
            map.remove(&key)
                .map_err(|_| EgressProgramError::RuleReplacementFailed)?;
        }

        let expected = Self::expected_keys(rules);
        for key in &expected {
            map.insert(key, ALLOW_VALUE, 0)
                .map_err(|_| EgressProgramError::RuleReplacementFailed)?;
        }

        Self::verify_loaded_rules(&loaded.ebpf, rules)
            .map_err(|_| EgressProgramError::RuleReplacementFailed)
    }

    fn verify_loaded_rules(
        ebpf: &Ebpf,
        rules: &[Ipv4EgressRule],
    ) -> Result<(), EgressProgramError> {
        let map = ebpf
            .map(FOCUS_EBPF_ALLOWED_MAP_NAME)
            .ok_or(EgressProgramError::VerificationFailed)?;
        let map = AyaHashMap::<_, u64, u8>::try_from(map)
            .map_err(|_| EgressProgramError::VerificationFailed)?;
        let observed = map
            .keys()
            .collect::<Result<BTreeSet<_>, _>>()
            .map_err(|_| EgressProgramError::VerificationFailed)?;
        let expected = Self::expected_keys(rules);
        if observed != expected {
            return Err(EgressProgramError::VerificationFailed);
        }
        for key in expected {
            if map
                .get(&key, 0)
                .map_err(|_| EgressProgramError::VerificationFailed)?
                != ALLOW_VALUE
            {
                return Err(EgressProgramError::VerificationFailed);
            }
        }
        Ok(())
    }

    fn verify_loaded_cgroup_link(expected_program_id: u32) -> Result<(), EgressProgramError> {
        for link in loaded_links() {
            let info = link.map_err(|_| EgressProgramError::VerificationFailed)?;
            let link_type = info
                .link_type()
                .map_err(|_| EgressProgramError::VerificationFailed)?;
            if link_type == LinkType::Cgroup && info.program_id() == expected_program_id {
                return Ok(());
            }
        }
        Err(EgressProgramError::VerificationFailed)
    }
}

impl EgressClassProgramControl for SystemEgressClassProgramControl {
    fn replace_rules(
        &mut self,
        class: FocusCgroupClass,
        rules: &[Ipv4EgressRule],
    ) -> Result<(), EgressProgramError> {
        let loaded = self.ensure_loaded(class, EgressProgramError::RuleReplacementFailed)?;
        Self::replace_loaded_rules(loaded, rules)
    }

    fn attach(&mut self, class: FocusCgroupClass) -> Result<(), EgressProgramError> {
        let cgroup = Self::open_safe_class_cgroup(class)?;
        let loaded = self.ensure_loaded(class, EgressProgramError::AttachFailed)?;
        if loaded.attached_program_id.is_some() {
            return Ok(());
        }

        let program = loaded
            .ebpf
            .program_mut(FOCUS_EBPF_PROGRAM_NAME)
            .ok_or(EgressProgramError::AttachFailed)?;
        let program: &mut CgroupSkb = program
            .try_into()
            .map_err(|_| EgressProgramError::AttachFailed)?;
        program
            .load()
            .map_err(|_| EgressProgramError::AttachFailed)?;
        program
            .attach(
                cgroup,
                CgroupSkbAttachType::Egress,
                CgroupAttachMode::Single,
            )
            .map_err(|_| EgressProgramError::AttachFailed)?;
        let program_id = program
            .info()
            .map_err(|_| EgressProgramError::AttachFailed)?
            .id();
        loaded.attached_program_id = Some(program_id);
        Ok(())
    }

    fn verify(
        &mut self,
        class: FocusCgroupClass,
        rules: &[Ipv4EgressRule],
    ) -> Result<(), EgressProgramError> {
        let loaded = self.ensure_loaded(class, EgressProgramError::VerificationFailed)?;
        let expected_program_id = loaded
            .attached_program_id
            .ok_or(EgressProgramError::VerificationFailed)?;
        let program = loaded
            .ebpf
            .program(FOCUS_EBPF_PROGRAM_NAME)
            .ok_or(EgressProgramError::VerificationFailed)?;
        let program: &CgroupSkb = program
            .try_into()
            .map_err(|_| EgressProgramError::VerificationFailed)?;
        if program
            .info()
            .map_err(|_| EgressProgramError::VerificationFailed)?
            .id()
            != expected_program_id
        {
            return Err(EgressProgramError::VerificationFailed);
        }
        Self::verify_loaded_cgroup_link(expected_program_id)?;
        Self::verify_loaded_rules(&loaded.ebpf, rules)
    }
}
