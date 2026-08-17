use std::{collections::BTreeMap, io, path::PathBuf};

use focus_linux::{
    ExecutionContextClassifier, LinuxExecutionFactSource, LinuxProcessControl,
    LinuxProcessInventorySource, ProcessCloseError, ProcessControl, ProcessHandleOps,
};

#[derive(Debug)]
struct Source {
    uids: BTreeMap<u32, u32>,
}

impl Source {
    fn new(entries: impl IntoIterator<Item = (u32, u32)>) -> Self {
        Self {
            uids: entries.into_iter().collect(),
        }
    }
}

impl LinuxExecutionFactSource for Source {
    fn executable_path(&self, _pid: u32) -> io::Result<PathBuf> {
        Err(io::Error::other("unused in inventory scope test"))
    }

    fn cmdline_bytes(&self, _pid: u32) -> io::Result<Vec<u8>> {
        Err(io::Error::other("unused in inventory scope test"))
    }

    fn cgroup_text(&self, _pid: u32) -> io::Result<String> {
        Err(io::Error::other("unused in inventory scope test"))
    }

    fn status_text(&self, pid: u32) -> io::Result<String> {
        let uid = self
            .uids
            .get(&pid)
            .copied()
            .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "process disappeared"))?;
        Ok(format!(
            "Name:\ttest\nUid:\t{uid}\t{uid}\t{uid}\t{uid}\nPPid:\t1\n"
        ))
    }

    fn stat_text(&self, _pid: u32) -> io::Result<String> {
        Err(io::Error::other("unused in inventory scope test"))
    }

    fn flatpak_info(&self, _pid: u32) -> io::Result<Option<String>> {
        Err(io::Error::other("unused in inventory scope test"))
    }

    fn security_label(&self, _pid: u32) -> io::Result<Option<String>> {
        Err(io::Error::other("unused in inventory scope test"))
    }
}

impl LinuxProcessInventorySource for Source {
    fn process_ids(&self) -> io::Result<Vec<u32>> {
        Ok(self.uids.keys().copied().collect())
    }
}

#[derive(Debug, Default)]
struct Ops;

impl ProcessHandleOps for Ops {
    type Handle = u32;

    fn open_process(&mut self, pid: u32) -> io::Result<Self::Handle> {
        Ok(pid)
    }

    fn terminate_process(&mut self, _handle: &Self::Handle) -> io::Result<()> {
        Ok(())
    }
}

#[test]
fn user_scoped_inventory_excludes_root_and_other_users() {
    let source = Source::new([(10, 0), (100, 1000), (101, 1001), (102, 1000)]);
    let control = LinuxProcessControl::for_uid(
        source,
        Ops,
        ExecutionContextClassifier::new(Vec::new()),
        1000,
    );

    assert_eq!(
        ProcessControl::process_ids(&control).unwrap(),
        vec![100, 102]
    );
}

#[test]
fn unreadable_uid_fails_closed_in_scoped_inventory() {
    #[derive(Debug)]
    struct BrokenSource;

    impl LinuxExecutionFactSource for BrokenSource {
        fn executable_path(&self, _pid: u32) -> io::Result<PathBuf> {
            unreachable!()
        }
        fn cmdline_bytes(&self, _pid: u32) -> io::Result<Vec<u8>> {
            unreachable!()
        }
        fn cgroup_text(&self, _pid: u32) -> io::Result<String> {
            unreachable!()
        }
        fn status_text(&self, _pid: u32) -> io::Result<String> {
            Err(io::Error::other("status unavailable"))
        }
        fn stat_text(&self, _pid: u32) -> io::Result<String> {
            unreachable!()
        }
        fn flatpak_info(&self, _pid: u32) -> io::Result<Option<String>> {
            unreachable!()
        }
        fn security_label(&self, _pid: u32) -> io::Result<Option<String>> {
            unreachable!()
        }
    }

    impl LinuxProcessInventorySource for BrokenSource {
        fn process_ids(&self) -> io::Result<Vec<u32>> {
            Ok(vec![200])
        }
    }

    let control = LinuxProcessControl::for_uid(
        BrokenSource,
        Ops,
        ExecutionContextClassifier::new(Vec::new()),
        1000,
    );

    assert_eq!(
        control.process_ids(),
        Err(ProcessCloseError::InventoryFailed)
    );
}
