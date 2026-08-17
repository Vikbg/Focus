use std::{io, os::fd::AsRawFd};

use focus_linux::{ProcessHandleOps, RustixPidfdOps};

#[test]
fn rustix_pidfd_ops_opens_a_stable_handle_for_current_process() {
    let mut ops = RustixPidfdOps;

    let handle = ops.open_process(std::process::id()).unwrap();

    assert!(handle.as_raw_fd() >= 0);
}

#[test]
fn rustix_pidfd_ops_rejects_zero_pid_before_opening_a_handle() {
    let mut ops = RustixPidfdOps;

    let error = ops.open_process(0).unwrap_err();

    assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
}

#[test]
fn rustix_pidfd_ops_rejects_values_outside_signed_pid_range() {
    let mut ops = RustixPidfdOps;

    let error = ops.open_process(u32::MAX).unwrap_err();

    assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
}
