use focus_linux::{FanotifyPermissionSource, NixFanotifyPermissionSource};
use nix::sys::fanotify::{EventFFlags, InitFlags, MarkFlags, MaskFlags};

fn assert_permission_source<T: FanotifyPermissionSource>() {}

#[test]
fn nix_source_implements_permission_transport_contract() {
    assert_permission_source::<NixFanotifyPermissionSource>();
}

#[test]
fn nix_source_uses_fail_closed_permission_configuration() {
    assert_eq!(
        NixFanotifyPermissionSource::init_flags(),
        InitFlags::FAN_CLASS_CONTENT | InitFlags::FAN_CLOEXEC | InitFlags::FAN_NONBLOCK
    );
    assert_eq!(
        NixFanotifyPermissionSource::event_flags(),
        EventFFlags::O_RDONLY | EventFFlags::O_CLOEXEC | EventFFlags::O_LARGEFILE
    );
    assert_eq!(
        NixFanotifyPermissionSource::mount_mark_flags(),
        MarkFlags::FAN_MARK_ADD | MarkFlags::FAN_MARK_MOUNT
    );
    assert_eq!(
        NixFanotifyPermissionSource::event_mask(),
        MaskFlags::FAN_OPEN_EXEC_PERM
    );
}
