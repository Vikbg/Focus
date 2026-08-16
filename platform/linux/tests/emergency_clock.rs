use focus_core::BootId;
use focus_linux::{parse_boot_id, parse_uptime_seconds, sample_emergency_clock};

#[test]
fn parses_linux_boot_id_uuid() {
    assert_eq!(
        parse_boot_id("550e8400-e29b-41d4-a716-446655440000\n").unwrap(),
        BootId(0x550e_8400_e29b_41d4_a716_4466_5544_0000)
    );
}

#[test]
fn parses_uptime_conservatively_to_whole_seconds() {
    assert_eq!(parse_uptime_seconds("12345.67 98765.43\n").unwrap(), 12_345);
}

#[test]
fn rejects_invalid_clock_sources() {
    assert!(parse_boot_id("not-a-uuid").is_err());
    assert!(parse_uptime_seconds("not-a-number").is_err());
}

#[test]
fn real_linux_clock_sample_has_nonzero_boot_id_and_wall_time() {
    let sample = sample_emergency_clock().unwrap();

    assert_ne!(sample.boot_id(), BootId(0));
    assert!(sample.unix_seconds() > 0);
}
