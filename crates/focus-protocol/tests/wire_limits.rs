use focus_protocol::{MAX_FRAME_BYTES, RequestEnvelope, WireError};

#[test]
fn oversized_complete_frame_is_rejected_before_parsing_fields() {
    let oversized = "x".repeat(MAX_FRAME_BYTES + 1);

    assert_eq!(
        RequestEnvelope::decode(&oversized),
        Err(WireError::FrameTooLarge)
    );
}

#[test]
fn unsupported_protocol_version_decodes_but_is_not_compatible() {
    let envelope = RequestEnvelope::decode("999|1|cli|status|-").unwrap();

    assert!(!envelope.is_compatible());
}

#[test]
fn malformed_typed_payloads_are_rejected() {
    for frame in [
        "1|1|desktop|start-session|7,3600",
        "1|1|desktop|start-session|x,3600,00",
        "1|1|desktop|start-session|7,x,00",
        "1|1|desktop|start-session|7,3600,0",
        "1|1|desktop|emergency-request|zz",
        "1|1|desktop|emergency-code|0",
    ] {
        assert!(RequestEnvelope::decode(frame).is_err(), "accepted {frame:?}");
    }
}

#[test]
fn arbitrary_utf8_input_never_panics_decoder() {
    let mut state = 0x9e37_79b9_u32;
    for length in 0..512_usize {
        let mut bytes = Vec::with_capacity(length);
        for _ in 0..length {
            state = state.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
            bytes.push((state >> 24) as u8);
        }
        let input = String::from_utf8_lossy(&bytes);
        let result = std::panic::catch_unwind(|| RequestEnvelope::decode(&input));
        assert!(result.is_ok(), "decoder panicked for {input:?}");
    }
}
