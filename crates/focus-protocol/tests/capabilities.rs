use focus_protocol::{ClientKind, Request, RequestEnvelope, RequestId, PROTOCOL_VERSION};

#[test]
fn browser_bridge_cannot_start_sessions() {
    let request = RequestEnvelope::new(
        RequestId(1),
        ClientKind::BrowserBridge,
        Request::StartSession,
    );

    assert!(!request.is_authorized());
}

#[test]
fn desktop_can_start_sessions() {
    let request = RequestEnvelope::new(RequestId(2), ClientKind::Desktop, Request::StartSession);

    assert!(request.is_authorized());
}

#[test]
fn envelope_uses_current_protocol_version() {
    let request = RequestEnvelope::new(RequestId(3), ClientKind::Cli, Request::GetStatus);

    assert_eq!(request.protocol_version(), PROTOCOL_VERSION);
}
