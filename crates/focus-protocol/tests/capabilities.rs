use focus_core::ProfileId;
use focus_protocol::{
    ClientKind, PROTOCOL_VERSION, ProtocolState, Request, RequestEnvelope, RequestId, Response,
    ResponseEnvelope, StartSessionRequest,
};

fn start_session() -> Request {
    Request::StartSession(StartSessionRequest {
        profile_id: ProfileId(7),
        minimum_duration_secs: 3_600,
        objective: "Deep work".to_owned(),
    })
}

#[test]
fn browser_bridge_cannot_start_sessions() {
    let request = RequestEnvelope::new(RequestId(1), ClientKind::BrowserBridge, start_session());

    assert!(!request.is_authorized());
}

#[test]
fn desktop_can_start_sessions() {
    let request = RequestEnvelope::new(RequestId(2), ClientKind::Desktop, start_session());

    assert!(request.is_authorized());
}

#[test]
fn cli_cannot_start_sessions() {
    let request = RequestEnvelope::new(RequestId(3), ClientKind::Cli, start_session());

    assert!(!request.is_authorized());
}

#[test]
fn envelope_uses_current_protocol_version() {
    let request = RequestEnvelope::new(RequestId(4), ClientKind::Cli, Request::GetStatus);

    assert_eq!(request.protocol_version(), PROTOCOL_VERSION);
}

#[test]
fn request_envelope_round_trips_over_wire() {
    let request = RequestEnvelope::new(RequestId(5), ClientKind::Cli, Request::VpnUp { id: 42 });

    let decoded = RequestEnvelope::decode(&request.encode()).unwrap();

    assert_eq!(decoded, request);
    assert!(decoded.is_compatible());
}

#[test]
fn response_envelope_round_trips_over_wire() {
    let response = ResponseEnvelope::new(
        RequestId(5),
        Response::Status(ProtocolState::ProtectionFailure),
    );

    let decoded = ResponseEnvelope::decode(&response.encode()).unwrap();

    assert_eq!(decoded, response);
    assert!(decoded.is_compatible());
}
