use focus_core::ProfileId;
use focus_protocol::{
    ClientKind, EmergencyCodePayload, EmergencyRequestPayload, Request, RequestEnvelope, RequestId,
    StartSessionRequest,
};

#[test]
fn start_session_payload_round_trips_without_delimiter_confusion() {
    let envelope = RequestEnvelope::new(
        RequestId(1001),
        ClientKind::Desktop,
        Request::StartSession(StartSessionRequest {
            profile_id: ProfileId(7),
            minimum_duration_secs: 3_600,
            objective: "Deep work | maths, physics + Rust".to_owned(),
        }),
    );

    let encoded = envelope.clone().encode();
    let decoded = RequestEnvelope::decode(&encoded).unwrap();

    assert_eq!(decoded, envelope);
}

#[test]
fn emergency_reason_payload_round_trips_unicode_and_protocol_delimiters() {
    let envelope = RequestEnvelope::new(
        RequestId(1002),
        ClientKind::Desktop,
        Request::RequestEmergencyUnlock(EmergencyRequestPayload {
            reason: "Urgence réelle | départ immédiat: жду 🚑".to_owned(),
        }),
    );

    let encoded = envelope.clone().encode();
    let decoded = RequestEnvelope::decode(&encoded).unwrap();

    assert_eq!(decoded, envelope);
}

#[test]
fn emergency_code_payload_round_trips_as_typed_data() {
    let envelope = RequestEnvelope::new(
        RequestId(1003),
        ClientKind::Desktop,
        Request::SubmitEmergencyCode(EmergencyCodePayload {
            code: "FG7K-P29M-4TXQ-R8VN".to_owned(),
        }),
    );

    let encoded = envelope.clone().encode();
    let decoded = RequestEnvelope::decode(&encoded).unwrap();

    assert_eq!(decoded, envelope);
}
