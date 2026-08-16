use focus_core::ProfileId;
use focus_protocol::{
    EmergencyCodePayload, EmergencyRequestPayload, ReplayPolicy, Request, StartSessionRequest,
};

#[test]
fn every_state_changing_request_is_at_most_once() {
    for request in [
        Request::StartSession(StartSessionRequest {
            profile_id: ProfileId(7),
            minimum_duration_secs: 3_600,
            objective: "Deep work".to_owned(),
        }),
        Request::RequestEmergencyUnlock(EmergencyRequestPayload {
            reason: "Real emergency".to_owned(),
        }),
        Request::SubmitEmergencyCode(EmergencyCodePayload {
            code: "FG7K-P29M-4TXQ-R8VN".to_owned(),
        }),
        Request::VpnUp { id: 42 },
        Request::VpnDown { id: 42 },
    ] {
        assert_eq!(request.replay_policy(), ReplayPolicy::AtMostOnce);
    }
}

#[test]
fn read_only_requests_are_repeatable() {
    for request in [
        Request::GetStatus,
        Request::GetSession,
        Request::GetProfiles,
        Request::Doctor,
        Request::GetVpnList,
    ] {
        assert_eq!(request.replay_policy(), ReplayPolicy::Repeatable);
    }
}
