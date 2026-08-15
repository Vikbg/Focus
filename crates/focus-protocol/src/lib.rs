//! Typed local protocol shared by Focus clients and the daemon.

use std::{error::Error, fmt};

use focus_core::ProfileId;

/// Current version of the local Focus IPC protocol.
pub const PROTOCOL_VERSION: u16 = 1;
/// Maximum accepted size of one newline-free IPC frame.
pub const MAX_FRAME_BYTES: usize = 64 * 1024;

/// Correlates an IPC response with its originating request.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct RequestId(pub u128);

/// Identifies the class of local process making a daemon request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClientKind {
    Desktop,
    Cli,
    BrowserBridge,
    Classifier,
}

impl ClientKind {
    const fn token(self) -> &'static str {
        match self {
            Self::Desktop => "desktop",
            Self::Cli => "cli",
            Self::BrowserBridge => "browser-bridge",
            Self::Classifier => "classifier",
        }
    }

    fn parse(token: &str) -> Result<Self, WireError> {
        match token {
            "desktop" => Ok(Self::Desktop),
            "cli" => Ok(Self::Cli),
            "browser-bridge" => Ok(Self::BrowserBridge),
            "classifier" => Ok(Self::Classifier),
            _ => Err(WireError::UnknownClient),
        }
    }
}

/// Typed request payload for starting a protected Focus session.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StartSessionRequest {
    pub profile_id: ProfileId,
    pub minimum_duration_secs: u64,
    pub objective: String,
}

/// Typed reason supplied when entering the emergency unlock workflow.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EmergencyRequestPayload {
    pub reason: String,
}

/// Typed recovery code submission for an already pending emergency request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EmergencyCodePayload {
    pub code: String,
}

/// Replay semantics required for one request class.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReplayPolicy {
    Repeatable,
    AtMostOnce,
}

/// Request set supported by the Focus daemon protocol.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Request {
    GetStatus,
    StartSession(StartSessionRequest),
    GetSession,
    RequestEmergencyUnlock(EmergencyRequestPayload),
    SubmitEmergencyCode(EmergencyCodePayload),
    GetProfiles,
    Doctor,
    GetVpnList,
    VpnUp { id: u128 },
    VpnDown { id: u128 },
}

impl Request {
    /// Returns the replay semantics required for this request class.
    #[must_use]
    pub const fn replay_policy(&self) -> ReplayPolicy {
        match self {
            Self::GetStatus
            | Self::GetSession
            | Self::GetProfiles
            | Self::Doctor
            | Self::GetVpnList => ReplayPolicy::Repeatable,
            Self::StartSession(_)
            | Self::RequestEmergencyUnlock(_)
            | Self::SubmitEmergencyCode(_)
            | Self::VpnUp { .. }
            | Self::VpnDown { .. } => ReplayPolicy::AtMostOnce,
        }
    }

    const fn allowed_for(&self, client: ClientKind) -> bool {
        match client {
            ClientKind::Desktop => true,
            ClientKind::Cli => matches!(
                self,
                Self::GetStatus
                    | Self::GetSession
                    | Self::Doctor
                    | Self::GetVpnList
                    | Self::VpnUp { .. }
                    | Self::VpnDown { .. }
            ),
            ClientKind::BrowserBridge | ClientKind::Classifier => {
                matches!(self, Self::GetStatus)
            }
        }
    }

    fn wire_parts(&self) -> (&'static str, String) {
        match self {
            Self::GetStatus => ("status", "-".to_owned()),
            Self::StartSession(payload) => (
                "start-session",
                format!(
                    "{},{},{}",
                    payload.profile_id.0,
                    payload.minimum_duration_secs,
                    encode_text(&payload.objective)
                ),
            ),
            Self::GetSession => ("session", "-".to_owned()),
            Self::RequestEmergencyUnlock(payload) => {
                ("emergency-request", encode_text(&payload.reason))
            }
            Self::SubmitEmergencyCode(payload) => ("emergency-code", encode_text(&payload.code)),
            Self::GetProfiles => ("profiles", "-".to_owned()),
            Self::Doctor => ("doctor", "-".to_owned()),
            Self::GetVpnList => ("vpn-list", "-".to_owned()),
            Self::VpnUp { id } => ("vpn-up", id.to_string()),
            Self::VpnDown { id } => ("vpn-down", id.to_string()),
        }
    }

    fn parse(token: &str, argument: &str) -> Result<Self, WireError> {
        let no_argument = || {
            if argument == "-" {
                Ok(())
            } else {
                Err(WireError::Malformed)
            }
        };

        match token {
            "status" => {
                no_argument()?;
                Ok(Self::GetStatus)
            }
            "start-session" => {
                let mut fields = argument.splitn(3, ',');
                let profile_id = fields
                    .next()
                    .ok_or(WireError::Malformed)?
                    .parse()
                    .map_err(|_| WireError::InvalidArgument)?;
                let minimum_duration_secs = fields
                    .next()
                    .ok_or(WireError::Malformed)?
                    .parse()
                    .map_err(|_| WireError::InvalidArgument)?;
                let objective = decode_text(fields.next().ok_or(WireError::Malformed)?)?;
                Ok(Self::StartSession(StartSessionRequest {
                    profile_id: ProfileId(profile_id),
                    minimum_duration_secs,
                    objective,
                }))
            }
            "session" => {
                no_argument()?;
                Ok(Self::GetSession)
            }
            "emergency-request" => Ok(Self::RequestEmergencyUnlock(EmergencyRequestPayload {
                reason: decode_text(argument)?,
            })),
            "emergency-code" => Ok(Self::SubmitEmergencyCode(EmergencyCodePayload {
                code: decode_text(argument)?,
            })),
            "profiles" => {
                no_argument()?;
                Ok(Self::GetProfiles)
            }
            "doctor" => {
                no_argument()?;
                Ok(Self::Doctor)
            }
            "vpn-list" => {
                no_argument()?;
                Ok(Self::GetVpnList)
            }
            "vpn-up" => Ok(Self::VpnUp {
                id: argument.parse().map_err(|_| WireError::InvalidArgument)?,
            }),
            "vpn-down" => Ok(Self::VpnDown {
                id: argument.parse().map_err(|_| WireError::InvalidArgument)?,
            }),
            _ => Err(WireError::UnknownRequest),
        }
    }
}

fn encode_text(value: &str) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut encoded = String::with_capacity(value.len() * 2);
    for byte in value.as_bytes() {
        encoded.push(char::from(HEX[usize::from(byte >> 4)]));
        encoded.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    encoded
}

fn decode_text(value: &str) -> Result<String, WireError> {
    if !value.len().is_multiple_of(2) {
        return Err(WireError::InvalidArgument);
    }

    let bytes = value.as_bytes();
    let mut decoded = Vec::with_capacity(bytes.len() / 2);
    for pair in bytes.chunks_exact(2) {
        let high = decode_hex_nibble(pair[0]).ok_or(WireError::InvalidArgument)?;
        let low = decode_hex_nibble(pair[1]).ok_or(WireError::InvalidArgument)?;
        decoded.push((high << 4) | low);
    }
    String::from_utf8(decoded).map_err(|_| WireError::InvalidArgument)
}

const fn decode_hex_nibble(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

/// Stable protocol representation of daemon session state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProtocolState {
    Idle,
    Preflight,
    Arming,
    Locked,
    EmergencyPending,
    EmergencyAuthorized,
    Ending,
    Recovering,
    ProtectionFailure,
}

impl ProtocolState {
    const fn token(self) -> &'static str {
        match self {
            Self::Idle => "Idle",
            Self::Preflight => "Preflight",
            Self::Arming => "Arming",
            Self::Locked => "Locked",
            Self::EmergencyPending => "EmergencyPending",
            Self::EmergencyAuthorized => "EmergencyAuthorized",
            Self::Ending => "Ending",
            Self::Recovering => "Recovering",
            Self::ProtectionFailure => "ProtectionFailure",
        }
    }

    fn parse(token: &str) -> Result<Self, WireError> {
        match token {
            "Idle" => Ok(Self::Idle),
            "Preflight" => Ok(Self::Preflight),
            "Arming" => Ok(Self::Arming),
            "Locked" => Ok(Self::Locked),
            "EmergencyPending" => Ok(Self::EmergencyPending),
            "EmergencyAuthorized" => Ok(Self::EmergencyAuthorized),
            "Ending" => Ok(Self::Ending),
            "Recovering" => Ok(Self::Recovering),
            "ProtectionFailure" => Ok(Self::ProtectionFailure),
            _ => Err(WireError::InvalidArgument),
        }
    }
}

/// Typed daemon response payload.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Response {
    Status(ProtocolState),
    Session(ProtocolState),
    DoctorReachable,
    VpnListEmpty,
    VpnUpRequested(u128),
    VpnDownRequested(u128),
    Error(ResponseError),
}

/// Stable error codes returned over local IPC.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ResponseError {
    Unauthorized,
    UnsupportedRequest,
    InvalidRequest,
    UnsupportedProtocolVersion,
    PeerAuthenticationFailed,
}

impl ResponseError {
    const fn token(self) -> &'static str {
        match self {
            Self::Unauthorized => "unauthorized",
            Self::UnsupportedRequest => "unsupported-request",
            Self::InvalidRequest => "invalid-request",
            Self::UnsupportedProtocolVersion => "unsupported-protocol-version",
            Self::PeerAuthenticationFailed => "peer-authentication-failed",
        }
    }

    fn parse(token: &str) -> Result<Self, WireError> {
        match token {
            "unauthorized" => Ok(Self::Unauthorized),
            "unsupported-request" => Ok(Self::UnsupportedRequest),
            "invalid-request" => Ok(Self::InvalidRequest),
            "unsupported-protocol-version" => Ok(Self::UnsupportedProtocolVersion),
            "peer-authentication-failed" => Ok(Self::PeerAuthenticationFailed),
            _ => Err(WireError::InvalidArgument),
        }
    }
}

/// Error returned while decoding local IPC wire data.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WireError {
    Malformed,
    FrameTooLarge,
    InvalidVersion,
    InvalidRequestId,
    UnknownClient,
    UnknownRequest,
    InvalidArgument,
    UnknownResponse,
}

impl fmt::Display for WireError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "invalid Focus IPC frame: {self:?}")
    }
}

impl Error for WireError {}

/// Versioned envelope sent from an IPC client to `focusd`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RequestEnvelope {
    protocol_version: u16,
    request_id: RequestId,
    client: ClientKind,
    request: Request,
}

impl RequestEnvelope {
    /// Creates an envelope using the current protocol version.
    #[must_use]
    pub fn new(request_id: RequestId, client: ClientKind, request: Request) -> Self {
        Self {
            protocol_version: PROTOCOL_VERSION,
            request_id,
            client,
            request,
        }
    }

    /// Decodes one complete newline-free request frame.
    ///
    /// # Errors
    ///
    /// Returns [`WireError`] when the frame is too large, malformed, or contains unknown fields.
    pub fn decode(line: &str) -> Result<Self, WireError> {
        if line.len() > MAX_FRAME_BYTES {
            return Err(WireError::FrameTooLarge);
        }
        let parts: Vec<_> = line.split('|').collect();
        if parts.len() != 5 {
            return Err(WireError::Malformed);
        }

        let protocol_version = parts[0].parse().map_err(|_| WireError::InvalidVersion)?;
        let request_id = RequestId(parts[1].parse().map_err(|_| WireError::InvalidRequestId)?);
        let client = ClientKind::parse(parts[2])?;
        let request = Request::parse(parts[3], parts[4])?;

        Ok(Self {
            protocol_version,
            request_id,
            client,
            request,
        })
    }

    /// Encodes this request as one newline-free frame.
    #[must_use]
    pub fn encode(&self) -> String {
        let (request, argument) = self.request.wire_parts();
        format!(
            "{}|{}|{}|{}|{}",
            self.protocol_version,
            self.request_id.0,
            self.client.token(),
            request,
            argument
        )
    }

    /// Returns the protocol version carried by this request.
    #[must_use]
    pub const fn protocol_version(&self) -> u16 {
        self.protocol_version
    }

    /// Returns whether this frame uses the current protocol version.
    #[must_use]
    pub const fn is_compatible(&self) -> bool {
        self.protocol_version == PROTOCOL_VERSION
    }

    /// Returns the request identifier.
    #[must_use]
    pub const fn request_id(&self) -> RequestId {
        self.request_id
    }

    /// Returns the sending client kind.
    #[must_use]
    pub const fn client(&self) -> ClientKind {
        self.client
    }

    /// Returns a clone of the typed request payload.
    #[must_use]
    pub fn request(&self) -> Request {
        self.request.clone()
    }

    /// Consumes the envelope and returns its typed request payload.
    #[must_use]
    pub fn into_request(self) -> Request {
        self.request
    }

    /// Returns whether the claimed client kind may issue this request class.
    #[must_use]
    pub const fn is_authorized(&self) -> bool {
        self.request.allowed_for(self.client)
    }

    /// Returns whether the authenticated peer identity matches the claim and may issue this request.
    #[must_use]
    pub fn is_authorized_as(&self, authenticated_client: ClientKind) -> bool {
        self.client == authenticated_client && self.request.allowed_for(authenticated_client)
    }
}

/// Versioned response envelope returned by `focusd`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ResponseEnvelope {
    protocol_version: u16,
    request_id: RequestId,
    response: Response,
}

impl ResponseEnvelope {
    /// Creates a response using the current protocol version.
    #[must_use]
    pub const fn new(request_id: RequestId, response: Response) -> Self {
        Self {
            protocol_version: PROTOCOL_VERSION,
            request_id,
            response,
        }
    }

    /// Decodes one complete newline-free response frame.
    ///
    /// # Errors
    ///
    /// Returns [`WireError`] when the frame is too large, malformed, or contains unknown fields.
    pub fn decode(line: &str) -> Result<Self, WireError> {
        if line.len() > MAX_FRAME_BYTES {
            return Err(WireError::FrameTooLarge);
        }
        let parts: Vec<_> = line.split('|').collect();
        if parts.len() != 5 {
            return Err(WireError::Malformed);
        }

        let protocol_version = parts[0].parse().map_err(|_| WireError::InvalidVersion)?;
        let request_id = RequestId(parts[1].parse().map_err(|_| WireError::InvalidRequestId)?);
        let response = match parts[2] {
            "status" => Response::Status(ProtocolState::parse(parts[3])?),
            "session" => Response::Session(ProtocolState::parse(parts[3])?),
            "doctor" if parts[3] == "reachable" => Response::DoctorReachable,
            "vpn-list" if parts[3] == "empty" => Response::VpnListEmpty,
            "vpn-up" => {
                Response::VpnUpRequested(parts[3].parse().map_err(|_| WireError::InvalidArgument)?)
            }
            "vpn-down" => Response::VpnDownRequested(
                parts[3].parse().map_err(|_| WireError::InvalidArgument)?,
            ),
            "error" => Response::Error(ResponseError::parse(parts[3])?),
            _ => return Err(WireError::UnknownResponse),
        };

        if parts[4] != "-" {
            return Err(WireError::Malformed);
        }

        Ok(Self {
            protocol_version,
            request_id,
            response,
        })
    }

    /// Encodes this response as one newline-free frame.
    #[must_use]
    pub fn encode(self) -> String {
        let (kind, value) = match self.response {
            Response::Status(state) => ("status", state.token().to_owned()),
            Response::Session(state) => ("session", state.token().to_owned()),
            Response::DoctorReachable => ("doctor", "reachable".to_owned()),
            Response::VpnListEmpty => ("vpn-list", "empty".to_owned()),
            Response::VpnUpRequested(id) => ("vpn-up", id.to_string()),
            Response::VpnDownRequested(id) => ("vpn-down", id.to_string()),
            Response::Error(error) => ("error", error.token().to_owned()),
        };

        format!(
            "{}|{}|{}|{}|-",
            self.protocol_version, self.request_id.0, kind, value
        )
    }

    /// Returns whether this frame uses the current protocol version.
    #[must_use]
    pub const fn is_compatible(self) -> bool {
        self.protocol_version == PROTOCOL_VERSION
    }

    /// Returns the correlated request identifier.
    #[must_use]
    pub const fn request_id(self) -> RequestId {
        self.request_id
    }

    /// Returns the typed response payload.
    #[must_use]
    pub const fn response(self) -> Response {
        self.response
    }
}
