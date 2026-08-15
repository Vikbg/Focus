//! Typed local protocol shared by Focus clients and the daemon.

use std::{error::Error, fmt};

/// Current version of the local Focus IPC protocol.
pub const PROTOCOL_VERSION: u16 = 1;

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

/// Initial request set supported by the Focus daemon protocol.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Request {
    GetStatus,
    StartSession,
    GetSession,
    RequestEmergencyUnlock,
    SubmitEmergencyCode,
    GetProfiles,
    Doctor,
    GetVpnList,
    VpnUp { id: u128 },
    VpnDown { id: u128 },
}

impl Request {
    const fn allowed_for(self, client: ClientKind) -> bool {
        match client {
            ClientKind::Desktop | ClientKind::Cli => true,
            ClientKind::BrowserBridge | ClientKind::Classifier => {
                matches!(self, Self::GetStatus)
            }
        }
    }

    const fn wire_parts(self) -> (&'static str, Option<u128>) {
        match self {
            Self::GetStatus => ("status", None),
            Self::StartSession => ("start-session", None),
            Self::GetSession => ("session", None),
            Self::RequestEmergencyUnlock => ("emergency-request", None),
            Self::SubmitEmergencyCode => ("emergency-code", None),
            Self::GetProfiles => ("profiles", None),
            Self::Doctor => ("doctor", None),
            Self::GetVpnList => ("vpn-list", None),
            Self::VpnUp { id } => ("vpn-up", Some(id)),
            Self::VpnDown { id } => ("vpn-down", Some(id)),
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
                no_argument()?;
                Ok(Self::StartSession)
            }
            "session" => {
                no_argument()?;
                Ok(Self::GetSession)
            }
            "emergency-request" => {
                no_argument()?;
                Ok(Self::RequestEmergencyUnlock)
            }
            "emergency-code" => {
                no_argument()?;
                Ok(Self::SubmitEmergencyCode)
            }
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
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RequestEnvelope {
    protocol_version: u16,
    request_id: RequestId,
    client: ClientKind,
    request: Request,
}

impl RequestEnvelope {
    /// Creates an envelope using the current protocol version.
    #[must_use]
    pub const fn new(request_id: RequestId, client: ClientKind, request: Request) -> Self {
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
    /// Returns [`WireError`] when the frame is malformed or contains unknown fields.
    pub fn decode(line: &str) -> Result<Self, WireError> {
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
    pub fn encode(self) -> String {
        let (request, argument) = self.request.wire_parts();
        let argument = argument.map_or_else(|| "-".to_owned(), |value| value.to_string());
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
    pub const fn protocol_version(self) -> u16 {
        self.protocol_version
    }

    /// Returns whether this frame uses the current protocol version.
    #[must_use]
    pub const fn is_compatible(self) -> bool {
        self.protocol_version == PROTOCOL_VERSION
    }

    /// Returns the request identifier.
    #[must_use]
    pub const fn request_id(self) -> RequestId {
        self.request_id
    }

    /// Returns the sending client kind.
    #[must_use]
    pub const fn client(self) -> ClientKind {
        self.client
    }

    /// Returns the request payload discriminator.
    #[must_use]
    pub const fn request(self) -> Request {
        self.request
    }

    /// Returns whether the claimed client kind may issue this request class.
    #[must_use]
    pub const fn is_authorized(self) -> bool {
        self.request.allowed_for(self.client)
    }

    /// Returns whether the authenticated peer identity matches the claim and may issue this request.
    #[must_use]
    pub const fn is_authorized_as(self, authenticated_client: ClientKind) -> bool {
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
    /// Returns [`WireError`] when the frame is malformed or contains unknown fields.
    pub fn decode(line: &str) -> Result<Self, WireError> {
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
            "vpn-up" => Response::VpnUpRequested(
                parts[3].parse().map_err(|_| WireError::InvalidArgument)?,
            ),
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
