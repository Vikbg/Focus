//! Typed local protocol shared by Focus clients and the daemon.

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

/// Initial request set supported by the Focus daemon protocol.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Request {
    GetStatus,
    StartSession,
    GetSession,
    RequestEmergencyUnlock,
    SubmitEmergencyCode,
    GetProfiles,
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
}

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

    /// Returns the protocol version carried by this request.
    #[must_use]
    pub const fn protocol_version(self) -> u16 {
        self.protocol_version
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

    /// Returns whether this client kind may issue this request class.
    #[must_use]
    pub const fn is_authorized(self) -> bool {
        self.request.allowed_for(self.client)
    }
}
