//! Transactional protected-state storage for Focus.

use std::{error::Error, fmt, path::Path};

use focus_core::{EmergencyRequest, RecoveryCodeHash, SessionId, SessionState};
use rusqlite::{Connection, OptionalExtension, params};

/// Error returned by the protected Focus store.
#[derive(Debug)]
pub enum StoreError {
    Sqlite(rusqlite::Error),
    StateMismatch,
    InvalidSessionId(String),
    InvalidSessionState(i64),
    InvalidCount(i64),
    TimestampOutOfRange(u64),
    InvalidTimestamp(i64),
    InvalidRecoveryCodeHashLength(usize),
    InvalidEmergencyRequest,
    SchemaMismatch(String),
}

impl fmt::Display for StoreError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Sqlite(error) => write!(formatter, "SQLite error: {error}"),
            Self::StateMismatch => formatter.write_str("active session state mismatch"),
            Self::InvalidSessionId(value) => write!(formatter, "invalid session id: {value}"),
            Self::InvalidSessionState(value) => write!(formatter, "invalid session state: {value}"),
            Self::InvalidCount(value) => write!(formatter, "invalid row count: {value}"),
            Self::TimestampOutOfRange(value) => {
                write!(formatter, "timestamp does not fit SQLite integer: {value}")
            }
            Self::InvalidTimestamp(value) => {
                write!(formatter, "invalid persisted timestamp: {value}")
            }
            Self::InvalidRecoveryCodeHashLength(length) => {
                write!(formatter, "invalid recovery code hash length: {length}")
            }
            Self::InvalidEmergencyRequest => {
                formatter.write_str("invalid persisted emergency request")
            }
            Self::SchemaMismatch(table) => write!(formatter, "unexpected SQLite schema: {table}"),
        }
    }
}

impl Error for StoreError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Sqlite(error) => Some(error),
            Self::StateMismatch
            | Self::InvalidSessionId(_)
            | Self::InvalidSessionState(_)
            | Self::InvalidCount(_)
            | Self::TimestampOutOfRange(_)
            | Self::InvalidTimestamp(_)
            | Self::InvalidRecoveryCodeHashLength(_)
            | Self::InvalidEmergencyRequest
            | Self::SchemaMismatch(_) => None,
        }
    }
}

impl From<rusqlite::Error> for StoreError {
    fn from(error: rusqlite::Error) -> Self {
        Self::Sqlite(error)
    }
}

/// Result returned by protected-store operations.
pub type StoreResult<T> = Result<T, StoreError>;

/// Security-relevant event appended to the protected local journal.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SecurityEvent {
    event_type: String,
    payload: Vec<u8>,
}

impl SecurityEvent {
    /// Creates a security journal event.
    #[must_use]
    pub fn new(event_type: impl Into<String>, payload: Vec<u8>) -> Self {
        Self {
            event_type: event_type.into(),
            payload,
        }
    }

    fn event_type(&self) -> &str {
        &self.event_type
    }

    fn payload(&self) -> &[u8] {
        &self.payload
    }
}

/// A persisted transition between two session states.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Transition {
    session_id: SessionId,
    from: SessionState,
    to: SessionState,
}

impl Transition {
    #[must_use]
    pub const fn new(session_id: SessionId, from: SessionState, to: SessionState) -> Self {
        Self {
            session_id,
            from,
            to,
        }
    }
}

/// Minimal representation of the active protected session.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StoredSession {
    id: SessionId,
    state: SessionState,
}

impl StoredSession {
    #[must_use]
    pub const fn id(self) -> SessionId {
        self.id
    }

    #[must_use]
    pub const fn state(self) -> SessionState {
        self.state
    }
}

/// Domain-specific storage operations required by the session engine.
pub trait FocusStore {
    /// Returns the currently active session, if one exists.
    ///
    /// # Errors
    ///
    /// Returns an error when the database cannot be queried or contains invalid state.
    fn active_session(&self) -> StoreResult<Option<StoredSession>>;

    /// Replaces the current active session state.
    ///
    /// # Errors
    ///
    /// Returns an error when the database write fails.
    fn set_active_session(&mut self, session_id: SessionId, state: SessionState)
    -> StoreResult<()>;

    /// Atomically appends a transition and updates the active session.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::StateMismatch`] when the stored source state does not match the
    /// transition source state. Database failures are returned as [`StoreError::Sqlite`].
    fn persist_transition(&mut self, transition: &Transition) -> StoreResult<()>;

    /// Appends one security-relevant event to the protected journal.
    ///
    /// # Errors
    ///
    /// Returns an error when the journal write fails.
    fn append_security_event(&mut self, event: &SecurityEvent) -> StoreResult<()>;

    /// Persists the currently pending emergency unlock request.
    ///
    /// # Errors
    ///
    /// Returns an error when the request timestamp cannot be represented or the write fails.
    fn persist_emergency_request(&mut self, request: &EmergencyRequest) -> StoreResult<()>;

    /// Restores the pending emergency unlock request, if one exists.
    ///
    /// # Errors
    ///
    /// Returns an error when the database cannot be queried or the persisted request is invalid.
    fn emergency_request(&self) -> StoreResult<Option<EmergencyRequest>>;

    /// Returns the number of committed session transitions.
    ///
    /// # Errors
    ///
    /// Returns an error when the transition journal cannot be queried.
    fn transition_count(&self) -> StoreResult<u64>;

    /// Returns the number of committed security events.
    ///
    /// # Errors
    ///
    /// Returns an error when the security journal cannot be queried.
    fn security_event_count(&self) -> StoreResult<u64>;
}

/// `SQLite` implementation of the protected Focus store.
pub struct SqliteStore {
    connection: Connection,
}

impl SqliteStore {
    /// Opens or creates a file-backed store and applies the current schema.
    ///
    /// # Errors
    ///
    /// Returns an error when `SQLite` cannot open or migrate the store.
    pub fn open(path: impl AsRef<Path>) -> StoreResult<Self> {
        let connection = Connection::open(path)?;
        let store = Self { connection };
        store.migrate()?;
        Ok(store)
    }

    /// Creates a temporary in-memory store and applies the current schema.
    ///
    /// # Errors
    ///
    /// Returns an error when `SQLite` cannot create or migrate the store.
    pub fn open_in_memory() -> StoreResult<Self> {
        let connection = Connection::open_in_memory()?;
        let store = Self { connection };
        store.migrate()?;
        Ok(store)
    }

    fn migrate(&self) -> StoreResult<()> {
        self.connection.execute_batch(
            "
            PRAGMA foreign_keys = ON;

            CREATE TABLE IF NOT EXISTS active_session (
                singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
                session_id TEXT NOT NULL,
                state INTEGER NOT NULL
            );

            CREATE TABLE IF NOT EXISTS session_transitions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                session_id TEXT NOT NULL,
                from_state INTEGER NOT NULL,
                to_state INTEGER NOT NULL
            );

            CREATE TABLE IF NOT EXISTS profiles (
                id TEXT PRIMARY KEY,
                version INTEGER NOT NULL,
                payload BLOB NOT NULL
            );

            CREATE TABLE IF NOT EXISTS schedules (
                id TEXT PRIMARY KEY,
                payload BLOB NOT NULL
            );

            CREATE TABLE IF NOT EXISTS vpn_identities (
                id TEXT PRIMARY KEY,
                payload BLOB NOT NULL
            );

            CREATE TABLE IF NOT EXISTS security_events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                event_type TEXT NOT NULL,
                payload BLOB NOT NULL
            );

            CREATE TABLE IF NOT EXISTS emergency_request (
                singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
                reason TEXT NOT NULL,
                requested_at INTEGER NOT NULL,
                code_hash BLOB NOT NULL
            );

            CREATE TABLE IF NOT EXISTS schema_migrations (
                version INTEGER PRIMARY KEY
            );
            ",
        )?;

        self.validate_table_columns("active_session", &["singleton", "session_id", "state"])?;
        self.validate_table_columns(
            "session_transitions",
            &["id", "session_id", "from_state", "to_state"],
        )?;
        self.validate_table_columns("profiles", &["id", "version", "payload"])?;
        self.validate_table_columns("schedules", &["id", "payload"])?;
        self.validate_table_columns("vpn_identities", &["id", "payload"])?;
        self.validate_table_columns("security_events", &["id", "event_type", "payload"])?;
        self.validate_table_columns(
            "emergency_request",
            &["singleton", "reason", "requested_at", "code_hash"],
        )?;
        self.validate_table_columns("schema_migrations", &["version"])?;
        Ok(())
    }

    fn validate_table_columns(&self, table: &str, expected: &[&str]) -> StoreResult<()> {
        let query = format!("PRAGMA table_info({table})");
        let mut statement = self.connection.prepare(&query)?;
        let columns = statement
            .query_map([], |row| row.get::<_, String>(1))?
            .collect::<Result<Vec<_>, _>>()?;

        if columns.iter().map(String::as_str).eq(expected.iter().copied()) {
            return Ok(());
        }

        Err(StoreError::SchemaMismatch(table.to_owned()))
    }
}

impl FocusStore for SqliteStore {
    fn active_session(&self) -> StoreResult<Option<StoredSession>> {
        let row = self
            .connection
            .query_row(
                "SELECT session_id, state FROM active_session WHERE singleton = 1",
                [],
                |row| Ok((row.get::<_, String>(0)?, row.get::<_, i64>(1)?)),
            )
            .optional()?;

        row.map(|(session_id, state)| {
            Ok(StoredSession {
                id: decode_session_id(&session_id)?,
                state: decode_state(state)?,
            })
        })
        .transpose()
    }

    fn set_active_session(
        &mut self,
        session_id: SessionId,
        state: SessionState,
    ) -> StoreResult<()> {
        self.connection.execute(
            "INSERT INTO active_session(singleton, session_id, state)
             VALUES(1, ?1, ?2)
             ON CONFLICT(singleton) DO UPDATE SET session_id = excluded.session_id, state = excluded.state",
            params![encode_session_id(session_id), encode_state(state)],
        )?;
        Ok(())
    }

    fn persist_transition(&mut self, transition: &Transition) -> StoreResult<()> {
        let transaction = self.connection.transaction()?;
        let session_id = encode_session_id(transition.session_id);

        transaction.execute(
            "INSERT INTO session_transitions(session_id, from_state, to_state) VALUES(?1, ?2, ?3)",
            params![
                session_id,
                encode_state(transition.from),
                encode_state(transition.to)
            ],
        )?;

        let changed = transaction.execute(
            "UPDATE active_session SET state = ?1
             WHERE singleton = 1 AND session_id = ?2 AND state = ?3",
            params![
                encode_state(transition.to),
                encode_session_id(transition.session_id),
                encode_state(transition.from)
            ],
        )?;

        if changed != 1 {
            transaction.rollback()?;
            return Err(StoreError::StateMismatch);
        }

        transaction.commit()?;
        Ok(())
    }

    fn append_security_event(&mut self, event: &SecurityEvent) -> StoreResult<()> {
        self.connection.execute(
            "INSERT INTO security_events(event_type, payload) VALUES(?1, ?2)",
            params![event.event_type(), event.payload()],
        )?;
        Ok(())
    }

    fn persist_emergency_request(&mut self, request: &EmergencyRequest) -> StoreResult<()> {
        let requested_at = i64::try_from(request.requested_at())
            .map_err(|_| StoreError::TimestampOutOfRange(request.requested_at()))?;
        let code_hash = request.code_hash().to_bytes();

        self.connection.execute(
            "INSERT INTO emergency_request(singleton, reason, requested_at, code_hash)
             VALUES(1, ?1, ?2, ?3)
             ON CONFLICT(singleton) DO UPDATE SET
                reason = excluded.reason,
                requested_at = excluded.requested_at,
                code_hash = excluded.code_hash",
            params![request.reason(), requested_at, code_hash.as_slice()],
        )?;
        Ok(())
    }

    fn emergency_request(&self) -> StoreResult<Option<EmergencyRequest>> {
        let row = self
            .connection
            .query_row(
                "SELECT reason, requested_at, code_hash FROM emergency_request WHERE singleton = 1",
                [],
                |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, i64>(1)?,
                        row.get::<_, Vec<u8>>(2)?,
                    ))
                },
            )
            .optional()?;

        row.map(|(reason, requested_at, code_hash)| {
            let requested_at = u64::try_from(requested_at)
                .map_err(|_| StoreError::InvalidTimestamp(requested_at))?;
            let hash_length = code_hash.len();
            let code_hash: [u8; 32] = code_hash
                .try_into()
                .map_err(|_| StoreError::InvalidRecoveryCodeHashLength(hash_length))?;
            EmergencyRequest::restore(
                reason,
                requested_at,
                RecoveryCodeHash::from_bytes(code_hash),
            )
            .map_err(|_| StoreError::InvalidEmergencyRequest)
        })
        .transpose()
    }

    fn transition_count(&self) -> StoreResult<u64> {
        count_rows(&self.connection, "session_transitions")
    }

    fn security_event_count(&self) -> StoreResult<u64> {
        count_rows(&self.connection, "security_events")
    }
}

fn count_rows(connection: &Connection, table: &str) -> StoreResult<u64> {
    let query = format!("SELECT COUNT(*) FROM {table}");
    let count = connection.query_row(&query, [], |row| row.get::<_, i64>(0))?;
    u64::try_from(count).map_err(|_| StoreError::InvalidCount(count))
}

fn encode_session_id(session_id: SessionId) -> String {
    format!("{:032x}", session_id.0)
}

fn decode_session_id(value: &str) -> StoreResult<SessionId> {
    u128::from_str_radix(value, 16)
        .map(SessionId)
        .map_err(|_| StoreError::InvalidSessionId(value.to_owned()))
}

const fn encode_state(state: SessionState) -> i64 {
    match state {
        SessionState::Idle => 0,
        SessionState::Preflight => 1,
        SessionState::Arming => 2,
        SessionState::Locked => 3,
        SessionState::EmergencyPending => 4,
        SessionState::EmergencyAuthorized => 5,
        SessionState::Ending => 6,
        SessionState::Recovering => 7,
        SessionState::ProtectionFailure => 8,
    }
}

fn decode_state(value: i64) -> StoreResult<SessionState> {
    match value {
        0 => Ok(SessionState::Idle),
        1 => Ok(SessionState::Preflight),
        2 => Ok(SessionState::Arming),
        3 => Ok(SessionState::Locked),
        4 => Ok(SessionState::EmergencyPending),
        5 => Ok(SessionState::EmergencyAuthorized),
        6 => Ok(SessionState::Ending),
        7 => Ok(SessionState::Recovering),
        8 => Ok(SessionState::ProtectionFailure),
        _ => Err(StoreError::InvalidSessionState(value)),
    }
}
