//! Transactional protected-state storage for Focus.

use std::{error::Error, fmt, path::Path};

use focus_core::{
    BootId, EmergencyRequest, EmergencyTimingState, PolicyVersion, ProfileId, RecoveryCodeHash,
    SESSION_POLICY_SCHEMA_VERSION, SessionId, SessionPolicySnapshot, SessionState,
    ValidatedTransition,
};
use rusqlite::{Connection, OptionalExtension, params};

const CURRENT_SCHEMA_VERSION: i64 = 3;

/// Error returned by the protected Focus store.
#[derive(Debug)]
pub enum StoreError {
    Sqlite(rusqlite::Error),
    StateMismatch,
    InvalidSessionId(String),
    InvalidProfileId(String),
    InvalidBootId(String),
    InvalidSessionState(i64),
    InvalidCount(i64),
    TimestampOutOfRange(u64),
    InvalidTimestamp(i64),
    InvalidPolicySchemaVersion(i64),
    InvalidPolicySnapshot,
    InvalidPolicyDigestLength(usize),
    PolicyDigestMismatch,
    InvalidRecoveryCodeHashLength(usize),
    InvalidEmergencyRequest,
    IncompleteActiveSession,
    UnsupportedSchemaVersion(i64),
    SchemaMismatch(String),
}

impl fmt::Display for StoreError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Sqlite(error) => write!(formatter, "SQLite error: {error}"),
            Self::StateMismatch => formatter.write_str("active session state mismatch"),
            Self::InvalidSessionId(value) => write!(formatter, "invalid session id: {value}"),
            Self::InvalidProfileId(value) => write!(formatter, "invalid profile id: {value}"),
            Self::InvalidBootId(value) => write!(formatter, "invalid boot id: {value}"),
            Self::InvalidSessionState(value) => write!(formatter, "invalid session state: {value}"),
            Self::InvalidCount(value) => write!(formatter, "invalid row count: {value}"),
            Self::TimestampOutOfRange(value) => {
                write!(formatter, "integer does not fit SQLite integer: {value}")
            }
            Self::InvalidTimestamp(value) => {
                write!(formatter, "invalid persisted integer: {value}")
            }
            Self::InvalidPolicySchemaVersion(value) => {
                write!(formatter, "invalid policy schema version: {value}")
            }
            Self::InvalidPolicySnapshot => formatter.write_str("invalid persisted policy snapshot"),
            Self::InvalidPolicyDigestLength(length) => {
                write!(formatter, "invalid policy digest length: {length}")
            }
            Self::PolicyDigestMismatch => formatter.write_str("persisted policy digest mismatch"),
            Self::InvalidRecoveryCodeHashLength(length) => {
                write!(formatter, "invalid recovery code hash length: {length}")
            }
            Self::InvalidEmergencyRequest => {
                formatter.write_str("invalid persisted emergency request")
            }
            Self::IncompleteActiveSession => {
                formatter.write_str("active session is missing frozen security context")
            }
            Self::UnsupportedSchemaVersion(version) => {
                write!(formatter, "unsupported SQLite schema version: {version}")
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
            | Self::InvalidProfileId(_)
            | Self::InvalidBootId(_)
            | Self::InvalidSessionState(_)
            | Self::InvalidCount(_)
            | Self::TimestampOutOfRange(_)
            | Self::InvalidTimestamp(_)
            | Self::InvalidPolicySchemaVersion(_)
            | Self::InvalidPolicySnapshot
            | Self::InvalidPolicyDigestLength(_)
            | Self::PolicyDigestMismatch
            | Self::InvalidRecoveryCodeHashLength(_)
            | Self::InvalidEmergencyRequest
            | Self::IncompleteActiveSession
            | Self::UnsupportedSchemaVersion(_)
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
    /// Creates one security journal event.
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

/// Complete immutable security context for the active protected session.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoredActiveSession {
    id: SessionId,
    state: SessionState,
    policy_snapshot: SessionPolicySnapshot,
    started_at_unix_ms: u64,
    minimum_end_at_unix_ms: u64,
    recovery_code_hash: RecoveryCodeHash,
}

impl StoredActiveSession {
    /// Creates a complete active-session record.
    #[must_use]
    pub const fn new(
        id: SessionId,
        state: SessionState,
        policy_snapshot: SessionPolicySnapshot,
        started_at_unix_ms: u64,
        minimum_end_at_unix_ms: u64,
        recovery_code_hash: RecoveryCodeHash,
    ) -> Self {
        Self {
            id,
            state,
            policy_snapshot,
            started_at_unix_ms,
            minimum_end_at_unix_ms,
            recovery_code_hash,
        }
    }

    #[must_use]
    pub const fn id(&self) -> SessionId {
        self.id
    }

    #[must_use]
    pub const fn state(&self) -> SessionState {
        self.state
    }

    #[must_use]
    pub const fn policy_snapshot(&self) -> &SessionPolicySnapshot {
        &self.policy_snapshot
    }

    #[must_use]
    pub fn policy_sha256(&self) -> [u8; 32] {
        self.policy_snapshot.policy_sha256()
    }

    #[must_use]
    pub const fn started_at_unix_ms(&self) -> u64 {
        self.started_at_unix_ms
    }

    #[must_use]
    pub const fn minimum_end_at_unix_ms(&self) -> u64 {
        self.minimum_end_at_unix_ms
    }

    #[must_use]
    pub const fn recovery_code_hash(&self) -> RecoveryCodeHash {
        self.recovery_code_hash
    }

    /// Updates the in-memory state for construction and test fixtures.
    /// Persisted lifecycle changes must use `persist_transition`.
    pub fn set_state(&mut self, state: SessionState) {
        self.state = state;
    }
}

/// Domain-specific storage operations required by the session engine.
pub trait FocusStore {
    /// Returns the currently active protected session, if one exists.
    ///
    /// # Errors
    ///
    /// Returns an error if the store cannot be queried or persisted session data is invalid.
    fn active_session(&self) -> StoreResult<Option<StoredActiveSession>>;

    /// Replaces the complete active-session record.
    ///
    /// # Errors
    ///
    /// Returns an error if the record cannot be encoded or persisted.
    fn set_active_session(&mut self, session: &StoredActiveSession) -> StoreResult<()>;

    /// Atomically journals and applies one domain-validated session-state transition.
    ///
    /// # Errors
    ///
    /// Returns an error if the stored source state does not match or the transaction fails.
    fn persist_transition(
        &mut self,
        session_id: SessionId,
        transition: &ValidatedTransition,
    ) -> StoreResult<()>;

    /// Appends one security-relevant event to the protected journal.
    ///
    /// # Errors
    ///
    /// Returns an error if the event cannot be persisted.
    fn append_security_event(&mut self, event: &SecurityEvent) -> StoreResult<()>;

    /// Persists a pending emergency request and its timing state.
    ///
    /// The request must be bound to the currently active session. The historical
    /// `code_hash` storage column is populated only from that active session and is never
    /// accepted from the request or used as an authorization source.
    ///
    /// # Errors
    ///
    /// Returns an error if the active session does not match or persistence fails.
    fn persist_emergency_request(&mut self, request: &EmergencyRequest) -> StoreResult<()>;

    /// Atomically persists emergency timing, an optional journal event, and an optional
    /// domain-validated session transition.
    ///
    /// # Errors
    ///
    /// Returns an error if the request does not match the active session or any part of
    /// the atomic observation cannot be committed.
    fn persist_emergency_observation(
        &mut self,
        request: &EmergencyRequest,
        event: Option<&SecurityEvent>,
        transition: Option<(SessionId, &ValidatedTransition)>,
    ) -> StoreResult<()>;

    /// Restores the pending emergency request, if one exists.
    ///
    /// # Errors
    ///
    /// Returns an error if persisted emergency state is incomplete or invalid.
    fn emergency_request(&self) -> StoreResult<Option<EmergencyRequest>>;

    /// Returns the number of committed state transitions.
    ///
    /// # Errors
    ///
    /// Returns an error if the transition journal cannot be queried.
    fn transition_count(&self) -> StoreResult<u64>;

    /// Returns the number of committed security events.
    ///
    /// # Errors
    ///
    /// Returns an error if the security journal cannot be queried.
    fn security_event_count(&self) -> StoreResult<u64>;
}

/// `SQLite` implementation of the protected Focus store.
pub struct SqliteStore {
    connection: Connection,
}

impl SqliteStore {
    /// Opens or creates a file-backed store and applies ordered schema migrations.
    ///
    /// # Errors
    ///
    /// Returns an error when `SQLite` cannot open or migrate the store.
    pub fn open(path: impl AsRef<Path>) -> StoreResult<Self> {
        let connection = Connection::open(path)?;
        let mut store = Self { connection };
        store.migrate()?;
        Ok(store)
    }

    /// Creates a temporary in-memory store and applies ordered schema migrations.
    ///
    /// # Errors
    ///
    /// Returns an error when `SQLite` cannot create or migrate the store.
    pub fn open_in_memory() -> StoreResult<Self> {
        let connection = Connection::open_in_memory()?;
        let mut store = Self { connection };
        store.migrate()?;
        Ok(store)
    }

    fn migrate(&mut self) -> StoreResult<()> {
        self.connection.execute_batch(
            "PRAGMA foreign_keys = ON;
             CREATE TABLE IF NOT EXISTS schema_migrations (
                 version INTEGER PRIMARY KEY
             );",
        )?;

        let mut version =
            self.connection
                .query_row("SELECT MAX(version) FROM schema_migrations", [], |row| {
                    row.get::<_, Option<i64>>(0)
                })?;

        if let Some(current) = version
            && current > CURRENT_SCHEMA_VERSION
        {
            return Err(StoreError::UnsupportedSchemaVersion(current));
        }

        if version.is_none() {
            self.create_v1_schema()?;
            self.connection
                .execute("INSERT INTO schema_migrations(version) VALUES(1)", [])?;
            version = Some(1);
        }

        if version == Some(1) {
            self.migrate_v1_to_v2()?;
            version = Some(2);
        }

        if version == Some(2) {
            self.migrate_v2_to_v3()?;
        }

        self.validate_current_schema()
    }

    fn create_v1_schema(&self) -> StoreResult<()> {
        self.connection.execute_batch(
            "
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

            CREATE TABLE IF NOT EXISTS emergency_timing (
                singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
                boot_id TEXT NOT NULL,
                monotonic_anchor INTEGER NOT NULL,
                unix_anchor INTEGER NOT NULL,
                verified_elapsed INTEGER NOT NULL
            );
            ",
        )?;
        Ok(())
    }

    fn migrate_v1_to_v2(&mut self) -> StoreResult<()> {
        let transaction = self.connection.transaction()?;
        transaction.execute_batch(
            "
            ALTER TABLE active_session ADD COLUMN profile_id TEXT;
            ALTER TABLE active_session ADD COLUMN profile_version INTEGER;
            ALTER TABLE active_session ADD COLUMN policy_schema_version INTEGER;
            ALTER TABLE active_session ADD COLUMN policy_payload BLOB;
            ALTER TABLE active_session ADD COLUMN policy_sha256 BLOB;
            ALTER TABLE active_session ADD COLUMN started_at_unix_ms INTEGER;
            ALTER TABLE active_session ADD COLUMN minimum_end_at_unix_ms INTEGER;
            ALTER TABLE active_session ADD COLUMN recovery_code_hash BLOB;
            INSERT INTO schema_migrations(version) VALUES(2);
            ",
        )?;
        transaction.commit()?;
        Ok(())
    }

    fn migrate_v2_to_v3(&mut self) -> StoreResult<()> {
        let transaction = self.connection.transaction()?;
        transaction.execute_batch(
            "
            ALTER TABLE emergency_request ADD COLUMN session_id TEXT;
            INSERT INTO schema_migrations(version) VALUES(3);
            ",
        )?;
        transaction.commit()?;
        Ok(())
    }

    fn validate_current_schema(&self) -> StoreResult<()> {
        self.validate_table_columns(
            "active_session",
            &[
                "singleton",
                "session_id",
                "state",
                "profile_id",
                "profile_version",
                "policy_schema_version",
                "policy_payload",
                "policy_sha256",
                "started_at_unix_ms",
                "minimum_end_at_unix_ms",
                "recovery_code_hash",
            ],
        )?;
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
            &[
                "singleton",
                "reason",
                "requested_at",
                "code_hash",
                "session_id",
            ],
        )?;
        self.validate_table_columns(
            "emergency_timing",
            &[
                "singleton",
                "boot_id",
                "monotonic_anchor",
                "unix_anchor",
                "verified_elapsed",
            ],
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

        if columns
            .iter()
            .map(String::as_str)
            .eq(expected.iter().copied())
        {
            return Ok(());
        }

        Err(StoreError::SchemaMismatch(table.to_owned()))
    }
}

impl FocusStore for SqliteStore {
    fn active_session(&self) -> StoreResult<Option<StoredActiveSession>> {
        let row = self
            .connection
            .query_row(
                "SELECT session_id, state, profile_id, profile_version, policy_schema_version,
                        policy_payload, policy_sha256, started_at_unix_ms, minimum_end_at_unix_ms,
                        recovery_code_hash
                 FROM active_session WHERE singleton = 1",
                [],
                |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, i64>(1)?,
                        row.get::<_, Option<String>>(2)?,
                        row.get::<_, Option<i64>>(3)?,
                        row.get::<_, Option<i64>>(4)?,
                        row.get::<_, Option<Vec<u8>>>(5)?,
                        row.get::<_, Option<Vec<u8>>>(6)?,
                        row.get::<_, Option<i64>>(7)?,
                        row.get::<_, Option<i64>>(8)?,
                        row.get::<_, Option<Vec<u8>>>(9)?,
                    ))
                },
            )
            .optional()?;

        let Some((
            session_id,
            state,
            Some(profile_id),
            Some(profile_version),
            Some(policy_schema_version),
            Some(policy_payload),
            Some(policy_sha256),
            Some(started_at_unix_ms),
            Some(minimum_end_at_unix_ms),
            Some(recovery_code_hash),
        )) = row
        else {
            return match row {
                None => Ok(None),
                Some(_) => Err(StoreError::IncompleteActiveSession),
            };
        };

        let policy_schema_version = u32::try_from(policy_schema_version)
            .map_err(|_| StoreError::InvalidPolicySchemaVersion(policy_schema_version))?;
        let snapshot = SessionPolicySnapshot::restore(
            decode_profile_id(&profile_id)?,
            PolicyVersion(decode_u64(profile_version)?),
            policy_schema_version,
            &policy_payload,
        )
        .map_err(|_| StoreError::InvalidPolicySnapshot)?;

        let digest_length = policy_sha256.len();
        let stored_digest: [u8; 32] = policy_sha256
            .try_into()
            .map_err(|_| StoreError::InvalidPolicyDigestLength(digest_length))?;
        if snapshot.policy_sha256() != stored_digest {
            return Err(StoreError::PolicyDigestMismatch);
        }

        let recovery_hash_length = recovery_code_hash.len();
        let recovery_code_hash: [u8; 32] = recovery_code_hash
            .try_into()
            .map_err(|_| StoreError::InvalidRecoveryCodeHashLength(recovery_hash_length))?;

        Ok(Some(StoredActiveSession::new(
            decode_session_id(&session_id)?,
            decode_state(state)?,
            snapshot,
            decode_u64(started_at_unix_ms)?,
            decode_u64(minimum_end_at_unix_ms)?,
            RecoveryCodeHash::from_bytes(recovery_code_hash),
        )))
    }

    fn set_active_session(&mut self, session: &StoredActiveSession) -> StoreResult<()> {
        let policy_payload = session.policy_snapshot().policy_payload();
        let policy_sha256 = session.policy_sha256();
        let recovery_code_hash = session.recovery_code_hash().to_bytes();
        self.connection.execute(
            "INSERT INTO active_session(
                singleton, session_id, state, profile_id, profile_version, policy_schema_version,
                policy_payload, policy_sha256, started_at_unix_ms, minimum_end_at_unix_ms,
                recovery_code_hash
             ) VALUES(1, ?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)
             ON CONFLICT(singleton) DO UPDATE SET
                session_id = excluded.session_id,
                state = excluded.state,
                profile_id = excluded.profile_id,
                profile_version = excluded.profile_version,
                policy_schema_version = excluded.policy_schema_version,
                policy_payload = excluded.policy_payload,
                policy_sha256 = excluded.policy_sha256,
                started_at_unix_ms = excluded.started_at_unix_ms,
                minimum_end_at_unix_ms = excluded.minimum_end_at_unix_ms,
                recovery_code_hash = excluded.recovery_code_hash",
            params![
                encode_session_id(session.id()),
                encode_state(session.state()),
                encode_profile_id(session.policy_snapshot().profile_id()),
                encode_u64(session.policy_snapshot().profile_version().0)?,
                i64::from(SESSION_POLICY_SCHEMA_VERSION),
                policy_payload.as_slice(),
                policy_sha256.as_slice(),
                encode_u64(session.started_at_unix_ms())?,
                encode_u64(session.minimum_end_at_unix_ms())?,
                recovery_code_hash.as_slice(),
            ],
        )?;
        Ok(())
    }

    fn persist_transition(
        &mut self,
        session_id: SessionId,
        transition: &ValidatedTransition,
    ) -> StoreResult<()> {
        let transaction = self.connection.transaction()?;
        persist_transition_in_transaction(&transaction, session_id, transition)?;
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
        self.persist_emergency_observation(request, None, None)
    }

    fn persist_emergency_observation(
        &mut self,
        request: &EmergencyRequest,
        event: Option<&SecurityEvent>,
        transition: Option<(SessionId, &ValidatedTransition)>,
    ) -> StoreResult<()> {
        let requested_at = encode_u64(request.requested_at())?;
        let timing = request.timing_state();
        let monotonic_anchor = encode_u64(timing.monotonic_anchor_nanos())?;
        let unix_anchor = encode_u64(timing.unix_anchor_seconds())?;
        let verified_elapsed = encode_u64(timing.verified_elapsed_nanos())?;
        let transaction = self.connection.transaction()?;
        let encoded_session_id = encode_session_id(request.session_id());

        let stored_hash = transaction
            .query_row(
                "SELECT recovery_code_hash FROM active_session
                 WHERE singleton = 1 AND session_id = ?1",
                params![encoded_session_id],
                |row| row.get::<_, Option<Vec<u8>>>(0),
            )
            .optional()?
            .flatten()
            .ok_or(StoreError::StateMismatch)?;

        transaction.execute(
            "INSERT INTO emergency_request(
                singleton, reason, requested_at, code_hash, session_id
             ) VALUES(1, ?1, ?2, ?3, ?4)
             ON CONFLICT(singleton) DO UPDATE SET
                reason = excluded.reason,
                requested_at = excluded.requested_at,
                code_hash = excluded.code_hash,
                session_id = excluded.session_id",
            params![
                request.reason(),
                requested_at,
                stored_hash,
                encoded_session_id,
            ],
        )?;
        transaction.execute(
            "INSERT INTO emergency_timing(
                singleton, boot_id, monotonic_anchor, unix_anchor, verified_elapsed
             ) VALUES(1, ?1, ?2, ?3, ?4)
             ON CONFLICT(singleton) DO UPDATE SET
                boot_id = excluded.boot_id,
                monotonic_anchor = excluded.monotonic_anchor,
                unix_anchor = excluded.unix_anchor,
                verified_elapsed = excluded.verified_elapsed",
            params![
                encode_boot_id(timing.boot_id()),
                monotonic_anchor,
                unix_anchor,
                verified_elapsed,
            ],
        )?;

        if let Some((session_id, transition)) = transition {
            if session_id != request.session_id() {
                transaction.rollback()?;
                return Err(StoreError::StateMismatch);
            }
            persist_transition_in_transaction(&transaction, session_id, transition)?;
        }

        if let Some(event) = event {
            transaction.execute(
                "INSERT INTO security_events(event_type, payload) VALUES(?1, ?2)",
                params![event.event_type(), event.payload()],
            )?;
        }

        transaction.commit()?;
        Ok(())
    }

    fn emergency_request(&self) -> StoreResult<Option<EmergencyRequest>> {
        let request_row = self
            .connection
            .query_row(
                "SELECT session_id, reason, requested_at
                 FROM emergency_request WHERE singleton = 1",
                [],
                |row| {
                    Ok((
                        row.get::<_, Option<String>>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, i64>(2)?,
                    ))
                },
            )
            .optional()?;

        let Some((Some(session_id), reason, requested_at)) = request_row else {
            return match request_row {
                None => Ok(None),
                Some(_) => Err(StoreError::InvalidEmergencyRequest),
            };
        };

        let timing_row = self
            .connection
            .query_row(
                "SELECT boot_id, monotonic_anchor, unix_anchor, verified_elapsed
                 FROM emergency_timing WHERE singleton = 1",
                [],
                |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, i64>(1)?,
                        row.get::<_, i64>(2)?,
                        row.get::<_, i64>(3)?,
                    ))
                },
            )
            .optional()?
            .ok_or(StoreError::InvalidEmergencyRequest)?;

        let timing = EmergencyTimingState::restore_nanos(
            decode_boot_id(&timing_row.0)?,
            decode_u64(timing_row.1)?,
            decode_u64(timing_row.2)?,
            decode_u64(timing_row.3)?,
        )
        .map_err(|_| StoreError::InvalidEmergencyRequest)?;

        EmergencyRequest::restore(
            decode_session_id(&session_id)?,
            reason,
            decode_u64(requested_at)?,
            timing,
        )
        .map(Some)
        .map_err(|_| StoreError::InvalidEmergencyRequest)
    }

    fn transition_count(&self) -> StoreResult<u64> {
        count_rows(&self.connection, "session_transitions")
    }

    fn security_event_count(&self) -> StoreResult<u64> {
        count_rows(&self.connection, "security_events")
    }
}

fn persist_transition_in_transaction(
    transaction: &rusqlite::Transaction<'_>,
    session_id: SessionId,
    transition: &ValidatedTransition,
) -> StoreResult<()> {
    transaction.execute(
        "INSERT INTO session_transitions(session_id, from_state, to_state) VALUES(?1, ?2, ?3)",
        params![
            encode_session_id(session_id),
            encode_state(transition.from()),
            encode_state(transition.to()),
        ],
    )?;

    let changed = transaction.execute(
        "UPDATE active_session SET state = ?1
         WHERE singleton = 1 AND session_id = ?2 AND state = ?3",
        params![
            encode_state(transition.to()),
            encode_session_id(session_id),
            encode_state(transition.from()),
        ],
    )?;

    if changed != 1 {
        return Err(StoreError::StateMismatch);
    }

    Ok(())
}

fn count_rows(connection: &Connection, table: &str) -> StoreResult<u64> {
    let query = format!("SELECT COUNT(*) FROM {table}");
    let count = connection.query_row(&query, [], |row| row.get::<_, i64>(0))?;
    u64::try_from(count).map_err(|_| StoreError::InvalidCount(count))
}

fn encode_u64(value: u64) -> StoreResult<i64> {
    i64::try_from(value).map_err(|_| StoreError::TimestampOutOfRange(value))
}

fn decode_u64(value: i64) -> StoreResult<u64> {
    u64::try_from(value).map_err(|_| StoreError::InvalidTimestamp(value))
}

fn encode_session_id(session_id: SessionId) -> String {
    format!("{:032x}", session_id.0)
}

fn decode_session_id(value: &str) -> StoreResult<SessionId> {
    u128::from_str_radix(value, 16)
        .map(SessionId)
        .map_err(|_| StoreError::InvalidSessionId(value.to_owned()))
}

fn encode_profile_id(profile_id: ProfileId) -> String {
    format!("{:032x}", profile_id.0)
}

fn decode_profile_id(value: &str) -> StoreResult<ProfileId> {
    u128::from_str_radix(value, 16)
        .map(ProfileId)
        .map_err(|_| StoreError::InvalidProfileId(value.to_owned()))
}

fn encode_boot_id(boot_id: BootId) -> String {
    format!("{:032x}", boot_id.0)
}

fn decode_boot_id(value: &str) -> StoreResult<BootId> {
    u128::from_str_radix(value, 16)
        .map(BootId)
        .map_err(|_| StoreError::InvalidBootId(value.to_owned()))
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
