from pathlib import Path

protocol = Path("crates/focus-protocol/src/lib.rs")
text = protocol.read_text()

anchor = '''/// Typed recovery code submission for an already pending emergency request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EmergencyCodePayload {
    pub code: String,
}

/// Request set supported by the Focus daemon protocol.
'''
replacement = '''/// Typed recovery code submission for an already pending emergency request.
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
'''
if anchor not in text:
    raise SystemExit("protocol replay enum anchor missing")
text = text.replace(anchor, replacement, 1)

anchor = '''impl Request {
    const fn allowed_for(&self, client: ClientKind) -> bool {
'''
replacement = '''impl Request {
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
'''
if anchor not in text:
    raise SystemExit("protocol request impl anchor missing")
text = text.replace(anchor, replacement, 1)
protocol.write_text(text)

storage = Path("crates/focus-storage/src/lib.rs")
text = storage.read_text()
text = text.replace("const CURRENT_SCHEMA_VERSION: i64 = 3;", "const CURRENT_SCHEMA_VERSION: i64 = 4;", 1)

anchor = '''/// Result returned by protected-store operations.
pub type StoreResult<T> = Result<T, StoreError>;

/// Security-relevant event appended to the protected local journal.
'''
replacement = '''/// Result returned by protected-store operations.
pub type StoreResult<T> = Result<T, StoreError>;

/// Durable reservation state for one at-most-once mutation request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MutationReservation {
    Started,
    InProgress,
    Completed(Vec<u8>),
}

/// Security-relevant event appended to the protected local journal.
'''
if anchor not in text:
    raise SystemExit("storage reservation enum anchor missing")
text = text.replace(anchor, replacement, 1)

anchor = '''    /// Returns the number of committed state transitions.
    ///
    /// # Errors
'''
replacement = '''    /// Atomically reserves one mutation request identifier before any effect executes.
    ///
    /// # Errors
    ///
    /// Returns an error if the replay ledger cannot be queried or updated.
    fn reserve_mutation(&mut self, request_id: u128) -> StoreResult<MutationReservation>;

    /// Marks one previously reserved mutation as complete and stores its replay response.
    ///
    /// # Errors
    ///
    /// Returns an error if the request was never reserved or persistence fails.
    fn complete_mutation(&mut self, request_id: u128, response: &[u8]) -> StoreResult<()>;

    /// Returns the number of committed state transitions.
    ///
    /// # Errors
'''
if anchor not in text:
    raise SystemExit("storage trait anchor missing")
text = text.replace(anchor, replacement, 1)

anchor = '''        if version == Some(2) {
            self.migrate_v2_to_v3()?;
        }

        self.validate_current_schema()
'''
replacement = '''        if version == Some(2) {
            self.migrate_v2_to_v3()?;
            version = Some(3);
        }

        if version == Some(3) {
            self.migrate_v3_to_v4()?;
        }

        self.validate_current_schema()
'''
if anchor not in text:
    raise SystemExit("storage migration chain anchor missing")
text = text.replace(anchor, replacement, 1)

anchor = '''    fn validate_current_schema(&self) -> StoreResult<()> {
'''
replacement = '''    fn migrate_v3_to_v4(&mut self) -> StoreResult<()> {
        let transaction = self.connection.transaction()?;
        transaction.execute_batch(
            "
            CREATE TABLE mutation_requests (
                request_id TEXT PRIMARY KEY,
                status INTEGER NOT NULL CHECK (status IN (0, 1)),
                response BLOB
            );
            INSERT INTO schema_migrations(version) VALUES(4);
            ",
        )?;
        transaction.commit()?;
        Ok(())
    }

    fn validate_current_schema(&self) -> StoreResult<()> {
'''
if anchor not in text:
    raise SystemExit("storage v4 migration anchor missing")
text = text.replace(anchor, replacement, 1)

anchor = '''        self.validate_table_columns(
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
'''
replacement = '''        self.validate_table_columns(
            "emergency_timing",
            &[
                "singleton",
                "boot_id",
                "monotonic_anchor",
                "unix_anchor",
                "verified_elapsed",
            ],
        )?;
        self.validate_table_columns(
            "mutation_requests",
            &["request_id", "status", "response"],
        )?;
        self.validate_table_columns("schema_migrations", &["version"])?;
'''
if anchor not in text:
    raise SystemExit("storage schema validation anchor missing")
text = text.replace(anchor, replacement, 1)

anchor = '''    fn transition_count(&self) -> StoreResult<u64> {
        count_rows(&self.connection, "session_transitions")
    }
'''
replacement = '''    fn reserve_mutation(&mut self, request_id: u128) -> StoreResult<MutationReservation> {
        let encoded_request_id = format!("{request_id:032x}");
        let transaction = self.connection.transaction()?;
        let existing = transaction
            .query_row(
                "SELECT status, response FROM mutation_requests WHERE request_id = ?1",
                params![encoded_request_id],
                |row| Ok((row.get::<_, i64>(0)?, row.get::<_, Option<Vec<u8>>>(1)?)),
            )
            .optional()?;

        let reservation = match existing {
            None => {
                transaction.execute(
                    "INSERT INTO mutation_requests(request_id, status, response) VALUES(?1, 0, NULL)",
                    params![encoded_request_id],
                )?;
                MutationReservation::Started
            }
            Some((0, None)) => MutationReservation::InProgress,
            Some((1, Some(response))) => MutationReservation::Completed(response),
            Some(_) => return Err(StoreError::SchemaMismatch("mutation_requests".to_owned())),
        };

        transaction.commit()?;
        Ok(reservation)
    }

    fn complete_mutation(&mut self, request_id: u128, response: &[u8]) -> StoreResult<()> {
        let encoded_request_id = format!("{request_id:032x}");
        let transaction = self.connection.transaction()?;
        let existing = transaction
            .query_row(
                "SELECT status, response FROM mutation_requests WHERE request_id = ?1",
                params![encoded_request_id],
                |row| Ok((row.get::<_, i64>(0)?, row.get::<_, Option<Vec<u8>>>(1)?)),
            )
            .optional()?;

        match existing {
            Some((0, None)) => {
                transaction.execute(
                    "UPDATE mutation_requests SET status = 1, response = ?2 WHERE request_id = ?1",
                    params![encoded_request_id, response],
                )?;
            }
            Some((1, Some(stored))) if stored == response => {}
            _ => return Err(StoreError::StateMismatch),
        }

        transaction.commit()?;
        Ok(())
    }

    fn transition_count(&self) -> StoreResult<u64> {
        count_rows(&self.connection, "session_transitions")
    }
'''
if anchor not in text:
    raise SystemExit("storage replay impl anchor missing")
text = text.replace(anchor, replacement, 1)
storage.write_text(text)
