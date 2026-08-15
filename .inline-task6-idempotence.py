from pathlib import Path

protocol = Path("crates/focus-protocol/src/lib.rs")
text = protocol.read_text()
anchor = '''    /// Returns the replay semantics required for this request class.
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

'''
replacement = anchor + '''    /// Returns stable bytes used to detect request-id reuse with a different payload.
    #[must_use]
    pub fn replay_fingerprint(&self) -> Vec<u8> {
        let (request, argument) = self.wire_parts();
        format!("{request}|{argument}").into_bytes()
    }

'''
if anchor not in text:
    raise SystemExit("replay fingerprint anchor missing")
text = text.replace(anchor, replacement, 1)

text = text.replace(
'''    PeerAuthenticationFailed,
}''',
'''    PeerAuthenticationFailed,
    RequestInProgress,
    InternalFailure,
}''',
1,
)
text = text.replace(
'''            Self::PeerAuthenticationFailed => "peer-authentication-failed",
''',
'''            Self::PeerAuthenticationFailed => "peer-authentication-failed",
            Self::RequestInProgress => "request-in-progress",
            Self::InternalFailure => "internal-failure",
''',
1,
)
text = text.replace(
'''            "peer-authentication-failed" => Ok(Self::PeerAuthenticationFailed),
''',
'''            "peer-authentication-failed" => Ok(Self::PeerAuthenticationFailed),
            "request-in-progress" => Ok(Self::RequestInProgress),
            "internal-failure" => Ok(Self::InternalFailure),
''',
1,
)
protocol.write_text(text)

storage = Path("crates/focus-storage/src/lib.rs")
text = storage.read_text()
text = text.replace(
'''pub enum MutationReservation {
    Started,
    InProgress,
    Completed(Vec<u8>),
}''',
'''pub enum MutationReservation {
    Started,
    InProgress,
    Completed(Vec<u8>),
    Conflict,
}''',
1,
)
text = text.replace(
'''    fn reserve_mutation(&mut self, request_id: u128) -> StoreResult<MutationReservation>;''',
'''    fn reserve_mutation(
        &mut self,
        request_id: u128,
        request_fingerprint: &[u8],
    ) -> StoreResult<MutationReservation>;''',
1,
)
text = text.replace(
'''            CREATE TABLE mutation_requests (
                request_id TEXT PRIMARY KEY,
                status INTEGER NOT NULL CHECK (status IN (0, 1)),
                response BLOB
            );''',
'''            CREATE TABLE mutation_requests (
                request_id TEXT PRIMARY KEY,
                request_fingerprint BLOB NOT NULL,
                status INTEGER NOT NULL CHECK (status IN (0, 1)),
                response BLOB
            );''',
1,
)
text = text.replace(
'''            &["request_id", "status", "response"],''',
'''            &["request_id", "request_fingerprint", "status", "response"],''',
1,
)
old = '''    fn reserve_mutation(&mut self, request_id: u128) -> StoreResult<MutationReservation> {
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
'''
new = '''    fn reserve_mutation(
        &mut self,
        request_id: u128,
        request_fingerprint: &[u8],
    ) -> StoreResult<MutationReservation> {
        let encoded_request_id = format!("{request_id:032x}");
        let transaction = self.connection.transaction()?;
        let existing = transaction
            .query_row(
                "SELECT request_fingerprint, status, response FROM mutation_requests WHERE request_id = ?1",
                params![encoded_request_id],
                |row| {
                    Ok((
                        row.get::<_, Vec<u8>>(0)?,
                        row.get::<_, i64>(1)?,
                        row.get::<_, Option<Vec<u8>>>(2)?,
                    ))
                },
            )
            .optional()?;

        let reservation = match existing {
            None => {
                transaction.execute(
                    "INSERT INTO mutation_requests(request_id, request_fingerprint, status, response) VALUES(?1, ?2, 0, NULL)",
                    params![encoded_request_id, request_fingerprint],
                )?;
                MutationReservation::Started
            }
            Some((stored_fingerprint, _, _)) if stored_fingerprint != request_fingerprint => {
                MutationReservation::Conflict
            }
            Some((_, 0, None)) => MutationReservation::InProgress,
            Some((_, 1, Some(response))) => MutationReservation::Completed(response),
            Some(_) => return Err(StoreError::SchemaMismatch("mutation_requests".to_owned())),
        };

        transaction.commit()?;
        Ok(reservation)
    }
'''
if old not in text:
    raise SystemExit("storage reserve mutation implementation anchor missing")
text = text.replace(old, new, 1)
storage.write_text(text)
