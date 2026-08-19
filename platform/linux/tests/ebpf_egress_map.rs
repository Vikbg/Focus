use std::{collections::BTreeSet, net::Ipv4Addr};

use focus_linux::{
    EgressAllowMap, EgressMapError, EgressProtocol, Ipv4EgressRule, replace_egress_rules,
};

#[derive(Debug, Default)]
struct RecordingMap {
    keys: BTreeSet<u64>,
    fail_insert: Option<u64>,
}

impl EgressAllowMap for RecordingMap {
    fn clear(&mut self) -> Result<(), EgressMapError> {
        self.keys.clear();
        Ok(())
    }

    fn insert(&mut self, key: u64) -> Result<(), EgressMapError> {
        if self.fail_insert == Some(key) {
            return Err(EgressMapError::MutationFailed);
        }
        self.keys.insert(key);
        Ok(())
    }

    fn keys(&mut self) -> Result<Vec<u64>, EgressMapError> {
        Ok(self.keys.iter().copied().collect())
    }
}

fn tcp(port: u16) -> Ipv4EgressRule {
    Ipv4EgressRule::new(Ipv4Addr::LOCALHOST, port, EgressProtocol::Tcp).unwrap()
}

#[test]
fn replacement_removes_stale_entries_and_canonicalizes_duplicates() {
    let stale = tcp(7000).map_key();
    let mut map = RecordingMap {
        keys: BTreeSet::from([stale]),
        fail_insert: None,
    };

    replace_egress_rules(&mut map, &[tcp(8000), tcp(8001), tcp(8000)]).unwrap();

    assert_eq!(
        map.keys,
        BTreeSet::from([tcp(8000).map_key(), tcp(8001).map_key()])
    );
}

#[test]
fn partial_map_update_is_reported_as_failure() {
    let denied_key = tcp(8101).map_key();
    let mut map = RecordingMap {
        keys: BTreeSet::new(),
        fail_insert: Some(denied_key),
    };

    assert_eq!(
        replace_egress_rules(&mut map, &[tcp(8100), tcp(8101)]),
        Err(EgressMapError::MutationFailed)
    );
}

#[test]
fn readback_mismatch_is_fail_closed() {
    #[derive(Debug)]
    struct LyingMap;

    impl EgressAllowMap for LyingMap {
        fn clear(&mut self) -> Result<(), EgressMapError> {
            Ok(())
        }

        fn insert(&mut self, _key: u64) -> Result<(), EgressMapError> {
            Ok(())
        }

        fn keys(&mut self) -> Result<Vec<u64>, EgressMapError> {
            Ok(Vec::new())
        }
    }

    assert_eq!(
        replace_egress_rules(&mut LyingMap, &[tcp(8200)]),
        Err(EgressMapError::VerificationFailed)
    );
}
