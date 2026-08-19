use std::{cell::RefCell, rc::Rc};

use focus_linux::{
    FocusNftablesControl, FocusNftablesError, FocusNftablesTransaction, NetworkGuardControl,
    ProductionNetworkGuard,
};

#[derive(Debug, Default)]
struct RecordingState {
    replacements: Vec<String>,
    verifications: Vec<String>,
    removals: usize,
}

#[derive(Debug, Clone)]
struct RecordingControl {
    state: Rc<RefCell<RecordingState>>,
}

impl FocusNftablesControl for RecordingControl {
    fn replace_focus_table(
        &mut self,
        transaction: &FocusNftablesTransaction,
    ) -> Result<(), FocusNftablesError> {
        self.state
            .borrow_mut()
            .replacements
            .push(transaction.render());
        Ok(())
    }

    fn verify_focus_table(
        &mut self,
        transaction: &FocusNftablesTransaction,
    ) -> Result<(), FocusNftablesError> {
        self.state
            .borrow_mut()
            .verifications
            .push(transaction.render());
        Ok(())
    }

    fn remove_focus_table(&mut self) -> Result<(), FocusNftablesError> {
        self.state.borrow_mut().removals += 1;
        Ok(())
    }
}

#[test]
fn production_network_guard_uses_strict_focus_owned_transaction_for_full_lifecycle() {
    let state = Rc::new(RefCell::new(RecordingState::default()));
    let control = RecordingControl {
        state: Rc::clone(&state),
    };
    let mut guard = ProductionNetworkGuard::with_control(control);

    guard.arm().unwrap();
    guard.verify().unwrap();
    guard.disarm().unwrap();

    let state = state.borrow();
    assert_eq!(state.replacements.len(), 1);
    assert_eq!(state.verifications.len(), 2);
    assert_eq!(state.removals, 1);
    assert!(state.replacements[0].contains("policy drop"));
    assert!(
        state
            .verifications
            .iter()
            .all(|script| script.contains("policy drop"))
    );
}
