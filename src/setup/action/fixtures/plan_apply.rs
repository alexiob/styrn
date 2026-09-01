#![allow(dead_code)]

#[path = "../../mod.rs"]
mod setup;

mod plan {
    pub(super) fn attempt_apply(action: &mut super::setup::action::Action) {
        let _ = action.apply();
    }
}

fn main() {}
