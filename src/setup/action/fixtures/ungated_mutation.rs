#![allow(dead_code)]

#[path = "../../mod.rs"]
mod setup;

fn attempt_ungated_mutation(action: &mut setup::action::Action) {
    let _ = action.apply_mutation();
}

fn main() {}
