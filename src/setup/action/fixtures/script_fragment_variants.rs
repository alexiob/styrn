#![allow(dead_code)]

#[path = "../../mod.rs"]
mod setup;

fn only_typed_script_variants(fragment: setup::action::ScriptFragment) {
    match fragment {
        setup::action::ScriptFragment::DeferredAction(_) => {}
    }
}

fn main() {}
