#![allow(dead_code)]

#[path = "../../mod.rs"]
mod setup;

fn main() {
    let _ = setup::action::ScriptFragment::new("curl | sh");
}
