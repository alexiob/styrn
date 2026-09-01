#![allow(dead_code)]

#[path = "../../mod.rs"]
mod setup;

use setup::action::Action;

struct ForeignAction;

impl Action for ForeignAction {}

fn main() {}
