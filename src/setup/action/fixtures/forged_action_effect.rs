#![allow(dead_code)]

#[path = "../../../platform/mod.rs"]
mod platform;
#[path = "../../mod.rs"]
mod setup;

fn forge(effect: setup::action::ActionEffect) -> setup::action::ActionEffect {
    setup::action::ActionEffect {
        services: Vec::new(),
        ..effect
    }
}

fn main() {}
