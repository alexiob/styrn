#![allow(dead_code)]

#[path = "../../mod.rs"]
mod setup;

use setup::action::{
    ActionCheck, ActionDescription, ActionEffect, ActionError, ActionImpl, ActionName, Privilege,
};

struct ForeignAction;

impl ActionImpl for ForeignAction {
    fn name(&self) -> &ActionName {
        panic!()
    }

    fn check(&self) -> Result<ActionCheck, ActionError> {
        panic!()
    }

    fn privilege(&self) -> Privilege {
        panic!()
    }

    fn describe(&self) -> &ActionDescription {
        panic!()
    }

    fn apply_mutation(&mut self) -> Result<ActionEffect, ActionError> {
        panic!()
    }
}

fn main() {}
