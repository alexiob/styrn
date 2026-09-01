#[path = "../../mod.rs"]
mod setup;

use serde::{Serialize, Serializer};

struct StatusProxy(setup::probe::ProbeStatus);

impl Serialize for StatusProxy {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        <setup::probe::ProbeStatus as Serialize>::serialize(&self.0, serializer)
    }
}

fn main() {}
