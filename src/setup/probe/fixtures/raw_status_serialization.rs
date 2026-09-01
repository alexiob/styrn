#[path = "../../mod.rs"]
mod setup;

fn main() {
    let _ = serde_json::to_value(setup::probe::ProbeStatus::Absent);
}
