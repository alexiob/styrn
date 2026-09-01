#[path = "../../src/output/mod.rs"]
mod output;

use chrono::{TimeZone, Utc};
use serde_json::json;

fn main() {
    eprintln!("fixture: preparing command output");
    let envelope = output::Envelope::success(
        "project status",
        Utc.with_ymd_and_hms(2026, 9, 1, 12, 0, 0).single().unwrap(),
        json!({"ready": true}),
        vec![],
    )
    .unwrap();
    output::write_json(std::io::stdout(), &envelope).unwrap();
}
