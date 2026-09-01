#[path = "../../mod.rs"]
mod setup;

fn main() {
    let _ = setup::probe::RemediationSpec::new(
        "unsafe shell command",
        Some(vec!["sh".to_owned(), "-c".to_owned(), "echo unsafe".to_owned()]),
    );
}
