//! Destructive native onboarding acceptance gate.
//!
//! Run only inside a fresh disposable ordinary-user account whose native home,
//! Styrn state, and OpenSSH `authorized_keys` may be modified:
//!
//! ```text
//! STYRN_NATIVE_ONBOARDING_DISPOSABLE_USER=1 cargo test --locked \
//!   --test native_onboarding -- --ignored --exact \
//!   native_disposable_user_setup_card_and_controller_enrollment
//! ```

use serde_json::Value;
use std::process::{Command, Output};

#[test]
#[ignore = "environmental: modifies a fresh disposable current user's native Styrn and OpenSSH state and requires a reachable real sshd"]
fn native_disposable_user_setup_card_and_controller_enrollment() {
    assert_eq!(
        std::env::var("STYRN_NATIVE_ONBOARDING_DISPOSABLE_USER").as_deref(),
        Ok("1"),
        "run only in a fresh disposable ordinary-user account"
    );
    for variable in [
        "STYRN_CONFIG_DIR",
        "XDG_CONFIG_HOME",
        "XDG_DATA_HOME",
        "XDG_STATE_HOME",
    ] {
        assert!(
            std::env::var_os(variable).is_none(),
            "{variable} must be unset so the local and SSH sessions use the same native state"
        );
    }

    let initial = success(&run(&["--json", "setup", "--yes", "--no-elevate"]), "setup");
    assert!(initial["data"]["enrollment_card"].is_null());

    let controller = success(&run(&["--json", "controller", "init"]), "controller init");
    assert_eq!(controller["data"]["created"], true, "account was not fresh");
    let public_key = controller["data"]["public_key"]
        .as_str()
        .expect("controller init must return its public key");

    let configured = success(
        &run(&[
            "--json",
            "setup",
            "--yes",
            "--no-elevate",
            "--authorized-keys",
            public_key,
        ]),
        "setup",
    );
    let card = &configured["data"]["enrollment_card"];
    let command = card["command"]
        .as_str()
        .expect("a ready real SSH transport must produce an enrollment card");
    assert!(command.contains(" --user "));
    assert!(command.contains(" --fingerprint SHA256:"));
    assert!(!configured["data"]["pending"]
        .as_array()
        .unwrap()
        .iter()
        .any(|item| item["action_id"] == "ssh.enrollment-card"));
    let manifest: toml::Value = toml::from_str(
        &std::fs::read_to_string(
            configured["data"]["manifest"]
                .as_str()
                .expect("setup must return the published manifest path"),
        )
        .unwrap(),
    )
    .unwrap();
    assert_eq!(
        manifest["ssh"]["host_key_fingerprint"].as_str(),
        card["fingerprint"].as_str()
    );

    let mut enroll_arguments = vec!["--json".to_owned()];
    enroll_arguments.extend(command.split_ascii_whitespace().skip(1).map(str::to_owned));
    success(&run_owned(&enroll_arguments), "host enroll");

    let repeated = success(
        &run(&[
            "--json",
            "setup",
            "--yes",
            "--no-elevate",
            "--authorized-keys",
            public_key,
        ]),
        "setup",
    );
    assert_eq!(repeated["data"]["enrollment_card"], card.clone());
    assert!(repeated["data"]["results"]
        .as_array()
        .unwrap()
        .iter()
        .any(|item| {
            item["action_id"] == "ssh.authorized-keys" && item["status"] == "unchanged"
        }));

    let rendered = format!("{configured}{repeated}");
    assert!(!rendered.contains("PRIVATE KEY"));
    assert!(!rendered.contains("tskey-"));
    assert!(!rendered.contains("password="));
}

fn run(arguments: &[&str]) -> Output {
    command().args(arguments).output().unwrap()
}

fn run_owned(arguments: &[String]) -> Output {
    command().args(arguments).output().unwrap()
}

fn command() -> Command {
    let mut command = Command::new(env!("CARGO_BIN_EXE_styrn"));
    command
        .env_remove("STYRN_CONFIG_DIR")
        .env_remove("STYRN_SSH")
        .env_remove("PHASE1_FIXTURE_ROOT")
        .env_remove("PHASE1_FIXTURE_STYRN")
        .env_remove("PHASE1_FIXTURE_WORKER_CONFIG")
        .stdin(std::process::Stdio::null());
    command
}

fn success(output: &Output, command: &str) -> Value {
    assert!(output.status.success(), "{command}: {output:?}");
    assert!(output.stderr.is_empty(), "{command}: {output:?}");
    let envelope: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(envelope["schema"], "styrn.command.v1");
    assert_eq!(envelope["command"], command);
    assert_eq!(envelope["ok"], true);
    envelope
}
