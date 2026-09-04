use serde_json::Value;
use std::fs;
use std::path::PathBuf;
use std::process::{Command, Output};
use uuid::Uuid;

const PUBLIC_KEY_ONE: &str = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIAABAgMEBQYHCAkKCwwNDg8QERITFBUWFxgZGhscHR4f onboarding-one";
const PUBLIC_KEY_TWO: &str = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIB8eHRwbGhkYFxYVFBMSERAPDg0MCwoJCAcGBQQDAgEA onboarding-two";

#[test]
fn setup_authorized_keys_plan_a_current_user_ssh_authorization_action() {
    let environment = IsolatedEnvironment::new("authorized-keys-plan");
    let output = environment.run(&[
        "--json",
        "setup",
        "--authorized-keys",
        PUBLIC_KEY_ONE,
        PUBLIC_KEY_TWO,
        "--dry-run",
    ]);

    assert!(output.status.success(), "{output:?}");
    assert!(output.stderr.is_empty(), "{output:?}");
    let document = exactly_one_json(&output.stdout);
    assert_eq!(document["schema"], "styrn.command.v1");
    assert_eq!(document["ok"], true);
    assert_eq!(document["command"], "setup");
    let action = document["data"]["plan"]
        .as_array()
        .unwrap()
        .iter()
        .find(|item| item["action_id"] == "ssh.authorized-keys")
        .expect("the dry-run must include the concrete SSH authorization action");
    assert_eq!(action["component"], "ssh-server");
    assert_eq!(action["scope"], "user");
    assert_eq!(action["account"], "current-user");
    assert_eq!(action["privilege"], "none");
    // Production deliberately resolves the native account home rather than
    // this process's test HOME. The exact non-mutating operation therefore
    // reflects the runner's real authorized_keys posture.
    assert!(matches!(
        action["operation"].as_str(),
        Some("create" | "done" | "needs_human")
    ));
    environment.assert_no_setup_state();
}

#[test]
fn setup_authorized_keys_reject_invalid_private_and_secret_shaped_inputs_without_echo_or_state() {
    let environment = IsolatedEnvironment::new("authorized-keys-invalid");
    let private =
        format!("{PUBLIC_KEY_ONE} -----BEGIN OPENSSH PRIVATE KEY----- private-key-never-echo");
    for (input, forbidden) in [
        (
            "ssh-ed25519 not-base64 invalid-key-never-echo".to_owned(),
            "invalid-key-never-echo",
        ),
        (private, "private-key-never-echo"),
        (
            "tskey-auth-k-onboarding-secret-never-echo".to_owned(),
            "onboarding-secret-never-echo",
        ),
        (
            "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIAABAgMEBQYHCAkKCwwNDg8QERITFBUWFxgZGhscHR4f password=hunter2-never-echo".to_owned(),
            "hunter2-never-echo",
        ),
    ] {
        let output =
            environment.run(&["--json", "setup", "--authorized-keys", &input, "--dry-run"]);

        assert_json_failure(&output, 2, "usage.config_invalid", &[&input, forbidden]);
        environment.assert_no_setup_state();
    }
}

#[cfg(target_os = "linux")]
#[test]
fn no_elevate_yes_keeps_machine_work_pending_after_useful_rootless_publication() {
    let environment = IsolatedEnvironment::new("no-elevate-rootless");
    let output = environment.run(&["--json", "setup", "--no-elevate", "--yes"]);

    assert!(output.status.success(), "{output:?}");
    assert!(output.stderr.is_empty(), "{output:?}");
    let document = exactly_one_json(&output.stdout);
    assert_eq!(document["ok"], true);
    let data = &document["data"];
    let plan = data["plan"].as_array().unwrap();
    assert!(plan.iter().all(|item| item["privilege"] == "none"));
    let machine_pending = plan
        .iter()
        .filter(|item| {
            matches!(
                item["component"].as_str(),
                Some("ssh-server" | "tailscale" | "sleep-policy")
            ) && item["operation"] == "needs_human"
        })
        .collect::<Vec<_>>();
    assert!(
        !machine_pending.is_empty(),
        "an unavailable machine capability must remain explicit pending work"
    );
    let pending = data["pending"].as_array().unwrap();
    assert!(machine_pending
        .iter()
        .all(|item| pending.iter().any(|pending| {
            pending["action_id"] == item["action_id"] && pending["severity"] == "warning"
        })));

    assert_eq!(
        data["manifest"],
        environment.manifest_path().to_str().unwrap()
    );
    assert_eq!(
        data["receipt"],
        environment.receipt_path().to_str().unwrap()
    );
    assert!(environment.manifest_path().is_file());
    assert!(environment.receipt_path().is_file());
    for child in ["repos", "jobs", "cache", "artifacts", "logs"] {
        assert!(environment.worker_root().join(child).is_dir());
    }

    let manifest: toml::Value =
        toml::from_str(&fs::read_to_string(environment.manifest_path()).unwrap()).unwrap();
    assert_eq!(manifest["installation"]["scope"].as_str(), Some("user"));
    assert_eq!(
        manifest["worker_identity"]["mode"].as_str(),
        Some("current-user")
    );
    assert_eq!(manifest["worker"]["enabled"].as_bool(), Some(true));
    assert!(manifest["transport"]["user"]
        .as_str()
        .is_some_and(|user| !user.is_empty()));
    assert!(manifest["pending_actions"]
        .as_array()
        .is_some_and(|items| !items.is_empty()));

    let receipt = exactly_one_json(&fs::read(environment.receipt_path()).unwrap());
    assert_eq!(receipt["installation_scope"], "user");
    assert!(receipt["entries"]
        .as_array()
        .is_some_and(|entries| !entries.is_empty()
            && entries
                .iter()
                .all(|entry| entry["privilege_used"] == "none")));
}

fn assert_json_failure(output: &Output, exit: i32, code: &str, forbidden: &[&str]) {
    assert_eq!(output.status.code(), Some(exit), "{output:?}");
    assert!(output.stderr.is_empty(), "{output:?}");
    let document = exactly_one_json(&output.stdout);
    assert_eq!(document["schema"], "styrn.command.v1");
    assert_eq!(document["ok"], false);
    assert!(document["data"].is_null());
    assert_eq!(document["errors"].as_array().unwrap().len(), 1);
    assert_eq!(document["errors"][0]["code"], code);
    let rendered = String::from_utf8_lossy(&output.stdout);
    for value in forbidden {
        assert!(!rendered.contains(value), "failure leaked forbidden input");
    }
}

fn exactly_one_json(stdout: &[u8]) -> Value {
    assert!(!stdout.is_empty());
    serde_json::from_slice(stdout).expect("stdout must contain exactly one JSON document")
}

struct IsolatedEnvironment {
    root: PathBuf,
    work: PathBuf,
    config: PathBuf,
    state: PathBuf,
    data: PathBuf,
}

impl IsolatedEnvironment {
    fn new(label: &str) -> Self {
        let root =
            std::env::temp_dir().join(format!("styrn-onboarding-cli-{label}-{}", Uuid::now_v7()));
        let work = root.join("work");
        fs::create_dir_all(&work).unwrap();
        Self {
            config: root.join("config"),
            state: root.join("state"),
            data: root.join("data"),
            root,
            work,
        }
    }

    fn run(&self, arguments: &[&str]) -> Output {
        let mut command = Command::new(env!("CARGO_BIN_EXE_styrn"));
        command
            .current_dir(&self.work)
            .env_clear()
            .env("HOME", &self.root)
            .env("USERPROFILE", &self.root)
            .env("APPDATA", &self.config)
            .env("LOCALAPPDATA", &self.data)
            .env("XDG_CONFIG_HOME", &self.config)
            .env("XDG_STATE_HOME", &self.state)
            .env("XDG_DATA_HOME", &self.data)
            .env("STYRN_CONFIG_DIR", &self.config)
            .args(arguments);
        command.output().unwrap()
    }

    #[cfg(target_os = "linux")]
    fn manifest_path(&self) -> PathBuf {
        self.config.join("machine.toml")
    }

    #[cfg(target_os = "linux")]
    fn receipt_path(&self) -> PathBuf {
        self.state.join("styrn/receipt.json")
    }

    #[cfg(target_os = "linux")]
    fn worker_root(&self) -> PathBuf {
        self.data.join("styrn")
    }

    fn assert_no_setup_state(&self) {
        assert!(!self.config.exists(), "config state must remain absent");
        assert!(!self.state.exists(), "receipt state must remain absent");
        assert!(!self.data.exists(), "worker data must remain absent");
        assert!(!self.work.join("setup-config.toml").exists());
    }
}

impl Drop for IsolatedEnvironment {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.root);
    }
}
