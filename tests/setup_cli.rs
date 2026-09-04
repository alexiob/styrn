use serde_json::Value;
use std::fs;
#[cfg(unix)]
use std::io::Write;
use std::path::PathBuf;
#[cfg(unix)]
use std::process::{Child, Stdio};
use std::process::{Command, Output};
use uuid::Uuid;

const CAVEAT: &str = "Current-user mode provides no OS-account isolation, no controller-credential isolation, and no same-user Styrn-state integrity boundary.";

#[test]
fn setup_dry_run_human_and_json_have_plan_only_and_write_nothing() {
    let environment = IsolatedEnvironment::new("dry-run");

    let human = environment.run(&["setup", "--dry-run"]);
    assert!(human.status.success(), "{human:?}");
    assert!(human.stderr.is_empty(), "{human:?}");
    let human_stdout = String::from_utf8(human.stdout).unwrap();
    assert!(human_stdout.contains("scope=user role=worker account=current-user"));
    assert!(human_stdout.contains(CAVEAT));
    assert!(human_stdout.contains("identity.directory.root"));
    environment.assert_no_setup_state();

    let json = environment.run(&["--json", "setup", "--dry-run"]);
    assert!(json.status.success(), "{json:?}");
    assert!(json.stderr.is_empty(), "{json:?}");
    let document = exactly_one_json(&json.stdout);
    assert_eq!(document["schema"], "styrn.command.v1");
    assert_eq!(document["ok"], true);
    assert_eq!(document["command"], "setup");
    let data = document["data"].as_object().unwrap();
    assert_eq!(data.len(), 1);
    let plan = data["plan"].as_array().unwrap();
    assert!(!plan.is_empty());
    assert!(plan.iter().all(|item| item["security_caveat"] == CAVEAT));
    assert!(document["warnings"].as_array().unwrap().is_empty());
    assert!(document["errors"].as_array().unwrap().is_empty());
    environment.assert_no_setup_state();
}

#[test]
fn bare_setup_without_tty_prints_plan_exits_confirmation_required_and_writes_nothing() {
    let environment = IsolatedEnvironment::new("confirmation-required");

    let human = environment.run(&["setup"]);
    assert_eq!(human.status.code(), Some(13), "{human:?}");
    let stdout = String::from_utf8(human.stdout).unwrap();
    assert!(stdout.contains("scope=user role=worker account=current-user"));
    assert!(stdout.contains(CAVEAT));
    assert!(stdout.contains("identity.directory.root"));
    assert_eq!(
        String::from_utf8(human.stderr).unwrap().trim(),
        "setup confirmation is required"
    );
    environment.assert_no_setup_state();

    let json = environment.run(&["--json", "setup"]);
    assert_eq!(json.status.code(), Some(13), "{json:?}");
    assert!(json.stderr.is_empty(), "{json:?}");
    let document = exactly_one_json(&json.stdout);
    assert_eq!(document["ok"], false);
    assert_eq!(document["errors"][0]["code"], "setup.confirmation_required");
    let plan = document["errors"][0]["details"]["plan"].as_array().unwrap();
    assert!(!plan.is_empty());
    assert!(plan.iter().all(|item| item["security_caveat"] == CAVEAT));
    environment.assert_no_setup_state();
}

#[test]
fn setup_json_config_probe_confirmation_apply_and_receipt_failures_are_one_secret_free_envelope() {
    let environment = IsolatedEnvironment::new("json-failures");
    let secret = "never-display-this-password-value";
    let config_path = environment.work.join("secret-config.toml");
    fs::write(
        &config_path,
        format!("schema_version = 1\npassword = {secret:?}\n"),
    )
    .unwrap();

    let config = environment.run(&[
        "--json",
        "setup",
        "--config",
        config_path.to_str().unwrap(),
        "--yes",
    ]);
    assert_one_failure(&config, 2, "usage.config_invalid", &[secret]);

    let clap = environment.run(&["--json", "setup", "--unknown-password", secret]);
    assert_one_failure(&clap, 2, "usage.invalid_argument", &[secret]);
    let environment_json = environment
        .command()
        .env("STYRN_JSON", "1")
        .args(["setup", "--unknown-password", secret])
        .output()
        .unwrap();
    assert_one_failure(&environment_json, 2, "usage.invalid_argument", &[secret]);

    let probe = environment
        .command()
        .env("STYRN_CONFIG_DIR", "relative-config-dir")
        .args(["--json", "setup", "--yes"])
        .output()
        .unwrap();
    assert_one_failure(&probe, 13, "setup.probe_failed", &[]);

    let confirmation = environment.run(&["--json", "setup"]);
    assert_one_failure(&confirmation, 13, "setup.confirmation_required", &[]);
    environment.assert_no_setup_state();

    let receipt_environment = IsolatedEnvironment::new("json-receipt-failure");
    let receipt_path = receipt_environment.receipt_path();
    fs::create_dir_all(receipt_path.parent().unwrap()).unwrap();
    fs::write(&receipt_path, b"{}\n").unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(
            receipt_path.parent().unwrap(),
            fs::Permissions::from_mode(0o700),
        )
        .unwrap();
        fs::set_permissions(&receipt_path, fs::Permissions::from_mode(0o600)).unwrap();
    }
    let receipt = receipt_environment.run(&["--json", "setup", "--yes"]);
    assert_one_failure(&receipt, 13, "setup.receipt_conflict", &[]);
    assert!(!receipt_environment.manifest_path().exists());
    #[cfg(target_os = "linux")]
    assert!(!receipt_environment.worker_root().exists());

    #[cfg(target_os = "linux")]
    {
        use std::os::unix::fs::PermissionsExt;
        let apply_environment = IsolatedEnvironment::new("json-apply-failure");
        fs::create_dir_all(&apply_environment.data).unwrap();
        fs::set_permissions(&apply_environment.data, fs::Permissions::from_mode(0o500)).unwrap();
        let apply = apply_environment.run(&["--json", "setup", "--yes"]);
        fs::set_permissions(&apply_environment.data, fs::Permissions::from_mode(0o700)).unwrap();
        assert_one_failure(&apply, 13, "setup.apply_failed", &[]);
        assert!(!apply_environment.manifest_path().exists());
        assert!(!apply_environment.worker_root().exists());
    }
}

#[test]
fn setup_interactive_without_tty_exits_usage_with_hint_and_writes_nothing() {
    let environment = IsolatedEnvironment::new("interactive-no-tty");

    let human = environment.run(&["setup", "--interactive"]);
    assert_eq!(human.status.code(), Some(2), "{human:?}");
    assert!(human.stdout.is_empty(), "{human:?}");
    let diagnostic = String::from_utf8(human.stderr).unwrap();
    assert!(diagnostic.contains("--interactive requires a terminal"));
    assert!(diagnostic.contains("--config"));
    assert!(diagnostic.contains("explicit flags"));
    environment.assert_no_setup_state();
}

#[cfg(unix)]
#[test]
fn bare_setup_in_tty_decline_prints_the_complete_plan_before_one_confirmation() {
    let environment = IsolatedEnvironment::new("tty-decline");
    let output = environment.run_in_pty(&["setup"], b"n\n");
    assert_eq!(output.status.code(), Some(13), "{output:?}");
    let transcript = String::from_utf8_lossy(&output.stdout);
    let plan_position = transcript.find("identity.directory.root").unwrap();
    let prompt = "Apply this rootless user-scope plan? [y/N]";
    let prompt_position = transcript.find(prompt).unwrap();
    assert!(plan_position < prompt_position);
    assert_eq!(transcript.matches(prompt).count(), 1);
    assert!(transcript.contains("setup confirmation is required"));
    environment.assert_no_setup_state();
}

#[cfg(target_os = "linux")]
#[test]
fn interactive_refusal_and_eof_at_final_confirmation_write_no_replay_or_setup_state() {
    let refusal = IsolatedEnvironment::new("interactive-refusal");
    let refused = refusal.run_in_pty(&["setup", "--interactive"], b"worker\n\nalpha\nn\n");
    let eof = IsolatedEnvironment::new("interactive-eof");
    let ended = eof.run_in_pty_then_eof(&["setup", "--interactive"], b"worker\n\nalpha\n");

    for (environment, output) in [(&refusal, refused), (&eof, ended)] {
        assert_eq!(output.status.code(), Some(13), "{output:?}");
        let transcript = String::from_utf8_lossy(&output.stdout);
        assert!(transcript.contains("identity.directory.root"));
        assert_eq!(
            transcript
                .matches("Apply this rootless user-scope plan? [y/N]")
                .count(),
            1
        );
        environment.assert_no_setup_state();
    }
}

#[cfg(target_os = "linux")]
#[test]
fn setup_yes_in_isolated_user_dirs_creates_exact_tree_receipt_and_manifest() {
    let environment = IsolatedEnvironment::new("yes");
    let output = environment.run(&["setup", "--yes"]);

    assert!(output.status.success(), "{output:?}");
    assert!(environment.manifest_path().is_file());
    assert!(environment.receipt_path().is_file());
    environment.assert_exact_worker_tree();
    let manifest = fs::read_to_string(environment.manifest_path()).unwrap();
    assert!(manifest.contains("scope = \"user\""));
    assert!(manifest.contains("mode = \"current-user\""));
    assert!(manifest.contains("isolation = \"shared-user\""));
}

#[cfg(target_os = "linux")]
#[test]
fn setup_json_success_is_one_envelope_with_plan_results_pending_and_paths() {
    let environment = IsolatedEnvironment::new("json-success");
    let output = environment.run(&["--json", "setup", "--yes"]);

    assert!(output.status.success(), "{output:?}");
    assert!(output.stderr.is_empty(), "{output:?}");
    let document = exactly_one_json(&output.stdout);
    assert_eq!(document["ok"], true);
    let data = document["data"].as_object().unwrap();
    assert_eq!(
        data.keys()
            .map(String::as_str)
            .collect::<std::collections::BTreeSet<_>>(),
        ["manifest", "pending", "plan", "receipt", "results"]
            .into_iter()
            .collect()
    );
    assert_eq!(
        data["manifest"],
        environment.manifest_path().to_str().unwrap()
    );
    assert_eq!(
        data["receipt"],
        environment.receipt_path().to_str().unwrap()
    );
    let result_ids = data["results"]
        .as_array()
        .unwrap()
        .iter()
        .map(|result| result["action_id"].as_str().unwrap())
        .collect::<std::collections::BTreeSet<_>>();
    assert_eq!(result_ids.len(), data["results"].as_array().unwrap().len());
    assert!(data["pending"]
        .as_array()
        .is_some_and(|items| !items.is_empty()));
}

#[cfg(target_os = "linux")]
#[test]
fn setup_yes_never_authorizes_or_elevates_and_missing_machine_work_is_pending() {
    let environment = IsolatedEnvironment::new("rootless-pending");
    let output = environment.run(&["--json", "setup", "--yes", "--no-elevate"]);

    assert!(output.status.success(), "{output:?}");
    let document = exactly_one_json(&output.stdout);
    assert!(document["data"]["plan"]
        .as_array()
        .unwrap()
        .iter()
        .all(|item| item["privilege"] == "none"));
    assert!(document["data"]["pending"]
        .as_array()
        .is_some_and(|items| !items.is_empty()));
    let receipt = exactly_one_json(&fs::read(environment.receipt_path()).unwrap());
    for entry in receipt["entries"].as_array().unwrap() {
        for field in [
            "files_created",
            "files_modified",
            "services",
            "accounts",
            "registry_keys",
            "firewall_rules",
        ] {
            assert_eq!(entry[field], serde_json::json!([]));
        }
        assert!(entry["download_provenance"].is_null());
    }
}

#[cfg(target_os = "linux")]
#[test]
fn setup_fail_on_pending_exits_thirteen_after_preserving_correct_state() {
    let environment = IsolatedEnvironment::new("fail-pending");
    let config = environment.work.join("strict.toml");
    fs::write(
        &config,
        "schema_version = 1\n[pending_policy]\nfail_on_pending = true\n",
    )
    .unwrap();
    let output = environment.run(&[
        "--json",
        "setup",
        "--yes",
        "--config",
        config.to_str().unwrap(),
    ]);

    assert_one_failure(&output, 13, "setup.needs_human", &[]);
    assert!(environment.manifest_path().is_file());
    assert!(environment.receipt_path().is_file());
    environment.assert_exact_worker_tree();
    assert!(output
        .stdout
        .windows(b"pending".len())
        .any(|value| value == b"pending"));
}

#[cfg(target_os = "linux")]
#[test]
fn setup_second_run_preserves_uuid_policy_and_bytes_without_duplicate_receipt_entries() {
    let environment = IsolatedEnvironment::new("rerun");
    let first = environment.run(&["--json", "setup", "--yes"]);
    assert!(first.status.success(), "{first:?}");
    let mut manifest: toml::Value =
        toml::from_str(&fs::read_to_string(environment.manifest_path()).unwrap()).unwrap();
    let machine_id = manifest["machine_id"].as_str().unwrap().to_owned();
    manifest["resources"]["policy"] = toml::toml! {
        reserved_memory_bytes = 7340032001_i64
        reserved_disk_percent = 23
        reserved_cpus = 2
        max_parallel_compile_jobs = 5
        max_parallel_test_jobs = 4
        max_heavy_jobs = 1
        max_job_disk_bytes = 9876543210_i64
    }
    .into();
    fs::write(
        environment.manifest_path(),
        toml::to_string_pretty(&manifest).unwrap(),
    )
    .unwrap();

    let second = environment.run(&["--json", "setup", "--yes"]);
    assert!(second.status.success(), "{second:?}");
    let rerun_manifest: toml::Value =
        toml::from_str(&fs::read_to_string(environment.manifest_path()).unwrap()).unwrap();
    assert_eq!(
        rerun_manifest["machine_id"].as_str(),
        Some(machine_id.as_str())
    );
    assert_eq!(
        rerun_manifest["resources"]["policy"]["reserved_disk_percent"].as_integer(),
        Some(23)
    );
    let receipt = exactly_one_json(&fs::read(environment.receipt_path()).unwrap());
    let ids = receipt["entries"]
        .as_array()
        .unwrap()
        .iter()
        .map(|entry| entry["action"]["parameters"]["action_id"].as_str().unwrap())
        .collect::<std::collections::BTreeSet<_>>();
    assert_eq!(ids.len(), receipt["entries"].as_array().unwrap().len());

    let manifest_bytes = fs::read(environment.manifest_path()).unwrap();
    let receipt_bytes = fs::read(environment.receipt_path()).unwrap();
    let third = environment.run(&["--json", "setup", "--yes"]);
    assert!(third.status.success(), "{third:?}");
    assert_eq!(
        fs::read(environment.manifest_path()).unwrap(),
        manifest_bytes
    );
    assert_eq!(fs::read(environment.receipt_path()).unwrap(), receipt_bytes);
}

#[cfg(target_os = "linux")]
#[test]
fn setup_config_and_equivalent_flags_converge_to_byte_identical_state() {
    let environment = IsolatedEnvironment::new("equivalent");
    let config = environment.work.join("equivalent.toml");
    fs::write(
        &config,
        "schema_version = 1\nrole = \"worker\"\nname = \"alpha\"\n[installation]\nscope = \"user\"\n[account]\nmode = \"current-user\"\n",
    )
    .unwrap();
    let configured = environment.run(&["setup", "--yes", "--config", config.to_str().unwrap()]);
    assert!(configured.status.success(), "{configured:?}");
    let manifest = fs::read(environment.manifest_path()).unwrap();
    let receipt = fs::read(environment.receipt_path()).unwrap();

    let flagged = environment.run(&[
        "setup",
        "--yes",
        "--role",
        "worker",
        "--scope",
        "user",
        "--account",
        "current-user",
        "--name",
        "alpha",
    ]);
    assert!(flagged.status.success(), "{flagged:?}");
    assert_eq!(fs::read(environment.manifest_path()).unwrap(), manifest);
    assert_eq!(fs::read(environment.receipt_path()).unwrap(), receipt);
    environment.assert_exact_worker_tree();
}

#[cfg(target_os = "linux")]
#[test]
fn bare_setup_in_tty_prints_plan_confirms_once_and_converges() {
    let environment = IsolatedEnvironment::new("bare-tty");
    let first = environment.run_in_pty(&["setup"], b"yes\n");
    assert!(first.status.success(), "{first:?}");
    let transcript = String::from_utf8_lossy(&first.stdout);
    assert_eq!(
        transcript
            .matches("Apply this rootless user-scope plan? [y/N]")
            .count(),
        1
    );
    let manifest = fs::read(environment.manifest_path()).unwrap();
    let second = environment.run(&["setup", "--yes"]);
    assert!(second.status.success(), "{second:?}");
    assert_eq!(fs::read(environment.manifest_path()).unwrap(), manifest);
}

#[cfg(target_os = "linux")]
#[test]
fn setup_interactive_in_pty_writes_replayable_config_and_matches_flags() {
    let environment = IsolatedEnvironment::new("interactive-pty");
    let output = environment.run_in_pty(&["setup", "--interactive"], b"worker\n\nalpha\nyes\n");
    assert!(output.status.success(), "{output:?}");
    let replay = environment.work.join("setup-config.toml");
    assert!(replay.is_file());
    let manifest = fs::read(environment.manifest_path()).unwrap();
    let receipt = fs::read(environment.receipt_path()).unwrap();
    let flagged = environment.run(&["setup", "--yes", "--name", "alpha"]);
    assert!(flagged.status.success(), "{flagged:?}");
    assert_eq!(fs::read(environment.manifest_path()).unwrap(), manifest);
    assert_eq!(fs::read(environment.receipt_path()).unwrap(), receipt);
    environment.assert_exact_worker_tree();
}

#[cfg(target_os = "linux")]
#[test]
fn setup_native_linux_xdg_journeys() {
    let environment = IsolatedEnvironment::new("native-linux");
    let output = environment.run(&["--json", "setup", "--yes"]);
    assert!(output.status.success(), "{output:?}");
    let document = exactly_one_json(&output.stdout);
    assert_eq!(
        document["data"]["manifest"],
        environment.manifest_path().to_str().unwrap()
    );
    assert_eq!(
        document["data"]["receipt"],
        environment.receipt_path().to_str().unwrap()
    );
    environment.assert_exact_worker_tree();
}

#[cfg(target_os = "macos")]
#[test]
#[ignore = "requires a disposable ordinary macOS account whose native pw_dir may be modified, plus native SSH, Tailscale, and power probe prerequisites"]
fn setup_native_macos_disposable_user_journeys() {
    assert_eq!(
        std::env::var("STYRN_TEST_DISPOSABLE_MACOS_USER").as_deref(),
        Ok("1"),
        "set STYRN_TEST_DISPOSABLE_MACOS_USER=1 only inside a disposable ordinary macOS account whose native pw_dir may be modified"
    );
    assert_ne!(
        unsafe { libc::geteuid() },
        0,
        "the disposable macOS test account must not be root"
    );
    let home = std::env::var_os("HOME").expect("the disposable macOS account requires HOME");
    let mut command = Command::new(env!("CARGO_BIN_EXE_styrn"));
    command
        .env_clear()
        .env("HOME", home)
        .env("LANG", "C")
        .args(["--json", "setup", "--yes"]);
    assert_native_apply(command.output().unwrap());
}

#[cfg(target_os = "windows")]
#[test]
#[ignore = "requires a disposable ordinary native Windows profile whose known folders may be modified, plus native OpenSSH, Tailscale, power, and optional ConPTY prerequisites"]
fn setup_native_windows_disposable_profile_journeys() {
    assert_eq!(
        std::env::var("STYRN_TEST_DISPOSABLE_WINDOWS_PROFILE").as_deref(),
        Ok("1"),
        "set STYRN_TEST_DISPOSABLE_WINDOWS_PROFILE=1 only inside a disposable ordinary native Windows profile whose known folders may be modified"
    );
    let app_data = std::env::var_os("APPDATA")
        .expect("the disposable native Windows profile requires APPDATA");
    let local_app_data = std::env::var_os("LOCALAPPDATA")
        .expect("the disposable native Windows profile requires LOCALAPPDATA");
    let user_profile = std::env::var_os("USERPROFILE")
        .expect("the disposable native Windows profile requires USERPROFILE");
    let mut command = Command::new(env!("CARGO_BIN_EXE_styrn"));
    command
        .env_clear()
        .env("APPDATA", app_data)
        .env("LOCALAPPDATA", local_app_data)
        .env("USERPROFILE", user_profile)
        .args(["--json", "setup", "--yes"]);
    assert_native_apply(command.output().unwrap());
}

#[cfg(any(target_os = "macos", target_os = "windows"))]
fn assert_native_apply(output: Output) {
    assert!(output.status.success(), "{output:?}");
    assert!(output.stderr.is_empty(), "{output:?}");
    let document = exactly_one_json(&output.stdout);
    assert_eq!(document["ok"], true);
    let data = &document["data"];
    assert!(data["plan"]
        .as_array()
        .unwrap()
        .iter()
        .all(|item| item["privilege"] == "none"));
    let manifest_path = PathBuf::from(data["manifest"].as_str().unwrap());
    let receipt_path = PathBuf::from(data["receipt"].as_str().unwrap());
    assert!(manifest_path.is_absolute() && manifest_path.is_file());
    assert!(receipt_path.is_absolute() && receipt_path.is_file());
    let manifest: toml::Value =
        toml::from_str(&fs::read_to_string(manifest_path).unwrap()).unwrap();
    assert_eq!(manifest["installation"]["scope"].as_str(), Some("user"));
    assert_eq!(
        manifest["worker_identity"]["mode"].as_str(),
        Some("current-user")
    );
    for name in ["root", "repos", "jobs", "cache", "artifacts", "logs"] {
        assert!(PathBuf::from(manifest["paths"][name].as_str().unwrap()).is_dir());
    }
    let receipt = exactly_one_json(&fs::read(receipt_path).unwrap());
    assert_eq!(receipt["schema_version"], 1);
}

#[cfg(target_os = "macos")]
#[test]
fn setup_macos_home_spoof_dry_run_does_not_write() {
    let environment = IsolatedEnvironment::new("macos-home-spoof");
    let output = environment.run(&["--json", "setup", "--dry-run"]);
    assert!(output.status.success(), "{output:?}");
    environment.assert_no_setup_state();
}

#[cfg(target_os = "windows")]
#[test]
fn setup_windows_localappdata_spoof_dry_run_does_not_write() {
    let environment = IsolatedEnvironment::new("windows-profile-spoof");
    let output = environment.run(&["--json", "setup", "--dry-run"]);
    assert!(output.status.success(), "{output:?}");
    environment.assert_no_setup_state();
}

fn assert_one_failure(output: &Output, exit: i32, code: &str, forbidden: &[&str]) {
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
        let root = std::env::temp_dir().join(format!("styrn-setup-cli-{label}-{}", Uuid::now_v7()));
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

    fn command(&self) -> Command {
        let mut command = Command::new(env!("CARGO_BIN_EXE_styrn"));
        self.configure_command(&mut command);
        command
    }

    fn configure_command(&self, command: &mut Command) {
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
            .env("STYRN_CONFIG_DIR", &self.config);
    }

    fn run(&self, arguments: &[&str]) -> Output {
        self.command().args(arguments).output().unwrap()
    }

    #[cfg(unix)]
    fn run_in_pty(&self, arguments: &[&str], input: &[u8]) -> Output {
        let mut command = self.pty_command(arguments);
        command
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        let mut child: Child = command.spawn().unwrap();
        let mut child_input = child.stdin.take().unwrap();
        child_input.write_all(input).unwrap();
        let output = child.wait_with_output().unwrap();
        drop(child_input);
        output
    }

    #[cfg(target_os = "linux")]
    fn run_in_pty_then_eof(&self, arguments: &[&str], input: &[u8]) -> Output {
        let mut command = self.pty_command(arguments);
        command
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        let mut child: Child = command.spawn().unwrap();
        child.stdin.take().unwrap().write_all(input).unwrap();
        child.wait_with_output().unwrap()
    }

    #[cfg(target_os = "macos")]
    fn pty_command(&self, arguments: &[&str]) -> Command {
        let mut command = Command::new("/usr/bin/script");
        self.configure_command(&mut command);
        command
            .args(["-q", "-e", "/dev/null", env!("CARGO_BIN_EXE_styrn")])
            .args(arguments);
        command
    }

    #[cfg(all(unix, not(target_os = "macos")))]
    fn pty_command(&self, arguments: &[&str]) -> Command {
        let executable = env!("CARGO_BIN_EXE_styrn");
        assert!(executable
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"/_-.".contains(&byte)));
        assert!(arguments.iter().all(|argument| argument
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"/_-.".contains(&byte))));
        let invocation = std::iter::once(executable)
            .chain(arguments.iter().copied())
            .collect::<Vec<_>>()
            .join(" ");
        let mut command = Command::new("script");
        self.configure_command(&mut command);
        command.args(["-q", "-e", "-c", &invocation, "/dev/null"]);
        command
    }

    fn manifest_path(&self) -> PathBuf {
        self.config.join("machine.toml")
    }

    fn receipt_path(&self) -> PathBuf {
        #[cfg(target_os = "linux")]
        let path = self.state.join("styrn/receipt.json");
        #[cfg(target_os = "macos")]
        let path = self
            .root
            .join("Library/Application Support/Styrn/receipt.json");
        #[cfg(target_os = "windows")]
        let path = self.data.join("Styrn/receipt.json");
        path
    }

    #[cfg(target_os = "linux")]
    fn worker_root(&self) -> PathBuf {
        self.data.join("styrn")
    }

    #[cfg(target_os = "linux")]
    fn assert_exact_worker_tree(&self) {
        let worker = self.data.join("styrn");
        let mut names = fs::read_dir(&worker)
            .unwrap()
            .map(|entry| entry.unwrap().file_name().into_string().unwrap())
            .collect::<Vec<_>>();
        names.sort();
        assert_eq!(names, ["artifacts", "cache", "jobs", "logs", "repos"]);
        assert!(names.iter().all(|name| worker.join(name).is_dir()));
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
