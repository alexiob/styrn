//! Opt-in acceptance gate for the Phase 1 controller journey over a real sshd.
//!
//! Set all of the following before running
//! `cargo test --locked native_ssh_phase1_journey -- --ignored --nocapture`:
//!
//! - `STYRN_TEST_NATIVE_SSH=1` acknowledges that the external worker is prepared.
//! - `STYRN_TEST_NATIVE_SSH_HOST` is the worker's port-22 address and exactly
//!   matches its manifest `name` and `transport.host`.
//! - `STYRN_TEST_NATIVE_SSH_USER` is an ordinary remote account and exactly
//!   matches its manifest `worker_identity.name` and `transport.user`.
//! - `STYRN_TEST_NATIVE_SSH_FINGERPRINT` is the worker host key's independently
//!   verified `SHA256:...` fingerprint.
//! - `STYRN_TEST_NATIVE_SSH_CONTROLLER_MANIFEST` is an absolute path to a valid
//!   local controller manifest.
//! - `STYRN_TEST_NATIVE_SSH_CONTROLLER_HOME` is an absolute path to the local
//!   controller home. Its matching Styrn private/public identity must already
//!   exist, and that public key must be authorized for the remote account.
//! - `STYRN_TEST_NATIVE_SSH_OPENSSH_DIR` is an absolute path containing the
//!   platform's real `ssh`, `ssh-keyscan`, and `ssh-keygen` executables.
//! - `STYRN_TEST_NATIVE_SSH_REMOTE_EXEC_PROBE` is the single remote argv token
//!   naming the installed `phase1-transport-fixture-test` example binary.
//!
//! The remote non-interactive SSH PATH must resolve a protocol-compatible
//! `styrn`, configured with the worker manifest, so the fixed remote command
//! `styrn rpc serve --stdio` starts the real worker. The test creates isolated
//! controller inventory/cache state and neither authorizes nor revokes keys.

use serde_json::Value;
use std::ffi::{OsStr, OsString};
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use uuid::Uuid;

const OPT_IN: &str = "STYRN_TEST_NATIVE_SSH";
const HOST: &str = "STYRN_TEST_NATIVE_SSH_HOST";
const USER: &str = "STYRN_TEST_NATIVE_SSH_USER";
const FINGERPRINT: &str = "STYRN_TEST_NATIVE_SSH_FINGERPRINT";
const CONTROLLER_MANIFEST: &str = "STYRN_TEST_NATIVE_SSH_CONTROLLER_MANIFEST";
const CONTROLLER_HOME: &str = "STYRN_TEST_NATIVE_SSH_CONTROLLER_HOME";
const OPENSSH_DIR: &str = "STYRN_TEST_NATIVE_SSH_OPENSSH_DIR";
const REMOTE_EXEC_PROBE: &str = "STYRN_TEST_NATIVE_SSH_REMOTE_EXEC_PROBE";

#[test]
#[ignore = "environmental: set STYRN_TEST_NATIVE_SSH=1 plus HOST, USER, FINGERPRINT, CONTROLLER_MANIFEST, CONTROLLER_HOME, OPENSSH_DIR, and REMOTE_EXEC_PROBE for a prepared real-sshd worker"]
fn native_ssh_phase1_journey() {
    assert_eq!(
        std::env::var(OPT_IN).as_deref(),
        Ok("1"),
        "set {OPT_IN}=1 only after preparing the real-sshd prerequisites named in this test's ignore reason"
    );

    let host = required_text(HOST);
    let user = required_text(USER);
    let fingerprint = required_text(FINGERPRINT);
    let controller_manifest = required_absolute_file(CONTROLLER_MANIFEST);
    let controller_home = required_absolute_directory(CONTROLLER_HOME);
    let openssh_dir = required_absolute_directory(OPENSSH_DIR);
    let remote_exec_probe = required_text(REMOTE_EXEC_PROBE);
    assert_native_openssh_tools(&openssh_dir);
    assert_existing_controller_identity(&controller_manifest, &controller_home);

    let environment = NativeSshEnvironment::new(&controller_manifest, controller_home, openssh_dir);

    let initialized = assert_json_success(
        &environment.run(["--json", "controller", "init"]),
        "controller init",
    );
    assert_eq!(
        initialized["data"]["created"], false,
        "the native gate requires a pre-existing identity whose public key is already authorized"
    );

    let enrolled = assert_json_success(
        &environment.run([
            "--json",
            "host",
            "enroll",
            &host,
            "--user",
            &user,
            "--fingerprint",
            &fingerprint,
        ]),
        "host enroll",
    );
    let machine_id = enrolled["data"]["machine_id"]
        .as_str()
        .expect("enrollment must return the worker machine_id")
        .to_owned();

    let listed = assert_json_success(&environment.run(["--json", "host", "list"]), "host list");
    assert!(
        listed["data"]["hosts"]
            .as_array()
            .expect("host list must return an array")
            .iter()
            .any(|candidate| {
                candidate["name"] == host && candidate["machine_id"] == machine_id
            }),
        "host list did not contain the enrolled native worker: {listed}"
    );

    let shown = assert_json_success(
        &environment.run(["--json", "host", "show", &host]),
        "host show",
    );
    assert_eq!(shown["data"]["name"], host, "{shown}");
    assert_eq!(shown["data"]["machine_id"], machine_id, "{shown}");

    let status = assert_json_success(
        &environment.run(["--json", "host", "status", &host]),
        "host status",
    );
    assert_eq!(status["data"]["host"], host, "{status}");
    assert_eq!(
        status["data"]["status"]["machine_id"], machine_id,
        "{status}"
    );
    assert!(
        status["data"]["status"]["memory"]["available_bytes"].is_u64(),
        "{status}"
    );
    assert!(
        status["data"]["status"]["disk"]["free_bytes"].is_u64(),
        "{status}"
    );

    let doctor = assert_json_success(
        &environment.run(["--json", "host", "doctor", &host]),
        "host doctor",
    );
    assert_eq!(doctor["data"]["host"], host, "{doctor}");
    assert_eq!(doctor["data"]["coverage"], "phase1_minimum", "{doctor}");
    assert_eq!(doctor["data"]["complete"], false, "{doctor}");
    assert!(doctor["data"]["controller_findings"].is_array(), "{doctor}");
    assert!(doctor["data"]["worker"]["findings"].is_array(), "{doctor}");

    let hostile_arguments = [
        "one argument",
        "\"quoted\"",
        "%PATH%",
        "trailing\\",
        "$(printf shell-expanded)",
        "; exit 99",
        "",
    ];
    let mut exec_arguments = vec![
        "--json".to_owned(),
        "exec".to_owned(),
        host.clone(),
        "--".to_owned(),
        remote_exec_probe.clone(),
        "echo-argv".to_owned(),
    ];
    exec_arguments.extend(
        hostile_arguments
            .iter()
            .map(|argument| (*argument).to_owned()),
    );
    let executed = assert_json_success(&environment.run(exec_arguments), "exec");
    assert_eq!(executed["data"]["exit_code"], 0, "{executed}");
    let received: Vec<String> = serde_json::from_str(
        executed["data"]["stdout"]
            .as_str()
            .expect("native exec stdout must be a string")
            .trim(),
    )
    .expect("the remote exec probe must emit its received argv as one JSON array");
    assert_eq!(received, hostile_arguments, "argv changed across real SSH");

    let remote_failure = environment.run([
        "--json",
        "exec",
        &host,
        "--",
        &remote_exec_probe,
        "exit-101",
    ]);
    assert_eq!(
        remote_failure.status.code(),
        Some(101),
        "{remote_failure:?}"
    );
    assert!(remote_failure.stderr.is_empty(), "{remote_failure:?}");
    let failure_envelope = exactly_one_envelope(&remote_failure);
    assert_eq!(failure_envelope["ok"], true, "{failure_envelope}");
    assert_eq!(failure_envelope["command"], "exec", "{failure_envelope}");
    assert_eq!(
        failure_envelope["data"]["exit_code"], 101,
        "{failure_envelope}"
    );
    assert_eq!(failure_envelope["errors"], serde_json::json!([]));
}

struct NativeSshEnvironment {
    root: PathBuf,
    config: PathBuf,
    state: PathBuf,
    data: PathBuf,
    work: PathBuf,
    controller_home: PathBuf,
    openssh_dir: PathBuf,
}

impl NativeSshEnvironment {
    fn new(controller_manifest: &Path, controller_home: PathBuf, openssh_dir: PathBuf) -> Self {
        let root = std::env::current_dir()
            .expect("the native SSH gate requires a current directory")
            .join("target")
            .join(format!("styrn-native-ssh-{}", Uuid::now_v7()));
        let environment = Self {
            config: root.join("config"),
            state: root.join("state"),
            data: root.join("data"),
            work: root.join("work"),
            controller_home,
            openssh_dir,
            root,
        };
        for directory in [
            &environment.root,
            &environment.config,
            &environment.state,
            &environment.data,
            &environment.work,
        ] {
            create_private_directory(directory);
        }
        let manifest = fs::read(controller_manifest)
            .unwrap_or_else(|error| panic!("failed to read {CONTROLLER_MANIFEST}: {error}"));
        let destination = environment.config.join("machine.toml");
        fs::write(&destination, manifest)
            .unwrap_or_else(|error| panic!("failed to stage the controller manifest: {error}"));
        harden_private_file(&destination);
        environment
    }

    fn run<I, S>(&self, arguments: I) -> Output
    where
        I: IntoIterator<Item = S>,
        S: AsRef<OsStr>,
    {
        let path = native_tool_path(&self.openssh_dir);
        let mut command = Command::new(env!("CARGO_BIN_EXE_styrn"));
        command
            .current_dir(&self.work)
            .env_remove("STYRN_JSON")
            .env("HOME", &self.controller_home)
            .env("USERPROFILE", &self.controller_home)
            .env("APPDATA", &self.config)
            .env("LOCALAPPDATA", &self.data)
            .env("XDG_CONFIG_HOME", &self.config)
            .env("XDG_STATE_HOME", &self.state)
            .env("XDG_DATA_HOME", &self.data)
            .env("STYRN_CONFIG_DIR", &self.config)
            .env("STYRN_SSH", executable(&self.openssh_dir, "ssh"))
            .env("PATH", path)
            .args(arguments);
        command.output().expect("failed to execute styrn")
    }
}

impl Drop for NativeSshEnvironment {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.root);
    }
}

fn assert_json_success(output: &Output, command: &str) -> Value {
    assert!(output.status.success(), "{command}: {output:?}");
    assert!(output.stderr.is_empty(), "{command}: {output:?}");
    let envelope = exactly_one_envelope(output);
    assert_eq!(envelope["ok"], true, "{envelope}");
    assert_eq!(envelope["command"], command, "{envelope}");
    assert_eq!(envelope["errors"], serde_json::json!([]), "{envelope}");
    envelope
}

fn exactly_one_envelope(output: &Output) -> Value {
    assert!(!output.stdout.is_empty(), "{output:?}");
    assert!(!output.stdout.contains(&0x1b), "{output:?}");
    let envelope: Value = serde_json::from_slice(&output.stdout)
        .expect("stdout must contain exactly one JSON document and no decoration");
    assert_eq!(envelope["schema"], "styrn.command.v1", "{envelope}");
    assert!(envelope["warnings"].is_array(), "{envelope}");
    assert!(envelope["errors"].is_array(), "{envelope}");
    envelope
}

fn required_text(name: &str) -> String {
    std::env::var(name)
        .ok()
        .filter(|value| !value.is_empty())
        .unwrap_or_else(|| panic!("{name} is required for the native SSH gate"))
}

fn required_absolute_file(name: &str) -> PathBuf {
    let path = PathBuf::from(required_text(name));
    assert!(path.is_absolute(), "{name} must be an absolute path");
    assert!(path.is_file(), "{name} must name an existing regular file");
    path
}

fn required_absolute_directory(name: &str) -> PathBuf {
    let path = PathBuf::from(required_text(name));
    assert!(path.is_absolute(), "{name} must be an absolute path");
    assert!(path.is_dir(), "{name} must name an existing directory");
    path
}

fn assert_native_openssh_tools(directory: &Path) {
    for name in ["ssh", "ssh-keyscan", "ssh-keygen"] {
        let path = executable(directory, name);
        assert!(
            path.is_file(),
            "{OPENSSH_DIR} must contain the native OpenSSH tool {}",
            path.display()
        );
    }
}

fn assert_existing_controller_identity(manifest_path: &Path, controller_home: &Path) {
    let bytes = fs::read(manifest_path)
        .unwrap_or_else(|error| panic!("failed to read {CONTROLLER_MANIFEST}: {error}"));
    let manifest: toml::Value = toml::from_slice(&bytes)
        .unwrap_or_else(|error| panic!("{CONTROLLER_MANIFEST} must be valid TOML: {error}"));
    let name = manifest
        .get("name")
        .and_then(toml::Value::as_str)
        .expect("the controller manifest requires name");
    let machine_id = manifest
        .get("machine_id")
        .and_then(toml::Value::as_str)
        .and_then(|value| Uuid::parse_str(value).ok())
        .expect("the controller manifest requires a UUID machine_id");
    let basename = format!("styrn_{name}_{}_ed25519", machine_id.simple());
    let private = controller_home.join(".ssh").join(&basename);
    let public = private.with_extension("pub");
    for path in [&private, &public] {
        let metadata = fs::symlink_metadata(path).unwrap_or_else(|_| {
            panic!(
                "the pre-existing controller identity file is required at {}",
                path.display()
            )
        });
        assert!(
            metadata.file_type().is_file(),
            "the controller identity must be a regular, non-link file: {}",
            path.display()
        );
    }
}

fn native_tool_path(openssh_dir: &Path) -> OsString {
    let mut paths = vec![openssh_dir.to_path_buf()];
    if let Some(existing) = std::env::var_os("PATH") {
        paths.extend(std::env::split_paths(&existing));
    }
    std::env::join_paths(paths).expect("the native OpenSSH PATH must be representable")
}

fn executable(directory: &Path, name: &str) -> PathBuf {
    directory.join(format!("{name}{}", std::env::consts::EXE_SUFFIX))
}

fn create_private_directory(path: &Path) {
    fs::create_dir_all(path)
        .unwrap_or_else(|error| panic!("failed to create {}: {error}", path.display()));
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        fs::set_permissions(path, fs::Permissions::from_mode(0o700))
            .unwrap_or_else(|error| panic!("failed to harden {}: {error}", path.display()));
    }
}

fn harden_private_file(path: &Path) {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        fs::set_permissions(path, fs::Permissions::from_mode(0o600))
            .unwrap_or_else(|error| panic!("failed to harden {}: {error}", path.display()));
    }
    #[cfg(not(unix))]
    let _ = path;
}
