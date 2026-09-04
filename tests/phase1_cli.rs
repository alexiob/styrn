#![allow(dead_code)]

#[path = "../src/platform/mod.rs"]
mod platform;

mod fixture_builder;

use serde_json::Value;
use std::ffi::OsString;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::sync::OnceLock;
use uuid::Uuid;

const VALID_FINGERPRINT: &str = "SHA256:ZkAslGjFiUHdGf/WUL8rQvkib4PTvQatUV0OUQSncCA";
const CHANGED_FINGERPRINT: &str = "SHA256:oIVTIburEfZKUwOmv9YkLGMk4rLhYLrW27NcxmLbxTU";
const CONTROLLER_ID: &str = "01991f5d-d72f-7b5e-a43d-9fcb61bd3266";
const WORKER_ID: &str = "01991f5d-d72f-7b5e-a43d-9fcb61bd3265";
type JsonRouteCase<'a> = (&'a [&'a str], i32, &'a str, bool, Option<&'a str>);

#[test]
fn host_enroll_requires_an_explicit_transport_user() {
    let environment = IsolatedEnvironment::new("required-user");

    let output = environment.run(&[
        "host",
        "enroll",
        "worker.example",
        "--fingerprint",
        VALID_FINGERPRINT,
    ]);

    assert_eq!(output.status.code(), Some(2), "{output:?}");
    assert!(
        output.stdout.is_empty(),
        "usage errors must not write stdout"
    );
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("--user"),
        "the usage diagnostic must name the missing required flag: {output:?}"
    );
    environment.assert_no_controller_state();
}

#[test]
fn json_enrollment_without_a_fingerprint_fails_before_creating_state() {
    let environment = IsolatedEnvironment::new("json-tofu-refusal");

    let output = environment.run(&[
        "--json",
        "host",
        "enroll",
        "worker.example",
        "--user",
        "alex",
    ]);

    assert_eq!(output.status.code(), Some(2), "{output:?}");
    assert!(output.stderr.is_empty(), "{output:?}");
    let envelope = exactly_one_envelope(&output);
    assert_eq!(envelope["ok"], false);
    assert_eq!(envelope["command"], "host enroll");
    assert_eq!(envelope["data"], Value::Null);
    assert_eq!(envelope["errors"][0]["code"], "usage.invalid_argument");
    environment.assert_no_controller_state();
}

#[test]
fn non_terminal_enrollment_without_a_fingerprint_fails_with_a_flag_hint() {
    let environment = IsolatedEnvironment::new("non-terminal-tofu-refusal");

    let output = environment.run(&["host", "enroll", "worker.example", "--user", "alex"]);

    assert_eq!(output.status.code(), Some(2), "{output:?}");
    assert!(output.stdout.is_empty(), "{output:?}");
    let diagnostic = String::from_utf8_lossy(&output.stderr);
    assert!(diagnostic.contains("--fingerprint"), "{output:?}");
    assert!(!diagnostic.contains('\u{1b}'), "{output:?}");
    environment.assert_no_controller_state();
}

#[test]
fn invalid_ssh_arguments_are_usage_errors_before_controller_state_or_tools() {
    let environment = IsolatedEnvironment::new("invalid-ssh-arguments");
    environment.install_transport_fixture();
    let invalid_cases: &[&[&str]] = &[
        &[
            "--json",
            "host",
            "enroll",
            "worker;example",
            "--user",
            "alex",
            "--fingerprint",
            VALID_FINGERPRINT,
        ],
        &[
            "--json",
            "host",
            "enroll",
            "worker.example",
            "--user",
            "alex root",
            "--fingerprint",
            VALID_FINGERPRINT,
        ],
        &[
            "--json",
            "host",
            "enroll",
            "worker.example",
            "--user",
            "alex",
            "--fingerprint",
            "SHA256:not-a-valid-fingerprint",
        ],
    ];

    for arguments in invalid_cases {
        let output = environment.run(arguments);
        assert_eq!(output.status.code(), Some(2), "{arguments:?}: {output:?}");
        assert!(output.stderr.is_empty(), "{arguments:?}: {output:?}");
        let envelope = exactly_one_envelope(&output);
        assert_eq!(envelope["errors"][0]["code"], "usage.invalid_argument");
    }
    environment.assert_no_controller_state();
    assert_eq!(environment.open_ssh_call_count(), 0);
}

#[test]
fn failed_first_enrollment_reports_the_public_key_path_and_truthful_next_step() {
    let environment = IsolatedEnvironment::new("first-enrollment-auth-failure");
    environment.install_transport_fixture();
    let user = environment.seed_controller_and_worker_manifests();
    fs::write(environment.fixture_root.join("ssh-mode"), b"auth-fail\n").unwrap();

    let output = environment.run_owned(&[
        "--json".to_owned(),
        "host".to_owned(),
        "enroll".to_owned(),
        "worker.example".to_owned(),
        "--user".to_owned(),
        user,
        "--fingerprint".to_owned(),
        VALID_FINGERPRINT.to_owned(),
    ]);

    assert_eq!(output.status.code(), Some(4), "{output:?}");
    assert!(output.stderr.is_empty(), "{output:?}");
    let envelope = exactly_one_envelope(&output);
    assert_eq!(envelope["errors"][0]["code"], "transport.auth_failed");
    let identity = environment.home.join(".ssh").join(format!(
        "styrn_controller_{}_ed25519",
        CONTROLLER_ID.replace('-', "")
    ));
    assert!(identity.is_file());
    assert_eq!(
        envelope["errors"][0]["details"]["public_key_path"],
        path_text(&identity.with_extension("pub"))
    );
    assert_eq!(
        envelope["errors"][0]["details"]["next_step"],
        "authorize the public key at this path for the requested SSH user, then rerun styrn host enroll"
    );
    assert!(!environment.config.join("inventory.toml").exists());
    assert!(!environment.config.join("known_hosts").exists());
    assert!(!environment
        .config
        .join("manifests")
        .join(WORKER_ID)
        .exists());
    let rendered = String::from_utf8_lossy(&output.stdout);
    assert!(!rendered.contains("fixture-private-key"));
    assert!(!rendered.contains("AAAAC3Nza"));

    let human_environment = IsolatedEnvironment::new("first-enrollment-auth-failure-human");
    human_environment.install_transport_fixture();
    let human_user = human_environment.seed_controller_and_worker_manifests();
    fs::write(
        human_environment.fixture_root.join("ssh-mode"),
        b"auth-fail\n",
    )
    .unwrap();
    let human = human_environment.run_owned(&[
        "host".to_owned(),
        "enroll".to_owned(),
        "worker.example".to_owned(),
        "--user".to_owned(),
        human_user,
        "--fingerprint".to_owned(),
        VALID_FINGERPRINT.to_owned(),
    ]);
    assert_eq!(human.status.code(), Some(4), "{human:?}");
    assert!(human.stdout.is_empty(), "{human:?}");
    let diagnostic = String::from_utf8_lossy(&human.stderr);
    assert!(diagnostic.contains("Controller public key:"), "{human:?}");
    assert!(
        diagnostic.contains("then rerun styrn host enroll"),
        "{human:?}"
    );
    assert!(!diagnostic.contains("fixture-private-key"));
    assert!(!diagnostic.contains("AAAAC3Nza"));
}

#[test]
fn phase1_public_routes_emit_one_typed_json_outcome() {
    let environment = IsolatedEnvironment::new("route-dispatch");
    let cases: &[JsonRouteCase<'_>] = &[
        (
            &["--json", "controller", "init"],
            2,
            "controller init",
            false,
            Some("machine.manifest_invalid"),
        ),
        (&["--json", "host", "list"], 0, "host list", true, None),
        (
            &["--json", "host", "show", "missing"],
            2,
            "host show",
            false,
            Some("usage.invalid_argument"),
        ),
        (
            &["--json", "host", "status", "missing"],
            2,
            "host status",
            false,
            Some("usage.invalid_argument"),
        ),
        (
            &["--json", "host", "refresh", "missing"],
            2,
            "host refresh",
            false,
            Some("usage.invalid_argument"),
        ),
        (
            &["--json", "host", "doctor", "missing"],
            2,
            "host doctor",
            false,
            Some("usage.invalid_argument"),
        ),
        (
            &[
                "--json",
                "host",
                "trust",
                "missing",
                "--fingerprint",
                VALID_FINGERPRINT,
            ],
            2,
            "host trust",
            false,
            Some("usage.invalid_argument"),
        ),
        (
            &["--json", "exec", "missing", "--", "program", "one argument"],
            2,
            "exec",
            false,
            Some("usage.invalid_argument"),
        ),
    ];

    for (arguments, exit, command, ok, error_code) in cases {
        let output = environment.run(arguments);
        assert_eq!(
            output.status.code(),
            Some(*exit),
            "{arguments:?}: {output:?}"
        );
        assert!(output.stderr.is_empty(), "{arguments:?}: {output:?}");
        let envelope = exactly_one_envelope(&output);
        assert_eq!(envelope["command"], *command, "{arguments:?}");
        assert_eq!(envelope["ok"], *ok, "{arguments:?}");
        match error_code {
            Some(code) => assert_eq!(envelope["errors"][0]["code"], *code, "{arguments:?}"),
            None => assert_eq!(envelope["errors"], serde_json::json!([]), "{arguments:?}"),
        }
    }
}

#[test]
fn inactive_phase1_routes_fail_closed_in_human_and_json_modes() {
    let environment = IsolatedEnvironment::new("inactive-routes");
    let cases: &[(&[&str], &str)] = &[
        (&["host", "remove", "worker.example"], "host remove"),
        (
            &[
                "host",
                "authorize-key",
                "worker.example",
                "--public-key",
                "controller.pub",
            ],
            "host authorize-key",
        ),
        (
            &[
                "host",
                "revoke-key",
                "worker.example",
                "--controller",
                "main",
            ],
            "host revoke-key",
        ),
        (&["shell", "worker.example"], "shell"),
        (&["fleet", "status"], "fleet status"),
        (&["job", "list"], "job list"),
    ];

    for (arguments, command) in cases {
        let human = environment.run(arguments);
        assert_eq!(human.status.code(), Some(7), "{arguments:?}: {human:?}");
        assert!(human.stdout.is_empty(), "{arguments:?}: {human:?}");
        assert!(
            String::from_utf8_lossy(&human.stderr).contains("not available in this build"),
            "{arguments:?}: {human:?}"
        );

        let mut json_arguments = vec!["--json"];
        json_arguments.extend_from_slice(arguments);
        let json = environment.run(&json_arguments);
        assert_eq!(json.status.code(), Some(7), "{arguments:?}: {json:?}");
        assert!(json.stderr.is_empty(), "{arguments:?}: {json:?}");
        let envelope = exactly_one_envelope(&json);
        assert_eq!(envelope["command"], *command, "{arguments:?}");
        assert_eq!(envelope["ok"], false, "{arguments:?}");
        assert_eq!(
            envelope["errors"][0]["code"], "capability.unsatisfied",
            "{arguments:?}"
        );
    }
}

#[test]
fn doctor_rejects_a_cache_not_bound_to_the_selected_host_and_live_manifest() {
    let environment = IsolatedEnvironment::new("doctor-cache-binding");
    environment.install_transport_fixture();
    let user = environment.seed_controller_and_worker_manifests();
    enroll_fixture_worker(&environment, &user);
    let cache_path = environment
        .config
        .join("manifests")
        .join(format!("{WORKER_ID}.toml"));
    let cache = fs::read_to_string(&cache_path).unwrap();
    fs::write(
        &cache_path,
        cache.replace("worker.example", "substitute.example"),
    )
    .unwrap();

    let doctor = assert_json_success(
        &environment.run(&["--json", "host", "doctor", "worker.example"]),
        "host doctor",
    );
    let finding = finding(&doctor, "controller.cache.state");
    assert_eq!(finding["state"], "fail", "{doctor}");
    assert_eq!(finding["severity"], "warning", "{doctor}");
    assert_eq!(
        finding["remediation"]["styrn_args"],
        serde_json::json!(["host", "refresh", "worker.example"]),
        "{doctor}"
    );
}

#[test]
fn doctor_reports_low_disk_pending_actions_and_remediations() {
    let environment = IsolatedEnvironment::new("doctor-minimum-findings");
    environment.install_transport_fixture();
    let user = environment.seed_controller_and_worker_manifests();
    let worker_manifest = environment.worker_config.join("machine.toml");
    let mut document: toml::Value =
        toml::from_str(&fs::read_to_string(&worker_manifest).unwrap()).unwrap();
    let additions: toml::Value = toml::from_str(
        r#"
[resources.policy]
reserved_disk_bytes = 9223372036854775807

[[pending_actions]]
id = "codex-first-login"
severity = "warning"
message = "Complete the first Codex login as the selected worker user."
"#,
    )
    .unwrap();
    document
        .as_table_mut()
        .unwrap()
        .extend(additions.as_table().unwrap().clone());
    let principal = platform::resolve_current_worker_principal().unwrap();
    write_manifest(
        &worker_manifest,
        &toml::to_string_pretty(&document).unwrap(),
        &principal,
    );
    enroll_fixture_worker(&environment, &user);

    let doctor = assert_json_success(
        &environment.run(&["--json", "host", "doctor", "worker.example"]),
        "host doctor",
    );
    let disk = finding(&doctor, "worker.disk.floor");
    assert_eq!(disk["state"], "fail", "{doctor}");
    assert_eq!(disk["severity"], "error", "{doctor}");
    assert!(disk["remediation"]["summary"].is_string(), "{doctor}");
    let pending = finding(&doctor, "worker.pending_actions");
    assert_eq!(pending["state"], "fail", "{doctor}");
    assert_eq!(pending["severity"], "warning", "{doctor}");
    assert!(pending["remediation"]["summary"].is_string(), "{doctor}");
    assert_eq!(
        doctor["data"]["pending_actions"][0]["id"], "codex-first-login",
        "{doctor}"
    );
    let worker_pending = doctor["data"]["worker"]["findings"]
        .as_array()
        .unwrap()
        .iter()
        .find(|finding| finding["id"] == "pending.action-1")
        .unwrap_or_else(|| panic!("missing worker pending-action projection: {doctor}"));
    assert_eq!(worker_pending["state"], "fail", "{doctor}");
    assert_eq!(worker_pending["severity"], "warning", "{doctor}");
    assert!(
        worker_pending["remediation"]["summary"].is_string(),
        "{doctor}"
    );
    assert!(
        doctor["data"]["controller_findings"]
            .as_array()
            .unwrap()
            .iter()
            .all(|finding| finding.as_object().unwrap().contains_key("remediation")),
        "every controller finding must carry a remediation field: {doctor}"
    );
}

#[test]
fn enrollment_transport_and_protocol_failures_are_typed_and_leave_no_host_state() {
    let cases = [
        (
            "keyscan-unreachable",
            "host-key",
            "unreachable",
            3,
            "transport.unreachable",
            0,
        ),
        (
            "crash-before-hello",
            "ssh-mode",
            "crash-before-hello",
            4,
            "transport.auth_failed",
            1,
        ),
        (
            "malformed-hello",
            "ssh-mode",
            "malformed-hello",
            8,
            "protocol.malformed",
            1,
        ),
        (
            "incompatible-hello",
            "ssh-mode",
            "incompatible-hello",
            8,
            "protocol.incompatible",
            1,
        ),
        (
            "malformed-manifest",
            "ssh-mode",
            "malformed-manifest",
            2,
            "machine.manifest_invalid",
            1,
        ),
    ];

    for (label, control, mode, expected_exit, expected_code, expected_ssh_calls) in cases {
        let environment = IsolatedEnvironment::new(label);
        environment.install_transport_fixture();
        let user = environment.seed_controller_and_worker_manifests();
        fs::write(environment.fixture_root.join(control), format!("{mode}\n")).unwrap();
        let output = environment.run_owned(&[
            "--json".to_owned(),
            "host".to_owned(),
            "enroll".to_owned(),
            "worker.example".to_owned(),
            "--user".to_owned(),
            user,
            "--fingerprint".to_owned(),
            VALID_FINGERPRINT.to_owned(),
        ]);

        assert_eq!(
            output.status.code(),
            Some(expected_exit),
            "{label}: {output:?}"
        );
        assert!(output.stderr.is_empty(), "{label}: {output:?}");
        let envelope = exactly_one_envelope(&output);
        assert_eq!(envelope["command"], "host enroll", "{label}: {envelope}");
        assert_eq!(envelope["ok"], false, "{label}: {envelope}");
        assert_eq!(
            envelope["errors"][0]["code"], expected_code,
            "{label}: {envelope}"
        );
        assert!(!String::from_utf8_lossy(&output.stdout).contains("fixture-secret-must-not-escape"));
        environment.assert_no_enrolled_host_state();
        assert_eq!(
            environment.open_ssh_call_count(),
            expected_ssh_calls,
            "{label}: a failure must not invoke a later transport step"
        );
    }
}

#[test]
fn enrolled_worker_identity_substitution_preserves_controller_state() {
    const SUBSTITUTE_ID: &str = "01991f5d-d72f-7b5e-a43d-9fcb61bd3267";
    let environment = IsolatedEnvironment::new("bound-worker-substitution");
    environment.install_transport_fixture();
    let user = environment.seed_controller_and_worker_manifests();
    enroll_fixture_worker(&environment, &user);
    let inventory_path = environment.config.join("inventory.toml");
    let known_hosts_path = environment.config.join("known_hosts");
    let cache_path = environment
        .config
        .join("manifests")
        .join(format!("{WORKER_ID}.toml"));
    let controller_state = [
        fs::read(&inventory_path).unwrap(),
        fs::read(&known_hosts_path).unwrap(),
        fs::read(&cache_path).unwrap(),
    ];
    let worker_manifest_path = environment.worker_config.join("machine.toml");
    let original_manifest = fs::read_to_string(&worker_manifest_path).unwrap();
    let principal = platform::resolve_current_worker_principal().unwrap();

    for substitution in ["machine-id", "name", "user"] {
        let mut document: toml::Value = toml::from_str(&original_manifest).unwrap();
        match substitution {
            "machine-id" => document["machine_id"] = toml::Value::String(SUBSTITUTE_ID.to_owned()),
            "name" => document["name"] = toml::Value::String("substitute.example".to_owned()),
            "user" => {
                fs::write(
                    environment.fixture_root.join("ssh-mode"),
                    b"substitute-user\n",
                )
                .unwrap();
            }
            _ => unreachable!(),
        }
        if substitution == "user" {
            write_manifest(&worker_manifest_path, &original_manifest, &principal);
        } else {
            write_manifest(
                &worker_manifest_path,
                &toml::to_string_pretty(&document).unwrap(),
                &principal,
            );
        }

        let output = environment.run(&["--json", "host", "status", "worker.example"]);
        assert_eq!(output.status.code(), Some(8), "{substitution}: {output:?}");
        assert!(output.stderr.is_empty(), "{substitution}: {output:?}");
        let envelope = exactly_one_envelope(&output);
        assert_eq!(
            envelope["errors"][0]["code"], "protocol.malformed",
            "{substitution}: {envelope}"
        );
        assert_eq!(fs::read(&inventory_path).unwrap(), controller_state[0]);
        assert_eq!(fs::read(&known_hosts_path).unwrap(), controller_state[1]);
        assert_eq!(fs::read(&cache_path).unwrap(), controller_state[2]);
        fs::write(environment.fixture_root.join("ssh-mode"), b"\n").unwrap();
    }
}

#[test]
fn public_exec_maps_remote_failure_and_redacts_secret_output_in_both_modes() {
    let environment = IsolatedEnvironment::new("exec-failures-and-redaction");
    environment.install_transport_fixture();
    let user = environment.seed_controller_and_worker_manifests();
    enroll_fixture_worker(&environment, &user);
    let missing_program = environment.root.join("program-that-does-not-exist");

    let failure = environment.run_owned(&[
        "--json".to_owned(),
        "exec".to_owned(),
        "worker.example".to_owned(),
        "--".to_owned(),
        path_text(&missing_program).to_owned(),
    ]);
    assert_eq!(failure.status.code(), Some(5), "{failure:?}");
    assert!(failure.stderr.is_empty(), "{failure:?}");
    let envelope = exactly_one_envelope(&failure);
    assert_eq!(envelope["errors"][0]["code"], "remote.execution_failed");

    let exec_arguments = [
        "exec".to_owned(),
        "worker.example".to_owned(),
        "--".to_owned(),
        path_text(transport_fixture()).to_owned(),
        "secret-output".to_owned(),
    ];
    let mut json_arguments = vec!["--json".to_owned()];
    json_arguments.extend(exec_arguments.iter().cloned());
    let json = assert_json_success(&environment.run_owned(&json_arguments), "exec");
    assert_eq!(json["data"]["stdout"], "[redacted secret-shaped output]");
    assert_eq!(json["data"]["stderr"], "[redacted secret-shaped output]");
    assert_eq!(json["data"]["stdout_redacted"], true);
    assert_eq!(json["data"]["stderr_redacted"], true);
    let rendered_json = json.to_string();
    assert!(!rendered_json.contains("fixture-secret-output-value"));
    assert!(!rendered_json.contains("fixture-secret-error-value"));

    let human = environment.run_owned(&exec_arguments);
    assert_eq!(human.status.code(), Some(0), "{human:?}");
    let rendered_human = format!(
        "{}{}",
        String::from_utf8_lossy(&human.stdout),
        String::from_utf8_lossy(&human.stderr)
    );
    assert!(rendered_human.contains("[redacted secret-shaped output]"));
    assert!(!rendered_human.contains("fixture-secret-output-value"));
    assert!(!rendered_human.contains("fixture-secret-error-value"));
}

#[test]
fn fake_ssh_public_journey_preserves_argv_and_rejects_a_changed_host_key() {
    let environment = IsolatedEnvironment::new("fake-ssh-journey");
    environment.install_transport_fixture();
    let user = environment.seed_controller_and_worker_manifests();
    let worker_manifest_path = environment.worker_config.join("machine.toml");
    let worker_manifest_before = fs::read(&worker_manifest_path).unwrap();
    let worker_manifest_mtime_before = fs::metadata(&worker_manifest_path)
        .unwrap()
        .modified()
        .unwrap();

    assert_json_success(
        &environment.run(&["--json", "controller", "init"]),
        "controller init",
    );
    let identity = environment.home.join(".ssh").join(format!(
        "styrn_controller_{}_ed25519",
        CONTROLLER_ID.replace('-', "")
    ));
    assert!(
        identity.is_file(),
        "controller private identity was not created"
    );
    assert!(
        identity.with_extension("pub").is_file(),
        "controller public identity was not created"
    );

    let enroll_arguments = [
        "--json".to_owned(),
        "host".to_owned(),
        "enroll".to_owned(),
        "worker.example".to_owned(),
        "--user".to_owned(),
        user,
        "--fingerprint".to_owned(),
        VALID_FINGERPRINT.to_owned(),
    ];
    let enroll = environment.run_owned(&enroll_arguments);
    let enrolled = assert_json_success(&enroll, "host enroll");
    assert_eq!(enrolled["data"]["machine_id"], WORKER_ID, "{enroll:?}");

    let inventory_path = environment.config.join("inventory.toml");
    let known_hosts_path = environment.config.join("known_hosts");
    let cache_path = environment
        .config
        .join("manifests")
        .join(format!("{WORKER_ID}.toml"));
    for path in [&inventory_path, &known_hosts_path, &cache_path] {
        assert!(
            path.is_file(),
            "missing committed state: {}",
            path.display()
        );
    }
    let inventory = fs::read_to_string(&inventory_path).unwrap();
    assert!(inventory.contains("worker.example"));
    assert!(inventory.contains(WORKER_ID));
    assert!(inventory.contains(VALID_FINGERPRINT));
    assert!(
        !inventory.contains("fixture-private-key"),
        "private key bytes escaped into controller state"
    );

    let inventory_before_repeat = fs::read(&inventory_path).unwrap();
    let inventory_mtime_before_repeat = fs::metadata(&inventory_path).unwrap().modified().unwrap();
    let known_hosts_before_repeat = fs::read(&known_hosts_path).unwrap();
    let known_hosts_mtime_before_repeat =
        fs::metadata(&known_hosts_path).unwrap().modified().unwrap();
    let identity_before_repeat = fs::read(&identity).unwrap();
    let identity_mtime_before_repeat = fs::metadata(&identity).unwrap().modified().unwrap();
    let repeated = assert_json_success(&environment.run_owned(&enroll_arguments), "host enroll");
    assert_eq!(repeated["data"]["created"], false, "{repeated}");
    assert_eq!(fs::read(&inventory_path).unwrap(), inventory_before_repeat);
    assert_eq!(
        fs::metadata(&inventory_path).unwrap().modified().unwrap(),
        inventory_mtime_before_repeat
    );
    assert_eq!(
        fs::read(&known_hosts_path).unwrap(),
        known_hosts_before_repeat
    );
    assert_eq!(
        fs::metadata(&known_hosts_path).unwrap().modified().unwrap(),
        known_hosts_mtime_before_repeat
    );
    assert_eq!(fs::read(&identity).unwrap(), identity_before_repeat);
    assert_eq!(
        fs::metadata(&identity).unwrap().modified().unwrap(),
        identity_mtime_before_repeat
    );

    let listed = assert_json_success(&environment.run(&["--json", "host", "list"]), "host list");
    assert!(
        listed["data"].to_string().contains("worker.example"),
        "{listed}"
    );
    let shown = assert_json_success(
        &environment.run(&["--json", "host", "show", "worker.example"]),
        "host show",
    );
    assert!(shown["data"].to_string().contains(WORKER_ID), "{shown}");

    let status = assert_json_success(
        &environment.run(&["--json", "host", "status", "worker.example"]),
        "host status",
    );
    assert_eq!(
        status["data"]["status"]["machine_id"], WORKER_ID,
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

    let refreshed = assert_json_success(
        &environment.run(&["--json", "host", "refresh", "worker.example"]),
        "host refresh",
    );
    assert_eq!(refreshed["data"]["machine_id"], WORKER_ID, "{refreshed}");

    let doctor = assert_json_success(
        &environment.run(&["--json", "host", "doctor", "worker.example"]),
        "host doctor",
    );
    assert_eq!(doctor["data"]["coverage"], "phase1_minimum", "{doctor}");
    assert_eq!(doctor["data"]["complete"], false, "{doctor}");
    assert!(doctor["data"]["controller_findings"].is_array(), "{doctor}");
    assert!(doctor["data"]["worker"]["findings"].is_array(), "{doctor}");

    let shell_marker = environment.root.join("shell-must-not-run");
    let hostile_arguments = vec![
        "one argument".to_owned(),
        "\"quoted\"".to_owned(),
        "%PATH%".to_owned(),
        "trailing\\".to_owned(),
        format!("$(touch {})", path_text(&shell_marker)),
        String::new(),
    ];
    let mut exec_arguments = vec![
        "--json".to_owned(),
        "exec".to_owned(),
        "worker.example".to_owned(),
        "--".to_owned(),
        path_text(transport_fixture()).to_owned(),
        "echo-argv".to_owned(),
    ];
    exec_arguments.extend(hostile_arguments.iter().cloned());
    let exec = environment.run_owned(&exec_arguments);
    let executed = assert_json_success(&exec, "exec");
    assert_eq!(executed["data"]["exit_code"], 0, "{exec:?}");
    let received: Vec<String> = serde_json::from_str(
        executed["data"]["stdout"]
            .as_str()
            .expect("exec stdout must be a string")
            .trim(),
    )
    .expect("the remote fixture must return its exact argv as JSON");
    assert_eq!(received, hostile_arguments);
    assert!(!shell_marker.exists(), "exec argv crossed a shell boundary");

    let remote_failure = environment.run_owned(&[
        "--json".to_owned(),
        "exec".to_owned(),
        "worker.example".to_owned(),
        "--".to_owned(),
        path_text(transport_fixture()).to_owned(),
        "exit-101".to_owned(),
    ]);
    assert_eq!(
        remote_failure.status.code(),
        Some(101),
        "{remote_failure:?}"
    );
    let remote_failure_envelope = exactly_one_envelope(&remote_failure);
    assert_eq!(remote_failure_envelope["ok"], true);
    assert_eq!(remote_failure_envelope["data"]["exit_code"], 101);
    assert_eq!(remote_failure_envelope["errors"], serde_json::json!([]));

    let old_inventory = fs::read(&inventory_path).unwrap();
    let old_known_hosts = fs::read(&known_hosts_path).unwrap();
    let old_cache = fs::read(&cache_path).unwrap();
    let ssh_calls_before = environment.open_ssh_call_count();
    fs::write(environment.fixture_root.join("host-key"), b"changed\n").unwrap();

    let changed = environment.run(&["--json", "host", "status", "worker.example"]);
    assert_eq!(changed.status.code(), Some(4), "{changed:?}");
    assert!(changed.stderr.is_empty(), "{changed:?}");
    let failure = exactly_one_envelope(&changed);
    assert_eq!(failure["ok"], false, "{failure}");
    assert_eq!(failure["command"], "host status", "{failure}");
    assert_eq!(
        failure["errors"][0]["code"], "transport.auth_failed",
        "{failure}"
    );
    assert_eq!(fs::read(&inventory_path).unwrap(), old_inventory);
    assert_eq!(fs::read(&known_hosts_path).unwrap(), old_known_hosts);
    assert_eq!(fs::read(&cache_path).unwrap(), old_cache);
    assert_eq!(
        environment.open_ssh_call_count(),
        ssh_calls_before,
        "a changed host key must fail before spawning ssh"
    );

    let trusted = assert_json_success(
        &environment.run(&[
            "--json",
            "host",
            "trust",
            "worker.example",
            "--fingerprint",
            CHANGED_FINGERPRINT,
        ]),
        "host trust",
    );
    assert_eq!(trusted["data"]["fingerprint"], CHANGED_FINGERPRINT);
    let updated_inventory = fs::read_to_string(&inventory_path).unwrap();
    assert!(updated_inventory.contains(CHANGED_FINGERPRINT));
    assert!(!updated_inventory.contains(VALID_FINGERPRINT));
    assert_json_success(
        &environment.run(&["--json", "host", "status", "worker.example"]),
        "host status",
    );
    assert_eq!(
        fs::read(&worker_manifest_path).unwrap(),
        worker_manifest_before,
        "finite inspection commands must not rewrite the worker manifest"
    );
    assert_eq!(
        fs::metadata(&worker_manifest_path)
            .unwrap()
            .modified()
            .unwrap(),
        worker_manifest_mtime_before,
        "finite inspection commands must preserve the worker manifest timestamp"
    );
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

fn enroll_fixture_worker(environment: &IsolatedEnvironment, user: &str) -> Value {
    assert_json_success(
        &environment.run_owned(&[
            "--json".to_owned(),
            "host".to_owned(),
            "enroll".to_owned(),
            "worker.example".to_owned(),
            "--user".to_owned(),
            user.to_owned(),
            "--fingerprint".to_owned(),
            VALID_FINGERPRINT.to_owned(),
        ]),
        "host enroll",
    )
}

fn finding<'a>(doctor: &'a Value, id: &str) -> &'a Value {
    doctor["data"]["controller_findings"]
        .as_array()
        .unwrap()
        .iter()
        .find(|finding| finding["id"] == id)
        .unwrap_or_else(|| panic!("missing doctor finding {id}: {doctor}"))
}

fn exactly_one_envelope(output: &Output) -> Value {
    assert!(!output.stdout.is_empty(), "{output:?}");
    assert!(!output.stdout.contains(&0x1b), "{output:?}");
    let envelope: Value = serde_json::from_slice(&output.stdout)
        .expect("stdout must contain exactly one JSON document and no decoration");
    assert_eq!(envelope["schema"], "styrn.command.v1");
    assert!(envelope["warnings"].is_array());
    assert!(envelope["errors"].is_array());
    envelope
}

struct IsolatedEnvironment {
    root: PathBuf,
    home: PathBuf,
    config: PathBuf,
    state: PathBuf,
    data: PathBuf,
    tools: PathBuf,
    work: PathBuf,
    worker_config: PathBuf,
    fixture_root: PathBuf,
}

impl IsolatedEnvironment {
    fn new(label: &str) -> Self {
        let root = std::env::current_dir()
            .unwrap()
            .join("target")
            .join(format!("styrn-phase1-cli-{label}-{}", Uuid::now_v7()));
        let environment = Self {
            home: root.join("home"),
            config: root.join("config"),
            state: root.join("state"),
            data: root.join("data"),
            tools: root.join("tools"),
            work: root.join("work"),
            worker_config: root.join("worker-config"),
            fixture_root: root.join("fixture-control"),
            root,
        };
        for directory in [
            &environment.root,
            &environment.home,
            &environment.config,
            &environment.state,
            &environment.data,
            &environment.tools,
            &environment.work,
            &environment.worker_config,
            &environment.fixture_root,
        ] {
            fs::create_dir_all(directory).unwrap();
            harden_test_directory(directory);
        }
        environment
    }

    fn run(&self, arguments: &[&str]) -> Output {
        self.run_arguments(arguments)
    }

    fn run_owned(&self, arguments: &[String]) -> Output {
        self.run_arguments(arguments)
    }

    fn run_arguments<I, S>(&self, arguments: I) -> Output
    where
        I: IntoIterator<Item = S>,
        S: AsRef<std::ffi::OsStr>,
    {
        let mut command = Command::new(env!("CARGO_BIN_EXE_styrn"));
        command
            .current_dir(&self.work)
            .env_clear()
            .env("HOME", &self.home)
            .env("USERPROFILE", &self.home)
            .env("APPDATA", &self.config)
            .env("LOCALAPPDATA", &self.data)
            .env("XDG_CONFIG_HOME", &self.config)
            .env("XDG_STATE_HOME", &self.state)
            .env("XDG_DATA_HOME", &self.data)
            .env("STYRN_CONFIG_DIR", &self.config)
            .env("STYRN_SSH", self.tools.join(executable_name("ssh")))
            .env("PHASE1_FIXTURE_ROOT", &self.fixture_root)
            .env("PHASE1_FIXTURE_STYRN", env!("CARGO_BIN_EXE_styrn"))
            .env("PHASE1_FIXTURE_WORKER_CONFIG", &self.worker_config)
            .env("PATH", &self.tools)
            .stdin(std::process::Stdio::null())
            .args(arguments);
        preserve_windows_process_environment(&mut command);
        command.output().unwrap()
    }

    fn install_transport_fixture(&self) {
        for name in ["ssh", "ssh-keyscan", "ssh-keygen"] {
            let destination = self.tools.join(executable_name(name));
            fs::copy(transport_fixture(), &destination).unwrap();
            harden_test_executable(&destination);
        }
    }

    fn seed_controller_and_worker_manifests(&self) -> String {
        let principal = platform::resolve_current_worker_principal()
            .expect("phase 1 CLI tests require a real non-privileged caller");
        let worker_root = isolated_worker_root(self, &principal);
        let controller = manifest_for(
            CONTROLLER_ID,
            "controller",
            &["controller"],
            None,
            &worker_root,
            &principal,
        );
        let worker = manifest_for(
            WORKER_ID,
            "worker.example",
            &["worker"],
            Some(("worker.example", principal.name())),
            &worker_root,
            &principal,
        );
        write_manifest(&self.config.join("machine.toml"), &controller, &principal);
        write_manifest(
            &self.worker_config.join("machine.toml"),
            &worker,
            &principal,
        );
        principal.name().to_owned()
    }

    fn open_ssh_call_count(&self) -> usize {
        let path = self.fixture_root.join("calls.jsonl");
        fs::read_to_string(path)
            .unwrap_or_default()
            .lines()
            .filter_map(|line| serde_json::from_str::<Value>(line).ok())
            .filter(|call| call["tool"] == "ssh")
            .count()
    }

    fn assert_no_controller_state(&self) {
        for path in [
            self.config.join("inventory.toml"),
            self.config.join("known_hosts"),
            self.home.join(".ssh"),
        ] {
            assert!(
                !path.exists(),
                "unexpected partial controller state: {}",
                path.display()
            );
        }
    }

    fn assert_no_enrolled_host_state(&self) {
        for path in [
            self.config.join("inventory.toml"),
            self.config.join("known_hosts"),
            self.config
                .join("manifests")
                .join(format!("{WORKER_ID}.toml")),
        ] {
            assert!(
                !path.exists(),
                "unexpected partial host state: {}",
                path.display()
            );
        }
    }
}

impl Drop for IsolatedEnvironment {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.root);
    }
}

fn executable_name(stem: &str) -> OsString {
    OsString::from(format!("{stem}{}", std::env::consts::EXE_SUFFIX))
}

fn transport_fixture() -> &'static PathBuf {
    static FIXTURE: OnceLock<PathBuf> = OnceLock::new();
    FIXTURE.get_or_init(|| fixture_builder::build_example("phase1-transport-fixture-test"))
}

fn isolated_worker_root(
    environment: &IsolatedEnvironment,
    principal: &platform::WorkerPrincipal,
) -> PathBuf {
    #[cfg(target_os = "linux")]
    {
        let _ = principal;
        environment.data.join("styrn")
    }
    #[cfg(any(target_os = "macos", target_os = "windows"))]
    {
        let _ = environment;
        platform::resolve_worker_directory_layout(
            platform::InstallationScope::User,
            principal,
            None,
        )
        .expect("the native current-user worker root must resolve")
        .root()
        .to_path_buf()
    }
}

fn manifest_for(
    machine_id: &str,
    name: &str,
    roles: &[&str],
    transport: Option<(&str, &str)>,
    worker_root: &Path,
    principal: &platform::WorkerPrincipal,
) -> String {
    let mut document: toml::Value =
        toml::from_str(include_str!("../examples/machine.controller-worker.toml")).unwrap();
    document["machine_id"] = toml::Value::String(machine_id.to_owned());
    document["name"] = toml::Value::String(name.to_owned());
    document["roles"] = toml::Value::Array(
        roles
            .iter()
            .map(|role| toml::Value::String((*role).to_owned()))
            .collect(),
    );
    document["platform"]["os"] = toml::Value::String(std::env::consts::OS.to_owned());
    document["platform"]["arch"] = toml::Value::String(std::env::consts::ARCH.to_owned());
    document["platform"]["hostname"] = toml::Value::String(name.to_owned());
    for (field, path) in [
        ("root", worker_root.to_path_buf()),
        ("repos", worker_root.join("repos")),
        ("jobs", worker_root.join("jobs")),
        ("cache", worker_root.join("cache")),
        ("artifacts", worker_root.join("artifacts")),
        ("logs", worker_root.join("logs")),
    ] {
        document["paths"][field] = toml::Value::String(path_text(&path).to_owned());
    }
    for field in [
        "worker",
        "resources",
        "capabilities",
        "scheduling",
        "tailscale",
        "ssh",
        "herdr",
        "agents",
        "toolchains",
        "caches",
        "install",
        "desktop",
        "pending_actions",
    ] {
        document.as_table_mut().unwrap().remove(field);
    }
    match transport {
        Some((host, user)) => {
            document.as_table_mut().unwrap().remove("controller");
            document["worker_identity"]["principal_kind"] = toml::Value::String(
                match principal.principal_kind() {
                    platform::PrincipalKind::UnixUid => "unix-uid",
                    platform::PrincipalKind::WindowsSid => "windows-sid",
                }
                .to_owned(),
            );
            document["worker_identity"]["principal_id"] =
                toml::Value::String(principal.principal_id().to_owned());
            document["worker_identity"]["name"] = toml::Value::String(user.to_owned());
            document["transport"]["host"] = toml::Value::String(host.to_owned());
            document["transport"]["user"] = toml::Value::String(user.to_owned());
        }
        None => {
            document.as_table_mut().unwrap().remove("worker_identity");
            document.as_table_mut().unwrap().remove("transport");
        }
    }
    toml::to_string_pretty(&document).unwrap()
}

fn write_manifest(path: &Path, contents: &str, principal: &platform::WorkerPrincipal) {
    fs::write(path, contents).unwrap();
    platform::harden_manifest_file(path, platform::ManifestOwner::User, principal).unwrap();
}

fn path_text(path: &Path) -> &str {
    path.to_str()
        .expect("phase 1 CLI fixture paths must be valid UTF-8")
}

fn preserve_windows_process_environment(command: &mut Command) {
    #[cfg(target_os = "windows")]
    for name in ["SYSTEMROOT", "WINDIR", "COMSPEC", "PATHEXT"] {
        if let Some(value) = std::env::var_os(name) {
            command.env(name, value);
        }
    }

    #[cfg(not(target_os = "windows"))]
    let _ = command;
}

fn harden_test_directory(path: &Path) {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(0o700)).unwrap();
    }

    #[cfg(not(unix))]
    let _ = path;
}

fn harden_test_executable(path: &Path) {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(0o700)).unwrap();
    }

    #[cfg(not(unix))]
    let _ = path;
}
