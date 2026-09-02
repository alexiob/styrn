use std::collections::BTreeSet;
use std::process::{Command, Output};

const ROOT_COMMANDS: &[&str] = &[
    "machine",
    "controller",
    "host",
    "shell",
    "desktop",
    "admin",
    "exec",
    "agent",
    "job",
    "project",
    "workflow",
    "matrix",
    "clean",
    "cache",
    "artifact",
    "fleet",
    "harness",
    "harness-hook",
    "upgrade",
    "setup",
    "bootstrap-script",
    "env",
    "monitor",
    "watch",
];

#[test]
fn root_help_exposes_only_the_canonical_command_set() {
    let output = run(&["--help"]);

    assert!(output.status.success());
    assert!(output.stderr.is_empty());
    assert_eq!(command_names(&output.stdout), expected(ROOT_COMMANDS));
}

#[test]
fn version_is_a_normal_success_response_on_stdout() {
    let output = run(&["--version"]);

    assert!(output.status.success());
    assert!(!output.stdout.is_empty());
    assert!(output.stderr.is_empty());
}

#[test]
fn inactive_privileged_setup_route_fails_closed() {
    let output = run(&[
        "setup",
        "privileged-phase",
        "--request",
        "/definitely/missing/styrn-request.json",
        "--digest",
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
    ]);

    assert_eq!(output.status.code(), Some(13));
    assert!(output.stdout.is_empty());
    assert!(!output.stderr.is_empty());
}

#[test]
fn inactive_privileged_setup_route_has_a_typed_json_failure() {
    let output = run(&[
        "--json",
        "setup",
        "privileged-phase",
        "--request",
        "/definitely/missing/styrn-request.json",
        "--digest",
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
    ]);

    assert_eq!(output.status.code(), Some(13));
    assert!(output.stderr.is_empty());
    let value: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(value["schema"], "styrn.command.v1");
    assert_eq!(value["ok"], false);
    assert_eq!(value["errors"][0]["code"], "setup.plan_invalid");
}

#[test]
fn inactive_setup_orchestration_never_reports_false_success() {
    let human = run(&["setup", "--yes", "--authorize-system"]);
    assert_eq!(human.status.code(), Some(13));
    assert!(human.stdout.is_empty());
    assert!(!human.stderr.is_empty());

    let json = run(&["--json", "setup", "--yes", "--authorize-system"]);
    assert_eq!(json.status.code(), Some(13));
    assert!(json.stderr.is_empty());
    let value: serde_json::Value = serde_json::from_slice(&json.stdout).unwrap();
    assert_eq!(value["schema"], "styrn.command.v1");
    assert_eq!(value["ok"], false);
    assert_eq!(value["errors"][0]["code"], "setup.plan_invalid");
}

#[test]
fn root_and_finite_help_advertise_the_global_machine_output_option() {
    for args in [
        &["--help"][..],
        &["host", "list", "--help"][..],
        &["workflow", "plan", "--help"][..],
    ] {
        let output = run(args);
        assert!(output.status.success(), "{}", display(args));
        let help = String::from_utf8_lossy(&output.stdout);
        assert!(
            help.lines()
                .any(|line| line.split_whitespace().any(|word| word == "--json")),
            "{} must advertise --json",
            display(args)
        );
        assert!(
            help.contains("machine-readable output"),
            "{} must describe --json as machine output",
            display(args)
        );
    }
}

#[test]
fn nested_help_exposes_the_canonical_command_sets() {
    let cases = [
        (
            &["machine", "--help"][..],
            &["roles", "role", "manifest", "init"][..],
        ),
        (&["machine", "role", "--help"][..], &["add", "remove"][..]),
        (&["controller", "--help"][..], &["init"][..]),
        (
            &["host", "--help"][..],
            &[
                "list",
                "show",
                "status",
                "enroll",
                "remove",
                "doctor",
                "refresh",
                "authorize-key",
                "revoke-key",
                "trust",
            ][..],
        ),
        (&["desktop", "--help"][..], &["open", "info"][..]),
        (&["admin", "--help"][..], &["open"][..]),
        (
            &["agent", "--help"][..],
            &["list", "start", "read", "prompt", "wait", "stop", "attach"][..],
        ),
        (
            &["job", "--help"][..],
            &["list", "show", "cancel", "logs"][..],
        ),
        (&["project", "--help"][..], &["list", "inspect", "init"][..]),
        (
            &["workflow", "--help"][..],
            &["list", "plan", "run", "cancel"][..],
        ),
        (&["matrix", "--help"][..], &["run"][..]),
        (&["clean", "--help"][..], &["plan", "run"][..]),
        (&["cache", "--help"][..], &["status", "trim"][..]),
        (&["artifact", "--help"][..], &["read"][..]),
        (
            &["fleet", "--help"][..],
            &[
                "status",
                "doctor",
                "versions",
                "selftest",
                "controllers",
                "workers",
            ][..],
        ),
        (&["harness", "--help"][..], &["run"][..]),
    ];

    for (args, names) in cases {
        let output = run(args);
        assert!(output.status.success(), "{}", display(args));
        assert!(output.stderr.is_empty(), "{}", display(args));
        assert_eq!(
            command_names(&output.stdout),
            expected(names),
            "{}",
            display(args)
        );
    }
}

#[test]
fn representative_paths_from_every_command_family_parse() {
    let cases = [
        &["machine", "roles"][..],
        &["machine", "role", "add", "worker"][..],
        &["controller", "init"][..],
        &["host", "list"][..],
        &["host", "show", "alpha"][..],
        &["host", "status"][..],
        &["host", "enroll", "alpha", "--fingerprint", "SHA256"][..],
        &["host", "remove", "alpha", "--revoke"][..],
        &["host", "doctor", "alpha"][..],
        &["host", "refresh"][..],
        &["host", "authorize-key", "alpha", "--public-key", "key.pub"][..],
        &["host", "revoke-key", "alpha", "--controller", "main"][..],
        &["host", "trust", "alpha", "--fingerprint", "SHA256"][..],
        &["shell", "alpha"][..],
        &["desktop", "open", "alpha"][..],
        &["desktop", "info", "alpha"][..],
        &["admin", "open", "alpha"][..],
        &["exec", "alpha", "--shell", "--", "echo", "hello"][..],
        &["agent", "list", "--host", "alpha", "--all"][..],
        &[
            "agent",
            "start",
            "alpha",
            "--harness",
            "codex",
            "--project",
            "demo",
            "--name",
            "worker",
        ][..],
        &["agent", "read", "agent-1", "--lines", "10"][..],
        &["agent", "prompt", "agent-1", "--text", "hello"][..],
        &["agent", "wait", "agent-1", "--state", "idle"][..],
        &["agent", "stop", "agent-1"][..],
        &["agent", "attach", "agent-1"][..],
        &["job", "list"][..],
        &["job", "show", "job-1"][..],
        &["job", "cancel", "job-1"][..],
        &["job", "logs", "job-1"][..],
        &["project", "list"][..],
        &["project", "inspect", "demo"][..],
        &["project", "init", "alpha", "demo"][..],
        &["workflow", "list", "demo"][..],
        &["workflow", "plan", "demo", "test", "--revision", "abc"][..],
        &[
            "workflow",
            "run",
            "demo",
            "test",
            "--host",
            "alpha",
            "--wait",
            "--snapshot",
        ][..],
        &["workflow", "cancel", "submission-1"][..],
        &["matrix", "run", "demo", "all", "--revision", "abc"][..],
        &["clean", "plan", "alpha"][..],
        &["clean", "run", "alpha"][..],
        &["cache", "status", "alpha"][..],
        &["cache", "trim", "alpha"][..],
        &["artifact", "read", "job://one", "--max-bytes", "100"][..],
        &["fleet", "status"][..],
        &["fleet", "doctor"][..],
        &["fleet", "versions"][..],
        &["fleet", "selftest"][..],
        &["fleet", "controllers"][..],
        &["fleet", "workers"][..],
        &["harness", "run", "claude", "--verbose"][..],
        &["harness-hook", "claude", "session-start"][..],
        &["upgrade", "alpha"][..],
        &["upgrade", "--all"][..],
        &["bootstrap-script", "--os", "linux"][..],
        &["env"][..],
        &["monitor", "--notify"][..],
        &["watch", "--all", "--herdr"][..],
    ];

    for args in cases {
        let output = run(args);
        assert!(output.status.success(), "{}: {output:?}", display(args));
        assert!(output.stdout.is_empty(), "{}", display(args));
        assert!(output.stderr.is_empty(), "{}", display(args));
    }
}

#[test]
fn global_json_is_accepted_before_and_after_finite_commands_without_ansi() {
    for args in [
        &["--json", "host", "list"][..],
        &["host", "list", "--json"][..],
        &["workflow", "plan", "demo", "test", "--json"][..],
        &["--json", "fleet", "status"][..],
    ] {
        let output = run(args);
        assert!(output.status.success(), "{}: {output:?}", display(args));
        assert!(!output.stdout.contains(&0x1b), "{}", display(args));
        assert!(!output.stderr.contains(&0x1b), "{}", display(args));
    }
}

#[test]
fn streaming_mode_is_limited_to_following_job_logs_and_monitor() {
    for args in [
        &["job", "logs", "job-1", "--follow", "--jsonl"][..],
        &["monitor", "--jsonl"][..],
    ] {
        assert!(run(args).status.success(), "{}", display(args));
    }

    for args in [
        &["job", "logs", "job-1", "--jsonl"][..],
        &["job", "logs", "job-1", "--follow", "--json", "--jsonl"][..],
        &["host", "list", "--jsonl"][..],
        &["monitor", "--json", "--jsonl"][..],
    ] {
        assert_usage_error(args);
    }
}

#[test]
fn malformed_invocations_are_usage_errors_without_stdout_or_json_envelopes() {
    for args in [
        &["--json", "--unknown"][..],
        &["host", "show"][..],
        &["machine", "role", "add", "coordinator"][..],
        &["workflow", "run", "demo", "test", "--wait", "--no-wait"][..],
        &["upgrade", "alpha", "--all"][..],
        &["exec", "alpha", "echo", "hello"][..],
        &["exec", "alpha", "--"][..],
    ] {
        assert_usage_error(args);
    }
}

fn assert_usage_error(args: &[&str]) {
    let output = run(args);
    assert_eq!(
        output.status.code(),
        Some(2),
        "{}: {output:?}",
        display(args)
    );
    assert!(output.stdout.is_empty(), "{} wrote stdout", display(args));
    assert!(
        !output.stderr.is_empty(),
        "{} must provide a usage diagnostic",
        display(args)
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("Usage:") || stderr.contains("try '--help'"),
        "{} must include usage context",
        display(args)
    );
    assert!(
        !String::from_utf8_lossy(&output.stderr).contains("styrn.command.v1"),
        "{} must not emit a JSON envelope",
        display(args)
    );
}

fn run(args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_styrn"))
        .args(args)
        .output()
        .unwrap()
}

fn command_names(help: &[u8]) -> BTreeSet<String> {
    let help = String::from_utf8_lossy(help);
    let Some((_, command_section)) = help.split_once("Commands:\n") else {
        return BTreeSet::new();
    };
    let command_section = command_section
        .split_once("\nOptions:")
        .map_or(command_section, |(names, _)| names);

    command_section
        .lines()
        .filter_map(|line| line.split_whitespace().next())
        .map(str::to_owned)
        .collect()
}

fn expected(names: &[&str]) -> BTreeSet<String> {
    names.iter().map(|name| (*name).to_owned()).collect()
}

fn display(args: &[&str]) -> String {
    format!("styrn {}", args.join(" "))
}
