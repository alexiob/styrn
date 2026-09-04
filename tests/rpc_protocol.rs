#![allow(dead_code)]

#[path = "../src/cli/mod.rs"]
mod cli;
#[path = "../src/manifest/mod.rs"]
mod manifest;
#[path = "../src/output/mod.rs"]
mod output;
#[path = "../src/platform/mod.rs"]
mod platform;
#[path = "../src/resources/mod.rs"]
mod resources;
#[path = "../src/rpc/mod.rs"]
mod rpc;
#[path = "../src/setup/mod.rs"]
mod setup;
#[path = "../src/transport/mod.rs"]
mod transport;

mod fixture_builder;

use rpc::frame::{FrameErrorKind, FrameReader, FrameWriter, MAX_FRAME_BYTES};
use rpc::{ExpectedPeer, RpcClient};
use serde_json::{json, Value};
use std::fs;
use std::io::{BufRead, BufReader, Cursor, Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Child, ChildStdin, ChildStdout, Command, Stdio};
use std::sync::OnceLock;
use transport::{LocalChildTransport, RpcProcess, RpcTarget, RpcTransport};
use uuid::Uuid;

const VALID_PUBLIC_KEY: &str =
    "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIAABAgMEBQYHCAkKCwwNDg8QERITFBUWFxgZGhscHR4f fixture";
const SECRET: &str = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJzdHlybi10ZXN0In0.signaturesegment123";

#[test]
fn rpc_frame_round_trips_canonical_golden_conversation() {
    let golden = include_bytes!("fixtures/rpc/canonical-conversation.ndjson");
    let mut reader = FrameReader::new(Cursor::new(golden));
    let mut rendered = Vec::new();
    let mut writer = FrameWriter::new(&mut rendered);

    while let Some(frame) = reader.read().unwrap() {
        writer.write(&frame).unwrap();
    }

    assert_eq!(rendered, golden);

    let additive = b"{\"id\":\"c1\",\"type\":\"request\",\"method\":\"machine.status\",\"params\":{},\"future\":{\"accepted\":true}}\n";
    assert!(FrameReader::new(Cursor::new(additive))
        .read()
        .unwrap()
        .is_some());
}

#[test]
fn rpc_frame_rejects_oversize_truncated_invalid_utf8_and_unknown_type_once() {
    let mut oversize = vec![b' '; MAX_FRAME_BYTES + 1];
    oversize.push(b'\n');
    let cases = [
        (oversize, FrameErrorKind::Oversize),
        (br#"{"id":"c1","type":"request""#.to_vec(), FrameErrorKind::Truncated),
        (vec![0xff, b'\n'], FrameErrorKind::InvalidUtf8),
        (
            b"{\"id\":\"c1\",\"type\":\"future\"}\n".to_vec(),
            FrameErrorKind::UnsupportedType,
        ),
        (
            b"{\"id\":\"c1\",\"id\":\"c2\",\"type\":\"request\",\"method\":\"machine.status\",\"params\":{}}\n".to_vec(),
            FrameErrorKind::InvalidJson,
        ),
    ];

    for (input, expected) in cases {
        let error = FrameReader::new(Cursor::new(input)).read().unwrap_err();
        assert_eq!(error.kind(), expected);
        assert!(!error.to_string().contains("future"));
    }
}

#[test]
fn rpc_frame_rejects_null_known_fields_but_accepts_null_unknown_fields() {
    let rejected = [
        concat!(
            r#"{"id":"hello","type":"hello","protocol":1,"styrn_version":"test","machine_id":null}"#,
            "\n"
        )
        .as_bytes(),
        concat!(
            r#"{"id":"hello","type":"hello","protocol_min":1,"protocol_max":1,"protocol":null,"styrn_version":"test","machine_id":"01990fff-f143-7e91-8361-b9bc9a57adca","name":"worker","manifest_schema_version":1}"#,
            "\n"
        )
        .as_bytes(),
        concat!(
            r#"{"id":"c1","type":"request","method":"machine.status","params":{},"ok":null}"#,
            "\n"
        )
        .as_bytes(),
        concat!(
            r#"{"id":"c1","type":"response","ok":true,"data":{},"errors":null}"#,
            "\n"
        )
        .as_bytes(),
        concat!(
            r#"{"id":"c1","type":"response","ok":false,"data":null,"errors":[{"code":"remote.execution_failed","message":"failed"}]}"#,
            "\n"
        )
        .as_bytes(),
        concat!(
            r#"{"id":"c1","type":"error","data":null,"errors":[{"code":"protocol.malformed","message":"malformed"}]}"#,
            "\n"
        )
        .as_bytes(),
        concat!(
            r#"{"id":"c1","type":"error","errors":[{"code":"protocol.malformed","message":"malformed","details":null}]}"#,
            "\n"
        )
        .as_bytes(),
        concat!(
            r#"{"id":"c1","type":"request","method":"machine.status","params":null}"#,
            "\n"
        )
        .as_bytes(),
    ];

    for input in rejected {
        let error = FrameReader::new(Cursor::new(input)).read().unwrap_err();
        assert_eq!(error.kind(), FrameErrorKind::InvalidJson);
    }

    let additive = concat!(
        r#"{"id":"c1","type":"request","method":"machine.status","params":{},"future":null}"#,
        "\n"
    );
    assert!(FrameReader::new(Cursor::new(additive))
        .read()
        .unwrap()
        .is_some());
}

mod rpc_hello_tests {
    use super::*;

    #[test]
    fn server_speaks_first_and_no_method_runs_before_matching_hello() {
        let environment = TestEnvironment::new("server-first");
        let marker = environment.root.join("must-not-run");
        let mut server = environment.spawn_raw_server();
        let hello = server.read_first_frame();
        assert_eq!(hello["id"], "hello");
        assert_eq!(hello["type"], "hello");

        let request = json!({
            "id": "c1",
            "type": "request",
            "method": "exec.run",
            "params": { "argv": [exec_fixture_text(), "touch", path_text(&marker)] }
        });
        let outcome = server.finish_with(&format!("{request}\n"));
        assert_eq!(outcome.status.code(), Some(8));
        assert_eq!(outcome.frames.len(), 1);
        assert_eq!(outcome.frames[0]["errors"][0]["code"], "protocol.malformed");
        assert!(!marker.exists());

        let mut negotiated = environment.spawn_raw_server();
        let _hello = negotiated.read_first_frame();
        let outcome = negotiated.finish_with(
            "{\"id\":\"hello\",\"type\":\"hello\",\"protocol\":1,\"styrn_version\":\"test\"}\n\
             {\"id\":\"c1\",\"type\":\"request\",\"method\":\"future.method\",\"params\":{}}\n",
        );
        assert_eq!(outcome.status.code(), Some(8));
        assert_eq!(outcome.frames.len(), 1);
        assert_eq!(outcome.frames[0]["id"], "c1");
        assert_eq!(outcome.frames[0]["errors"][0]["code"], "protocol.malformed");
    }

    #[test]
    fn highest_protocol_intersection_is_selected_and_disjoint_ranges_close_exit_8() {
        assert_eq!(rpc::highest_protocol_intersection(1..=5, 3..=7), Some(5));
        assert_eq!(rpc::highest_protocol_intersection(1..=2, 3..=4), None);

        let environment = TestEnvironment::new("version-disjoint");
        let mut server = environment.spawn_raw_server();
        let _hello = server.read_first_frame();
        let outcome = server.finish_with(
            "{\"id\":\"hello\",\"type\":\"hello\",\"protocol\":2,\"styrn_version\":\"test\"}\n",
        );
        assert_eq!(outcome.status.code(), Some(8));
        assert_eq!(outcome.frames.len(), 1);
        assert_eq!(
            outcome.frames[0]["errors"][0]["code"],
            "protocol.incompatible"
        );

        let unsupported_schema = rpc::frame::ServerHello {
            protocol_min: 1,
            protocol_max: 1,
            styrn_version: "test".to_owned(),
            machine_id: Uuid::parse_str("01991f5d-d72f-7b5e-a43d-9fcb61bd3265").unwrap(),
            name: "worker".to_owned(),
            manifest_schema_version: 2,
        };
        let error = rpc::negotiate_server_hello(&unsupported_schema).unwrap_err();
        assert_eq!(error.code(), output::ErrorCode::ProtocolIncompatible);
        let diagnostic = rpc::incompatible_server_hello_diagnostic(&unsupported_schema);
        assert!(diagnostic
            .message
            .contains("controller protocol range [1, 1]"));
        assert!(diagnostic.message.contains("worker protocol range [1, 1]"));
        assert!(diagnostic.message.contains("worker manifest schema 2"));

        let non_v7 = b"{\"id\":\"hello\",\"type\":\"hello\",\"protocol_min\":1,\"protocol_max\":1,\"styrn_version\":\"test\",\"machine_id\":\"550e8400-e29b-41d4-a716-446655440000\",\"name\":\"worker\",\"manifest_schema_version\":1}\n";
        assert_eq!(
            FrameReader::new(Cursor::new(non_v7))
                .read()
                .unwrap_err()
                .kind(),
            FrameErrorKind::InvalidJson
        );
    }

    #[test]
    fn pre_hello_incompatible_error_requires_hello_id_and_one_plain_diagnostic() {
        let environment = TestEnvironment::new("incompatible-error-shape");
        let mut accepted = environment.spawn_raw_server();
        let _hello = accepted.read_first_frame();
        let outcome = accepted.finish_with(
            "{\"id\":\"hello\",\"type\":\"error\",\"errors\":[{\"code\":\"protocol.incompatible\",\"message\":\"ranges do not intersect\"}]}\n",
        );
        assert!(outcome.status.success(), "{outcome:?}");
        assert!(outcome.frames.is_empty());

        for malformed in [
            "{\"id\":\"c1\",\"type\":\"error\",\"errors\":[{\"code\":\"protocol.incompatible\",\"message\":\"ranges do not intersect\"}]}\n",
            "{\"id\":\"hello\",\"type\":\"error\",\"errors\":[{\"code\":\"protocol.incompatible\",\"message\":\"ranges do not intersect\"},{\"code\":\"protocol.malformed\",\"message\":\"extra diagnostic\"}]}\n",
            "{\"id\":\"hello\",\"type\":\"error\",\"errors\":[{\"code\":\"protocol.incompatible\",\"message\":\"ranges do not intersect\",\"details\":{}}]}\n",
            "{\"id\":\"hello\",\"type\":\"error\",\"errors\":[{\"code\":\"protocol.incompatible\",\"message\":\"ranges do not intersect\",\"details\":null}]}\n",
        ] {
            let mut rejected = environment.spawn_raw_server();
            let _hello = rejected.read_first_frame();
            let outcome = rejected.finish_with(malformed);
            assert_eq!(outcome.status.code(), Some(8), "{outcome:?}");
            assert_eq!(outcome.frames.len(), 1);
            assert_eq!(outcome.frames[0]["id"], "hello");
            assert_eq!(
                outcome.frames[0]["errors"],
                json!([{
                    "code": "protocol.malformed",
                    "message": "the RPC peer sent a malformed frame"
                }])
            );
        }
    }
}

#[test]
fn local_child_rpc_fetches_the_bound_manifest_status_and_worker_findings() {
    let environment = TestEnvironment::new("local-child");
    let mut client = environment.connect();
    let expected = environment.expected_peer();
    let manifest = client.machine_manifest(&expected).unwrap();
    assert_eq!(manifest.machine_id, expected.machine_id());
    assert_eq!(manifest.name, "mbp-main");

    let status = serde_json::to_value(client.machine_status().unwrap()).unwrap();
    assert_eq!(status["machine_id"], expected.machine_id().to_string());
    assert!(status["cpu"]["logical"]
        .as_u64()
        .is_some_and(|value| value >= 1));
    assert!(status["memory"]["total_bytes"]
        .as_u64()
        .is_some_and(|value| value >= 1));
    assert_eq!(status["jobs"], json!({"running": 0, "heavy_running": 0}));
    assert_eq!(
        status["substrate"],
        json!({"kind": null, "state": "none", "session": null})
    );

    let doctor = serde_json::to_value(client.machine_doctor(VALID_PUBLIC_KEY).unwrap()).unwrap();
    assert_eq!(doctor["coverage"], "phase1_minimum");
    assert_eq!(doctor["complete"], false);
    assert!(doctor["findings"]
        .as_array()
        .is_some_and(|items| !items.is_empty()));
    client.finish().unwrap();
}

#[test]
fn local_child_rpc_rejects_hello_manifest_machine_or_user_substitution() {
    let environment = TestEnvironment::new("binding-substitution");
    let mut client = environment.connect();
    let hello = client.server_hello().clone();
    let manifest = client
        .machine_manifest(&environment.expected_peer())
        .unwrap();

    let mut changed_machine = manifest.clone();
    changed_machine.machine_id = Uuid::now_v7();
    assert_protocol_rejection(rpc::validate_hello_manifest_binding(
        &hello,
        &changed_machine,
        &environment.expected_peer(),
    ));

    let mut changed_name = manifest.clone();
    changed_name.name = "substitute".to_owned();
    assert_protocol_rejection(rpc::validate_hello_manifest_binding(
        &hello,
        &changed_name,
        &environment.expected_peer(),
    ));

    let mut changed_user = manifest;
    changed_user.transport.as_mut().unwrap().user = Some("substitute".to_owned());
    assert_protocol_rejection(rpc::validate_hello_manifest_binding(
        &hello,
        &changed_user,
        &environment.expected_peer(),
    ));
    client.finish().unwrap();
}

#[test]
fn rpc_exec_argv_is_exact_and_secret_bounded() {
    let environment = TestEnvironment::new("exec-argv");
    let shell_marker = environment.root.join("shell-effect");
    let expected = vec![
        "one argument".to_owned(),
        "\"quoted\"".to_owned(),
        "%VAR%".to_owned(),
        format!("$(touch {})", shell_marker.display()),
        "; touch never".to_owned(),
        "Unicode 🙂".to_owned(),
        "trailing\\".to_owned(),
        "sk-test".to_owned(),
        "secret sauce".to_owned(),
        "password manager".to_owned(),
        "token status".to_owned(),
        String::new(),
    ];
    let mut argv = vec![exec_fixture_text(), "echo-argv".to_owned()];
    argv.extend(expected.clone());

    let mut client = environment.connect();
    let result = client.exec(&argv).unwrap();
    assert_eq!(result.exit_code, 0);
    assert_eq!(
        serde_json::from_str::<Vec<String>>(result.stdout.trim()).unwrap(),
        expected
    );
    assert!(!shell_marker.exists());

    let invalid = client
        .exec(&[exec_fixture_text(), "invalid-output".to_owned()])
        .unwrap();
    assert!(invalid.stdout_lossy);
    assert!(invalid.stderr_lossy);
    assert!(invalid.stdout.contains('\u{fffd}'));
    assert!(invalid.stderr.contains('\u{fffd}'));

    let marker = environment.root.join("secret-argv-ran");
    for secret_shaped in [
        SECRET,
        "--token=not-a-real-credential",
        "prefix/ghp_not-a-real-credential",
        "diagnostic: -----BEGIN OPENSSH PRIVATE KEY-----",
    ] {
        let secret_argv = vec![
            exec_fixture_text(),
            "mark-and-echo".to_owned(),
            path_text(&marker).to_owned(),
            secret_shaped.to_owned(),
        ];
        assert_usage_rejection(client.exec(&secret_argv));
        assert!(!marker.exists());
    }

    let oversized = vec![
        exec_fixture_text(),
        "mark-and-echo".to_owned(),
        path_text(&marker).to_owned(),
        "x".repeat(32 * 1024 + 1),
    ];
    assert_usage_rejection(client.exec(&oversized));
    assert!(!marker.exists());
    client.finish().unwrap();
}

#[test]
fn rpc_exec_overflow_kills_and_reaps_without_a_partial_response() {
    let environment = TestEnvironment::new("exec-overflow");
    let marker = environment.root.join("overflow-completed");
    let mut client = environment.connect();
    let error = client
        .exec(&[
            exec_fixture_text(),
            "overflow".to_owned(),
            path_text(&marker).to_owned(),
        ])
        .unwrap_err();
    assert_eq!(error.code(), output::ErrorCode::RemoteExecutionFailed);
    assert_eq!(error.exit_code().as_i32(), 5);
    assert!(
        !marker.exists(),
        "overflowing child reached normal completion"
    );
    client.finish().unwrap();
}

#[test]
fn rpc_exec_result_is_rechecked_before_controller_output() {
    let result = rpc::ExecResult {
        exit_code: 0,
        stdout: SECRET.to_owned(),
        stderr: "ordinary stderr".to_owned(),
        duration_ms: 1,
        stdout_lossy: false,
        stderr_lossy: false,
        stdout_redacted: false,
        stderr_redacted: false,
    }
    .sanitize_for_client()
    .unwrap();
    assert_eq!(result.stdout, "[redacted secret-shaped output]");
    assert!(result.stdout_redacted);

    let error = rpc::ExecResult {
        stdout: "x".repeat(1024 * 1024 + 1),
        ..result
    }
    .sanitize_for_client()
    .unwrap_err();
    assert_eq!(error.code(), output::ErrorCode::ProtocolMalformed);
}

#[test]
fn rpc_labeled_secret_output_is_redacted_on_worker_and_controller() {
    assert!(manifest::contains_secret_shaped_text(
        "password: redacted hunter2"
    ));
    assert!(manifest::contains_secret_shaped_text(
        r#"{"token":"missing actual-secret"}"#
    ));
    assert!(!manifest::contains_secret_shaped_text("password: redacted"));
    assert!(!manifest::contains_secret_shaped_text(
        r#"{"token":"missing"}"#
    ));

    let environment = TestEnvironment::new("labeled-secret-output");
    let mut client = environment.connect();
    let result = client
        .exec(&[exec_fixture_text(), "labeled-output".to_owned()])
        .unwrap();
    assert_eq!(result.stdout, "[redacted secret-shaped output]");
    assert_eq!(result.stderr, "[redacted secret-shaped output]");
    assert!(result.stdout_redacted);
    assert!(result.stderr_redacted);
    client.finish().unwrap();
}

#[test]
fn rpc_remote_status_and_doctor_are_typed_bound_and_secret_free() {
    let machine_id = Uuid::parse_str("01991f5d-d72f-7b5e-a43d-9fcb61bd3265").unwrap();
    let status = serde_json::from_value::<resources::MachineStatus>(json!({
        "machine_id": machine_id,
        "time": "2026-09-04T12:00:00Z",
        "cpu": {"logical": 8, "load_percent": 25.0},
        "memory": {"total_bytes": 1024, "available_bytes": 512},
        "disk": {"root": "/worker", "free_bytes": 512},
        "jobs": {"running": 1, "heavy_running": 0},
        "substrate": {"kind": null, "state": "none", "session": null}
    }))
    .unwrap();
    status.validate_for_client(machine_id).unwrap();
    assert!(status.validate_for_client(Uuid::now_v7()).is_err());

    let invalid_status = serde_json::from_value::<resources::MachineStatus>(json!({
        "machine_id": machine_id,
        "time": "not-a-timestamp",
        "cpu": {"logical": 0, "load_percent": 101.0},
        "memory": {"total_bytes": 1, "available_bytes": 2},
        "disk": {"root": "password: hunter2", "free_bytes": 0},
        "jobs": {"running": 0, "heavy_running": 1},
        "substrate": {"kind": "future", "state": "invented", "session": "token: value"}
    }))
    .unwrap();
    assert!(invalid_status.validate_for_client(machine_id).is_err());

    let report = rpc::WorkerDoctorReport::from_remote_value(json!({
        "findings": [{
            "id": "worker.git",
            "state": "pass",
            "severity": "error",
            "message": "Git: healthy"
        }],
        "coverage": "phase1_minimum",
        "complete": false,
        "future": {"note": "ordinary additive data"}
    }))
    .unwrap();
    report.validate_for_client().unwrap();

    for malformed in [
        json!({
            "findings": [{
                "id": "worker.git",
                "state": "pass",
                "severity": "error",
                "message": "password: hunter2"
            }],
            "coverage": "phase1_minimum",
            "complete": false
        }),
        json!({"findings": [], "coverage": "future", "complete": true}),
        json!({
            "findings": [{
                "id": "worker.git",
                "state": "pass",
                "severity": "error",
                "message": "Git: healthy"
            }],
            "coverage": "phase1_minimum",
            "complete": false,
            "future": {"api_key": "value"}
        }),
    ] {
        assert!(rpc::WorkerDoctorReport::from_remote_value(malformed).is_err());
    }

    rpc::validate_remote_value_for_test(&json!({"future": "ordinary additive data"})).unwrap();
    assert!(rpc::validate_remote_value_for_test(&json!({
        "future": {"token": "value"}
    }))
    .is_err());
}

#[test]
fn rpc_doctor_canonicalizes_public_key_before_framing() {
    let commented = format!("{VALID_PUBLIC_KEY} {SECRET}");
    let canonical = rpc::canonical_authorized_public_key(&commented).unwrap();
    assert_eq!(canonical.split_ascii_whitespace().count(), 2);
    assert!(!canonical.contains(SECRET));

    let environment = TestEnvironment::new("doctor-canonical-key");
    let mut client = environment.connect();
    client.machine_doctor(&commented).unwrap();
    client.finish().unwrap();
}

#[test]
fn rpc_protocol_failure_terminates_client_but_remote_failure_does_not() {
    let environment = TestEnvironment::new("client-terminal");
    let mut client = environment.connect();
    let error = client.request_for_test("future.method").unwrap_err();
    assert_eq!(error.code(), output::ErrorCode::ProtocolMalformed);
    assert!(client.terminated_for_test());
    assert!(client.request_for_test("machine.status").is_err());

    let reusable = TestEnvironment::new("client-remote-reuse");
    let marker = reusable.root.join("overflow-completed");
    let mut client = reusable.connect();
    let error = client
        .exec(&[
            exec_fixture_text(),
            "overflow".to_owned(),
            path_text(&marker).to_owned(),
        ])
        .unwrap_err();
    assert_eq!(error.code(), output::ErrorCode::RemoteExecutionFailed);
    client.machine_status().unwrap();
    client.finish().unwrap();
}

#[test]
fn rpc_malformed_failure_response_terminates_the_client() {
    for variant in ["wrong-code", "wrong-message", "multiple", "details"] {
        let mut child = Command::new(exec_fixture())
            .args(["fake-rpc-malformed-failure", variant])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        let input = child.stdin.take().unwrap();
        let output = child.stdout.take().unwrap();
        let stderr = child.stderr.take().unwrap();
        let process = RpcProcess::for_test(child, input, output, stderr);
        let mut client = RpcClient::connect(process).unwrap();
        let error = client.request_for_test("machine.status").unwrap_err();
        assert_eq!(error.code(), output::ErrorCode::ProtocolMalformed);
        assert!(client.terminated_for_test());
    }
}

#[test]
fn rpc_server_self_heals_only_a_missing_machine_id() {
    let environment = TestEnvironment::new("manifest-self-heal");
    let original = fs::read_to_string(&environment.manifest_path).unwrap();
    let missing_id = original
        .lines()
        .filter(|line| !line.starts_with("machine_id = "))
        .collect::<Vec<_>>()
        .join("\n")
        + "\n";
    fs::write(&environment.manifest_path, &missing_id).unwrap();

    let mut server = environment.spawn_raw_server();
    let hello = server.read_first_frame();
    let outcome = server.finish_with("");
    assert!(outcome.status.success(), "{outcome:?}");
    assert_eq!(outcome.stderr, "machine_id was minted and persisted\n");
    let persisted = manifest::MachineManifest::parse_toml(
        &fs::read_to_string(&environment.manifest_path).unwrap(),
    )
    .unwrap();
    assert_eq!(hello["machine_id"], persisted.machine_id.to_string());
    assert_eq!(persisted.machine_id.get_version_num(), 7);

    let invalid = TestEnvironment::new("manifest-self-heal-invalid");
    let original = fs::read_to_string(&invalid.manifest_path).unwrap();
    let malformed = original
        .lines()
        .filter(|line| !line.starts_with("machine_id = "))
        .collect::<Vec<_>>()
        .join("\n")
        .replacen("schema_version = 1", "schema_version = 2", 1)
        + "\n";
    fs::write(&invalid.manifest_path, &malformed).unwrap();
    let before = fs::read(&invalid.manifest_path).unwrap();
    let outcome = invalid.spawn_raw_server().finish_with("");
    assert_eq!(outcome.status.code(), Some(2));
    assert!(outcome.frames.is_empty());
    assert_eq!(fs::read(&invalid.manifest_path).unwrap(), before);
}

#[test]
fn rpc_status_and_doctor_never_rewrite_manifest() {
    let environment = TestEnvironment::new("read-only");
    let before = fs::read(&environment.manifest_path).unwrap();
    let identity = platform::private_file_identity(&environment.manifest_path).unwrap();
    let modified = fs::metadata(&environment.manifest_path)
        .unwrap()
        .modified()
        .unwrap();

    let mut client = environment.connect();
    client.machine_status().unwrap();
    client.machine_doctor(VALID_PUBLIC_KEY).unwrap();
    client.machine_status().unwrap();
    client.machine_doctor(VALID_PUBLIC_KEY).unwrap();
    client.finish().unwrap();

    assert_eq!(fs::read(&environment.manifest_path).unwrap(), before);
    assert_eq!(
        platform::private_file_identity(&environment.manifest_path).unwrap(),
        identity
    );
    assert_eq!(
        fs::metadata(&environment.manifest_path)
            .unwrap()
            .modified()
            .unwrap(),
        modified
    );
}

#[test]
fn rpc_stdout_is_frames_only_and_hostile_worker_text_never_reaches_it() {
    let environment = TestEnvironment::new("stdout-boundary");
    let mut server = environment.spawn_raw_server();
    let hello = server.read_first_frame();
    assert_eq!(hello["type"], "hello");
    let input = format!(
        "{{\"id\":\"hello\",\"type\":\"hello\",\"protocol\":1,\"styrn_version\":\"test\"}}\n{{\"id\":\"c1\",\"type\":\"request\",\"method\":\"exec.run\",\"params\":{{\"argv\":[{},\"hostile-output\"]}}}}\n",
        serde_json::to_string(&exec_fixture_text()).unwrap()
    );
    let outcome = server.finish_with(&input);
    assert!(outcome.status.success(), "{outcome:?}");
    assert_eq!(outcome.frames.len(), 1);
    assert_eq!(outcome.frames[0]["ok"], true);
    assert_eq!(outcome.frames[0]["data"]["stdout_redacted"], true);
    assert_eq!(outcome.frames[0]["data"]["stderr_redacted"], true);
    assert_eq!(
        outcome.frames[0]["data"]["stdout"],
        "[redacted secret-shaped output]"
    );
    assert_eq!(
        outcome.frames[0]["data"]["stderr"],
        "[redacted secret-shaped output]"
    );
    assert!(!outcome.raw_stdout.contains(SECRET));
    assert!(!outcome.stderr.contains(SECRET));
}

fn assert_protocol_rejection(result: Result<(), rpc::RpcError>) {
    let error = result.unwrap_err();
    assert_eq!(error.code(), output::ErrorCode::ProtocolMalformed);
    assert_eq!(error.exit_code().as_i32(), 8);
}

fn assert_usage_rejection<T>(result: Result<T, rpc::RpcError>) {
    let error = result.err().expect("invalid argv must be rejected");
    assert_eq!(error.code(), output::ErrorCode::UsageInvalidArgument);
    assert_eq!(error.exit_code().as_i32(), 2);
    assert!(!error.to_string().contains(SECRET));
}

fn exec_fixture() -> &'static PathBuf {
    static FIXTURE: OnceLock<PathBuf> = OnceLock::new();
    FIXTURE.get_or_init(|| fixture_builder::build_example("rpc-exec-fixture-test"))
}

fn exec_fixture_text() -> String {
    path_text(exec_fixture()).to_owned()
}

fn path_text(path: &Path) -> &str {
    path.to_str().expect("test paths must be UTF-8")
}

struct TestEnvironment {
    root: PathBuf,
    config: PathBuf,
    manifest_path: PathBuf,
    principal_name: String,
}

impl TestEnvironment {
    fn new(label: &str) -> Self {
        let root = std::env::temp_dir().join(format!("styrn-rpc-{label}-{}", Uuid::now_v7()));
        fs::create_dir_all(&root).unwrap();
        let root = fs::canonicalize(root).unwrap();
        let config = root.join("config");
        fs::create_dir_all(&config).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();
            fs::set_permissions(&config, fs::Permissions::from_mode(0o700)).unwrap();
        }
        let (manifest_text, principal_name) = current_user_manifest();
        let manifest_path = config.join("machine.toml");
        fs::write(&manifest_path, manifest_text).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&manifest_path, fs::Permissions::from_mode(0o600)).unwrap();
        }
        Self {
            root,
            config,
            manifest_path,
            principal_name,
        }
    }

    fn connect(&self) -> RpcClient {
        let transport = LocalChildTransport::for_test(env!("CARGO_BIN_EXE_styrn"), &self.config);
        let process = transport.connect(&RpcTarget::local_for_test()).unwrap();
        RpcClient::connect(process).unwrap()
    }

    fn expected_peer(&self) -> ExpectedPeer {
        ExpectedPeer::new(
            Uuid::parse_str("01991f5d-d72f-7b5e-a43d-9fcb61bd3266").unwrap(),
            "mbp-main",
            &self.principal_name,
        )
        .unwrap()
    }

    fn spawn_raw_server(&self) -> RawServer {
        let mut child = Command::new(env!("CARGO_BIN_EXE_styrn"));
        configure_child(&mut child, &self.config);
        let mut child = child
            .args(["rpc", "serve", "--stdio"])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        RawServer {
            stdin: child.stdin.take().unwrap(),
            stdout: BufReader::new(child.stdout.take().unwrap()),
            child,
        }
    }
}

impl Drop for TestEnvironment {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.root);
    }
}

struct RawServer {
    child: Child,
    stdin: ChildStdin,
    stdout: BufReader<ChildStdout>,
}

impl RawServer {
    fn read_first_frame(&mut self) -> Value {
        let mut line = String::new();
        self.stdout.read_line(&mut line).unwrap();
        if line.is_empty() {
            let status = self.child.wait().unwrap();
            let mut stderr = String::new();
            self.child
                .stderr
                .take()
                .unwrap()
                .read_to_string(&mut stderr)
                .unwrap();
            panic!("server did not speak first ({status}): {stderr}");
        }
        serde_json::from_str(&line).unwrap()
    }

    fn finish_with(mut self, input: &str) -> RawOutcome {
        self.stdin.write_all(input.as_bytes()).unwrap();
        drop(self.stdin);
        let mut remaining = String::new();
        self.stdout.read_to_string(&mut remaining).unwrap();
        let status = self.child.wait().unwrap();
        let mut stderr = String::new();
        self.child
            .stderr
            .take()
            .unwrap()
            .read_to_string(&mut stderr)
            .unwrap();
        let frames = remaining
            .lines()
            .map(|line| serde_json::from_str(line).expect("stdout must contain frames only"))
            .collect();
        RawOutcome {
            status,
            frames,
            raw_stdout: remaining,
            stderr,
        }
    }
}

#[derive(Debug)]
struct RawOutcome {
    status: std::process::ExitStatus,
    frames: Vec<Value>,
    raw_stdout: String,
    stderr: String,
}

fn configure_child(command: &mut Command, config: &Path) {
    command
        .env_remove("STYRN_JSON")
        .env("STYRN_CONFIG_DIR", config);
}

fn current_user_manifest() -> (String, String) {
    let principal = platform::resolve_current_worker_principal().unwrap();
    let layout = platform::resolve_worker_directory_layout(
        platform::InstallationScope::User,
        &principal,
        None,
    )
    .unwrap();
    let mut input: toml::Value =
        toml::from_str(&fs::read_to_string("examples/machine.controller-worker.toml").unwrap())
            .unwrap();
    input["platform"]["os"] = toml::Value::String(std::env::consts::OS.to_owned());
    input["worker_identity"]["principal_kind"] = toml::Value::String(
        match principal.principal_kind() {
            platform::PrincipalKind::UnixUid => "unix-uid",
            platform::PrincipalKind::WindowsSid => "windows-sid",
        }
        .to_owned(),
    );
    input["worker_identity"]["principal_id"] =
        toml::Value::String(principal.principal_id().to_owned());
    input["worker_identity"]["name"] = toml::Value::String(principal.name().to_owned());
    input["transport"]["user"] = toml::Value::String(principal.name().to_owned());
    for field in [
        "tailscale",
        "ssh",
        "herdr",
        "agents",
        "toolchains",
        "caches",
        "desktop",
    ] {
        input.as_table_mut().unwrap().remove(field);
    }
    input["capabilities"]["agent"] = toml::Value::Boolean(false);
    for (field, path) in [
        ("root", layout.root()),
        ("repos", layout.repos()),
        ("jobs", layout.jobs()),
        ("cache", layout.cache()),
        ("artifacts", layout.artifacts()),
        ("logs", layout.logs()),
    ] {
        input["paths"][field] = toml::Value::String(path_text(path).to_owned());
    }
    let parsed =
        manifest::MachineManifest::parse_toml(&toml::to_string_pretty(&input).unwrap()).unwrap();
    (parsed.to_toml().unwrap(), principal.name().to_owned())
}
