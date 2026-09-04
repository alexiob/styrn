use serde_json::json;
use std::fs::{self, OpenOptions};
use std::io::{BufRead as _, Write as _};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

const PRIMARY_KEY: &str = "AAAAC3NzaC1lZDI1NTE5AAAAIAABAgMEBQYHCAkKCwwNDg8QERITFBUWFxgZGhscHR4f";
const CHANGED_KEY: &str = "AAAAC3NzaC1lZDI1NTE5AAAAIB8eHRwbGhkYFxYVFBMSERAPDg0MCwoJCAcGBQQDAgEA";
const WORKER_ID: &str = "01991f5d-d72f-7b5e-a43d-9fcb61bd3265";

fn main() {
    let executable = std::env::args_os()
        .next()
        .and_then(|path| PathBuf::from(path).file_stem().map(|stem| stem.to_owned()))
        .and_then(|stem| stem.to_str().map(str::to_owned))
        .expect("fixture executable name must be UTF-8");
    let arguments = std::env::args().skip(1).collect::<Vec<_>>();
    match executable.as_str() {
        "ssh" => fake_ssh(&arguments),
        "ssh-keyscan" => fake_keyscan(&arguments),
        "ssh-keygen" => fake_keygen(&arguments),
        _ => exec_fixture(&arguments),
    }
}

fn fake_ssh(arguments: &[String]) {
    log_call("ssh", arguments);
    assert_eq!(arguments.len(), 16, "unexpected ssh argv");
    assert_eq!(arguments[0], "-T");
    assert_eq!(arguments[1], "-oBatchMode=yes");
    assert_eq!(arguments[2], "-oIdentitiesOnly=yes");
    assert_eq!(arguments[3], "-oStrictHostKeyChecking=yes");
    assert!(arguments[4].starts_with("-oUserKnownHostsFile="));
    assert_eq!(arguments[5], "-oGlobalKnownHostsFile=none");
    assert_eq!(arguments[6], "-oCheckHostIP=no");
    assert_eq!(arguments[7], "-oConnectTimeout=10");
    assert_eq!(arguments[8], "-oConnectionAttempts=1");
    assert_eq!(arguments[9], "-i");
    assert!(Path::new(&arguments[10]).is_absolute());
    assert_eq!(arguments[11], "-p");
    assert_eq!(arguments[12], "22");
    assert_eq!(arguments[13], "--");
    assert!(arguments[14].ends_with("@worker.example"));
    assert_eq!(arguments[15], "styrn rpc serve --stdio");

    if let Ok(mode) = fs::read_to_string(fixture_root().join("ssh-mode")) {
        match mode.trim() {
            "auth-fail" => {
                eprintln!("fixture authentication refused");
                std::process::exit(255);
            }
            "crash-before-hello" => {
                eprintln!("token=fixture-secret-must-not-escape");
                std::process::exit(23);
            }
            "malformed-hello" => {
                eprintln!("token=fixture-secret-must-not-escape");
                println!("not a JSON frame");
                return;
            }
            "incompatible-hello" => {
                eprintln!("token=fixture-secret-must-not-escape");
                println!(
                    "{}",
                    json!({
                        "id": "hello",
                        "type": "hello",
                        "protocol_min": 2,
                        "protocol_max": 2,
                        "styrn_version": "9.0.0",
                        "machine_id": WORKER_ID,
                        "name": "worker.example",
                        "manifest_schema_version": 1,
                    })
                );
                return;
            }
            "malformed-manifest" => {
                serve_malformed_manifest();
                return;
            }
            "substitute-user" => {
                serve_substituted_user_manifest();
                return;
            }
            "" => {}
            unexpected => panic!("unknown fake SSH mode {unexpected}"),
        }
    }

    let status = Command::new(required_path("PHASE1_FIXTURE_STYRN"))
        .args(["rpc", "serve", "--stdio"])
        .env_remove("STYRN_JSON")
        .env(
            "STYRN_CONFIG_DIR",
            required_path("PHASE1_FIXTURE_WORKER_CONFIG"),
        )
        .stdin(Stdio::inherit())
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit())
        .status()
        .expect("the fake ssh transport must start the local worker");
    std::process::exit(status.code().unwrap_or(1));
}

fn fake_keyscan(arguments: &[String]) {
    log_call("ssh-keyscan", arguments);
    assert_eq!(
        arguments,
        [
            "-T",
            "10",
            "-p",
            "22",
            "-t",
            "ed25519,ecdsa,rsa",
            "--",
            "worker.example",
        ]
    );
    let host_key_mode = fs::read_to_string(fixture_root().join("host-key")).unwrap_or_default();
    if host_key_mode.trim() == "unreachable" {
        eprintln!("token=fixture-secret-must-not-escape");
        std::process::exit(1);
    }
    let changed = host_key_mode.trim() == "changed";
    let key = if changed { CHANGED_KEY } else { PRIMARY_KEY };
    println!("worker.example ssh-ed25519 {key}");
}

fn fake_keygen(arguments: &[String]) {
    log_call("ssh-keygen", arguments);
    match arguments {
        [quiet, derive, file, private] if quiet == "-q" && derive == "-y" && file == "-f" => {
            assert!(Path::new(private).is_absolute());
            println!("ssh-ed25519 {PRIMARY_KEY}");
        }
        [quiet, key_type, algorithm, no_passphrase, passphrase, comment, label, file, private]
            if quiet == "-q"
                && key_type == "-t"
                && algorithm == "ed25519"
                && no_passphrase == "-N"
                && passphrase.is_empty()
                && comment == "-C"
                && label == "styrn-controller"
                && file == "-f" =>
        {
            let private = PathBuf::from(private);
            assert!(private.is_absolute());
            fs::write(&private, b"fixture-private-key\n").unwrap();
            fs::write(
                private.with_extension("pub"),
                format!("ssh-ed25519 {PRIMARY_KEY} styrn-controller\n"),
            )
            .unwrap();
        }
        _ => panic!("unexpected ssh-keygen argv"),
    }
}

fn exec_fixture(arguments: &[String]) {
    let (scenario, arguments) = arguments
        .split_first()
        .expect("remote exec fixture scenario is required");
    match scenario.as_str() {
        "echo-argv" => println!("{}", serde_json::to_string(arguments).unwrap()),
        "exit-101" => std::process::exit(101),
        "secret-output" => {
            println!("password: fixture-secret-output-value");
            eprintln!("token=fixture-secret-error-value");
        }
        _ => panic!("unknown remote exec fixture scenario"),
    }
}

fn serve_malformed_manifest() {
    serve_manifest_response("not valid TOML = [".to_owned());
}

fn serve_substituted_user_manifest() {
    let output = Command::new(required_path("PHASE1_FIXTURE_STYRN"))
        .args(["machine", "manifest"])
        .env_remove("STYRN_JSON")
        .env(
            "STYRN_CONFIG_DIR",
            required_path("PHASE1_FIXTURE_WORKER_CONFIG"),
        )
        .output()
        .expect("the substitute fixture must read the worker manifest");
    assert!(
        output.status.success(),
        "worker manifest read failed: {output:?}"
    );
    let manifest = String::from_utf8(output.stdout).unwrap();
    let document: toml::Value = toml::from_str(&manifest).unwrap();
    let user = document["transport"]["user"].as_str().unwrap();
    let substituted = manifest
        .replace(
            &format!("user = {}", toml::Value::String(user.to_owned())),
            "user = \"substitute-user\"",
        )
        .replace(
            &format!("name = {}", toml::Value::String(user.to_owned())),
            "name = \"substitute-user\"",
        );
    assert_ne!(substituted, manifest);
    serve_manifest_response(substituted);
}

fn serve_manifest_response(manifest_toml: String) {
    println!(
        "{}",
        json!({
            "id": "hello",
            "type": "hello",
            "protocol_min": 1,
            "protocol_max": 1,
            "styrn_version": "0.1.0",
            "machine_id": WORKER_ID,
            "name": "worker.example",
            "manifest_schema_version": 1,
        })
    );
    std::io::stdout().flush().unwrap();
    let stdin = std::io::stdin();
    let mut lines = stdin.lock().lines();
    let _client_hello = lines.next().expect("missing client hello").unwrap();
    let request: serde_json::Value = serde_json::from_str(
        &lines
            .next()
            .expect("missing machine.manifest request")
            .unwrap(),
    )
    .unwrap();
    println!(
        "{}",
        json!({
            "id": request["id"],
            "type": "response",
            "ok": true,
            "data": {"toml": manifest_toml},
        })
    );
    std::io::stdout().flush().unwrap();
}

fn log_call(tool: &str, arguments: &[String]) {
    let mut log = OpenOptions::new()
        .create(true)
        .append(true)
        .open(fixture_root().join("calls.jsonl"))
        .unwrap();
    serde_json::to_writer(&mut log, &json!({ "tool": tool, "argv": arguments })).unwrap();
    writeln!(log).unwrap();
    log.flush().unwrap();
}

fn fixture_root() -> PathBuf {
    required_path("PHASE1_FIXTURE_ROOT")
}

fn required_path(name: &str) -> PathBuf {
    std::env::var_os(name)
        .filter(|value| !value.is_empty())
        .map(PathBuf::from)
        .unwrap_or_else(|| panic!("{name} is required"))
}
