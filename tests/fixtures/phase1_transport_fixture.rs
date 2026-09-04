use serde_json::json;
use std::fs::{self, OpenOptions};
use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

const PRIMARY_KEY: &str = "AAAAC3NzaC1lZDI1NTE5AAAAIAABAgMEBQYHCAkKCwwNDg8QERITFBUWFxgZGhscHR4f";
const CHANGED_KEY: &str = "AAAAC3NzaC1lZDI1NTE5AAAAIB8eHRwbGhkYFxYVFBMSERAPDg0MCwoJCAcGBQQDAgEA";

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
    let changed = fs::read_to_string(fixture_root().join("host-key"))
        .is_ok_and(|state| state.trim() == "changed");
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
        _ => panic!("unknown remote exec fixture scenario"),
    }
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
