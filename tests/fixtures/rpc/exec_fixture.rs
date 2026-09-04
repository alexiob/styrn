use std::fs;
use std::io::{self, BufRead, Write};
use std::path::Path;
use std::time::Duration;

const SECRET: &str = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJzdHlybi10ZXN0In0.signaturesegment123";

fn main() {
    let mut arguments = std::env::args().skip(1);
    let scenario = arguments.next().expect("fixture scenario is required");
    match scenario.as_str() {
        "echo-argv" => {
            println!(
                "{}",
                serde_json::to_string(&arguments.collect::<Vec<_>>()).unwrap()
            );
        }
        "mark-and-echo" => {
            let marker = arguments.next().expect("marker path is required");
            fs::write(marker, b"ran").unwrap();
            println!("ran");
        }
        "overflow" => {
            let marker = arguments.next().expect("marker path is required");
            let bytes = vec![b'x'; 1_048_577];
            io::stdout().write_all(&bytes).unwrap();
            io::stdout().flush().unwrap();
            std::thread::sleep(Duration::from_secs(10));
            fs::write(marker, b"completed").unwrap();
        }
        "hostile-output" => {
            println!("{SECRET}");
            eprintln!("{SECRET}");
        }
        "labeled-output" => {
            println!("password: hunter2");
            eprintln!(r#"{{"api_key":"value"}}"#);
        }
        "invalid-output" => {
            io::stdout().write_all(&[b'o', 0xff, b'\n']).unwrap();
            io::stderr().write_all(&[b'e', 0xfe, b'\n']).unwrap();
        }
        "fake-rpc-malformed-failure" => {
            fake_rpc_malformed_failure(arguments.next().as_deref().unwrap_or("wrong-code"))
        }
        "touch" => {
            let marker = arguments.next().expect("marker path is required");
            fs::write(Path::new(&marker), b"touched").unwrap();
        }
        _ => panic!("unknown fixture scenario"),
    }
}

fn fake_rpc_malformed_failure(variant: &str) {
    let mut stdout = io::stdout().lock();
    writeln!(
        stdout,
        "{{\"id\":\"hello\",\"type\":\"hello\",\"protocol_min\":1,\"protocol_max\":1,\"styrn_version\":\"test\",\"machine_id\":\"01991f5d-d72f-7b5e-a43d-9fcb61bd3265\",\"name\":\"worker\",\"manifest_schema_version\":1}}"
    )
    .unwrap();
    stdout.flush().unwrap();

    let stdin = io::stdin();
    let mut lines = stdin.lock().lines();
    let _selection = lines.next().unwrap().unwrap();
    let request: serde_json::Value = serde_json::from_str(&lines.next().unwrap().unwrap()).unwrap();
    let diagnostic = serde_json::json!({
        "code": "remote.execution_failed",
        "message": "the worker could not complete the RPC method"
    });
    let errors = match variant {
        "wrong-code" => vec![serde_json::json!({
            "code": "future.failure",
            "message": "the worker could not complete the RPC method"
        })],
        "wrong-message" => vec![serde_json::json!({
            "code": "remote.execution_failed",
            "message": "future failure shape"
        })],
        "multiple" => vec![diagnostic.clone(), diagnostic.clone()],
        "details" => vec![serde_json::json!({
            "code": "remote.execution_failed",
            "message": "the worker could not complete the RPC method",
            "details": {"retryable": false}
        })],
        _ => panic!("unknown malformed failure variant"),
    };
    let response = serde_json::json!({
        "id": request["id"],
        "type": "response",
        "ok": false,
        "errors": errors
    });
    writeln!(stdout, "{response}").unwrap();
    stdout.flush().unwrap();
    let _ = lines.next();
}
