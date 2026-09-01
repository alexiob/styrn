#[allow(dead_code)]
#[path = "../../src/output/mod.rs"]
mod output;

use chrono::{TimeZone, Utc};

fn timestamp() -> chrono::DateTime<Utc> {
    Utc.with_ymd_and_hms(2026, 9, 1, 12, 0, 0).single().unwrap()
}

fn main() {
    let mut arguments = std::env::args().skip(1);
    let scenario = arguments.next().expect("fixture scenario is required");

    match scenario.as_str() {
        "exit" => exit(arguments.next().expect("exit code is required")),
        "registry" => registry(arguments.next().expect("registry code is required")),
        "workflow-101" => workflow_101(),
        "exec-101" => exec_101(),
        "panic" => panic_boundary(),
        _ => panic!("unknown fixture scenario"),
    }
}

fn exit(value: String) -> ! {
    let value: i32 = value.parse().expect("exit code must be an integer");
    let exit = output::StyrnExit::from_i32(value).expect("documented Styrn exit code");
    output::exit_process(exit)
}

fn registry(name: String) -> ! {
    let code = output::ErrorCode::from_str(&name).expect("registered error code");
    println!("{} {}", code.as_str(), code.exit_code().as_i32());
    output::exit_process(code.exit_code())
}

fn workflow_101() -> ! {
    let failure = output::WorkflowFailure::new("workflow run", timestamp(), 101).unwrap();
    output::write_json(std::io::stdout(), failure.envelope()).unwrap();
    output::exit_process(failure.exit_code())
}

fn exec_101() -> ! {
    let outcome =
        output::ExecOutcome::new(timestamp(), 101, "fixture stdout", "fixture stderr", 12).unwrap();
    output::write_json(std::io::stdout(), outcome.envelope()).unwrap();
    std::process::exit(outcome.process_exit_code())
}

fn panic_boundary() -> ! {
    let previous_hook = std::panic::take_hook();
    std::panic::set_hook(Box::new(|_| {}));
    let failure =
        output::catch_unmapped_panic("host status", timestamp(), || panic!("fixture panic"))
            .expect_err("panic must become a failure envelope");
    std::panic::set_hook(previous_hook);
    output::write_json(std::io::stdout(), failure.envelope()).unwrap();
    output::exit_process(failure.exit_code())
}
