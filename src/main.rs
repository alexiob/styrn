mod cli;
mod config;
mod desktop;
mod git;
mod harness;
mod integrations;
mod inventory;
mod jobs;
mod manifest;
mod mcp;
mod notification;
#[allow(dead_code)]
mod output;
mod platform;
mod project;
mod resources;
mod rpc;
mod scheduler;
mod setup;
mod transport;

fn main() {
    match cli::Cli::try_parse_process() {
        Ok(parsed) => run(parsed),
        Err(failure) => {
            let exit = if failure.is_display() {
                output::StyrnExit::Success
            } else {
                output::StyrnExit::Usage
            };

            let stdout = std::io::stdout();
            let stderr = std::io::stderr();
            cli::render_parse_failure(&failure, &mut stdout.lock(), &mut stderr.lock())
                .expect("writing CLI output must succeed");
            if exit != output::StyrnExit::Success {
                output::exit_process(exit);
            }
        }
    }
}

fn run(parsed: cli::ParsedCli) {
    let Some(action) = parsed.machine_action() else {
        return;
    };
    let command = match action {
        cli::MachineAction::Manifest => "machine manifest",
        cli::MachineAction::Init => "machine init",
    };
    let result = match manifest::configured_manifest_store() {
        Ok(store) => match action {
            cli::MachineAction::Manifest => store.read(),
            cli::MachineAction::Init => store.reconcile(),
        },
        Err(error) => Err(error),
    };
    match result {
        Ok(outcome) => {
            if outcome.machine_id_minted {
                eprintln!("machine_id was minted and persisted");
            }
            if parsed.json_output() {
                let warnings = if outcome.machine_id_minted {
                    vec![output::Diagnostic::new(
                        "machine.machine_id_minted",
                        "machine_id was minted and persisted",
                        None,
                    )
                    .expect("the built-in manifest warning must be valid")]
                } else {
                    Vec::new()
                };
                let envelope = output::Envelope::success(
                    command,
                    chrono::Utc::now(),
                    outcome
                        .manifest
                        .to_json_value()
                        .expect("validated manifest must serialize"),
                    warnings,
                )
                .expect("the built-in manifest output must be valid");
                output::write_json(std::io::stdout().lock(), &envelope)
                    .expect("writing command output must succeed");
            } else {
                print!(
                    "{}",
                    outcome
                        .manifest
                        .to_toml()
                        .expect("validated manifest must serialize")
                );
            }
        }
        Err(error) => {
            if parsed.json_output() {
                let failure = output::CommandFailure::new(
                    command,
                    chrono::Utc::now(),
                    output::ErrorCode::MachineManifestInvalid,
                    error.to_string(),
                )
                .expect("the built-in manifest error must be valid");
                output::write_json(std::io::stdout().lock(), failure.envelope())
                    .expect("writing command output must succeed");
                output::exit_process(failure.exit_code());
            }
            eprintln!("{error}");
            output::exit_process(output::StyrnExit::Usage);
        }
    }
}
