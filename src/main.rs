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

            if !failure.is_display() && failure.is_setup_json_failure() {
                fail_setup(
                    true,
                    output::ErrorCode::UsageInvalidArgument,
                    failure.safe_setup_message(),
                    None,
                );
            } else {
                let stdout = std::io::stdout();
                let stderr = std::io::stderr();
                cli::render_parse_failure(&failure, &mut stdout.lock(), &mut stderr.lock())
                    .expect("writing CLI output must succeed");
            }
            if exit != output::StyrnExit::Success {
                output::exit_process(exit);
            }
        }
    }
}

fn run(parsed: cli::ParsedCli) {
    if parsed.privileged_setup_request().is_some() {
        fail_unavailable_setup(
            &parsed,
            "setup privileged-phase",
            "privileged setup execution is not available in this build",
        );
    }
    if let Some(request) = parsed.setup_request() {
        run_rootless_setup(request);
        return;
    }
    if parsed.is_setup_command() {
        fail_unavailable_setup(
            &parsed,
            "setup user-phase",
            "setup user-phase execution is not available in this build",
        );
    }
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

fn run_rootless_setup(request: cli::SetupRequest) {
    let json = request.json();
    if let Err(error) = setup::validate_rootless_setup_request(&request) {
        fail_setup_input(json, error);
    }
    let effective = if request.interactive() {
        let stdin = std::io::stdin();
        let stdout = std::io::stdout();
        match setup::collect_interactive_answers(
            &mut stdin.lock(),
            &mut stdout.lock(),
            request.stdin_terminal(),
        ) {
            Ok(effective) => effective,
            Err(error) => fail_setup_input(json, error),
        }
    } else {
        match setup::load_effective_rootless_setup(&request) {
            Ok(effective) => effective,
            Err(error) => fail_setup_input(json, error),
        }
    };
    let selected_components = effective.selected_component_names().collect::<Vec<_>>();
    let prepared = match setup::prepare_rootless_setup(effective) {
        Ok(prepared) => prepared,
        Err(error) => fail_setup_orchestrator(json, &error),
    };

    if json {
        if request.dry_run() {
            let envelope = output::Envelope::success(
                "setup",
                chrono::Utc::now(),
                serde_json::json!({ "plan": setup_plan_json(prepared.plan_items()) }),
                Vec::new(),
            )
            .expect("the built-in setup dry-run output must be valid");
            output::write_json(std::io::stdout().lock(), &envelope)
                .expect("writing setup output must succeed");
            return;
        }
    } else {
        render_setup_plan(&selected_components, prepared.plan_items());
        if request.dry_run() {
            println!("Dry run complete; no changes were applied.");
            return;
        }
    }

    if !request.yes() {
        let accepted = if json || !request.stdin_terminal() {
            false
        } else {
            let stdin = std::io::stdin();
            let stdout = std::io::stdout();
            confirm_rootless_setup(&mut stdin.lock(), &mut stdout.lock())
        };
        if !accepted {
            fail_setup(
                json,
                output::ErrorCode::SetupConfirmationRequired,
                "setup confirmation is required",
                json.then(|| serde_json::json!({ "plan": setup_plan_json(prepared.plan_items()) })),
            );
        }
    }

    if request.interactive() {
        let destination = match std::env::current_dir() {
            Ok(directory) => directory.join("setup-config.toml"),
            Err(_) => fail_setup(
                json,
                output::ErrorCode::SetupPlanInvalid,
                "interactive replay destination is unavailable",
                None,
            ),
        };
        if let Err(error) = setup::persist_interactive_replay(prepared.effective(), &destination) {
            fail_setup_input(json, error);
        }
        println!("Replay configuration: {}", destination.display());
    }

    match setup::apply_rootless_setup(prepared) {
        Ok(outcome) => render_setup_outcome(json, &outcome),
        Err(error) => {
            if let Some(outcome) = error.outcome() {
                render_setup_pending_failure(json, &error, outcome);
            }
            fail_setup_orchestrator(json, &error);
        }
    }
}

fn confirm_rootless_setup(
    input: &mut dyn std::io::BufRead,
    output: &mut dyn std::io::Write,
) -> bool {
    if output
        .write_all(b"Apply this rootless user-scope plan? [y/N] ")
        .and_then(|()| output.flush())
        .is_err()
    {
        return false;
    }
    let mut answer = String::new();
    if input
        .read_line(&mut answer)
        .ok()
        .filter(|read| *read != 0)
        .is_none()
    {
        return false;
    }
    matches!(answer.trim().to_ascii_lowercase().as_str(), "y" | "yes")
}

fn render_setup_plan(components: &[&str], plan: &[setup::RootlessSetupPlanItem]) {
    println!("scope=user role=worker account=current-user");
    println!("components={}", components.join(","));
    if let Some(item) = plan.first() {
        println!("security: {}", item.security_caveat());
    }
    println!("plan:");
    for item in plan {
        println!(
            "  {} {} {} [{}] {}",
            item.action_id(),
            item.component(),
            item.operation(),
            item.privilege(),
            item.description()
        );
    }
}

fn setup_plan_json(plan: &[setup::RootlessSetupPlanItem]) -> Vec<serde_json::Value> {
    plan.iter()
        .map(|item| {
            serde_json::json!({
                "action_id": item.action_id(),
                "component": item.component(),
                "operation": item.operation(),
                "privilege": item.privilege(),
                "description": item.description(),
                "scope": item.scope(),
                "role": item.role(),
                "account": item.account(),
                "security_caveat": item.security_caveat(),
            })
        })
        .collect()
}

fn setup_outcome_json(outcome: &setup::RootlessSetupOutcome) -> serde_json::Value {
    serde_json::json!({
        "plan": setup_plan_json(outcome.plan_items()),
        "results": outcome.execution_results().map(|(action_id, status)| {
            serde_json::json!({ "action_id": action_id, "status": status })
        }).collect::<Vec<_>>(),
        "pending": setup_pending_json(outcome.pending()),
        "manifest": setup_path_text(outcome.manifest_path()),
        "receipt": setup_path_text(outcome.receipt_path()),
    })
}

fn setup_pending_json(pending: &[setup::RootlessPendingResult]) -> Vec<serde_json::Value> {
    pending
        .iter()
        .map(|item| {
            serde_json::json!({
                "action_id": item.action_id(),
                "severity": item.severity(),
                "message": item.message(),
            })
        })
        .collect()
}

fn setup_path_text(path: &std::path::Path) -> &str {
    path.to_str()
        .expect("validated rootless setup paths must be valid UTF-8")
}

fn setup_pending_warnings(pending: &[setup::RootlessPendingResult]) -> Vec<output::Diagnostic> {
    pending
        .iter()
        .map(|item| {
            output::Diagnostic::new(
                "setup.needs_human",
                item.message(),
                Some(serde_json::json!({ "action_id": item.action_id() })),
            )
            .expect("rootless pending output must be valid")
        })
        .collect()
}

fn render_setup_outcome(json: bool, outcome: &setup::RootlessSetupOutcome) {
    if json {
        let envelope = output::Envelope::success(
            "setup",
            chrono::Utc::now(),
            setup_outcome_json(outcome),
            setup_pending_warnings(outcome.pending()),
        )
        .expect("the built-in setup output must be valid");
        output::write_json(std::io::stdout().lock(), &envelope)
            .expect("writing setup output must succeed");
        return;
    }
    render_setup_summary(outcome);
}

fn render_setup_summary(outcome: &setup::RootlessSetupOutcome) {
    println!("Rootless user-scope state published.");
    println!("manifest: {}", outcome.manifest_path().display());
    println!("receipt: {}", outcome.receipt_path().display());
    println!("results:");
    for (action_id, status) in outcome.execution_results() {
        println!("  {action_id}: {status}");
    }
    if !outcome.pending().is_empty() {
        println!("pending actions:");
        for pending in outcome.pending() {
            println!("  {}: {}", pending.action_id(), pending.message());
        }
    }
    println!("security: {}", outcome.security_caveat());
}

fn render_setup_pending_failure(
    json: bool,
    error: &setup::RootlessSetupError,
    outcome: &setup::RootlessSetupOutcome,
) -> ! {
    if json {
        let code = output::ErrorCode::from_str(error.error_code())
            .expect("rootless setup errors must use the registered output codes");
        let diagnostic = output::ErrorDiagnostic::new(
            code,
            error.to_string(),
            Some(setup_outcome_json(outcome)),
        )
        .expect("the built-in pending failure must be valid");
        let envelope = output::Envelope::failure(
            "setup",
            chrono::Utc::now(),
            vec![diagnostic],
            setup_pending_warnings(outcome.pending()),
        )
        .expect("the built-in pending failure output must be valid");
        output::write_json(std::io::stdout().lock(), &envelope)
            .expect("writing setup output must succeed");
    } else {
        render_setup_summary(outcome);
        eprintln!("{error}");
    }
    output::exit_process(output::StyrnExit::Setup);
}

fn fail_setup_input(json: bool, error: setup::SetupInputError) -> ! {
    let code = match error {
        setup::SetupInputError::Usage(_) => output::ErrorCode::UsageInvalidArgument,
        setup::SetupInputError::Config(_) => output::ErrorCode::UsageConfigInvalid,
        setup::SetupInputError::Plan(_) => output::ErrorCode::SetupPlanInvalid,
    };
    fail_setup(json, code, &error.to_string(), None)
}

fn fail_setup_orchestrator(json: bool, error: &setup::RootlessSetupError) -> ! {
    let code = output::ErrorCode::from_str(error.error_code())
        .expect("rootless setup errors must use the registered output codes");
    fail_setup(json, code, &error.to_string(), error.details())
}

fn fail_setup(
    json: bool,
    code: output::ErrorCode,
    message: &str,
    details: Option<serde_json::Value>,
) -> ! {
    if json {
        let envelope = setup_failure_envelope(code, message, details);
        output::write_json(std::io::stdout().lock(), &envelope)
            .expect("writing setup output must succeed");
    } else {
        eprintln!("{message}");
    }
    output::exit_process(code.exit_code());
}

fn setup_failure_envelope(
    code: output::ErrorCode,
    message: &str,
    details: Option<serde_json::Value>,
) -> output::Envelope {
    let error = output::ErrorDiagnostic::new(code, message, details)
        .expect("the built-in setup diagnostic must be valid");
    output::Envelope::failure("setup", chrono::Utc::now(), vec![error], Vec::new())
        .expect("the built-in setup failure output must be valid")
}

fn fail_unavailable_setup(parsed: &cli::ParsedCli, command: &str, message: &str) -> ! {
    if parsed.json_output() {
        let failure = output::CommandFailure::new(
            command,
            chrono::Utc::now(),
            output::ErrorCode::SetupPlanInvalid,
            message,
        )
        .expect("the built-in setup error must be valid");
        output::write_json(std::io::stdout().lock(), failure.envelope())
            .expect("writing command output must succeed");
        output::exit_process(failure.exit_code());
    }
    eprintln!("{message}");
    output::exit_process(output::StyrnExit::Setup);
}

#[cfg(test)]
mod setup_failure_output_tests {
    #[test]
    fn operation_failure_reaches_json_details_and_safe_human_remediation() {
        let error = crate::setup::RootlessSetupError::operation_failed_for_output_test();
        let code = crate::output::ErrorCode::from_str(error.error_code()).unwrap();
        let envelope = super::setup_failure_envelope(code, &error.to_string(), error.details());
        let mut bytes = Vec::new();
        crate::output::write_json(&mut bytes, &envelope).unwrap();
        let document: serde_json::Value = serde_json::from_slice(&bytes).unwrap();

        assert_eq!(document["errors"][0]["details"]["phase"], "execution");
        assert_eq!(
            document["errors"][0]["details"]["action_id"],
            "identity.directory.root"
        );
        assert_eq!(
            document["errors"][0]["details"]["cause_category"],
            "action_apply"
        );
        assert!(document["errors"][0]["details"]["remediation"]
            .as_str()
            .unwrap()
            .contains("retry setup"));
        let human = error.to_string();
        assert!(human.contains("identity.directory.root"));
        assert!(human.contains("retry setup"));
        assert!(!String::from_utf8(bytes).unwrap().contains("native-secret"));
        assert!(!human.contains("native-secret"));
    }
}
