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
    if parsed.rpc_serve_stdio() {
        if let Err(error) = rpc::serve_stdio() {
            eprintln!("{error}");
            output::exit_process(error.exit_code());
        }
        return;
    }
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
    if let Some(action) = parsed.controller_action() {
        run_controller_command(action, parsed.json_output());
        return;
    }
    if let Some(action) = parsed.host_action() {
        run_host_command(action, parsed.json_output(), parsed.stdin_terminal());
        return;
    }
    if let Some(request) = parsed.exec_request() {
        run_exec_command(request, parsed.json_output());
        return;
    }
    if let Some(action) = parsed.machine_action() {
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
        return;
    }

    fail_phase1(
        parsed.json_output(),
        parsed.command_name(),
        Phase1CommandError::new(
            output::ErrorCode::CapabilityUnsatisfied,
            "this command is not available in this build",
        ),
    );
}

#[derive(Clone)]
struct Phase1CommandError {
    code: output::ErrorCode,
    message: &'static str,
    recovery_public_key_path: Option<std::path::PathBuf>,
}

impl Phase1CommandError {
    const fn new(code: output::ErrorCode, message: &'static str) -> Self {
        Self {
            code,
            message,
            recovery_public_key_path: None,
        }
    }

    fn with_public_key_recovery(mut self, public_key_path: &std::path::Path) -> Self {
        self.recovery_public_key_path = Some(public_key_path.to_path_buf());
        self
    }
}

#[derive(Clone, Copy)]
struct Phase1Warning {
    code: &'static str,
    message: &'static str,
}

const KNOWN_HOSTS_WARNING: Phase1Warning = Phase1Warning {
    code: "inventory.known_hosts_rebuild_failed",
    message: "the host was committed but the derived known-hosts file needs repair",
};

fn run_controller_command(action: cli::ControllerAction, json: bool) {
    match action {
        cli::ControllerAction::Init => match configured_controller_identity() {
            Ok(identity) => {
                let data = serde_json::json!({
                    "created": identity.created(),
                    "private_path": identity.private_path(),
                    "public_path": identity.public_path(),
                    "public_key": identity.public_line(),
                    "fingerprint": identity.fingerprint(),
                });
                let human = format!(
                    "Controller identity {}\nPublic key: {}\nFingerprint: {}\n",
                    identity.public_path().display(),
                    identity.public_line(),
                    identity.fingerprint()
                );
                render_phase1_success(json, "controller init", data, &human, &[]);
            }
            Err(error) => fail_phase1(json, "controller init", error),
        },
    }
}

fn run_host_command(action: cli::HostAction, json: bool, stdin_terminal: bool) {
    let command = match &action {
        cli::HostAction::List => "host list",
        cli::HostAction::Show { .. } => "host show",
        cli::HostAction::Status { .. } => "host status",
        cli::HostAction::Enroll { .. } => "host enroll",
        cli::HostAction::Doctor { .. } => "host doctor",
        cli::HostAction::Refresh { .. } => "host refresh",
        cli::HostAction::Trust { .. } => "host trust",
    };
    let result = match action {
        cli::HostAction::List => host_list(),
        cli::HostAction::Show { host } => host_show(&host),
        cli::HostAction::Status { host } => host_status(host.as_deref()),
        cli::HostAction::Enroll {
            host,
            user,
            fingerprint,
        } => host_enroll(&host, &user, fingerprint.as_deref(), json, stdin_terminal),
        cli::HostAction::Doctor { host } => host_doctor(host.as_deref()),
        cli::HostAction::Refresh { host } => host_refresh(host.as_deref()),
        cli::HostAction::Trust { host, fingerprint } => host_trust(&host, &fingerprint),
    };
    match result {
        Ok((data, human, warnings)) => {
            render_phase1_success(json, command, data, &human, &warnings)
        }
        Err(error) => fail_phase1(json, command, error),
    }
}

type HostCommandSuccess = (serde_json::Value, String, Vec<Phase1Warning>);

fn host_list() -> Result<HostCommandSuccess, Phase1CommandError> {
    let store = inventory::InventoryStore::configured().map_err(inventory_error)?;
    let document = store.read().map_err(inventory_error)?;
    let hosts = document.hosts().iter().map(host_json).collect::<Vec<_>>();
    let human = if document.hosts().is_empty() {
        "No enrolled hosts.\n".to_owned()
    } else {
        let mut text = String::new();
        for host in document.hosts() {
            text.push_str(host.name());
            text.push('\n');
        }
        text
    };
    Ok((serde_json::json!({ "hosts": hosts }), human, Vec::new()))
}

fn host_show(name: &str) -> Result<HostCommandSuccess, Phase1CommandError> {
    let store = inventory::InventoryStore::configured().map_err(inventory_error)?;
    let document = store.read().map_err(inventory_error)?;
    let host = document.select(Some(name)).map_err(inventory_error)?;
    let data = host_json(host);
    let human = format!(
        "{}\n  machine_id  {}\n  endpoint    {}:{}\n  user        {}\n  fingerprint {}\n",
        host.name(),
        host.machine_id(),
        host.transport().host(),
        host.transport().port(),
        host.transport().user(),
        host.transport().host_key().fingerprint(),
    );
    Ok((data, human, Vec::new()))
}

fn host_status(name: Option<&str>) -> Result<HostCommandSuccess, Phase1CommandError> {
    let store = inventory::InventoryStore::configured().map_err(inventory_error)?;
    let host = select_host_for_network(&store, name)?;
    let (_identity, mut client) = connect_host(&store, &host)?;
    let expected = expected_peer(&host)?;
    let manifest = client.machine_manifest(&expected).map_err(rpc_error)?;
    validate_manifest_endpoint(&manifest, &host)?;
    let status = client.machine_status().map_err(rpc_error)?;
    client.finish().map_err(rpc_error)?;
    let data = serde_json::json!({ "host": host.name(), "status": status });
    let human = format!(
        "{}: {} CPUs, {} bytes available memory, {} bytes free disk\n",
        host.name(),
        status.cpu.logical,
        status.memory.available_bytes,
        status.disk.free_bytes
    );
    Ok((data, human, Vec::new()))
}

fn host_refresh(name: Option<&str>) -> Result<HostCommandSuccess, Phase1CommandError> {
    let store = inventory::InventoryStore::configured().map_err(inventory_error)?;
    let host = select_host_for_network(&store, name)?;
    let (_identity, mut client) = connect_host(&store, &host)?;
    let expected = expected_peer(&host)?;
    let version = client.server_hello().styrn_version.clone();
    let manifest = client.machine_manifest(&expected).map_err(rpc_error)?;
    validate_manifest_endpoint(&manifest, &host)?;
    client.finish().map_err(rpc_error)?;
    let cache =
        inventory::ManifestCache::new(chrono::Utc::now().fixed_offset(), &version, &manifest)
            .map_err(inventory_error)?;
    store.write_cache(&cache).map_err(inventory_error)?;
    Ok((
        serde_json::json!({ "host": host.name(), "machine_id": host.machine_id(), "refreshed": true }),
        format!("Refreshed {}\n", host.name()),
        Vec::new(),
    ))
}

fn host_doctor(name: Option<&str>) -> Result<HostCommandSuccess, Phase1CommandError> {
    let store = inventory::InventoryStore::configured().map_err(inventory_error)?;
    let host = select_host_for_network(&store, name)?;
    let cache = store.read_cache(host.machine_id());
    let (identity, mut client) = connect_host(&store, &host)?;
    let expected = expected_peer(&host)?;
    let version = client.server_hello().styrn_version.clone();
    let manifest = client.machine_manifest(&expected).map_err(rpc_error)?;
    validate_manifest_endpoint(&manifest, &host)?;
    let status = client.machine_status().map_err(rpc_error)?;
    let worker = client
        .machine_doctor(identity.public_line())
        .map_err(rpc_error)?;
    client.finish().map_err(rpc_error)?;

    let clock_skew_seconds =
        chrono::DateTime::parse_from_rfc3339(&status.time)
            .ok()
            .map(|worker_time| {
                (chrono::Utc::now().timestamp() - worker_time.timestamp()).unsigned_abs()
            });
    let cache_stale = cache.as_ref().is_ok_and(|cache| {
        chrono::Utc::now().fixed_offset() - cache.cached_at() > chrono::Duration::days(7)
    });
    let version_drift = cache
        .as_ref()
        .is_ok_and(|cache| cache.styrn_version() != version);
    let cache_bound_to_live_worker = cache.as_ref().is_ok_and(|cache| {
        cache.manifest().is_ok_and(|cached_manifest| {
            manifest_matches_host(&cached_manifest, &host)
                && cached_manifest.to_toml().ok() == manifest.to_toml().ok()
        })
    });
    let cache_healthy = cache_bound_to_live_worker && !cache_stale && !version_drift;
    let clock_healthy = clock_skew_seconds.is_some_and(|seconds| seconds <= 30);
    let disk_floor = configured_disk_floor(&manifest);
    let disk_state = match disk_floor {
        Some(floor) if status.disk.free_bytes >= floor => "pass",
        Some(_) => "fail",
        None => "unknown",
    };
    let pending_actions = manifest.pending_actions.as_deref().unwrap_or(&[]);
    let pending_state = if pending_actions.is_empty() {
        "pass"
    } else {
        "fail"
    };
    let controller_findings = serde_json::json!([
        {"id":"controller.transport.ssh","state":"pass","severity":"info","message":"SSH and RPC completed","remediation":null},
        {"id":"controller.protocol.compatible","state":"pass","severity":"info","message":"RPC protocol is compatible","remediation":null},
        {"id":"controller.manifest.binding","state":"pass","severity":"info","message":"worker identity and manifest are bound","remediation":null},
        {"id":"controller.clock.skew","state": if clock_healthy {"pass"} else {"fail"},"severity": if clock_healthy {"info"} else {"warning"},"message":"worker clock skew was checked","remediation": if clock_healthy {serde_json::Value::Null} else {doctor_remediation("synchronize the controller and worker system clocks, then rerun styrn host doctor", None)}},
        {"id":"controller.cache.state","state": if cache_healthy {"pass"} else {"fail"},"severity": if cache_healthy {"info"} else {"warning"},"message":"manifest cache binding, age, and worker version were checked","remediation": if cache_healthy {serde_json::Value::Null} else {doctor_remediation("refresh the selected worker manifest cache", Some(vec!["host".to_owned(), "refresh".to_owned(), host.name().to_owned()]))}},
        {"id":"worker.disk.floor","state":disk_state,"severity":if disk_state == "fail" {"error"} else {"info"},"message":"live free disk space was checked against the configured hard floor","remediation":if disk_state == "pass" {serde_json::Value::Null} else {doctor_remediation("free disk space or correct the worker's configured disk reserve, then rerun styrn host doctor", None)}},
        {"id":"worker.pending_actions","state":pending_state,"severity":if pending_state == "fail" {"warning"} else {"info"},"message":if pending_state == "fail" {"the worker manifest has unresolved pending actions"} else {"the worker manifest has no unresolved pending actions"},"remediation":if pending_state == "pass" {serde_json::Value::Null} else {doctor_remediation("complete each pending action reported by the worker manifest, then rerun styrn host doctor", None)}},
        {"id":"controller.coverage.deferred","state":"unknown","severity":"info","message":"remaining fleet and platform-specific checks are deferred","remediation":doctor_remediation("run the documented native platform acceptance checks for the deferred doctor coverage", None)}
    ]);
    let data = serde_json::json!({
        "host": host.name(),
        "coverage": "phase1_minimum",
        "complete": false,
        "controller_findings": controller_findings,
        "pending_actions": pending_actions,
        "worker": worker,
        "status": status,
    });
    Ok((
        data,
        format!(
            "Doctor completed for {} (phase1 minimum; incomplete)\n",
            host.name()
        ),
        Vec::new(),
    ))
}

fn host_enroll(
    host: &str,
    user: &str,
    fingerprint: Option<&str>,
    json: bool,
    stdin_terminal: bool,
) -> Result<HostCommandSuccess, Phase1CommandError> {
    transport::validate_ssh_destination(host, user, 22).map_err(|_| invalid_ssh_argument())?;
    if let Some(fingerprint) = fingerprint {
        transport::validate_host_key_fingerprint(fingerprint)
            .map_err(|_| invalid_ssh_argument())?;
    } else if json || !stdin_terminal {
        return Err(Phase1CommandError::new(
            output::ErrorCode::UsageInvalidArgument,
            "non-interactive enrollment requires --fingerprint",
        ));
    }

    let identity = configured_controller_identity()?;
    let result = (|| {
        let store = inventory::InventoryStore::configured().map_err(inventory_error)?;
        let snapshot = store.read().map_err(inventory_error)?;
        let named = snapshot.host(host);
        let mut endpoint_matches = snapshot.hosts().iter().filter(|record| {
            record.transport().host() == host && record.transport().user() == user
        });
        let endpoint = endpoint_matches.next();
        if endpoint_matches.next().is_some()
            || matches!((named, endpoint), (Some(named), Some(endpoint)) if named != endpoint)
        {
            return Err(Phase1CommandError::new(
                output::ErrorCode::UsageConfigInvalid,
                "the enrollment endpoint is ambiguous in local inventory",
            ));
        }
        let previous = named.or(endpoint).cloned();
        let scanner = transport::SshTransport::configured(store.known_hosts_path().to_path_buf());
        let pin = scanner
            .scan_host_key(host, 22, fingerprint)
            .map_err(transport_error)?;
        if fingerprint.is_none() && !confirm_host_key(pin.fingerprint()) {
            return Err(Phase1CommandError::new(
                output::ErrorCode::TransportAuthFailed,
                "the worker host key was not confirmed",
            ));
        }

        let stored = inventory::StoredSsh::new(
            host,
            user,
            22,
            identity.private_path().to_path_buf(),
            pin.clone(),
        )
        .map_err(inventory_error)?;
        if previous
            .as_ref()
            .is_some_and(|record| record.transport() != &stored)
        {
            return Err(Phase1CommandError::new(
                output::ErrorCode::UsageConfigInvalid,
                "the enrolled host endpoint or trust binding conflicts with local inventory",
            ));
        }

        let candidate = store
            .candidate_known_hosts(host, 22, &pin)
            .map_err(inventory_error)?;
        let target = stored.rpc_target().map_err(transport_error)?;
        let enrollment_transport =
            transport::SshTransport::configured(candidate.path().to_path_buf());
        let process = transport::RpcTransport::connect(&enrollment_transport, &target)
            .map_err(transport_error)?;
        let mut client = rpc::RpcClient::connect(process).map_err(rpc_error)?;
        let machine_id = previous
            .as_ref()
            .map(inventory::InventoryHost::machine_id)
            .unwrap_or(client.server_hello().machine_id);
        let expected_name = previous.as_ref().map_or_else(
            || client.server_hello().name.as_str(),
            inventory::InventoryHost::name,
        );
        let expected =
            rpc::ExpectedPeer::new(machine_id, expected_name, user).map_err(rpc_error)?;
        let version = client.server_hello().styrn_version.clone();
        let manifest = client.machine_manifest(&expected).map_err(rpc_error)?;
        let record = inventory::InventoryHost::new(&manifest.name, manifest.machine_id, stored)
            .map_err(inventory_error)?;
        validate_manifest_endpoint(&manifest, &record)?;
        let status = client.machine_status().map_err(rpc_error)?;
        let doctor = client
            .machine_doctor(identity.public_line())
            .map_err(rpc_error)?;
        client.finish().map_err(rpc_error)?;
        drop(candidate);

        if snapshot.hosts().iter().any(|existing| {
            existing.machine_id() == record.machine_id() && existing.name() != record.name()
        }) {
            return Err(Phase1CommandError::new(
                output::ErrorCode::UsageConfigInvalid,
                "the worker machine identity is already enrolled under another name",
            ));
        }
        let cache =
            inventory::ManifestCache::new(chrono::Utc::now().fixed_offset(), &version, &manifest)
                .map_err(inventory_error)?;
        let (created, known_hosts_failed) = store
            .with_lock(|locked| {
                let mut current = locked.read_locked()?;
                let created = current.upsert_exact(record.clone())?;
                store.write_cache(&cache)?;
                if created {
                    locked.replace_inventory(&current)?;
                }
                let known_hosts_failed = locked.rebuild_known_hosts(&current).is_err();
                Ok((created, known_hosts_failed))
            })
            .map_err(inventory_error)?;
        let warnings = known_hosts_failed
            .then_some(KNOWN_HOSTS_WARNING)
            .into_iter()
            .collect();
        let data = serde_json::json!({
            "host": record.name(),
            "machine_id": record.machine_id(),
            "created": created,
            "fingerprint": pin.fingerprint(),
            "status": status,
            "doctor": doctor,
        });
        Ok((data, format!("Enrolled {}\n", record.name()), warnings))
    })();
    result.map_err(|error| {
        if identity.created() {
            error.with_public_key_recovery(identity.public_path())
        } else {
            error
        }
    })
}

fn host_trust(
    host_name: &str,
    fingerprint: &str,
) -> Result<HostCommandSuccess, Phase1CommandError> {
    transport::validate_host_key_fingerprint(fingerprint).map_err(|_| invalid_ssh_argument())?;
    let store = inventory::InventoryStore::configured().map_err(inventory_error)?;
    let snapshot = store.read().map_err(inventory_error)?;
    let existing = snapshot
        .select(Some(host_name))
        .map_err(inventory_error)?
        .clone();
    let scanner = transport::SshTransport::configured(store.known_hosts_path().to_path_buf());
    let pin = scanner
        .scan_host_key(
            existing.transport().host(),
            existing.transport().port(),
            Some(fingerprint),
        )
        .map_err(transport_error)?;
    let stored = inventory::StoredSsh::new(
        existing.transport().host(),
        existing.transport().user(),
        existing.transport().port(),
        existing.transport().identity().to_path_buf(),
        pin.clone(),
    )
    .map_err(inventory_error)?;
    let replacement = inventory::InventoryHost::new(existing.name(), existing.machine_id(), stored)
        .map_err(inventory_error)?;
    let known_hosts_failed = store
        .with_lock(|locked| {
            let mut current = locked.read_locked()?;
            current.replace_exact(&existing, replacement.clone())?;
            locked.replace_inventory(&current)?;
            Ok(locked.rebuild_known_hosts(&current).is_err())
        })
        .map_err(inventory_error)?;
    let warnings = known_hosts_failed
        .then_some(KNOWN_HOSTS_WARNING)
        .into_iter()
        .collect();
    Ok((
        serde_json::json!({ "host": existing.name(), "fingerprint": pin.fingerprint() }),
        format!("Updated host-key trust for {}\n", existing.name()),
        warnings,
    ))
}

fn run_exec_command(request: cli::ExecRequest, json: bool) {
    if request.shell() {
        fail_phase1(
            json,
            "exec",
            Phase1CommandError::new(
                output::ErrorCode::UsageInvalidArgument,
                "exec --shell is not available; pass an argv vector after --",
            ),
        );
    }
    if let Err(error) = rpc::validate_exec_argv(request.argv()) {
        fail_phase1(json, "exec", rpc_error(error));
    }
    let result = (|| {
        let store = inventory::InventoryStore::configured().map_err(inventory_error)?;
        let host = select_host_for_network(&store, Some(request.host()))?;
        let (_identity, mut client) = connect_host(&store, &host)?;
        let expected = expected_peer(&host)?;
        let manifest = client.machine_manifest(&expected).map_err(rpc_error)?;
        validate_manifest_endpoint(&manifest, &host)?;
        let result = client.exec(request.argv()).map_err(rpc_error)?;
        client.finish().map_err(rpc_error)?;
        Ok::<_, Phase1CommandError>(result)
    })();
    let result = match result {
        Ok(result) => result,
        Err(error) => fail_phase1(json, "exec", error),
    };
    if json {
        let outcome = output::ExecOutcome::new_sanitized(
            chrono::Utc::now(),
            result.exit_code,
            &result.stdout,
            &result.stderr,
            result.duration_ms,
            result.stdout_lossy,
            result.stderr_lossy,
            result.stdout_redacted,
            result.stderr_redacted,
        )
        .expect("validated RPC exec output must form an envelope");
        output::write_json(std::io::stdout().lock(), outcome.envelope())
            .expect("writing exec output must succeed");
        std::process::exit(outcome.process_exit_code());
    }
    print!("{}", result.stdout);
    eprint!("{}", result.stderr);
    std::process::exit(result.exit_code);
}

fn select_host_for_network(
    store: &inventory::InventoryStore,
    name: Option<&str>,
) -> Result<inventory::InventoryHost, Phase1CommandError> {
    store
        .with_lock(|locked| {
            let document = locked.read_locked()?;
            let host = locked.select(&document, name)?;
            locked.rebuild_known_hosts(&document)?;
            Ok(host)
        })
        .map_err(inventory_error)
}

fn connect_host(
    store: &inventory::InventoryStore,
    host: &inventory::InventoryHost,
) -> Result<(transport::ControllerIdentity, rpc::RpcClient), Phase1CommandError> {
    let identity = configured_controller_identity()?;
    if identity.private_path() != host.transport().identity() {
        return Err(Phase1CommandError::new(
            output::ErrorCode::UsageConfigInvalid,
            "the enrolled host refers to a different controller identity",
        ));
    }
    let target = host.rpc_target().map_err(transport_error)?;
    let transport = transport::SshTransport::configured(store.known_hosts_path().to_path_buf());
    let process = transport::RpcTransport::connect(&transport, &target).map_err(transport_error)?;
    let client = rpc::RpcClient::connect(process).map_err(rpc_error)?;
    Ok((identity, client))
}

fn expected_peer(host: &inventory::InventoryHost) -> Result<rpc::ExpectedPeer, Phase1CommandError> {
    rpc::ExpectedPeer::new(host.machine_id(), host.name(), host.transport().user())
        .map_err(rpc_error)
}

fn configured_controller_identity() -> Result<transport::ControllerIdentity, Phase1CommandError> {
    let store = manifest::configured_manifest_store().map_err(|_| machine_manifest_error())?;
    let manifest = store.read().map_err(|_| machine_manifest_error())?.manifest;
    transport::ControllerIdentity::load_or_create_configured(&manifest).map_err(identity_error)
}

fn validate_manifest_endpoint(
    manifest: &manifest::MachineManifest,
    host: &inventory::InventoryHost,
) -> Result<(), Phase1CommandError> {
    if !manifest_matches_host(manifest, host) {
        return Err(Phase1CommandError::new(
            output::ErrorCode::ProtocolMalformed,
            "the worker manifest identity and endpoint do not match the selected host",
        ));
    }
    Ok(())
}

fn manifest_matches_host(
    manifest: &manifest::MachineManifest,
    host: &inventory::InventoryHost,
) -> bool {
    let transport = manifest.transport.as_ref();
    manifest.machine_id == host.machine_id()
        && manifest.name == host.name()
        && manifest
            .worker_identity
            .as_ref()
            .is_some_and(|identity| identity.name == host.transport().user())
        && transport.is_some_and(|transport| {
            transport.host == host.transport().host()
                && transport.port.unwrap_or(22) == host.transport().port()
                && transport.user.as_deref() == Some(host.transport().user())
        })
}

fn configured_disk_floor(manifest: &manifest::MachineManifest) -> Option<u64> {
    let resources = manifest.resources.as_ref()?;
    let policy = resources.policy.as_ref()?;
    policy.reserved_disk_bytes.or_else(|| {
        let percent = u64::from(policy.reserved_disk_percent?);
        let total = resources.detected.as_ref()?.disk_bytes?;
        total.checked_mul(percent)?.checked_div(100)
    })
}

fn doctor_remediation(summary: &str, styrn_args: Option<Vec<String>>) -> serde_json::Value {
    serde_json::json!({
        "summary": summary,
        "styrn_args": styrn_args,
    })
}

fn host_json(host: &inventory::InventoryHost) -> serde_json::Value {
    serde_json::json!({
        "name": host.name(),
        "machine_id": host.machine_id(),
        "manifest_cache": host.manifest_cache(),
        "transport": {
            "kind": "ssh",
            "host": host.transport().host(),
            "user": host.transport().user(),
            "port": host.transport().port(),
            "identity": host.transport().identity(),
            "host_key_algorithm": host.transport().host_key().algorithm(),
            "host_key_fingerprint": host.transport().host_key().fingerprint(),
        }
    })
}

fn confirm_host_key(fingerprint: &str) -> bool {
    use std::io::Write as _;
    eprint!("Trust worker host key {fingerprint}? [y/N] ");
    if std::io::stderr().flush().is_err() {
        return false;
    }
    let mut answer = String::new();
    std::io::stdin()
        .read_line(&mut answer)
        .is_ok_and(|_| matches!(answer.trim(), "y" | "yes"))
}

fn render_phase1_success(
    json: bool,
    command: &str,
    data: serde_json::Value,
    human: &str,
    warnings: &[Phase1Warning],
) {
    if json {
        let warnings = warnings
            .iter()
            .map(|warning| {
                output::Diagnostic::new(warning.code, warning.message, None)
                    .expect("built-in phase-1 warning must be valid")
            })
            .collect();
        let envelope = output::Envelope::success(command, chrono::Utc::now(), data, warnings)
            .expect("built-in phase-1 output must be valid");
        output::write_json(std::io::stdout().lock(), &envelope)
            .expect("writing command output must succeed");
    } else {
        print!("{human}");
        for warning in warnings {
            eprintln!("warning: {}", warning.message);
        }
    }
}

fn fail_phase1(json: bool, command: &str, error: Phase1CommandError) -> ! {
    if json {
        let details = error.recovery_public_key_path.as_ref().map(|path| {
            serde_json::json!({
                "public_key_path": path,
                "next_step": "authorize the public key at this path for the requested SSH user, then rerun styrn host enroll",
            })
        });
        let diagnostic = output::ErrorDiagnostic::new(error.code, error.message, details)
            .expect("built-in phase-1 error must be valid");
        let envelope =
            output::Envelope::failure(command, chrono::Utc::now(), vec![diagnostic], Vec::new())
                .expect("built-in phase-1 failure must be valid");
        output::write_json(std::io::stdout().lock(), &envelope)
            .expect("writing command output must succeed");
    } else {
        eprintln!("{}", error.message);
        if let Some(path) = &error.recovery_public_key_path {
            eprintln!("Controller public key: {}", path.display());
            eprintln!(
                "Authorize the public key at this path for the requested SSH user, then rerun styrn host enroll."
            );
        }
    }
    output::exit_process(error.code.exit_code())
}

fn machine_manifest_error() -> Phase1CommandError {
    Phase1CommandError::new(
        output::ErrorCode::MachineManifestInvalid,
        "the local machine manifest is invalid; run styrn setup --yes",
    )
}

fn inventory_error(error: inventory::InventoryError) -> Phase1CommandError {
    Phase1CommandError::new(
        error.code(),
        match error.code() {
            output::ErrorCode::UsageInvalidArgument => {
                "the requested host is not uniquely enrolled"
            }
            _ => "the local host inventory is invalid or insecure",
        },
    )
}

fn invalid_ssh_argument() -> Phase1CommandError {
    Phase1CommandError::new(
        output::ErrorCode::UsageInvalidArgument,
        "the SSH host, user, or fingerprint argument is invalid",
    )
}

fn identity_error(error: transport::IdentityError) -> Phase1CommandError {
    match error {
        transport::IdentityError::CapabilityUnavailable => Phase1CommandError::new(
            output::ErrorCode::CapabilityUnsatisfied,
            "OpenSSH ssh-keygen is unavailable",
        ),
        transport::IdentityError::Invalid => machine_manifest_error(),
        transport::IdentityError::Conflict | transport::IdentityError::OperationFailed => {
            Phase1CommandError::new(
                output::ErrorCode::UsageConfigInvalid,
                "the controller SSH identity is invalid or insecure",
            )
        }
    }
}

fn transport_error(error: transport::TransportError) -> Phase1CommandError {
    Phase1CommandError::new(
        error.code(),
        match error.code() {
            output::ErrorCode::CapabilityUnsatisfied => "a required OpenSSH tool is unavailable",
            output::ErrorCode::TransportAuthFailed => {
                "the worker SSH identity or authentication could not be verified"
            }
            _ => "the worker host is unreachable",
        },
    )
}

fn rpc_error(error: rpc::RpcError) -> Phase1CommandError {
    let code = error.code();
    Phase1CommandError::new(
        code,
        match code {
            output::ErrorCode::TransportAuthFailed => "SSH authentication failed before RPC hello",
            output::ErrorCode::TransportSessionLost => "the worker RPC session was lost",
            output::ErrorCode::ProtocolIncompatible => {
                "the controller and worker RPC versions are incompatible"
            }
            output::ErrorCode::ProtocolMalformed => "the worker RPC response was malformed",
            output::ErrorCode::RemoteExecutionFailed => {
                "the worker could not execute the RPC method"
            }
            output::ErrorCode::MachineManifestInvalid => "the worker machine manifest is invalid",
            output::ErrorCode::UsageInvalidArgument => "the RPC request is invalid",
            _ => "the worker RPC operation failed",
        },
    )
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
        "enrollment_card": outcome.enrollment_card().map(setup_enrollment_card_json),
    })
}

fn setup_enrollment_card_json(card: &setup::EnrollmentCard) -> serde_json::Value {
    serde_json::json!({
        "name": card.name(),
        "host": card.host(),
        "user": card.user(),
        "fingerprint": card.fingerprint(),
        "command": card.command(),
        "integrity_guidance": card.integrity_guidance(),
        "controller_recovery": card.controller_recovery(),
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
    if let Some(card) = outcome.enrollment_card() {
        println!("Ready to enroll. From any controller, run:");
        println!();
        println!("  {}", card.command());
        println!();
        println!("integrity: {}", card.integrity_guidance());
        println!("controller recovery: {}", card.controller_recovery());
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
    const HOST_KEY_FINGERPRINT: &str = "SHA256:ZkAslGjFiUHdGf/WUL8rQvkib4PTvQatUV0OUQSncCA";

    #[test]
    fn setup_json_projects_the_complete_secret_free_enrollment_card() {
        let host_key = crate::transport::PinnedHostKey::from_parts(
            "ssh-ed25519",
            "AAAAC3NzaC1lZDI1NTE5AAAAIAABAgMEBQYHCAkKCwwNDg8QERITFBUWFxgZGhscHR4f",
            HOST_KEY_FINGERPRINT,
        )
        .unwrap();
        let card = crate::setup::EnrollmentCard::new(
            "worker-01",
            "worker-01.example",
            "alex",
            22,
            &host_key,
        )
        .unwrap();

        let value = super::setup_enrollment_card_json(&card);

        assert_eq!(value["name"], "worker-01");
        assert_eq!(value["host"], "worker-01.example");
        assert_eq!(value["user"], "alex");
        assert_eq!(value["fingerprint"], HOST_KEY_FINGERPRINT);
        assert_eq!(
            value["command"],
            format!(
                "styrn host enroll worker-01.example --user alex --fingerprint {HOST_KEY_FINGERPRINT}"
            )
        );
        assert!(value["integrity_guidance"]
            .as_str()
            .unwrap()
            .contains("worker's own console"));
        assert!(value["controller_recovery"]
            .as_str()
            .unwrap()
            .contains("styrn controller init"));
        assert!(!value.to_string().contains("ssh-ed25519"));
    }

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
