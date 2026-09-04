#![allow(dead_code)]

use clap::{Args, CommandFactory, FromArgMatches, Parser, Subcommand, ValueEnum};
use std::ffi::OsString;
use std::io::{IsTerminal, Write};
use std::path::PathBuf;

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct CliFacts {
    stdin_terminal: bool,
    stdout_terminal: bool,
    stderr_terminal: bool,
    styrn_json: Option<OsString>,
}

impl CliFacts {
    fn capture() -> Self {
        Self {
            stdin_terminal: std::io::stdin().is_terminal(),
            stdout_terminal: std::io::stdout().is_terminal(),
            stderr_terminal: std::io::stderr().is_terminal(),
            styrn_json: std::env::var_os("STYRN_JSON"),
        }
    }

    pub(crate) fn for_test(
        stdin_terminal: bool,
        stdout_terminal: bool,
        stderr_terminal: bool,
    ) -> Self {
        Self {
            stdin_terminal,
            stdout_terminal,
            stderr_terminal,
            styrn_json: None,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct AnsiPolicy {
    pub(crate) stdout: bool,
    pub(crate) stderr: bool,
}

impl AnsiPolicy {
    pub(crate) fn from_terminals(stdout: bool, stderr: bool, machine_mode: bool) -> Self {
        if machine_mode {
            Self {
                stdout: false,
                stderr: false,
            }
        } else {
            Self { stdout, stderr }
        }
    }

    fn for_stream(self, stderr: bool) -> bool {
        if stderr {
            self.stderr
        } else {
            self.stdout
        }
    }
}

#[derive(Debug)]
pub(crate) struct ParsedCli {
    cli: Cli,
    policy: AnsiPolicy,
    facts: CliFacts,
}

/// Closed CLI input for the rootless setup composer.  The setup module receives
/// this projection instead of the clap-derived command structure.
#[derive(Clone, Debug)]
pub(crate) struct SetupRequest {
    scope: Option<crate::platform::InstallationScope>,
    role: Option<String>,
    name: Option<String>,
    account: Option<String>,
    install: Option<String>,
    config: Option<PathBuf>,
    interactive: bool,
    yes: bool,
    no_elevate: bool,
    authorize_system: bool,
    dry_run: bool,
    emit_script: Option<String>,
    uninstall: bool,
    json: bool,
    facts: CliFacts,
}

impl SetupRequest {
    pub(crate) fn scope(&self) -> Option<crate::platform::InstallationScope> {
        self.scope
    }
    pub(crate) fn role(&self) -> Option<&str> {
        self.role.as_deref()
    }
    pub(crate) fn name(&self) -> Option<&str> {
        self.name.as_deref()
    }
    pub(crate) fn account(&self) -> Option<&str> {
        self.account.as_deref()
    }
    pub(crate) fn install(&self) -> Option<&str> {
        self.install.as_deref()
    }
    pub(crate) fn config(&self) -> Option<&std::path::Path> {
        self.config.as_deref()
    }
    pub(crate) fn interactive(&self) -> bool {
        self.interactive
    }
    pub(crate) fn yes(&self) -> bool {
        self.yes
    }
    pub(crate) fn no_elevate(&self) -> bool {
        self.no_elevate
    }
    pub(crate) fn authorize_system(&self) -> bool {
        self.authorize_system
    }
    pub(crate) fn dry_run(&self) -> bool {
        self.dry_run
    }
    pub(crate) fn emit_script(&self) -> Option<&str> {
        self.emit_script.as_deref()
    }
    pub(crate) fn uninstall(&self) -> bool {
        self.uninstall
    }
    pub(crate) fn json(&self) -> bool {
        self.json
    }
    pub(crate) fn stdin_terminal(&self) -> bool {
        self.facts.stdin_terminal
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum MachineAction {
    Manifest,
    Init,
}

impl ParsedCli {
    pub(crate) fn is_setup_command(&self) -> bool {
        matches!(self.cli.command, RootCommand::Setup(_))
    }

    pub(crate) fn setup_request(&self) -> Option<SetupRequest> {
        let RootCommand::Setup(setup) = &self.cli.command else {
            return None;
        };
        if setup.internal.is_some() {
            return None;
        }
        Some(SetupRequest {
            scope: setup.scope,
            role: setup.role.clone(),
            name: setup.name.clone(),
            account: setup.account.clone(),
            install: setup.install.clone(),
            config: setup.config.clone(),
            interactive: setup.interactive,
            yes: setup.yes,
            no_elevate: setup.no_elevate,
            authorize_system: setup.authorize_system,
            dry_run: setup.dry_run,
            emit_script: setup.emit_script.clone(),
            uninstall: setup.uninstall,
            json: self.cli.json,
            facts: self.facts.clone(),
        })
    }

    pub(crate) fn privileged_setup_request(&self) -> Option<&std::path::Path> {
        match &self.cli.command {
            RootCommand::Setup(SetupArgs {
                internal: Some(SetupInternalCommand::PrivilegedPhase { request, .. }),
                ..
            }) => Some(request),
            _ => None,
        }
    }

    pub(crate) fn machine_action(&self) -> Option<MachineAction> {
        match &self.cli.command {
            RootCommand::Machine {
                command: MachineCommand::Manifest,
            } => Some(MachineAction::Manifest),
            RootCommand::Machine {
                command: MachineCommand::Init,
            } => Some(MachineAction::Init),
            _ => None,
        }
    }

    pub(crate) const fn json_output(&self) -> bool {
        self.cli.json
    }
}

#[derive(Debug)]
pub(crate) struct ParseFailure {
    error: clap::Error,
    policy: AnsiPolicy,
    setup_invocation: bool,
    json_output: bool,
    setup_class: SetupParseFailureClass,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum SetupParseFailureClass {
    Generic,
    InvalidScope,
}

impl ParseFailure {
    pub(crate) fn is_display(&self) -> bool {
        matches!(
            self.error.kind(),
            clap::error::ErrorKind::DisplayHelp | clap::error::ErrorKind::DisplayVersion
        )
    }

    pub(crate) const fn is_setup_json_failure(&self) -> bool {
        self.setup_invocation && self.json_output
    }

    pub(crate) const fn safe_setup_message(&self) -> &'static str {
        match self.setup_class {
            SetupParseFailureClass::InvalidScope => {
                "invalid value for --scope; allowed values: user, system"
            }
            SetupParseFailureClass::Generic => {
                "setup arguments are invalid; use 'styrn setup --help'"
            }
        }
    }
}

#[derive(Debug, Parser)]
#[command(name = "styrn", version, disable_help_subcommand = true)]
pub(crate) struct Cli {
    #[arg(
        long,
        global = true,
        help = "Emit machine-readable output for finite commands"
    )]
    json: bool,
    #[command(subcommand)]
    command: RootCommand,
}

impl Cli {
    pub(crate) fn try_parse_process() -> Result<ParsedCli, ParseFailure> {
        Self::try_parse_with_facts(std::env::args_os().collect(), CliFacts::capture())
    }

    fn try_parse_with_terminals(
        args: Vec<OsString>,
        stdout_terminal: bool,
        stderr_terminal: bool,
    ) -> Result<ParsedCli, ParseFailure> {
        Self::try_parse_with_facts(
            args,
            CliFacts::for_test(false, stdout_terminal, stderr_terminal),
        )
    }

    pub(crate) fn try_parse_with_facts(
        args: Vec<OsString>,
        facts: CliFacts,
    ) -> Result<ParsedCli, ParseFailure> {
        let args = normalize_harness_tail(args);
        let setup_invocation = preparse_setup_invocation(&args);
        let setup_class = preparse_setup_failure_class(&args);
        let requested_json = preparse_machine_mode(&args)
            || facts.styrn_json.as_deref() == Some(std::ffi::OsStr::new("1"));
        let error_policy = AnsiPolicy::from_terminals(
            facts.stdout_terminal,
            facts.stderr_terminal,
            requested_json,
        );
        let matches = Self::command()
            .try_get_matches_from(args)
            .map_err(|error| ParseFailure {
                error,
                policy: error_policy,
                setup_invocation,
                json_output: requested_json,
                setup_class,
            })?;
        let cli = Self::from_arg_matches(&matches).map_err(|error| ParseFailure {
            error,
            policy: error_policy,
            setup_invocation,
            json_output: requested_json,
            setup_class,
        })?;
        let env_json = match facts.styrn_json.as_deref() {
            None => false,
            Some(value) if value == std::ffi::OsStr::new("0") => false,
            Some(value) if value == std::ffi::OsStr::new("1") => true,
            Some(_) if cli.json => false,
            Some(_) => {
                return Err(ParseFailure {
                    error: Self::command().error(
                        clap::error::ErrorKind::InvalidValue,
                        "STYRN_JSON must be exactly 0 or 1",
                    ),
                    policy: error_policy,
                    setup_invocation,
                    json_output: requested_json,
                    setup_class,
                });
            }
        };
        let cli = Cli {
            json: cli.json || env_json,
            ..cli
        };
        if cli.json
            && matches!(
                &cli.command,
                RootCommand::Setup(SetupArgs {
                    interactive: true,
                    ..
                })
            )
        {
            return Err(ParseFailure {
                error: Self::command().error(
                    clap::error::ErrorKind::ArgumentConflict,
                    "--interactive cannot be used with JSON output",
                ),
                policy: error_policy,
                setup_invocation,
                json_output: true,
                setup_class,
            });
        }
        let policy = AnsiPolicy::from_terminals(
            facts.stdout_terminal,
            facts.stderr_terminal,
            cli.uses_machine_output(),
        );

        Ok(ParsedCli { cli, policy, facts })
    }

    fn uses_machine_output(&self) -> bool {
        self.json
            || matches!(
                &self.command,
                RootCommand::Job {
                    command: JobCommand::Logs(JobLogsArgs { jsonl: true, .. })
                } | RootCommand::Monitor(MonitorArgs { jsonl: true, .. })
            )
    }
}

fn normalize_harness_tail(mut args: Vec<OsString>) -> Vec<OsString> {
    let mut index = 1;
    while args.get(index).is_some_and(|argument| argument == "--json") {
        index += 1;
    }
    if args.get(index).is_none_or(|argument| argument != "harness") {
        return args;
    }

    index += 1;
    while args.get(index).is_some_and(|argument| argument == "--json") {
        index += 1;
    }
    if args.get(index).is_none_or(|argument| argument != "run") {
        return args;
    }

    index += 1;
    while args.get(index).is_some_and(|argument| argument == "--json") {
        index += 1;
    }
    if args
        .get(index)
        .is_none_or(|argument| argument != "codex" && argument != "claude")
    {
        return args;
    }

    index += 1;
    if args.get(index).is_some_and(|argument| argument != "--") {
        args.insert(index, OsString::from("--"));
    }
    args
}

fn preparse_machine_mode(args: &[OsString]) -> bool {
    args.iter()
        .skip(1)
        .take_while(|argument| argument.as_os_str() != std::ffi::OsStr::new("--"))
        .any(|argument| argument == "--json" || argument == "--jsonl")
}

fn preparse_setup_invocation(args: &[OsString]) -> bool {
    args.iter()
        .skip(1)
        .find(|argument| argument.as_os_str() != std::ffi::OsStr::new("--json"))
        .is_some_and(|argument| argument.as_os_str() == std::ffi::OsStr::new("setup"))
}

fn preparse_setup_failure_class(args: &[OsString]) -> SetupParseFailureClass {
    let mut arguments = args.iter().skip(1).peekable();
    while let Some(argument) = arguments.next() {
        if argument == "--" {
            break;
        }
        if argument == "--scope" {
            return match arguments.peek().and_then(|value| value.to_str()) {
                Some("user" | "system") => SetupParseFailureClass::Generic,
                _ => SetupParseFailureClass::InvalidScope,
            };
        }
        if let Some(value) = argument
            .to_str()
            .and_then(|value| value.strip_prefix("--scope="))
        {
            return if matches!(value, "user" | "system") {
                SetupParseFailureClass::Generic
            } else {
                SetupParseFailureClass::InvalidScope
            };
        }
    }
    SetupParseFailureClass::Generic
}

pub(crate) fn render_parse_failure(
    failure: &ParseFailure,
    stdout: &mut dyn Write,
    stderr: &mut dyn Write,
) -> std::io::Result<()> {
    if failure.setup_invocation && !failure.is_display() {
        return writeln!(stderr, "error: {}", failure.safe_setup_message());
    }
    let use_stderr = failure.error.use_stderr();
    let rendered = failure.error.render();

    if use_stderr {
        if failure.policy.for_stream(true) {
            write!(stderr, "{}", rendered.ansi())
        } else {
            write!(stderr, "{rendered}")
        }
    } else if failure.policy.for_stream(false) {
        write!(stdout, "{}", rendered.ansi())
    } else {
        write!(stdout, "{rendered}")
    }
}

#[derive(Debug, Subcommand)]
enum RootCommand {
    Machine {
        #[command(subcommand)]
        command: MachineCommand,
    },
    Controller {
        #[command(subcommand)]
        command: ControllerCommand,
    },
    Host {
        #[command(subcommand)]
        command: HostCommand,
    },
    Shell {
        host: String,
    },
    Desktop {
        #[command(subcommand)]
        command: DesktopCommand,
    },
    Admin {
        #[command(subcommand)]
        command: AdminCommand,
    },
    Exec(ExecArgs),
    Agent {
        #[command(subcommand)]
        command: AgentCommand,
    },
    Job {
        #[command(subcommand)]
        command: JobCommand,
    },
    Project {
        #[command(subcommand)]
        command: ProjectCommand,
    },
    Workflow {
        #[command(subcommand)]
        command: WorkflowCommand,
    },
    Matrix {
        #[command(subcommand)]
        command: MatrixCommand,
    },
    Clean {
        #[command(subcommand)]
        command: CleanCommand,
    },
    Cache {
        #[command(subcommand)]
        command: CacheCommand,
    },
    Artifact {
        #[command(subcommand)]
        command: ArtifactCommand,
    },
    Fleet {
        #[command(subcommand)]
        command: FleetCommand,
    },
    Harness {
        #[command(subcommand)]
        command: HarnessCommand,
    },
    #[command(name = "harness-hook")]
    HarnessHook {
        harness: HookHarness,
        event: String,
    },
    Upgrade(UpgradeArgs),
    Setup(SetupArgs),
    #[command(name = "bootstrap-script")]
    BootstrapScript {
        #[arg(long)]
        os: BootstrapOs,
    },
    Env,
    Monitor(MonitorArgs),
    Watch(WatchArgs),
}

#[derive(Debug, Subcommand)]
enum MachineCommand {
    Roles,
    Role {
        #[command(subcommand)]
        command: MachineRoleCommand,
    },
    Manifest,
    Init,
}

#[derive(Debug, Subcommand)]
enum MachineRoleCommand {
    Add { role: MachineRole },
    Remove { role: MachineRole },
}

#[derive(Clone, Debug, ValueEnum)]
enum MachineRole {
    Controller,
    Worker,
}

#[derive(Debug, Subcommand)]
enum ControllerCommand {
    Init,
}

#[derive(Debug, Subcommand)]
enum HostCommand {
    List,
    Show {
        host: String,
    },
    Status {
        host: Option<String>,
    },
    Enroll {
        host: String,
        #[arg(long)]
        fingerprint: Option<String>,
    },
    Remove {
        host: String,
        #[arg(long)]
        revoke: bool,
    },
    Doctor {
        host: Option<String>,
    },
    Refresh {
        host: Option<String>,
    },
    #[command(name = "authorize-key")]
    AuthorizeKey {
        host: String,
        #[arg(long)]
        public_key: PathBuf,
    },
    #[command(name = "revoke-key")]
    RevokeKey {
        host: String,
        #[arg(long)]
        controller: String,
    },
    Trust {
        host: String,
        #[arg(long)]
        fingerprint: String,
    },
}

#[derive(Debug, Subcommand)]
enum DesktopCommand {
    Open { host: String },
    Info { host: String },
}

#[derive(Debug, Subcommand)]
enum AdminCommand {
    Open { host: String },
}

#[derive(Args, Debug)]
struct ExecArgs {
    host: String,
    #[arg(long)]
    shell: bool,
    #[arg(last = true, required = true, num_args = 1..)]
    command: Vec<String>,
}

#[derive(Debug, Subcommand)]
enum AgentCommand {
    List(AgentListArgs),
    Start(AgentStartArgs),
    Read {
        agent: String,
        #[arg(long)]
        lines: Option<usize>,
    },
    Prompt {
        agent: String,
        #[arg(long)]
        text: String,
    },
    Wait(AgentWaitArgs),
    Stop {
        agent: String,
    },
    Attach {
        agent: String,
    },
}

#[derive(Args, Debug)]
struct AgentListArgs {
    #[arg(long)]
    host: Option<String>,
    #[arg(long)]
    all: bool,
}

#[derive(Args, Debug)]
struct AgentStartArgs {
    host: String,
    #[arg(long)]
    harness: Harness,
    #[arg(long)]
    project: String,
    #[arg(long)]
    name: String,
}

#[derive(Args, Debug)]
struct AgentWaitArgs {
    agent: String,
    #[arg(long)]
    state: Option<AgentWaitState>,
}

#[derive(Clone, Debug, ValueEnum)]
enum Harness {
    Codex,
    Claude,
}

#[derive(Clone, Debug, ValueEnum)]
enum HookHarness {
    Claude,
}

#[derive(Clone, Debug, ValueEnum)]
enum AgentWaitState {
    Idle,
    Done,
    Blocked,
}

#[derive(Debug, Subcommand)]
enum JobCommand {
    List,
    Show { id: String },
    Cancel { id: String },
    Logs(JobLogsArgs),
}

#[derive(Args, Debug)]
struct JobLogsArgs {
    id: String,
    #[arg(long)]
    follow: bool,
    #[arg(long, requires = "follow", conflicts_with = "json")]
    jsonl: bool,
}

#[derive(Debug, Subcommand)]
enum ProjectCommand {
    List,
    Inspect { name: String },
    Init { host: String, name: String },
}

#[derive(Debug, Subcommand)]
enum WorkflowCommand {
    List { project: String },
    Plan(WorkflowPlanArgs),
    Run(WorkflowRunArgs),
    Cancel { target: String },
}

#[derive(Args, Debug)]
struct WorkflowPlanArgs {
    project: String,
    workflow: String,
    #[arg(long)]
    revision: Option<String>,
}

#[derive(Args, Debug)]
struct WorkflowRunArgs {
    project: String,
    workflow: String,
    #[arg(long)]
    host: Option<String>,
    #[arg(long)]
    revision: Option<String>,
    #[arg(long, conflicts_with = "no_wait")]
    wait: bool,
    #[arg(long, conflicts_with = "wait")]
    no_wait: bool,
    #[arg(long)]
    snapshot: bool,
}

#[derive(Debug, Subcommand)]
enum MatrixCommand {
    Run(MatrixRunArgs),
}

#[derive(Args, Debug)]
struct MatrixRunArgs {
    project: String,
    matrix: String,
    #[arg(long)]
    revision: Option<String>,
}

#[derive(Debug, Subcommand)]
enum CleanCommand {
    Plan { host: String },
    Run { host: String },
}

#[derive(Debug, Subcommand)]
enum CacheCommand {
    Status { host: String },
    Trim { host: String },
}

#[derive(Debug, Subcommand)]
enum ArtifactCommand {
    Read {
        job_uri: String,
        #[arg(long)]
        max_bytes: Option<u64>,
    },
}

#[derive(Debug, Subcommand)]
enum FleetCommand {
    Status,
    Doctor,
    Versions,
    Selftest,
    Controllers,
    Workers,
}

#[derive(Debug, Subcommand)]
enum HarnessCommand {
    Run(HarnessRunArgs),
}

#[derive(Args, Debug)]
struct HarnessRunArgs {
    harness: Harness,
    #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
    args: Vec<String>,
}

#[derive(Args, Debug)]
struct UpgradeArgs {
    #[arg(conflicts_with = "all")]
    host: Option<String>,
    #[arg(long, conflicts_with = "host")]
    all: bool,
}

#[derive(Args, Debug)]
#[command(args_conflicts_with_subcommands = true)]
struct SetupArgs {
    #[command(subcommand)]
    internal: Option<SetupInternalCommand>,
    #[arg(long)]
    scope: Option<crate::platform::InstallationScope>,
    #[arg(long)]
    role: Option<String>,
    #[arg(long, help = "Public machine name for the rootless worker")]
    name: Option<String>,
    #[arg(long, help = "Worker account mode (current-user or dedicated[:NAME])")]
    account: Option<String>,
    #[arg(long)]
    install: Option<String>,
    #[arg(long)]
    config: Option<PathBuf>,
    #[arg(long, conflicts_with_all = ["config", "role", "scope", "name", "account", "install", "yes", "no_elevate", "authorize_system", "dry_run", "emit_script", "uninstall", "json"])]
    interactive: bool,
    #[arg(long)]
    yes: bool,
    #[arg(long, conflicts_with = "authorize_system")]
    no_elevate: bool,
    #[arg(long)]
    authorize_system: bool,
    #[arg(long)]
    dry_run: bool,
    #[arg(long, num_args = 0..=1, default_missing_value = "", require_equals = true)]
    emit_script: Option<String>,
    #[arg(long)]
    uninstall: bool,
}

#[derive(Debug, Subcommand)]
enum SetupInternalCommand {
    #[command(name = "privileged-phase", hide = true)]
    PrivilegedPhase {
        #[arg(long)]
        request: PathBuf,
        #[arg(long)]
        digest: String,
    },
    #[command(name = "user-phase", hide = true)]
    UserPhase,
}

#[derive(Clone, Debug, ValueEnum)]
enum BootstrapOs {
    Linux,
    Macos,
    Windows,
}

#[derive(Args, Debug)]
struct MonitorArgs {
    #[arg(long)]
    notify: bool,
    #[arg(long, conflicts_with = "json")]
    jsonl: bool,
}

#[derive(Args, Debug)]
struct WatchArgs {
    #[arg(long)]
    all: bool,
    #[arg(long)]
    herdr: bool,
}

#[cfg(test)]
mod tests {
    use super::{render_parse_failure, AnsiPolicy, Cli, CliFacts, MachineAction};
    use std::ffi::OsString;

    #[test]
    fn machine_mode_disables_ansi_in_the_actual_error_renderer() {
        let failure =
            Cli::try_parse_with_terminals(args(["styrn", "--json", "--unknown"]), true, true)
                .unwrap_err();
        let mut stdout = Vec::new();
        let mut stderr = Vec::new();

        render_parse_failure(&failure, &mut stdout, &mut stderr).unwrap();

        assert!(stdout.is_empty());
        assert!(!stderr.is_empty());
        assert!(!stderr.contains(&0x1b));
    }

    #[test]
    fn human_error_rendering_follows_the_stderr_terminal_state() {
        let failure =
            Cli::try_parse_with_terminals(args(["styrn", "--unknown"]), false, true).unwrap_err();
        let mut stdout = Vec::new();
        let mut stderr = Vec::new();

        render_parse_failure(&failure, &mut stdout, &mut stderr).unwrap();

        assert!(stdout.is_empty());
        assert!(stderr.contains(&0x1b));
    }

    #[test]
    fn human_help_rendering_follows_the_stdout_terminal_state() {
        let failure =
            Cli::try_parse_with_terminals(args(["styrn", "--help"]), true, false).unwrap_err();
        let mut stdout = Vec::new();
        let mut stderr = Vec::new();

        render_parse_failure(&failure, &mut stdout, &mut stderr).unwrap();

        assert!(stdout.contains(&0x1b));
        assert!(stderr.is_empty());
    }

    #[test]
    fn non_terminal_streams_render_without_ansi() {
        let failure =
            Cli::try_parse_with_terminals(args(["styrn", "--unknown"]), true, false).unwrap_err();
        let mut stdout = Vec::new();
        let mut stderr = Vec::new();

        render_parse_failure(&failure, &mut stdout, &mut stderr).unwrap();

        assert!(stdout.is_empty());
        assert!(!stderr.is_empty());
        assert!(!stderr.contains(&0x1b));
    }

    #[test]
    fn parsed_output_mode_ignores_literal_json_arguments_after_the_separator() {
        let parsed = Cli::try_parse_with_terminals(
            args(["styrn", "exec", "host", "--", "echo", "--json"]),
            true,
            true,
        )
        .unwrap();

        let policy = AnsiPolicy::from_terminals(true, true, true);
        assert_eq!(
            parsed.policy,
            AnsiPolicy {
                stdout: true,
                stderr: true
            }
        );
        assert_ne!(parsed.policy, policy);
    }

    #[test]
    fn parsed_output_mode_ignores_harness_forwarded_json_arguments() {
        let parsed = Cli::try_parse_with_terminals(
            args(["styrn", "harness", "run", "codex", "--json"]),
            true,
            true,
        )
        .unwrap();

        assert_eq!(
            parsed.policy,
            AnsiPolicy {
                stdout: true,
                stderr: true
            }
        );
    }

    #[test]
    fn machine_manifest_and_init_parse_without_invoking_the_domain_handler() {
        for (arguments, expected) in [
            (["styrn", "machine", "manifest"], MachineAction::Manifest),
            (["styrn", "machine", "init"], MachineAction::Init),
        ] {
            let parsed = Cli::try_parse_with_terminals(args(arguments), false, false).unwrap();
            assert_eq!(parsed.machine_action(), Some(expected));
        }
    }

    #[test]
    fn setup_scope_and_authorization_flags_are_closed_and_non_implicit() {
        let parsed = Cli::try_parse_with_terminals(
            args([
                "styrn",
                "setup",
                "--scope",
                "system",
                "--yes",
                "--authorize-system",
            ]),
            false,
            false,
        )
        .unwrap();
        let super::RootCommand::Setup(setup) = parsed.cli.command else {
            panic!("setup command expected")
        };
        assert_eq!(
            setup.scope,
            Some(crate::platform::InstallationScope::System)
        );
        assert!(setup.yes);
        assert!(setup.authorize_system);
        assert!(!setup.no_elevate);

        let parsed =
            Cli::try_parse_with_terminals(args(["styrn", "setup", "--yes"]), false, false).unwrap();
        let super::RootCommand::Setup(setup) = parsed.cli.command else {
            panic!("setup command expected")
        };
        assert!(
            !setup.authorize_system,
            "--yes must not authorize privilege"
        );

        assert!(Cli::try_parse_with_terminals(
            args(["styrn", "setup", "--no-elevate", "--authorize-system"]),
            false,
            false,
        )
        .is_err());
        assert!(Cli::try_parse_with_terminals(
            args(["styrn", "setup", "--scope", "machine"]),
            false,
            false,
        )
        .is_err());
    }

    #[test]
    fn styrn_json_environment_preserves_the_interactive_json_conflict() {
        let mut facts = CliFacts::for_test(true, true, true);
        facts.styrn_json = Some(OsString::from("1"));

        let failure = Cli::try_parse_with_facts(args(["styrn", "setup", "--interactive"]), facts)
            .unwrap_err();

        assert!(failure.is_setup_json_failure());
    }

    #[test]
    fn setup_internal_phases_are_hidden_and_accept_only_their_fixed_shapes() {
        let parsed = Cli::try_parse_with_terminals(
            args([
                "styrn",
                "setup",
                "privileged-phase",
                "--request",
                "/private/state/authorization-request.json",
                "--digest",
                "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            ]),
            false,
            false,
        )
        .unwrap();
        let super::RootCommand::Setup(setup) = parsed.cli.command else {
            panic!("setup command expected")
        };
        assert!(matches!(
            setup.internal,
            Some(super::SetupInternalCommand::PrivilegedPhase { request, digest })
                if request == std::path::Path::new("/private/state/authorization-request.json")
                    && digest == "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        ));

        assert!(Cli::try_parse_with_terminals(
            args([
                "styrn",
                "setup",
                "--yes",
                "privileged-phase",
                "--request",
                "/private/state/authorization-request.json",
                "--digest",
                "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
            ]),
            false,
            false,
        )
        .is_err());

        let parsed =
            Cli::try_parse_with_terminals(args(["styrn", "setup", "user-phase"]), false, false)
                .unwrap();
        let super::RootCommand::Setup(setup) = parsed.cli.command else {
            panic!("setup command expected")
        };
        assert!(matches!(
            setup.internal,
            Some(super::SetupInternalCommand::UserPhase)
        ));
        assert!(Cli::try_parse_with_terminals(
            args(["styrn", "setup", "user-phase", "unexpected"]),
            false,
            false,
        )
        .is_err());

        let failure =
            Cli::try_parse_with_terminals(args(["styrn", "setup", "--help"]), false, false)
                .unwrap_err();
        let mut stdout = Vec::new();
        let mut stderr = Vec::new();
        render_parse_failure(&failure, &mut stdout, &mut stderr).unwrap();
        let stdout = String::from_utf8(stdout).unwrap();
        assert!(!stdout.contains("privileged-phase"));
        assert!(!stdout.contains("user-phase"));
    }

    #[test]
    fn setup_parse_failures_hide_secret_shaped_values_in_human_mode() {
        for arguments in [
            ["styrn", "setup", "--scope", "token-never-render-this"],
            [
                "styrn",
                "setup",
                "--unknown-password",
                "secret-never-render-this",
            ],
        ] {
            let failure = Cli::try_parse_with_terminals(args(arguments), false, false).unwrap_err();
            let mut stdout = Vec::new();
            let mut stderr = Vec::new();
            render_parse_failure(&failure, &mut stdout, &mut stderr).unwrap();
            let rendered = String::from_utf8(stderr).unwrap();

            assert!(stdout.is_empty());
            assert!(rendered.contains(if arguments[2] == "--scope" {
                "invalid value for --scope; allowed values: user, system"
            } else {
                "setup arguments are invalid"
            }));
            assert!(!rendered.contains("never-render-this"));
        }
    }

    #[test]
    fn setup_help_and_version_remain_clap_rendered() {
        for arguments in [["styrn", "setup", "--help"], ["styrn", "--version", ""]] {
            let arguments = arguments
                .into_iter()
                .filter(|argument| !argument.is_empty())
                .map(OsString::from)
                .collect();
            let failure = Cli::try_parse_with_terminals(arguments, false, false).unwrap_err();
            assert!(failure.is_display());
            let mut stdout = Vec::new();
            let mut stderr = Vec::new();
            render_parse_failure(&failure, &mut stdout, &mut stderr).unwrap();
            assert!(!stdout.is_empty());
            assert!(stderr.is_empty());
        }
    }

    fn args<const N: usize>(values: [&str; N]) -> Vec<OsString> {
        values.into_iter().map(OsString::from).collect()
    }
}
