#![allow(dead_code)]

use clap::{Args, CommandFactory, FromArgMatches, Parser, Subcommand, ValueEnum};
use std::ffi::OsString;
use std::io::{IsTerminal, Write};
use std::path::PathBuf;

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
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum MachineAction {
    Manifest,
    Init,
}

impl ParsedCli {
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
}

impl ParseFailure {
    pub(crate) fn is_display(&self) -> bool {
        matches!(
            self.error.kind(),
            clap::error::ErrorKind::DisplayHelp | clap::error::ErrorKind::DisplayVersion
        )
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
        Self::try_parse_with_terminals(
            std::env::args_os().collect(),
            std::io::stdout().is_terminal(),
            std::io::stderr().is_terminal(),
        )
    }

    fn try_parse_with_terminals(
        args: Vec<OsString>,
        stdout_terminal: bool,
        stderr_terminal: bool,
    ) -> Result<ParsedCli, ParseFailure> {
        let args = normalize_harness_tail(args);
        let error_policy = AnsiPolicy::from_terminals(
            stdout_terminal,
            stderr_terminal,
            preparse_machine_mode(&args),
        );
        let matches = Self::command()
            .try_get_matches_from(args)
            .map_err(|error| ParseFailure {
                error,
                policy: error_policy,
            })?;
        let cli = Self::from_arg_matches(&matches).map_err(|error| ParseFailure {
            error,
            policy: error_policy,
        })?;
        let policy =
            AnsiPolicy::from_terminals(stdout_terminal, stderr_terminal, cli.uses_machine_output());

        Ok(ParsedCli { cli, policy })
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

pub(crate) fn render_parse_failure(
    failure: &ParseFailure,
    stdout: &mut dyn Write,
    stderr: &mut dyn Write,
) -> std::io::Result<()> {
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
struct SetupArgs {
    #[arg(long)]
    role: Option<String>,
    #[arg(long)]
    install: Option<String>,
    #[arg(long)]
    config: Option<PathBuf>,
    #[arg(long)]
    interactive: bool,
    #[arg(long)]
    yes: bool,
    #[arg(long)]
    dry_run: bool,
    #[arg(long, num_args = 0..=1, default_missing_value = "", require_equals = true)]
    emit_script: Option<String>,
    #[arg(long)]
    uninstall: bool,
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
    use super::{render_parse_failure, AnsiPolicy, Cli};
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

    fn args<const N: usize>(values: [&str; N]) -> Vec<OsString> {
        values.into_iter().map(OsString::from).collect()
    }
}
