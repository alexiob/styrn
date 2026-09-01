#![allow(dead_code)]

use clap::{Args, ColorChoice, CommandFactory, FromArgMatches, Parser, Subcommand, ValueEnum};
use std::ffi::OsString;
use std::io::IsTerminal;
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

    fn for_process() -> Self {
        Self::from_terminals(
            std::io::stdout().is_terminal(),
            std::io::stderr().is_terminal(),
            machine_mode_requested(),
        )
    }

    fn clap_color_choice(self) -> ColorChoice {
        if self.stdout && self.stderr {
            ColorChoice::Always
        } else {
            ColorChoice::Never
        }
    }
}

fn machine_mode_requested() -> bool {
    std::env::args_os().any(|argument| argument == "--json" || argument == "--jsonl")
}

#[derive(Debug, Parser)]
#[command(name = "styrn", version, disable_help_subcommand = true)]
pub(crate) struct Cli {
    #[arg(long, global = true, hide = true)]
    json: bool,
    #[command(subcommand)]
    command: RootCommand,
}

impl Cli {
    pub(crate) fn try_parse_process() -> Result<Self, clap::Error> {
        Self::try_parse_with_policy(std::env::args_os(), AnsiPolicy::for_process())
    }

    fn try_parse_with_policy<I, T>(args: I, policy: AnsiPolicy) -> Result<Self, clap::Error>
    where
        I: IntoIterator<Item = T>,
        T: Into<OsString> + Clone,
    {
        let matches = Self::command_with_policy(policy).try_get_matches_from(args)?;
        Self::from_arg_matches(&matches)
    }

    fn command_with_policy(policy: AnsiPolicy) -> clap::Command {
        Self::command().color(policy.clap_color_choice())
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
    use super::AnsiPolicy;

    #[test]
    fn machine_modes_disable_ansi_even_when_both_streams_are_terminals() {
        let policy = AnsiPolicy::from_terminals(true, true, true);
        assert_eq!(
            policy,
            AnsiPolicy {
                stdout: false,
                stderr: false
            }
        );
        let error = super::Cli::try_parse_with_policy(["styrn", "--json", "--unknown"], policy)
            .unwrap_err();
        assert!(!error.to_string().contains('\x1b'));
        assert_eq!(
            AnsiPolicy::from_terminals(true, true, false),
            AnsiPolicy {
                stdout: true,
                stderr: true
            }
        );
        assert_eq!(
            AnsiPolicy::from_terminals(true, false, false),
            AnsiPolicy {
                stdout: true,
                stderr: false
            }
        );
    }
}
