# Styrn

**One control plane for development machines, remote jobs, and coding agents.**

Styrn is a planned cross-platform command-line tool for operating a fleet of macOS, Linux, and native Windows development machines from any enrolled controller. It will set up and inspect hosts, run project-defined workflows under resource limits, keep remote jobs alive after the controller disconnects, and—on hosts where Herdr is installed and registered—manage persistent Codex and Claude Code sessions through it. Herdr is optional per host: everything except the agent-session surface runs without it.

> [!IMPORTANT]
> **Styrn is early software, not a supported release.** The rootless
> current-user `styrn setup` path and the first finite Phase 1 controller journey
> are runnable from a built checkout, but Phase 0 and Phase 1 remain incomplete
> and there is no released or installable binary. Fleet fanout, persistent jobs,
> agents, and most other commands below still describe the intended interface.

## Runnable rootless setup

The implemented setup slice supports an ordinary current user as a user-scope
worker, with no account creation and no root/Administrator requirement:

```console
# Review the complete plan without writing setup state.
styrn setup --dry-run

# Apply the rootless plan without the ordinary confirmation prompt.
styrn setup --yes

# Replay desired state from TOML, or collect it through terminal prompts.
styrn setup --config examples/setup-config.rootless.toml --yes
styrn setup --interactive

# Receive one styrn.command.v1 document on stdout.
styrn setup --dry-run --json
styrn setup --yes --json
```

Bare setup probes the host, displays one complete plan, and asks once before
applying. A non-TTY invocation without `--yes` displays that plan and exits 13
with `setup.confirmation_required`; `--yes` confirms only the unprivileged
plan and never authorizes or elevates. `--interactive` collects role,
components, and machine name, then displays the same prepared plan before its
single confirmation and writes a replayable `./setup-config.toml` only after
acceptance.

Apply creates or reconciles the current user's canonical worker directory
tree, durable setup receipt, and user machine manifest. It adopts already
healthy SSH-server, Tailscale, Git, and sleep posture without claiming
ownership. Missing, broken, or unprovable machine-wide work—and the not-yet-
shipped `styrnd` service—is recorded as pending with static remediation.
Current-user mode is explicitly not OS-account, controller-credential, or
same-user Styrn-state isolation.

This slice does **not** install packages, edit SSH/firewall/service/power
configuration, authenticate Tailscale, create or adopt a dedicated account,
request sudo/UAC, emit setup scripts, enroll the machine, or make it remotely
job-ready. System scope, controller/both roles, dedicated identity, privileged
and user phases, uninstall, and enrollment output remain unavailable and fail
closed.

## Runnable controller-to-worker slice

After rootless setup has produced a local manifest, `controller init` lazily
creates one current-user ED25519 identity with system `ssh-keygen`. Authorize
the printed public key for an ordinary account on a prepared worker, then pin
that worker's host key during enrollment:

```console
styrn controller init
styrn host enroll worker.example --user alex \
  --fingerprint SHA256:<verified-fingerprint>
styrn host list
styrn host show worker.example
styrn host status worker.example
styrn host refresh worker.example
styrn host doctor worker.example
styrn exec worker.example -- program "one argument"
```

Enrollment without `--fingerprint` is allowed only at an interactive terminal
and requires one explicit host-key confirmation. JSON and non-terminal calls
must provide the fingerprint. Later connections use the pinned key and refuse
a change; `host trust --fingerprint ...` is the explicit recovery operation.
Each command opens one bounded system-OpenSSH session to the fixed remote
`styrn rpc serve --stdio` command. There is no daemon, shell interpolation,
fanout, retry framework, or persistent remote job in this slice. Doctor reports
`phase1_minimum`/`complete: false`; the native real-sshd journey is not yet
certified across all three supported operating systems.

## Why Styrn?

A small development fleet often becomes a collection of SSH aliases, machine-specific scripts, hand-tuned build settings, and agent sessions that are difficult to find or resume. Styrn is designed to turn those machines into one development fabric without hiding their native operating systems.

The intended result is a single `styrn` binary that can:

- control the fleet from Windows, Linux, or macOS;
- discover machine resources and admit work without oversubscribing a worker;
- run repository-defined checks, tests, and validation matrices;
- preserve jobs—and, where Herdr is registered, coding-agent sessions—when a laptop closes or a connection drops;
- expose stable human-readable, JSON, and JSON Lines interfaces;
- give Codex and Claude Code structured, project-scoped operations through MCP; and
- use familiar infrastructure—Tailscale, OpenSSH, Git, and optionally Herdr—instead of a central cluster service.

Styrn is not intended to be a container orchestrator, CI server, or replacement for each project's build system. Project-specific behavior belongs in `.styrn.toml`; Styrn supplies the cross-platform execution, scheduling, policy, and observability primitives.

## Target experience

From any enrolled controller, the planned workflow looks like this:

```console
# See every enrolled machine and its current capacity.
styrn fleet status

# Start a persistent coding agent on a suitable Windows worker.
styrn agent start win-mini \
  --harness codex \
  --project fricos \
  --name windows-fs

# Ask it to work, then validate its commit across operating systems.
styrn agent prompt windows-fs \
  --text "Investigate issue #351 and use the declared project workflows."
styrn matrix run fricos cross-platform --revision <commit>

# Leave and reconnect later; the remote sessions and jobs continue.
styrn agent list --all
styrn job list
```

Every finite, non-interactive command is designed to support `--json`. Streaming commands use `--jsonl`, keeping structured output on stdout and diagnostics on stderr.

## How it is designed

```text
Codex / Claude Code                         Human operator
        |                                        |
        +--------------- MCP / CLI --------------+
                             |
                    controller: styrn
                             |
                   Tailscale + OpenSSH
                             |
               worker: styrn rpc serve --stdio
                    /                      \
      resource-governed jobs          Herdr sessions
       in clean worktrees          (optional; persistent agents)
```

There is no permanent master. A machine may have either or both independent roles:

- **Controller** — holds fleet inventory and credentials, plans work, and dispatches requests.
- **Worker** — advertises capabilities and runs admitted jobs as an unprivileged account.
- **Controller + worker** — does both; being a controller does not automatically make a host eligible for jobs.

The same Rust executable is designed to act as the CLI, remote RPC endpoint, resource detector, job runner, workflow engine, integration adapter, and MCP server. OpenSSH provides the authenticated transport over Tailscale; no custom network API or central coordinator is required for the initial fleet.

## Project-defined workflows

Each repository describes its own workflows and requirements in `.styrn.toml`. Styrn remains build-system-agnostic: it expands resource values, selects an eligible worker, and executes the declared command.

```toml
schema_version = 1

[project]
name = "example"

[workflows.check]
description = "Fast workspace check"
resource_class = "light"
command = ["cargo", "check", "--workspace"]

[workflows.check.requirements]
build = true

[workflows.check.environment]
CARGO_BUILD_JOBS = "${resources.compile_jobs}"
CARGO_TARGET_DIR = "${job.root}/target"
```

The worker—not the controller or coding agent—makes the final admission decision using current CPU, memory, disk, capability, concurrency, and policy information. Validation runs in a clean worktree at an exact Git commit; an agent's modifying workspace cannot certify itself.

## Design principles

- **Frictionless by default:** autodetect what can be discovered, provide useful defaults, and prefer one convergent command over setup rituals.
- **Rootless first:** the primary user-scope installation runs entirely as the
  invoking account. Missing machine integrations may be completed through one
  optional, itemized native sudo/UAC authorization; declining remains a useful
  supported rootless installation.
- **Native and cross-platform:** support macOS, Linux, and native Windows without requiring WSL or a language runtime.
- **Persistent by design:** worker-owned job supervisors outlive controller connections; where Herdr is registered, agent sessions do too.
- **Generic, not abstract:** provide durable fleet primitives while leaving Cargo or other build-system knowledge in the project profile.
- **Automation is a contract:** finite commands have a versioned JSON envelope, documented error codes, and stable exit semantics.
- **Security boundaries are explicit:** current-user/user scope is the frictionless default and creates no account or privilege prompt. Same-user code can alter user-owned Styrn state, so that mode is not advertised as containment; optional system/dedicated mode adds protected state and OS-account isolation under any configured valid name.
- **Secrets stay out of manifests:** machine manifests, job records, logs, and command payloads must not contain private keys, auth keys, API keys, tokens, or passwords.

## Planned integrations

| Component | Purpose |
|---|---|
| Tailscale and MagicDNS | Private connectivity and stable host names |
| OpenSSH | Authentication and cross-platform transport |
| Git and worktrees | Commit-addressed source distribution and isolated validation |
| Herdr (optional) | Persistent terminals, worktrees, and coding-agent lifecycle on hosts that register it |
| Codex and Claude Code | Agent harnesses controlled through adapters and MCP |
| sccache | Optional shared compilation acceleration |

Styrn is not literally dependency-free: v1 relies on system OpenSSH for transport and integrates with the capabilities enabled on each machine. The binary itself needs no separate language or package-manager runtime; the design does not require Python, Node.js, Java, Docker, or a database to run Styrn.

## Repository status

Implementation includes the runnable rootless portion of **Phase 0** and a
finite vertical slice of **Phase 1**. Phase 1 now includes bounded sequential
JSON RPC, lazy controller identity creation, pinned system-OpenSSH transport,
atomic TOML inventory and manifest cache, controller initialization,
enrollment/list/show/status/refresh/partial-doctor/trust, and exact-argv remote
execution. The fixture-backed process journey is tested end to end, but native
real-sshd acceptance on macOS, Linux, and Windows remains outstanding; this is
not yet the complete Phase 1 fleet surface. The repository defines a three-OS
CI matrix for formatting, build, tests, and lints; there is no release or
supported installation path yet.

| Phase | Intended outcome |
|---:|---|
| 0 | A fresh machine becomes an enrollable worker |
| 1 | Every machine is visible and reachable from one controller |
| 2 | A governed remote job survives controller disconnection |
| 3 | Project workflows and cross-platform matrices run end to end |
| 4 | Agents are governed wherever Herdr is registered, without losing lifecycle parity |
| 5 | Agents can request structured remote validation through MCP |
| 6 | Releases can be upgraded across the fleet |
| 7 | Setup gains reversible and script-rendered operations |
| 8 | Monitoring, TUI, desktop, and presentation conveniences land |

The detailed, testable task list is in the [implementation plan](docs/implementation-plan.md).

## Documentation map

| Document | Use it for |
|---|---|
| [Canonical design, revision H](docs/design.md) | Current architecture, behavior, security model, protocols, and binding decisions |
| [Implementation plan](docs/implementation-plan.md) | Ordered work items, positive tests, negative tests, and phase exit criteria |
| [Revision-D review](docs/design-review-D.md) | Historical adversarial review and proportionality analysis; not the current specification |

When documents disagree, `docs/design.md` wins. Historical examples described by the design are provenance, not installation or implementation guidance.

## Contributing

The Rust workspace remains early software with incomplete Phase 0 and Phase 1
delivery slices.
To contribute:

1. Read the [canonical design](docs/design.md), especially the part governing the subsystem you plan to change.
2. Choose an unchecked task from the [implementation plan](docs/implementation-plan.md), beginning with Phase 0 unless a dependency has already landed.
3. Implement both its positive and negative behavior. A task is complete only when both are tested.
4. Preserve the binding contracts for structured output, exit codes, secret handling, worker-side admission, and cross-platform behavior.

Run the local validation suite with the pinned toolchain:

```console
cargo fmt --all -- --check
cargo build --locked
cargo test --locked
cargo clippy --workspace --all-targets --all-features -- -D warnings
```

These commands validate the current foundation and runnable rootless setup
slice; they do not install a supported Styrn release. There is no supported
installation path yet.

## Naming

The canonical names are: project **Styrn**, command and repository `styrn`, project file `.styrn.toml`, and environment-variable prefix `STYRN_`. There is no required service-user name; `styrn` is only the suggested name for optional dedicated-account mode.

## License

Styrn is available under the [MIT License](LICENSE).
