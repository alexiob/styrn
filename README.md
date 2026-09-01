# Styrn

**One control plane for development machines, remote jobs, and coding agents.**

Styrn is a planned cross-platform command-line tool for operating a fleet of macOS, Linux, and native Windows development machines from any enrolled controller. It will set up and inspect hosts, run project-defined workflows under resource limits, keep remote jobs alive after the controller disconnects, and—on hosts where Herdr is installed and registered—manage persistent Codex and Claude Code sessions through it. Herdr is optional per host: everything except the agent-session surface runs without it.

> [!IMPORTANT]
> **Styrn is not yet usable software.** Implementation has begun — the repository contains a Rust crate that builds and tests on Linux, macOS, and Windows — but it is early in Phase 0 of nine, there is no release or installable binary, and no command yet performs real fleet work. Commands in this README describe the intended interface, not current behavior.

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
- **Native and cross-platform:** support macOS, Linux, and native Windows without requiring WSL or a language runtime.
- **Persistent by design:** worker-owned job supervisors outlive controller connections; where Herdr is registered, agent sessions do too.
- **Generic, not abstract:** provide durable fleet primitives while leaving Cargo or other build-system knowledge in the project profile.
- **Automation is a contract:** finite commands have a versioned JSON envelope, documented error codes, and stable exit semantics.
- **Security boundaries are explicit:** untrusted work runs without fleet credentials as the dedicated `styrn` user; MCP profiles improve least-privilege ergonomics but are not treated as containment from a process that already has controller shell access.
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

Implementation is in **early Phase 0 of nine phases (0–8)**: the crate,
command-line surface, output envelope, exit-code registry, machine manifest,
and setup probe layer are taking shape. The repository defines a three-OS CI
matrix for formatting, build, tests, and lints. Everything from Phase 1 onward
is unstarted; there is no release or supported installation path yet.

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
| [Canonical design, revision F](docs/design.md) | Current architecture, behavior, security model, protocols, and binding decisions |
| [Implementation plan](docs/implementation-plan.md) | Ordered work items, positive tests, negative tests, and phase exit criteria |
| [Revision-D review](docs/design-review-D.md) | Historical adversarial review and proportionality analysis; not the current specification |

When documents disagree, `docs/design.md` wins. Historical examples described by the design are provenance, not installation or implementation guidance.

## Contributing

The Rust workspace is scaffolded, but Styrn is still an early Phase-0 project.
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

These commands validate the current foundation; they do not install a usable
Styrn release. There is no supported installation path yet.

## Naming

The canonical names are: project **Styrn**, command and repository `styrn`, project file `.styrn.toml`, environment-variable prefix `STYRN_`, and service user `styrn`.

## License

Styrn is available under the [MIT License](LICENSE).
