# CLAUDE.md

This file provides Claude-specific orientation. **Read and follow `AGENTS.md`
first; it is the shared authoritative development guide for every coding
agent.** If this file drifts from `AGENTS.md`, the latter wins.

## Repository state

This repository contains the **design documents, reference examples and schemas, and a Rust crate under active implementation**. Phase 0 (foundations and setup core) is in progress, committed directly to `main` — expect the working tree to be dirty and to move under you.

```bash
cargo build                                                        # binary: styrn
cargo test                                                         # unit + integration suites
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo fmt --all -- --check
```

The toolchain is pinned to **Rust 1.98.0** (`rust-toolchain.toml`, and `rust-version` in `Cargo.toml`). CI runs all four commands on `ubuntu-latest`, `macos-latest`, and `windows-latest`; clippy warnings are errors. Crates are those Part 16.2 specifies — no database.

Most modules in `src/` are still one-line placeholders. Substance currently lives in `cli/`, `output/`, `manifest/`, `platform/`, and `setup/probe/`, with the heaviest test coverage in `tests/manifest_contract.rs` and `tests/cli_contract.rs`.

**Progress is not tracked by the checkboxes in `docs/implementation-plan.md`** — they are all still unticked. The real ledger is `.superpowers/sdd/implementation-plan/progress.md`, which records completed tasks, deferred findings, and the standing rulings where a task's wording was overridden by the design. Read it before assuming a task is unstarted.

`examples/` and `schemas/` are real, validated artefacts, not sketches: `machine.toml`, `machine.controller-worker.toml`, `fricos.styrn.toml`, `tailscale-grants.json`, and the three JSON Schemas (`machine-v1`, `project-v1`, `command-v1`). The schemas are normative renderings of design.md 2.4/2.4.2, 9.1, and 10.2/10.3 — **if an implementation and a schema disagree, check the design Part first, then fix whichever is wrong.** The examples validate against them.

The design specifies what gets built: a **single cross-platform Rust binary** (`styrn`). Follow the design's own decisions rather than inventing new ones:

- Repository layout → Part 16.1 (`src/{cli,setup,config,manifest,inventory,transport,rpc,mcp,platform,resources,scheduler,jobs,project,git,harness,integrations,desktop,notification,output}`, plus `integrations/`, `schemas/`, `bootstrap/`, `examples/`, `docs/`)
- Crate choices → Part 16.2 (clap, serde, tokio, thiserror, uuid, sysinfo, tracing; **no database in v1** — inventory is TOML files, jobs are filesystem objects)
- Build order → Part 16.3, **Phases 0–8** (setup core → fleet visibility → jobs → workflows/matrix/styrnd → agents on the session substrate → MCP → packaging → setup completions → convenience). Jobs come before agents, deliberately. The TUI is Phase 8; do not start there.
- Task-level breakdown → `docs/implementation-plan.md`. Its placement rule (Part 16.3) is binding: **every new component must be placed in exactly one phase in the same change**, or it is not specified.

## Document map

| File | What it is |
|---|---|
| `docs/design.md` | **Canonical spec (revision H).** Organized into Parts 0–19, with a 40-issue register (`S-01`…`S-40`, Part 18), a decision log (`D-1`…`D-9`, Part 19 — all decided), a phase plan (Part 16.3), and Appendix A. Cite **Part numbers**. |
| `docs/implementation-plan.md` | 125 implementation tasks across Phases 0–8, each with a positive and a negative test checkbox, plus continuous testing obligations (C1–C11) and open items (O1–O5). Tick a task only when both tests pass. |
| `docs/design-review-D.md` | Independent adversarial review of rev. D, focused on proportionality. Its proposed v1 cut line was **consciously not adopted** — correctness fixes were applied with nothing cut (Part 18 preamble). Useful if scope is revisited; not a description of the current design. |
| `README.md` | Public-facing overview. States plainly that Styrn is not yet usable software and that its command examples describe the intended interface — keep both accurate as code lands. |

**The original design (revision A) and its example and bootstrap files have been removed** as obsolete. The `(orig. §N)` annotations throughout `design.md`, and Appendix A, are historical provenance recording where material originated and proving the carry-forward was complete — they are not links to anything readable. Cite Part numbers.

## Naming contract (design.md §0.3 — binding, do not deviate)

Project `Styrn` · CLI `styrn` · repo `styrn` · project file `.styrn.toml` · env
prefix `STYRN_*`. There is no required service account: current-user is the
default, while optional dedicated mode accepts any valid configured
non-administrator name (`styrn` is only a suggestion).

## Architecture essentials

- **One binary, many hats.** The same executable is controller, remote RPC endpoint (`styrn rpc serve --stdio` over SSH), resource detector, job runner, workflow engine, and MCP server. No custom network daemon in v1.
- **Peer-capable roles, no master.** `roles = ["controller"]`, `["worker"]`, or both. Controller status grants *no* scheduling eligibility, and worker status grants *no* admin rights. Roles (what Styrn may do) are distinct from `[capabilities]` (what work the host can run).
- **Transport** is OpenSSH over Tailscale with MagicDNS naming. No Kubernetes/Docker/Nomad/Jenkins/WSL anywhere in the core design.
- **Herdr is the *optional* session substrate** for interactive sessions and coding agents (Part 11.0, D-9). It is per-host, with state `none | registered | active`; the manifest `[herdr]` table (`installed` + operator-owned `enabled`) is the registration authority. A fleet with no substrate anywhere is fully healthy: jobs, workflows, doctor, and selftest all pass. Critical asymmetry (§11): Herdr supports Windows as a remote *client* but not as a `herdr --remote` *target*. Styrn must hide this — programmatic control goes through SSH → remote `styrn rpc serve --stdio` → local Herdr CLI on every OS, never through `herdr --remote`.
- **MCP server lives in the same binary** (`styrn mcp serve --profile readonly|developer|orchestrator|admin`, §81–87). Deliberately never expose an `ssh_exec(host, arbitrary_command)` tool; arbitrary remote execution stays a human CLI capability. Tools are project-scoped by default. Harness approval and Styrn's own `[mcp.mutations]` policy are separate layers.

## Binding contracts

These are invariants, not suggestions — check the cited section before changing behavior in these areas.

- **CLI output (§23).** Every non-interactive command supports `--json`; streaming ones add `--jsonl`. JSON on stdout (exactly one document for finite commands), diagnostics on stderr, never mixed. `--json` disables color. Envelope: `{schema, ok, command, timestamp, data, warnings, errors}` with `schema: "styrn.command.v1"`. RFC 3339 timestamps, bytes as integers, durations in integer ms. Removing a field requires a schema-version bump; adding optional fields does not.
- **Exit codes (§24).** `0` ok, `2` usage, `3` unreachable, `4` auth, `5` remote exec, `6` resource admission denied, `7` capability unavailable, `8` schema incompatibility, `9` partial fleet op, `10` timeout, `11` agent/harness, `12` workflow. Agent state `blocked` is a valid state, not an error.
- **Manifests carry no secrets (§19, §41).** Machine manifests contain no private keys, API keys, Tailscale auth keys, or passwords. SSH identity paths are controller-local (`inventory.toml`) and never copied into a worker manifest.
- **Admission control before every job (§27).** The worker — not an agent — computes `resources.compile_jobs` / `test_jobs` from CPU and memory budgets. Scheduling requires worker role AND `enabled` AND `accept_jobs` AND capability match AND dynamic admission AND policy.
- **Agent jobs ≠ validation jobs (§36).** Agent jobs edit source and commit; validation jobs run on a clean worktree at an exact SHA and never edit. A modifying agent must not certify its own workspace. Sync source via Git commits + worktrees, never rsync (§35).
- **Frictionless defaults are a binding tenet (§0.6), not a preference.** It is the explicit tiebreaker: between two equally correct designs, the one needing less setup, fewer flags, fewer manual steps, and fewer permission prompts wins. Sensible defaults over required config; autodetection over declaration; one command over a documented sequence; opt-in hardening rather than opt-out friction. Its stated boundary: it never overrides correctness of results, and never silently weakens a Part 4.5 security boundary.
- **Herdr parity is an invariant (S-33, Part 12.9.1), scoped to pane context on a registered substrate.** An agent started by `styrn harness run` in a Herdr pane must be indistinguishable to Herdr from a manual launch — same detection, lifecycle states, and control. In standalone context (no pane, or no substrate at all) the launcher is fully governing but makes no parity claim; that is vacuity, not a weakening, and never an excuse to skip the probe where a substrate is registered. `execvp` on Unix; on Windows a minimal-footprint direct child verified by a live probe. If parity cannot be achieved, the launcher refuses to wrap and falls back to unwrapped rather than producing an undetectable session.
- **Generic, not abstract (§66).** Styrn expands resource variables and executes declared workflows; build-system knowledge (Cargo flags, parallelism) belongs in each project's `.styrn.toml`. Do not compile project-specific subcommands into Styrn.
