# Styrn: Cross-Platform Agent and Development Machine Control Plane — Consolidated Design

**Status:** Specification. Nothing described here is implemented. There is no source code, no `Cargo.toml`, and no release. Every statement about behavior is a design decision to be implemented, not a description of an existing system.
**Revision:** H (consolidated; rootless user scope is the primary/default installation)
**Date:** 2026-09-02
**Primary use case:** centrally control heterogeneous macOS, Linux, and native Windows development machines and persistent coding-agent harnesses from any enrolled controller machine.
**Initial project profile:** FriCOS / Rust development.
**Project name:** `Styrn`
**CLI:** `styrn`

---

## 0. About this document

### 0.1 Supersession

This document **supersedes** the original design, revision A (`styrn-complete-design.md`), together with its companion example files and the five bootstrap/install scripts. Those files were **removed from the repository as obsolete** after rev. E; this document is now the sole design of record, and nothing in the repository depends on them. The `(orig. §N)` annotations throughout, and Appendix A, are retained as **provenance** — they record where each decision originated and that no original material was dropped — but they no longer point at a file in this repository. Where this document and any recovered copy of the original disagree, this document wins. The original's bootstrap scripts are superseded outright by the `styrn setup` subsystem (Part 15, esp. 15.12).

This revision was produced by an adversarial architecture review of revision A. The review found five blocker-level defects (jobs die when the controller's SSH session drops; workers cannot fetch private repositories under the stated credential policy; resource admission has no atomicity story; the RPC protocol has no framing or negotiation specification; and the security claims made for MCP and project-declared workflows do not hold against the stated threat model). All are resolved inline in the relevant sections and cross-referenced from the consolidated **issues register** (Part 18). The pass-1 follow-up (rev. C) raised one further blocker — S-33, Herdr launcher parity — likewise resolved inline (12.9.1, 12.10). Questions that revision B left open have since been decided and are recorded in the **decision log** (Part 19). Rev. G made current-user the identity default; rev. H makes rootless user scope the installation default. Dedicated/system scope remains optional hardening.

### 0.2 Traceability conventions

- The original document's numbered sections run **§1–§126**, plus one unnumbered "Styrn machine role model" chapter (referenced here as **§RM**). (Some earlier notes described the original as having "103 numbered sections"; that count is wrong — the actual numbering, verified against the file, is 1–126 with §2 containing subsections 2.1–2.10. No original section has been dropped.)
- Every section of this document that carries forward original material is annotated **(orig. §N)**.
- Sections and mechanisms that are **new in this revision** — i.e., the reviewer's additions rather than the original author's — are annotated **(new in rev. B)**, usually with the issue ID that motivated them (e.g., *resolves S-01*).
- Appendix A contains the full §1–§126 → new-section mapping table.
- **The original document is no longer in this repository** (removed as obsolete after rev. E). The `(orig. §N)` annotations and Appendix A are therefore historical provenance, not cross-references to a readable file: they record where material came from and prove the carry-forward was complete. Cite **Part numbers** of this document when referring to a decision; cite `(orig. §N)` only when the question is genuinely about origin.

### 0.3 Naming contract (binding)

Originally stated in `NAMING.md` (removed with the rest of the original design, §0.2); the contract itself is unchanged and **this section is now its authority**:

```text
Project       Styrn
CLI           styrn
Repository    styrn
Project file  .styrn.toml
Config env    STYRN_*
Suggested dedicated worker user  styrn
```

A Styrn machine may have either or both roles: `controller`, `worker`, or `controller + worker`. **There is no permanent master node.**

### 0.4 Canonical vocabulary frozen in this revision (new in rev. B)

To stop terminology drift, the following forms are canonical everywhere in this document and in the implementation. The superseded forms from revision A appear only in the issues register.

| Canonical | Supersedes (rev. A) | Issue |
|---|---|---|
| `styrn monitor [--notify] [--jsonl]` (headless event follower) | `styrn watch --notify` in orig. §40 | S-12 |
| `styrn watch` (interactive TUI only; no `--notify`) | mixed use in orig. §40/§80/§101 | S-12 |
| `--harness codex\|claude` on `styrn agent start` and in MCP `styrn_agent_start` | `--kind codex\|claude` (orig. §25), `harness=` (orig. §89) | S-20 |
| MCP tool names always `styrn_`-prefixed (`styrn_fleet_status`, …) | unprefixed names in orig. §83 | S-20 |
| Artifact URIs are host-qualified: `job://<host>/<job-id>/<path>` | host-less `job://0199.../stdout.log` (orig. §120) | S-14 |
| `[resources.policy] max_job_disk_bytes` | per-job quota values with no schema key (orig. §31) | S-28 |
| Job IDs and `machine_id` are UUIDv7 | "uuid" unspecified (orig. §19, §45) | S-25 |
| `styrn machine …` = local-machine commands; `styrn host …` = inventory/remote commands | undocumented split (orig. §19 vs §25) | S-20 |
| Herdr headless invocation: `HERDR_SESSION=fleet herdr server` (env-var form) | "depending on the invocation style you standardize on" (orig. §11) | S-23 |
| Exit code `1` = unexpected internal error | undefined (orig. §24) | S-11 |
| **"session substrate"** (Herdr; per host; optional — Part 11.0). *"Package substrate"* (15.2.1, 15.7.6) is a different thing; bare "substrate" is never used alone | "persistent execution substrate" as an unconditional description (11.1 title, rev. A–E) | S-40 |
| Substrate state `none \| registered \| active` (11.0.1) | the undefined mix of manifest `[herdr]`, `[components] herdr`, and plugin-install as implicit signals | S-40 |

### 0.5 Summary of the major revisions (new in rev. B)

1. **Jobs are owned by a detached worker-side supervisor, never by the controller's SSH session** (Part 7.8; resolves S-01). Closing the controller no longer kills a running validation job — the original promised this (orig. §61) but its execution model contradicted it.
2. **Source reaches workers via controller push over the existing SSH transport; workers hold no git credentials by default** (Part 8.2; resolves S-02, the §35-vs-§41 contradiction). Read-only deploy keys are an explicit opt-in.
3. **Resource admission is worker-side, serialized under a local lock, and tracks committed budgets of running jobs** (Part 7.2–7.3; resolves S-03 and the double-counting defect S-07). Controllers only *predict* admission; workers *decide* it.
4. **The stdio RPC protocol is specified**: NDJSON framing, hello negotiation with a version range, request multiplexing, log streaming, chunked artifact transfer (Part 5; resolves S-04).
5. **Security claims are restated honestly** (Part 4.5; resolves S-06). Project-declared workflow commands are attacker-controlled input; MCP tool narrowing is least-privilege ergonomics, not a security boundary against an agent with shell access on a credentialed controller. The real boundaries are OS accounts, credential placement, sandboxes, and worker-side enforcement.
6. **Key lifecycle is specified**: per-controller keypairs, host-key pinning at enrollment, and defined revocation semantics for `styrn host remove` (Part 4.3–4.4, 6.1; resolves S-05).
7. **Exit codes, error codes, the JSON envelope, revision resolution, disk-quota mechanics, Windows execution semantics, schema compatibility policy, audit logging, and a testing strategy** are all specified where revision A was silent or self-contradictory (Parts 5, 7, 8, 10, 14, 16; resolves S-08, S-09, S-11, S-13, S-15, S-16, S-19).

### 0.6 Design tenet: developers must not fight the tool (new in rev. C)

The operator's requirement, verbatim and binding:

> "this is a developer's tool and must be flexible, powerful but easy to start using and with good frictionless defaults and permissions. developers do not want to fight their tools!"

This is a first-class design tenet, and it is the **tiebreaker** used throughout this document: when two designs are equally correct, the one requiring less setup, fewer flags, fewer manual steps, and fewer permission prompts wins. Concretely:

- **Sensible defaults over required configuration.** Every knob has a working default; configuration expresses *deviation*, never table stakes.
- **Autodetection over declaration.** Styrn never asks a developer to invent
  information it can discover itself (project, revision, key material, repo
  state on a worker). Setup resolves the transport user and emits it explicitly
  in the enrollment card; the controller does not guess an account default.
- **One command over a documented sequence.** If the docs say "first run X, then Y", Y should run X implicitly when it is safe to.
- **Opt-in hardening rather than opt-out friction.** Security postures that add ceremony (profile pinning, deploy keys, keychain storage) exist and are one config block away — they are never the default a developer must dismantle to get started.
- **Powerful stays possible, never mandatory.** Nothing in the frictionless path forecloses the advanced path.

The tenet has one deliberate boundary: it never overrides *correctness of results* (a dirty worktree still refuses to masquerade as a clean commit — the fix is a crystal-clear one-flag remedy in the refusal message, not silent guessing). When an operator selects a lower-friction security posture, Styrn states the resulting boundary honestly rather than silently claiming the stronger posture from Part 4.5.

Applied in this revision at: 4.3.1 (lazy key generation), 6.1 (transport defaults), 7.6 (TTY-aware queueing), 8.2 (implicit repo bootstrap), 9.1 (starter-profile on-ramp), 12.9–12.10 (Herdr parity — a Styrn-launched agent must never be worse than a manually launched one), and every decision in Part 19.

### 0.7 Revision C changelog (pass 1) (new in rev. C)

1. **Design tenet added** (§0.6) and applied as the explicit tiebreaker.
2. **Every open question decided.** Part 19 is now a decision log (D-1…D-8, preserving the former OQ-1…OQ-8 numbering); all inline "open question" hedges in the body are replaced by the decisions. Only D-3 (Windows hardened bootstrap mode) is deferred — it belongs to the pass-2 `styrn setup` redesign.
3. **Blockers finalized to implementation depth.** 7.8 gains submission unhappy-path semantics (spawn-ack, registry rollback, `submission_id` idempotency for lost-session resubmits); 7.3 gains lock-liveness rules; 8.1–8.2 replace `refs/styrn/jobs/<job-id>` with SHA-keyed `refs/styrn/revisions/<sha>` — fixing a rev.-B ordering conflict in which the push refspec needed a job id that is only minted later, at admission — and make `repo.ensure` implicit in submission.
4. **Herdr parity invariant** (S-33, blocker): `styrn harness run` must be indistinguishable to Herdr from a manual launch, with normative per-OS mechanisms, environment pass-through rules, hook coexistence, refusal-over-degradation fallback, and a conformance test (12.9–12.10, 16.6).
5. **Friction audit:** implicit worker-repo bootstrap (S-29), lazy per-controller key generation (S-30), TTY-aware wait-on-busy default (S-31), starter `.styrn.toml` on-ramp (S-32).
6. **Register grows to 33 issues** (6 blocker / 13 major / 14 minor). Part 15 untouched by design — it is superseded wholesale by the pass-2 setup redesign.

### 0.8 Revision D changelog (pass 2 — the setup redesign) (new in rev. D)

1. **Part 15 replaced wholesale** by the `styrn setup` subsystem: one probe→diff→plan→apply engine with typed, reversible, journaled Actions; `doctor` and `setup` are two frontends of one probe layer (15.2, amending 6.5). The operator's CLI surface — `--install …/--role …`, `--config …`, `--interactive` — is adopted verbatim, plus `--dry-run`, `--emit-script`, `--uninstall`, `--adopt` (15.4, 15.13). Bare `styrn setup` provisions a worker with **two human decisions** (one Enter, one Tailscale browser login); zero with `--yes --auth-key`.
2. **D-3 originally decided hardened mode as the Windows default** (15.8); rev. G supersedes only that default. The transient-logon path remains available as optional dedicated-account hardening, while current-user now requires no account creation.
3. **`styrnd` worker service** (S-34): the maintenance executor Part 6.8 lacked, and the Windows supervisor-spawn broker 7.8 needed — per-worker and local-only, with selected-principal maintenance separated from the narrow credential-free Windows broker, explicitly reconciled with orig. §63's no-central-daemon rule (15.9).
4. **Enrollment ergonomics resolved** (S-36): enrollment stays controller-initiated; setup ends with an **enrollment card** (name/address + explicit transport user + host-key fingerprint) making a worker enrollable in one pasted line; `styrn bootstrap-script --os <os>` emits a customized stage-zero script with the controller key baked in (15.10, 15.11.4).
5. **Script generation** specified as a third renderer of the same Action plan (`render_posix`/`render_powershell`), with the four hard breaks handled: runtime secrets via `Secret<T>`, embedded guard checks against state drift, interactive auth passthrough, and `--adopt` receipt reconciliation (15.11).
6. **winget demoted** (S-35): unusable from SYSTEM/service/SSH-non-interactive contexts — the rev. A Windows script was built on it; direct MSI/EXE is the dependable Windows channel (15.7.6).
7. Exit code 13 and the `setup.*` error-code family added (10.3, 10.4, 15.13); reference scripts demoted with S-10/S-17/S-18/S-27 supersession recorded (15.12); Appendix A remapped for orig. §42–§49, §60, §111–§114.
8. **Register grows to 36 issues** (6 blocker / 15 major / 15 minor).

### 0.9 Revision E changelog (pass 3 — response to the independent review) (new in rev. E)

1. **Scope decision recorded:** `docs/design-review-D.md` — a fresh adversarial review of rev. D — proposed a proportionality cut line alongside correctness findings. The operator chose **"correctness only, cut nothing"**: every mechanism stays in scope and fully specified; the cut-line analysis is preserved in that file as context for a later decision (Part 18 preamble).
2. **Every correctness finding fixed** (consolidated as S-39; each fix annotated "(rev. E; review D §…)" at its site): the 12.9/12.10 exit-status contradiction, the LSA-credential honesty drift, the doctor/probe unification scoped to worker-local probes, `styrn_workflow_cancel` defined, Part 10.5 completed (machine/controller/harness/selftest/upgrade/cancel commands), admission-formula defaults pinned, workflow cwd stated, list fan-outs exit 0 with warnings (exit 9 reserved for required participants), the error registry fully exit-mapped and the envelope given its N/N−1 window, `submission_id` dedupe retention, `--host` override semantics, log files inside the quota walk, and enrollment-card channel sensitivity.
3. **Packaging and upgrade specified** (Part 15.14; resolves S-37, the review's "most significant absence"): per-platform channels own `styrn` binary upgrades — GitHub Releases substrate, Homebrew tap, winget (human-present only, S-35 nuance preserved), `.deb` asset, `cargo install` fallback; `[install]` provenance in the manifest; `fleet versions` channel column with per-host upgrade commands; `styrn upgrade` as a channel *delegator* (never self-update); replacement mechanics safe under running jobs; **N/N−1 declared load-bearing** (mixed versions are the expected steady state) with all compatibility contracts binding from the first tagged release (2.8).
4. **Phase plan rebuilt** (16.3): nine phases 0–8, every specified component placed exactly once, each phase independently useful, jobs before agents; 16.4's integration phases absorbed with an explicit mapping.
5. **`styrn watch` specified** (14.5): five Tier-1 views (live matrix grid, job view with resource traces against budgets, the 11.10 fleet board, a host-labelled all-agents superset board making 11.12 a hierarchy, doctor view), Tier-2 review panes, normative Herdr-citizenship constraints, the absolute projection rule — and the not-TUI decisions (setup prompts, headless monitor, static fleet versions) preserved, not reopened.
6. **`sleep-policy` worker component** (S-38): laptops that sleep were an unstated availability assumption.
7. **Register grows to 39 issues** (6 blocker / 16 major / 17 minor).

### 0.10 Revision F changelog (pass 4 — the session substrate is optional) (new in rev. F)

Raised by a new operator requirement, verbatim and binding:

> "styrn should not depend on herdr: it should be able to run independently, while leveraging herdr when present and in-use and registered."

1. **The session substrate model** (11.0): Herdr is an optional, per-host **session substrate** with one machine-local state — `none | registered | active` — and a defined precedence among the three signals that previously all touched Herdr independently (manifest `[herdr]` is the registration authority; `[components] herdr` is desired-state input only; `integrate herdr install` points the other way and implies nothing). Vocabulary frozen in §0.4.
2. **The substrate degradation contract** (11.0.3, binding): substrate-requiring operations on a `none` host fail with exit 7 / `capability.substrate_unregistered`; query-shaped operations answer empty-and-healthy with **no warnings**; registered-but-broken remains exit 11 / `agent.harness_error`. One new error code, no new exit code — 7 already means "required capability unavailable".
3. **Provider matrix and the no-second-provider decision** (11.2): `HerdrProvider` stays the only v1 implementation and provider resolution is substrate-gated. A reduced provider over the detached supervisor (7.8) is explicitly rejected — it could not honestly implement `prompt`/`read`/`wait`/`attach`, and the need it would serve is already served by batch agent runs as ordinary workflows (§66; `harness.jsonl` already reserved in 7.7/12.5).
4. **`styrn harness run` gains an explicit standalone context** (12.9): its governance — project identification, job context, computed limits, resource environment, admission accounting — was always substrate-independent and is now specified as such.
5. **The S-33 Herdr-parity invariant is rescoped, not weakened** (12.9.1): it binds at full force in pane context on a registered substrate, and is *vacuous* — not relaxed — in standalone context, where there is no observer to be indistinguishable to. The scope condition may never be used to skip the parity probe where a substrate is registered.
6. **Six surfaces conditionalized:** events (5.7), doctor (6.5), the fleet and agent boards (11.10, 14.5.1), `fleet selftest` (16.6 item 6), the MCP agent tools (13.3), and `integrate all` (12.18). A Herdr-less fleet enrolls healthy, passes doctor, and passes selftest.
7. **`styrn herdr status|attach` added to the canonical surface** (10.5) — they had appeared in 10.7 and the Phase-4 listings but were never in 10.5, a latent violation of the design's own rule that every command is in 10.5. They stay vendor-named (D-9).
8. **Dependency framing corrected** throughout Parts 1, 11, and 16.9; `[herdr].enabled` added to the manifest (2.4, 2.4.2) and to `schemas/machine-v1.schema.json`; ephemeral `substrate` added to `machine.status` (2.5).
9. **Register grows to 40 issues** (6 blocker / 17 major / 17 minor); decision log grows to D-9.

### 0.11 Revision G changelog (pass 5 — worker identity is configurable) (new in rev. G)

Raised by a new operator requirement, verbatim and binding:

> "I do not think we should enforce a specific account for styrn to work: that is a friction we do not need"

1. **No named account is a prerequisite.** Every OS-facing permission, ownership, service, SSH, receipt, and manifest operation receives a resolved `WorkerPrincipal`; implementation code must never look up a literal account name as hidden global state.
2. **Current user is the frictionless default.** `[account] mode = "current-user"` requires no account creation and is the default on Linux, macOS, and Windows. Bare `styrn setup` works under that identity. The selected principal is recorded in generated machine state so later commands resolve the same identity deterministically.
3. **Dedicated identity is optional hardening.** `[account] mode = "dedicated"` creates or adopts the configured unprivileged local account. `name = "styrn"` is only the suggested default for this opt-in mode; any valid, non-administrator local account name is supported. `--account dedicated[:<name>]` selects it explicitly.
4. **Security claims are posture-dependent.** Current-user mode does not claim OS-account separation from the operator's files or credentials. Setup, doctor, and the manifest surface that caveat. Dedicated mode retains the stronger Part 4.5 filesystem and credential-placement boundary and its native acceptance tests.
5. **Tests select a principal explicitly.** Native permission tests may use any explicitly supplied real unprivileged account; they must not require an account literally named `styrn`. Tests that prove dedicated-account isolation remain environmental where root/Administrator and a second account are required.
6. **D-3 is superseded.** Windows still supports the transient-logon hardened path, but it is opt-in and parameterized by the selected account. The default does not create an account or manufacture a password.

### 0.12 Revision H changelog (pass 6 — rootless is the primary path) (new in rev. H)

Raised by a new operator requirement, verbatim and binding:

> "we have to assume that the vast majority of styrn users will use it in their own user account, almost always without root or admin privileges . they do not whant to give it to a cli tool. styrn must work fine in that case, which is the main use case"

1. **User scope is the default and core setup requires no elevation.** Bare
   `styrn setup` can complete a useful local installation using only the
   invoking user's standard config/state/data directories.
2. **Machine completion is one explicit, optional native authorization.** If
   the requested outcome needs missing OS packages/services/firewall changes,
   interactive setup groups the exact closed actions and asks once. On consent,
   the OS owns the `sudo`/UAC credential UI; Styrn never sees or stores a
   password. Declining completes user scope and records the remote/system delta
   as pending. Noninteractive setup never surprise-prompts.
3. **System scope is explicit optional hardening.** `--scope system` and every
   dedicated-account installation may use the same one-shot native
   authorization path or an already-elevated invocation. User-level actions
   still execute as the original user.
4. **Security claims follow storage scope.** User-owned manifests, receipts,
   locks, authorized keys, and registries are integrity-checked and atomic, but
   are not a containment boundary against hostile code running as that same
   user. System scope retains the protected-state boundary.
5. **Missing machine-wide prerequisites degrade honestly.** User scope uses
   existing SSH/Tailscale services and user-level service managers where
   present. A missing system service becomes a structured `NeedsHuman` or an
   unavailable remote capability; local workflows/controller functions remain
   usable. Setup never fails merely because root was not granted.
6. **User services are first class.** systemd user units, LaunchAgents, and a
   credential-free per-user Windows task/startup mechanism provide maintenance
   and broker behavior within the login-session guarantees of each OS. Always-
   on, pre-login, or logout-surviving service guarantees require explicit
   system scope and are advertised as separate capabilities.

---

# Part 1 — Purpose, scope, and rationale

## 1.1 Executive recommendation (orig. §1)

The system should be generalized now.

Do **not** make `fricosctl` the infrastructure layer. Build a separate, project-independent repository containing a cross-platform Rust control binary, and make FriCOS a project profile that describes:

- repository location and Git policy;
- supported operating systems;
- build/check/test workflows;
- resource requirements;
- environment variables such as `CARGO_BUILD_JOBS`;
- cleanup policy;
- which machines are allowed to run heavy validation.

A good separation is:

```text
styrn/                         independent infrastructure repository
├── src/
├── bootstrap/
├── schemas/
├── examples/
└── docs/

fricos/
├── ...
├── AGENTS.md
├── CLAUDE.md
└── .styrn.toml                FriCOS-specific policy
```

`styrn` should be a **single Rust executable** built for macOS, Linux, and Windows. The same binary can act as:

- controller;
- remote RPC endpoint over SSH stdio;
- resource detector;
- machine manifest generator;
- job launcher;
- project workflow runner;
- cleanup engine;
- adapter for Herdr (the optional session substrate; Part 11.0);
- adapter for Codex, Claude Code, and future agent harnesses.

It does not need a custom network daemon in the first version. Use SSH as the authenticated transport and execute the same `styrn` binary remotely.

Long-running interactive jobs and coding agents should live inside **Herdr**, which (per the upstream claims recorded in Part 17 — verify against current upstream docs before implementation) supplies persistent terminal sessions, panes, worktrees, agent discovery, lifecycle state, JSON-oriented automation, and detach/reattach semantics — **on hosts where the session substrate is registered (Part 11.0)**. Herdr is optional per host: Styrn runs, governs jobs, and passes doctor without it. The substrate adds the interactive-agent surface and nothing else depends on it.

### Recommended high-level stack (orig. §1)

| Layer | Recommendation |
|---|---|
| Private network | Tailscale |
| Stable naming | Tailscale MagicDNS |
| Remote transport | OpenSSH over Tailscale |
| Fleet control | `styrn` Rust binary |
| Persistent terminals/agents | Herdr — optional session substrate, per host (Part 11.0) |
| Agent CLIs | Codex CLI, Claude Code, future adapters |
| Source distribution | Git + worktrees (controller-push; see Part 8.2) |
| Build resource policy | `styrn` resource governor |
| Rust compilation cache | sccache |
| Linux admin GUI | Cockpit, optional |
| Windows GUI | RDP, optional |
| macOS GUI | Screen Sharing / Remote Management, optional |
| Last-resort recovery | remotely controlled power + firmware auto-power-on |
| Project policy | `.styrn.toml` in each project |

No Kubernetes, Docker Swarm, Nomad, Jenkins, or WSL is required for the core design.

## 1.2 Why generalize it? (orig. §2)

The machine-control problem is not specific to FriCOS. You are really building a system with these generic primitives:

1. discover a machine;
2. identify OS, architecture, CPU, RAM, disk, toolchains, and capabilities;
3. connect securely;
4. run commands;
5. run persistent agent sessions;
6. create and clean isolated workspaces;
7. schedule work according to available resources;
8. retrieve structured results;
9. open a shell or graphical desktop;
10. recover/restart a headless host.

FriCOS is simply the first project that consumes those primitives.

### 1.2.1 Infrastructure remains usable when FriCOS is broken (orig. §2.1)

A fleet controller should not depend on the repository it is expected to repair. If FriCOS has:

- a broken Cargo workspace;
- a bad `rust-toolchain.toml`;
- a branch that no longer compiles;
- a dependency problem;
- a destructive build script;

the control plane still works.

### 1.2.2 Reusable for every future repository (orig. §2.2)

You can later run:

```text
styrn workflow run my-other-project test
styrn agent start win-heavy --project some-tool --harness codex
styrn workflow run macos-app ui-test
```

without cloning the orchestration code.

### 1.2.3 Cleaner security boundary (orig. §2.3)

Machine credentials, Tailscale details, remote hosts and power-control configuration do not belong in the FriCOS source repository.

### 1.2.4 Independent release cadence (orig. §2.4)

Infrastructure fixes can ship without modifying FriCOS. FriCOS build-policy changes can ship without replacing the fleet controller.

### 1.2.5 Easier testing (orig. §2.5)

`styrn` can have its own:

- protocol tests;
- manifest schema tests;
- Windows/Linux/macOS CI;
- mocked SSH transport tests;
- scheduling tests;
- resource-admission tests.

Revision A left testing at this aspirational list; the concrete testing strategy is now specified in Part 16.6 (resolves S-16).

### 1.2.6 Better abstractions (orig. §2.6)

A machine is a machine. A project is a project. An agent harness is an agent harness. A workflow is a workflow. Keeping those entities separate prevents FriCOS-specific assumptions from leaking into the fleet layer.

## 1.3 Drawbacks and mitigations (orig. §2.7–2.10)

### 1.3.1 Two repositories instead of one (orig. §2.7)

There is more version management. Mitigation:

```toml
# .styrn.toml
schema_version = 1
minimum_styrn_version = "0.3.0"
```

### 1.3.2 General abstractions take more initial design work (orig. §2.8)

It is easy to over-generalize. Avoid implementing an extensible enterprise scheduler in v1. Support exactly the primitives you currently need:

- machine inventory;
- SSH transport;
- Herdr (optional session substrate — Part 11.0);
- Codex;
- Claude;
- Git worktrees;
- generic commands;
- project workflows;
- resource limits;
- cleanup.

### 1.3.3 Project-specific optimizations need a configuration layer (orig. §2.9)

For example, Cargo uses:

```text
CARGO_BUILD_JOBS
CARGO_TARGET_DIR
CARGO_INCREMENTAL
RUST_TEST_THREADS
RUSTC_WRAPPER
```

A CMake or Go project will use something else. The solution is **resource variables** exposed by Styrn and mapped to environment variables by a project profile (specified in Part 9.3).

### 1.3.4 Compatibility has to be managed (orig. §2.10 — superseded mechanism)

A controller may be version 0.5 while a worker binary is 0.4. Revision A proposed that "every remote call begins with a protocol handshake" consisting of a single JSON blob:

```json
{
  "protocol": 1,
  "styrn_version": "0.5.0"
}
```

and said the controller "should reject incompatible protocol versions cleanly" — without defining who speaks first, what "incompatible" means, what range of versions a binary must support, or how rejection is expressed. **That handshake is superseded** by the negotiated hello exchange and compatibility policy in Part 5.2 (resolves S-04) and the schema-compatibility policy in Part 2.8 (resolves S-15).

## 1.4 One binary, runnable from any platform (orig. §3)

The control command must not be macOS-specific.

- A Windows machine should be able to control Linux and macOS workers.
- A Linux machine should be able to control Windows and macOS workers.
- A macOS machine should be able to control all three.

The proposed executable is:

```text
styrn
```

The same binary has both local-controller and remote-worker commands. Examples:

```text
styrn host list
styrn host status win-light
styrn agent list --all
styrn workflow run fricos test-windows
```

Remote invocation uses the same binary:

```text
ssh win-light styrn rpc serve --stdio
```

The local controller speaks a versioned JSON protocol to that process through stdin/stdout (framing specified in Part 5).

This is preferable to creating a custom TCP service in v1 because it gives you:

- existing SSH authentication;
- existing host-key verification;
- no additional listening port;
- no TLS PKI to invent;
- easy auditing;
- easy manual debugging;
- Tailscale isolation;
- no general-purpose privileged worker daemon. The sole exception is the narrow,
  local Windows admission/spawn broker in Part 15.9; it accepts no arbitrary
  executable, arguments, network input, or unadmitted job.

**Clarification (new in rev. B, resolves part of S-01):** the SSH/stdio RPC session is a *control channel*, not an *execution container*. Long-running jobs submitted through it are handed off to a detached worker-side supervisor (Part 7.8) and survive the channel. Only the interactive stream (`styrn shell`, `styrn agent attach`) is inherently tied to the SSH session's lifetime.

## 1.5 What "no dependencies" should mean (orig. §4)

A literal zero-dependency fleet is impossible because the entire point is to manage external tools:

- Tailscale;
- Git;
- Herdr (optional — Part 11.0);
- Codex;
- Claude Code;
- Rust;
- Visual Studio Build Tools;
- RDP/VNC clients.

The useful goal is:

> `styrn` itself has no language runtime or package-manager runtime dependency.

It should not require:

- Python;
- Node.js;
- Go;
- Java;
- Ruby;
- PowerShell modules;
- a database;
- Docker.

Rust crates are compiled into the executable and are not runtime package dependencies.

Recommended release targets:

```text
aarch64-apple-darwin
x86_64-apple-darwin
x86_64-unknown-linux-musl
aarch64-unknown-linux-musl
x86_64-pc-windows-msvc
aarch64-pc-windows-msvc     optional initially
```

For Linux, `*-unknown-linux-musl` is a good way to produce a highly portable binary with the C runtime statically linked by default.

For Windows, consider:

```text
-C target-feature=+crt-static
```

for the Styrn release build if all dependencies tolerate it.

macOS applications still rely on Apple system libraries; the goal there is a single application binary without third-party runtime installation.

### 1.5.1 OpenSSH: external or embedded? (orig. §4)

Two reasonable approaches exist.

**V1 recommendation: use system OpenSSH.** Benefits:

- battle-tested;
- supports existing `~/.ssh/config`;
- ssh-agent;
- hardware keys;
- ProxyJump;
- known-host semantics;
- familiar troubleshooting;
- native PTY behavior.

macOS and modern Linux already include it. Windows supports Microsoft OpenSSH.

**Later option: embedded Rust SSH transport.** A crate such as `russh` could remove the CLI dependency for non-interactive RPC. Drawbacks:

- key-agent compatibility work;
- more cryptographic surface in Styrn;
- more host-key and SSH-config semantics to implement;
- interactive terminal behavior becomes your responsibility.

Keep transport behind a trait so an embedded implementation can be added later:

```rust
trait Transport {
    async fn rpc(&self, host: &Host, request: Request) -> Result<Response>;
    async fn exec(&self, host: &Host, command: ExecRequest) -> Result<ExecResult>;
    async fn interactive_shell(&self, host: &Host) -> Result<()>;
}
```

**Addendum (new in rev. B):** when system OpenSSH is the transport, Styrn invokes `ssh` with an explicit, controlled option set (`-o BatchMode=yes`, an explicit `-o UserKnownHostsFile` pointing at Styrn's pinned host-key store — see Part 4.4 — and `-o IdentitiesOnly=yes` with the inventory-configured identity). Styrn must not silently inherit whatever interactive behavior the user's `~/.ssh/config` produces for non-interactive RPC channels; user SSH config is honored for `styrn shell` but overridden where it would break machine channels.

## 1.6 Why not a custom central server? (orig. §63)

You do not currently need one. A central daemon introduces:

- availability dependency;
- TLS;
- authentication;
- database;
- upgrade coordination;
- another machine that can fail.

Three or four workers are small enough for direct controller-to-worker SSH.

If you later reach dozens of machines and multiple simultaneous users, a server may make sense. Design the protocol so it can be proxied later, but do not build it now.

**Consequence made explicit (new in rev. B):** with no central server, the *worker* is the only place where fleet-wide invariants about that worker (admission, heavy-job exclusivity, quotas) can be enforced. Every design element in Part 7 follows from this: controllers hold *caches and predictions*; workers hold *authoritative state* about their own jobs. This is what makes multiple simultaneous controllers safe (resolves S-03 in principle; mechanics in Part 7.3).

## 1.7 Why not Ansible as the control plane? (orig. §64)

Ansible is useful for provisioning, but it is not a good primary agent-session control surface here. It does not replace:

- Herdr;
- persistent interactive agents;
- agent state;
- job resource admission;
- cross-platform GUI attach;
- workflow scheduler.

You could use Ansible later to supplement Linux/macOS provisioning. The bootstrap scripts are simpler initially.

## 1.8 Why Rust from the start is reasonable (orig. §65)

For this specific tool, Rust is a good fit:

- one executable;
- strong cross-platform support;
- straightforward structured serialization;
- async SSH/process orchestration;
- precise process-tree/resource handling;
- no Python environment management;
- no Node runtime;
- easy distribution as release assets;
- the project itself becomes a useful test workload for the fleet.

The main cost is slower initial implementation than a Python prototype. Given that this will become infrastructure you use continuously, the trade-off is justified.

## 1.9 Important design rule: keep Styrn generic, not abstract (orig. §66)

Good generic primitive:

```text
workflow requires os=windows and heavy_test=true
```

Bad premature abstraction:

```text
multi-tenant fairness scheduler with pluggable distributed consensus
```

Good generic primitive:

```text
resource variable resources.compile_jobs
```

Bad:

```text
Styrn automatically guesses every build system's parallelism flags
```

Let project profiles define that mapping.

## 1.10 Final shape of the recommendation (orig. §68)

Create a separate repository. Use a project-independent name. Build one Rust executable. Treat:

```text
machine
project
workflow
job
agent
harness
transport
```

as separate concepts.

Use Tailscale and OpenSSH for connectivity. Use Herdr for persistent agent terminals where its substrate is registered (Part 11.0). Use Styrn for orchestration, manifests, resource admission, structured output, and project workflow execution. Keep FriCOS-specific Rust policy in `.styrn.toml`.

The result is not a FriCOS tool that happens to manage machines. It is a general heterogeneous development/agent fleet controller that FriCOS happens to use first. That is the more durable architecture.

---

# Part 2 — Machine model

## 2.1 Roles (orig. §RM)

A Styrn machine can have either role independently, or both:

```toml
roles = ["controller"]
```

```toml
roles = ["worker"]

[installation]
scope = "user"
```

```toml
roles = ["controller", "worker"]
```

This is a foundational model, not a topology convention.

### Controller role

A controller can:

- maintain or synchronize an inventory of enrolled hosts;
- establish SSH/Tailscale connections;
- query host, job, workflow, and agent state;
- dispatch project workflows;
- control remote Herdr sessions and coding agents on substrate-registered hosts (Part 11.0);
- expose/use Styrn's MCP integration;
- enroll and remove machines subject to local authorization.

A controller is **not** automatically eligible to receive work.

### Worker role

A worker can:

- accept jobs and workflows;
- host Herdr sessions and coding agents (only where the session substrate is registered — Part 11.0);
- provide native OS/toolchain capabilities;
- create isolated Git worktrees;
- enforce RAM, disk, CPU, timeout, and cleanup policy;
- return structured job results and artifacts.

A worker is **not** automatically authorized to administer other machines.

### Both roles

A host with:

```toml
roles = ["controller", "worker"]
```

can dispatch work and also execute work.

For the initial environment, a natural configuration is:

```text
M1 MacBook Pro       controller + worker   macOS/aarch64
Mac Pro 2013         worker                Linux/x86_64
Ryzen mini-PC        worker                Windows/x86_64
HP laptop            controller + worker   Windows/x86_64   (optional controller role)
```

The MacBook can remain the preferred daily console without becoming a permanent master node.

### There is no Styrn master (orig. §RM)

Styrn is deliberately peer-capable:

```text
                  +--------------------------+
                  |  mbp-main                |
                  |  controller + worker     |
                  +------------+-------------+
                               |
                         SSH/Tailscale
                               |
        +----------------------+----------------------+
        |                      |                      |
+-------v--------+     +-------v--------+     +-------v--------+
| linux-macpro  |     | win-mini       |     | win-hp         |
| worker        |     | worker         |     | controller +   |
|               |     |                |     | worker         |
+----------------+     +----------------+     +----------------+
```

Any controller with the required inventory and credentials can operate reachable workers.

**Concurrency consequence (new in rev. B, resolves S-03):** "any controller can operate any worker" implies two controllers may act on the same worker at the same time. Revision A never said what happens then. The rule adopted here: *controllers never coordinate with each other; they only race at the worker, and the worker serializes them.* Every worker-side mutating operation (job admission, job cancel, cleanup, enrollment metadata updates) is serialized through the worker's local registry lock (Part 7.3). Controller-side inventories are caches that may briefly diverge and are reconciled by querying workers (Part 6.7). No cross-controller locking, leases, or consensus is introduced in v1 — the worker is the single point of truth for its own state, which is sufficient at this fleet size.

### Roles and capabilities are different (orig. §RM)

Roles describe what **Styrn may do from/on the host**. Capabilities describe what **work the host is technically able and permitted to execute**.

Example:

```toml
roles = ["controller", "worker"]

[controller]
enabled = true
inventory = "local"

[worker]
enabled = true
accept_jobs = true

[capabilities]
agent = true
build = true
heavy_build = true
heavy_test = true
interactive_gui = true
xcode = true
```

A powerful machine can deliberately be controller-only:

```toml
roles = ["controller"]

[controller]
enabled = true

[worker]
enabled = false
accept_jobs = false
```

Even if Rust and 64 GiB RAM are present, the scheduler must not select it. Likewise, a worker-only machine may execute jobs without possessing fleet-administration credentials.

### Scheduler eligibility (orig. §RM)

A machine is eligible for scheduling only when all of the following hold:

```text
"worker" is present in roles
AND worker.enabled == true
AND worker.accept_jobs == true
AND required capabilities match
AND dynamic resource admission succeeds
AND scheduling policy allows the host
```

Controller status has no effect on worker eligibility.

**Clarification (new in rev. B):** "dynamic resource admission succeeds" is evaluated twice with different authority: (1) *predictively* on the controller during `workflow plan`, using cached manifest + freshly queried status — this can be wrong by the time the job starts; (2) *authoritatively* on the worker at `job submit`, under the registry lock. Only (2) admits the job. A plan that predicted "pass" can still be denied at submission; the controller then retries the next candidate host or fails with exit code 6.

### CLI implications (orig. §RM)

```text
styrn machine roles
styrn machine roles --json

styrn machine role add controller
styrn machine role add worker
styrn machine role remove controller
styrn machine role remove worker

styrn fleet controllers
styrn fleet workers
styrn fleet status
```

Example:

```text
HOST            OS              ROLES                STATE
mbp-main        macOS/arm64     controller,worker    online
linux-macpro    Linux/x64       worker               online
win-mini        Windows/x64     worker               online
win-hp          Windows/x64     controller,worker    online
```

JSON output uses arrays rather than comma-separated strings:

```json
{
  "name": "mbp-main",
  "roles": ["controller", "worker"]
}
```

### Bootstrap role selection (orig. §RM)

Machine bootstrap accepts:

```text
--role controller
--role worker
--role both
```

and defaults to `worker` for headless execution nodes.

The production Rust bootstrap should write both:

```toml
roles = [...]
```

and explicit controller/worker sections so intent is unambiguous.

## 2.2 The initial fleet (orig. §5)

The currently described machines map cleanly to capabilities rather than equal cluster nodes.

```text
                         ANY CONTROLLER
                macOS / Linux / Windows
                              |
                         TAILSCALE
                              |
        +---------------------+----------------------+
        |                     |                      |
        v                     v                      v
 Linux x86_64             Windows x86_64        Windows x86_64
 Mac Pro 2013             Ryzen mini-PC         HP laptop
 Ubuntu                    native Windows        native Windows
 64 GB RAM                 16 GB RAM             32 GB RAM
 1 TB                      480 GB                larger disk
 headless                  headless              heavy worker
        |
        +---------------------------------------------+
                              |
                        future macOS workers
                    Intel or Apple Silicon
```

The M1 64 GB MacBook Pro is currently your preferred daily controller, but Styrn should not encode that assumption. It may also be enrolled as:

```toml
roles = ["controller", "worker"]
```

if you want occasional macOS-native builds or tests. Decided (D-8): it enrolls as controller+worker with `accept_jobs = true` and low scheduling priority — macOS workflows then just work with zero reconfiguration, while priority 20, the self-dispatch penalty (6.4), and interactive-session budgeting (12.9) keep daily-driver impact minimal.

## 2.3 Machine roles are capabilities, not fixed classes (orig. §6)

Do not hard-code:

```text
win-light
win-heavy
linux-heavy
```

into the scheduler. Those are useful labels, but the scheduler should act on capability metadata.

Example (mini-PC):

```toml
[capabilities]
os = "windows"
arch = "x86_64"
agent = true
build = true
heavy_build = false
heavy_test = false
interactive_gui = true
native_windows = true
```

HP:

```toml
[capabilities]
os = "windows"
arch = "x86_64"
agent = true
build = true
heavy_build = true
heavy_test = true
interactive_gui = true
native_windows = true
```

Mac Pro:

```toml
[capabilities]
os = "linux"
arch = "x86_64"
agent = true
build = true
heavy_build = true
heavy_test = true
interactive_gui = false
```

A future Mac:

```toml
[capabilities]
os = "macos"
arch = "aarch64"
agent = true
build = true
heavy_build = true
heavy_test = true
interactive_gui = true
xcode = true
```

A workflow requests capabilities:

```toml
[workflows.test-windows.requirements]
os = "windows"
heavy_test = true
```

The physical host is selected only when scheduling occurs.

**Schema note (new in rev. B):** `os` and `arch` appear both under `[platform]` and inside `[capabilities]` in revision A's examples. Canonically, `[platform]` is authoritative for `os`/`arch`; capability matching treats `os` and `arch` requirement keys as matching against `[platform]`, and all other requirement keys as matching boolean capability flags. `[capabilities]` entries must be booleans; putting `os = "windows"` inside `[capabilities]` (as some rev. A examples did) is accepted for backward compatibility during v1 but normalized to the platform fields, and the bootstrap generator writes only the boolean form.

## 2.4 Canonical machine manifest (orig. §19)

Use TOML as the canonical local file because it is easy to read and edit. Styrn should be able to render it as JSON:

```text
styrn machine manifest --json
```

Recommended locations:

- Linux user scope: `${XDG_CONFIG_HOME:-~/.config}/styrn/machine.toml`
- macOS user scope: `~/Library/Application Support/Styrn/machine.toml`
- Windows user scope: `%APPDATA%\Styrn\machine.toml`
- Linux system scope: `/etc/styrn/machine.toml`
- macOS system scope: `/Library/Application Support/Styrn/machine.toml`
- Windows system scope: `C:\ProgramData\Styrn\machine.toml`

User scope is canonical unless setup was explicitly invoked with
`--scope system`. Discovery never merges the two: an explicit CLI scope wins;
otherwise the user manifest is used when present, then the system manifest may
be read as an already-provisioned installation. Conflicting machine IDs are a
hard error, not an invitation to guess.

The manifest must contain **no private SSH keys, API keys, Tailscale auth keys, agent access tokens, or passwords**.

Example:

```toml
schema_version = 1
machine_id = "01991f5d-d72f-7b5e-a43d-9fcb61bd3265"
name = "win-mini"

roles = ["worker"]

[platform]
os = "windows"
arch = "x86_64"
hostname = "win-mini"
headless = true

[transport]
kind = "ssh"
host = "win-mini"
port = 22
user = "alex"

[worker_identity]
mode = "current-user"
principal_kind = "windows-sid"
principal_id = "S-1-5-21-111111111-222222222-333333333-1001"
name = "alex"
isolation = "shared-user"

[paths]
root = "C:\\Users\\alex\\AppData\\Local\\Styrn"
repos = "C:\\Users\\alex\\AppData\\Local\\Styrn\\repos"
jobs = "C:\\Users\\alex\\AppData\\Local\\Styrn\\jobs"
cache = "C:\\Users\\alex\\AppData\\Local\\Styrn\\cache"
artifacts = "C:\\Users\\alex\\AppData\\Local\\Styrn\\artifacts"
logs = "C:\\Users\\alex\\AppData\\Local\\Styrn\\logs"

[resources.detected]
logical_cpus = 8
memory_bytes = 17179869184
disk_bytes = 480000000000

[resources.policy]
reserved_memory_bytes = 5368709120
reserved_disk_bytes = 85899345920
reserved_cpus = 1
max_parallel_compile_jobs = 3
max_parallel_test_jobs = 3
max_heavy_jobs = 1
max_job_disk_bytes = 37580963840        # 35 GiB (new key; resolves S-28)

[capabilities]
agent = true
build = true
heavy_build = false
heavy_test = false
native_windows = true
interactive_gui = true

[tailscale]
installed = true
mode = "service"
unattended = true

[ssh]
installed = true
server = true
public_key_auth = true

[herdr]                          # optional; absent table = substrate state "none" (Part 11.0)
installed = true
enabled = true                   # operator-owned (rev. F); false = installed but not registered
session = "fleet"
autostart = "on-demand-ssh"

[agents.codex]
installed = true
sandbox = "elevated"

[agents.claude]
installed = true
sandbox = "unsupported-native-windows"
shell = "powershell"

[toolchains.rust]
installed = true
host = "x86_64-pc-windows-msvc"

[caches.sccache]
installed = true
max_bytes = 8589934592

[install]                        # rev. E; binary provenance (Part 15.14.3)
channel = "direct"
version = "0.4.0"
installed_at = "2026-09-01T10:00:00+02:00"

[desktop]
kind = "rdp"
enabled = true
```

### 2.4.1 `machine_id` minting (new in rev. B; resolves S-25)

Revision A's canonical manifest requires `machine_id`, but none of the reference bootstrap scripts generate one, and orig. §50's "bootstrap-generated manifest example" omits it entirely. The rule adopted:

- `machine_id` is a **UUIDv7**, minted exactly once per machine by `styrn machine init` (performed by `styrn setup` as one of its manifest actions, Part 15.3.2).
- If any command that reads the manifest (`styrn machine manifest`, `styrn rpc serve`, `styrn rpc hello`) finds a manifest without `machine_id`, it mints one, writes it back atomically (temp file + rename), and logs a warning. This self-heals manifests produced by the current stage-zero scripts.
- `machine_id` never changes for the life of the installation, even if `name` changes. Controllers key their manifest caches and job indexes by `machine_id` and treat a `name` that suddenly maps to a different `machine_id` as a hard error (probable host substitution — refuse and require re-enrollment).

### 2.4.2 Manifest field constraints (new in rev. B; resolves part of S-18)

- A manifest with the `worker` role requires `[transport].user` and a
  `[worker_identity]` record. `mode` is `current-user | dedicated`,
  `principal_kind` is `unix-uid | windows-sid`, `principal_id` is the stable
  numeric uid or SID, `name` is the resolved login name, and `isolation` is
  `shared-user | dedicated-account`. `transport.user` must equal
  `worker_identity.name`. Renaming or deleting that uid/SID is identity drift;
  Styrn refuses worker operation rather than silently selecting another
  account. In this greenfield v1, a worker manifest missing the record is
  invalid and the remediation is to rerun setup; there is no ambiguous
  name-only migration.
- `[installation].scope` is required and is `user | system`. It selects the
  single canonical path family and states the integrity posture; it is not
  inferred from the file's owner or location. Bare setup emits `user`.
- Exactly one of `reserved_disk_bytes` or `reserved_disk_percent` may be present in `[resources.policy]`. Both present is a validation error (`project.profile_invalid` analog for manifests: `machine.manifest_invalid`). `reserved_disk_percent` is evaluated against the *total size* of the filesystem containing `[paths].root`, computed at admission time.
- All `*_bytes` fields are non-negative integers (bytes). All `max_*` counts are positive integers.
- `[pending_actions]` (Part 15.2.4) is a list of tables and may be present in the manifest after bootstrap; `styrn host doctor` reports unresolved entries.
- `[herdr].enabled` (optional boolean, default `true`, new in rev. F) is **operator-owned** in the sense of 15.3.2: setup re-runs preserve it, exactly as they preserve `[resources.policy]`. Registration semantics — and why an absent `[herdr]` table means substrate state `none` rather than "unknown" — are in Part 11.0.2.

## 2.5 Dynamic status is not the manifest (orig. §20)

Do not rewrite the static manifest every few seconds. A status request returns ephemeral data:

```json
{
  "machine_id": "01991f5d-d72f-7b5e-a43d-9fcb61bd3265",
  "time": "2026-09-01T08:30:00+02:00",
  "cpu": {
    "logical": 8,
    "load_percent": 17.4
  },
  "memory": {
    "total_bytes": 17179869184,
    "available_bytes": 11100000000
  },
  "disk": {
    "root": "C:\\Styrn",
    "free_bytes": 124000000000
  },
  "jobs": {
    "running": 1,
    "heavy_running": 0
  },
  "substrate": {
    "kind": "herdr",
    "state": "active",
    "session": "fleet"
  }
}
```

`substrate` (new in rev. F; Part 11.0.3) is ephemeral like everything else here and is **never** written to the manifest — the manifest records *registration*, status reports *liveness*. On a host with no session substrate it is `{"kind": null, "state": "none", "session": null}`. The field is an additive envelope change (2.8.5); an older controller must ignore it.

Controller scheduling uses:

```text
static capabilities
+
dynamic resource status
+
project requirements
```

**Clock-skew note (new in rev. B; resolves S-24):** status timestamps come from each worker's own clock. Styrn compares timestamps across machines only for display and coarse staleness checks (minutes), never for ordering decisions. Machines are assumed NTP-synchronized (Tailscale-connected machines in practice are); `styrn host doctor` warns when a worker's reported time differs from the controller's by more than 30 seconds.

## 2.6 Controller inventory (orig. §21)

Each controller maintains a local inventory. Suggested path:

```text
~/.config/styrn/inventory.toml
```

Windows:

```text
%APPDATA%\Styrn\inventory.toml
```

Example:

```toml
schema_version = 1

[[hosts]]
name = "linux-macpro"
machine_id = "01991f60-1111-7abc-9def-0123456789ab"   # recorded at enrollment (new in rev. B)
manifest_cache = "manifests/linux-macpro.toml"

[hosts.transport]
kind = "ssh"
host = "linux-macpro"
user = "buildbot"
port = 22
identity = "~/.ssh/styrn_ed25519"

[[hosts]]
name = "win-mini"
machine_id = "01991f5d-d72f-7b5e-a43d-9fcb61bd3265"
manifest_cache = "manifests/win-mini.toml"

[hosts.transport]
kind = "ssh"
host = "win-mini"
user = "alex"
port = 22
identity = "~/.ssh/styrn_ed25519"
```

The identity path is controller-local and never copied into a worker manifest.

**Per-controller identities (new in rev. B; resolves part of S-05):** the example above shows one `styrn_ed25519` key. The recommended practice is one keypair **per controller machine** (e.g. `styrn_mbp-main_ed25519`, `styrn_win-hp_ed25519`), each authorized on the workers, so that losing one controller means revoking one line from each worker's `authorized_keys` rather than rotating a shared key everywhere. See Part 4.3.

## 2.7 Per-machine manifests for the initial fleet (orig. §50–§53)

### Bootstrap-generated manifest for the mini-PC (orig. §50)

```toml
schema_version = 1
machine_id = "<minted by styrn machine init>"   # rev. B: required; see 2.4.1
name = "win-mini"
roles = ["worker"]

[platform]
os = "windows"
arch = "x86_64"
headless = true

[transport]
kind = "ssh"
host = "win-mini"
port = 22
user = "alex"

[worker_identity]
mode = "current-user"
principal_kind = "windows-sid"
principal_id = "S-1-5-21-111111111-222222222-333333333-1001"
name = "alex"
isolation = "shared-user"

[resources.policy]
reserved_memory_bytes = 5368709120
reserved_disk_bytes = 85899345920
reserved_cpus = 1
max_parallel_compile_jobs = 3
max_parallel_test_jobs = 3
max_heavy_jobs = 1
max_job_disk_bytes = 37580963840

[capabilities]
agent = true
build = true
heavy_build = false
heavy_test = false
native_windows = true
interactive_gui = true
```

### HP manifest differences (orig. §51)

```toml
name = "win-hp"

[resources.policy]
reserved_memory_bytes = 8589934592
reserved_disk_percent = 15
max_parallel_compile_jobs = 8
max_parallel_test_jobs = 8
max_heavy_jobs = 1
max_job_disk_bytes = 107374182400       # 100 GiB

[capabilities]
heavy_build = true
heavy_test = true
```

Actual CPU-derived maximums should be detected and the scheduler may lower these values.

### Mac Pro manifest differences (orig. §52)

```toml
name = "linux-macpro"

[platform]
os = "linux"
arch = "x86_64"
headless = true

[resources.policy]
reserved_memory_bytes = 12884901888
reserved_disk_bytes = 161061273600
max_parallel_compile_jobs = 10
max_parallel_test_jobs = 10
max_heavy_jobs = 1
max_job_disk_bytes = 161061273600       # 150 GiB

[capabilities]
heavy_build = true
heavy_test = true
interactive_gui = false

[admin]
kind = "cockpit"
url = "https://linux-macpro:9090"
```

### M1 MacBook manifest (orig. §53)

The MacBook can be both controller and worker:

```toml
name = "mbp-main"
roles = ["controller", "worker"]

[platform]
os = "macos"
arch = "aarch64"
headless = false

[capabilities]
agent = true
build = true
heavy_build = true
heavy_test = true
interactive_gui = true
xcode = true
```

You can leave scheduler priority low so it is used only when a workflow specifically requires macOS:

```toml
[scheduling]
priority = 20
prefer_remote_workers = true
```

**Semantics defined (new in rev. B; the original never defined the scale):** `[scheduling].priority` is an integer 0–100, default 50, **higher = more preferred**. `20` therefore deprioritizes the MacBook relative to default workers, matching the original intent ("used only when a workflow specifically requires macOS"). `prefer_remote_workers = true` means: when this machine is acting as the controller for a dispatch and is itself a capability-eligible worker, other eligible workers win ties. Full scheduling algorithm in Part 6.4.

The `machine.roles.example.toml` companion file was removed with the original design (§0.2); the manifest shape it demonstrated is specified in full above and remains valid under this revision, with the addition of `machine_id` handling per 2.4.1. It has been **recreated** at `examples/machine.toml` (worker) and `examples/machine.controller-worker.toml` (both roles), from this section; both validate against `schemas/machine-v1.schema.json`.

## 2.8 Schema and version compatibility policy (new in rev. B; resolves S-15; extends orig. §2.7, §2.10, §57)

Revision A introduced four independently versioned surfaces without a compatibility policy. The policy adopted:

There are four versioned schemas plus the wire protocol:

| Surface | Version field | Current |
|---|---|---|
| Machine manifest | `schema_version` in `machine.toml` | 1 |
| Project profile | `schema_version` in `.styrn.toml` | 1 |
| Command envelope | `"schema": "styrn.command.v1"` | v1 |
| Event/stream lines | `"schema": "styrn.event.v1"` | v1 |
| RPC protocol | negotiated integer (Part 5.2) | 1 |

Rules:

1. **Within a schema version, additions are compatible.** Readers MUST ignore unknown fields/keys ("must-ignore"). Adding an optional field, key, warning, or error code does not bump the version.
2. **Removals, renames, and semantic changes bump the version.** A reader encountering a schema version it does not support fails with exit code 8 and error code `protocol.incompatible`, naming both versions in the error details.
3. **Support window:** each Styrn release must read schema version N (current) and N−1 for manifests and project profiles, must speak protocol N and N−1, and must read command-envelope/event-schema version N and N−1 (the envelope's window was previously unstated — rev. E; review D §4.9). This gives a one-step upgrade path with mixed controller/worker versions, which `styrn fleet versions` (Part 6.6) surfaces. **The window is load-bearing, not speculative (rev. E):** binary upgrades are owned by per-platform package channels (Part 15.14), which are inherently non-atomic across a fleet — machines upgrade when their operator gets to them — so mixed controller/worker versions are the *expected steady state* between upgrade rounds, not an edge case. A controller meeting a worker outside the window refuses with exit 8 / `protocol.incompatible`, and the message names the exact upgrade command for that worker's platform (from the cached manifest's `[install]` record, 15.14).
4. `minimum_styrn_version` in `.styrn.toml` is enforced by whichever binary loads the profile (controller at plan time, worker at execution time): if the running binary is older, fail with exit 8 / `protocol.incompatible` before doing anything.
5. Error **codes** (Part 10.3) and exit codes are append-only within envelope v1; renaming or removing one requires `styrn.command.v2`.
6. **Binding point (rev. E):** the windows above, 10.3's append-only rule, and the §0.4 frozen vocabulary become binding at the **first tagged release**; before it there is nothing to be compatible with, and everything may change freely.
7. Controllers cache worker manifests; the cache records the manifest `schema_version` and the worker's `styrn_version` from the last hello. `styrn host refresh` re-fetches; `styrn host doctor` warns when the cache is older than 7 days or the worker's reported version has changed since caching (staleness policy — resolves S-26).

---

# Part 3 — Network architecture and transport

## 3.1 Tailscale (orig. §7)

Use Tailscale for private connectivity and MagicDNS for names. Example names:

```text
mbp-main
linux-macpro
win-mini
win-hp
mac-build-01
```

Styrn inventory should use the MagicDNS hostname rather than a mutable LAN IP.

### Tailscale grants (orig. §7)

For new policies, Tailscale recommends grants rather than legacy ACLs *(recorded from rev. A's research pass of 2026-09-01 — verify against current upstream docs)*.

A minimal conceptual policy is:

```json
{
  "tagOwners": {
    "tag:styrn-controller": ["autogroup:admin"],
    "tag:styrn-worker": ["autogroup:admin"]
  },
  "grants": [
    {
      "src": ["tag:styrn-controller"],
      "dst": ["tag:styrn-worker"],
      "ip": ["tcp:22"]
    }
  ]
}
```

Add RDP only if needed:

```json
{
  "src": ["tag:styrn-controller"],
  "dst": ["tag:styrn-worker"],
  "ip": ["tcp:3389"]
}
```

Add Cockpit:

```json
{
  "src": ["tag:styrn-controller"],
  "dst": ["tag:styrn-worker"],
  "ip": ["tcp:9090"]
}
```

Prefer a controller tag only if controllers are trusted machines. A personal tailnet can also use user selectors rather than device tags.

**Companion-file correction (new in rev. B; part of S-18):** `tailscale-grants.example.json` currently grants `tcp:3389` and `tcp:9090` to *all* workers unconditionally in a single combined grant, contradicting the "add only if needed" guidance above (RDP is meaningless on the Linux worker and Cockpit is meaningless on the Windows workers). The example should ship with only the `tcp:22` grant active and the RDP/Cockpit grants present but commented as optional per-destination additions.

## 3.2 Tailscale behavior by OS (orig. §8)

### Linux

Tailscale normally runs as a system service and remains available without a logged-in user. This is ideal for the headless Mac Pro.

### Windows

Enable unattended mode:

```powershell
tailscale up --unattended=true
```

This allows Tailscale to operate as a system service even after logout/reboot.

### macOS

This needs explicit design. The ordinary GUI variants do not behave like Windows unattended mode. Tailscale documents a CLI-only open-source `tailscaled` variant that can run before login under `launchd` *(verify against current upstream docs)*.

Therefore Styrn should model two macOS network modes:

```toml
[tailscale]
mode = "gui"
unattended = false
```

or:

```toml
[tailscale]
mode = "tailscaled"
unattended = true
```

For your actively used MacBook, the normal standalone Tailscale application is reasonable. For a truly headless Mac worker, prefer the CLI `tailscaled` variant and make `styrn doctor` warn if a machine is marked `headless=true` but Tailscale cannot run before login.

## 3.3 SSH is the universal management path (orig. §9)

Use ordinary OpenSSH transported over Tailscale.

Why not standardize on Tailscale SSH? Because native Windows is an important target and Tailscale's SSH-server behavior is not equivalent across every platform *(verify against current upstream docs)*. Normal OpenSSH gives you one protocol everywhere.

- **Windows:** use Microsoft's OpenSSH Server optional component and make `sshd` automatic.
- **Linux:** use normal `openssh-server`.
- **macOS:** enable Remote Login.

For all workers, prefer:

- public-key authentication;
- the invoking account for the frictionless default, or an explicitly chosen
  dedicated account when OS-account isolation is wanted;
- no public router port forwarding;
- Tailscale-only network reachability;
- no shared personal SSH private keys stored on workers.

**Hardening addendum (new in rev. B; amended rev. G):** bootstrap should
additionally set, on workers, `PasswordAuthentication no` (or the Windows
sshd_config equivalent) once key auth is verified working. On a dedicated
worker it may restrict `AllowUsers` to the safely rendered selected principal,
while preserving unrelated sshd configuration and existing users. It never
writes a literal username or narrows a shared current-user machine globally.

## 3.4 Remote GUI / headless control (orig. §17)

A headless system must be operable even when no physical display is connected.

### Linux

Primary:

```text
SSH
Herdr
Styrn
```

Optional browser administration:

```text
Cockpit :9090
```

Do not install a desktop environment merely for administration.

### Windows

Primary:

```text
SSH
Herdr
PowerShell
Styrn
```

Optional GUI:

```text
RDP
```

Styrn can expose:

```text
styrn desktop open win-hp
```

The local implementation is platform-specific:

- macOS: open a configured RDP client;
- Windows: `mstsc`;
- Linux: configured RDP client.

Do not make RDP a requirement for normal build and agent control.

### macOS

Primary:

```text
SSH
Herdr
Styrn
```

Optional GUI:

- Screen Sharing;
- Remote Management / Apple Remote Desktop;
- VNC-compatible clients if configured.

Apple documents that Screen Sharing and Remote Management cannot both be active simultaneously *(verify against current upstream docs)*.

Also, modern macOS does not allow fully reliable command-line enablement of Screen Sharing/Remote Management in all cases without MDM/user consent. Bootstrap should report this as a `pending_action` rather than falsely report success. Example:

```toml
[[pending_actions]]
id = "macos-screen-sharing"
severity = "info"
message = "Enable Screen Sharing for the selected worker user in System Settings > General > Sharing."
```

## 3.5 Hard recovery for headless systems (orig. §18)

SSH is not out-of-band management. Neither are:

- Tailscale;
- Herdr;
- Cockpit;
- RDP;
- Screen Sharing.

If the OS kernel hangs, they all disappear.

The Mac Pro and consumer mini-PC do not have server BMC/IPMI/iLO/iDRAC. For machines that must be recoverable without walking to them, add:

```text
remotely controlled smart plug / PDU
```

and configure firmware to power on after AC loss.

Styrn can later define a power-provider interface:

```rust
trait PowerProvider {
    async fn power_on(&self);
    async fn power_off(&self);
    async fn power_cycle(&self);
}
```

Do not put smart-plug credentials into the public machine manifest. Decided (D-4): select plugs/PDUs by the criterion *local-network API, no cloud round-trip*; credentials and endpoints live in a controller-only `~/.config/styrn/power.toml` (mode 0600) — schema and rationale in D-4.

---

# Part 4 — Security and trust model

## 4.1 Worker identity and filesystem root (orig. §10; amended rev. G)

Styrn resolves one explicit worker identity per machine. The default is the
current user and requires no account creation. A dedicated unprivileged account
is optional hardening for machines that execute untrusted jobs; its suggested,
not required, name is `styrn`. A configured dedicated identity must not be an
administrator/root account. The resolved principal, rather than a literal user
name, is passed to every native ownership and ACL operation.

The default **user-scope** roots require no privilege:

| OS | Root |
|---|---|
| Linux | `${XDG_DATA_HOME:-~/.local/share}/styrn/` |
| macOS | `~/Library/Application Support/Styrn/` |
| Windows | `%LOCALAPPDATA%\Styrn\` |

The layouts below are the optional **system-scope** roots. Dedicated identity
mode implies system scope. Both scopes contain the same
`repos/jobs/cache/artifacts/logs` children, so generic job code never depends on
which scope selected the root.

Linux filesystem:

```text
/srv/styrn/
├── repos/
├── jobs/
├── cache/
├── artifacts/
└── logs/
```

Windows:

```text
C:\Styrn\
├── repos\
├── jobs\
├── cache\
├── artifacts\
└── logs\
```

macOS:

```text
/Users/Shared/Styrn/
├── repos/
├── jobs/
├── cache/
├── artifacts/
└── logs/
```

The worker identity should not normally have administrator/root privileges.
User scope runs entirely as that identity. System provisioning is a separate,
operator-selected administrator operation; agent execution is never elevated.
Current-user mode may use an administrator-capable interactive user, but jobs do
not request elevation and Styrn reports that this mode provides no OS-account or
same-user state-integrity separation from that user's files or credentials.

## 4.2 What may be stored where (orig. §41)

### Workers

Do not store:

- personal SSH private keys;
- unrelated GitHub tokens;
- browser profiles;
- personal documents;
- administrator credentials;
- Tailscale reusable auth keys.

**Clarified (new in rev. B; resolves S-02's policy half):** the default posture is *zero git-remote credentials on workers* — source arrives by controller push (Part 8.2). Where a project explicitly opts in (`[source.auth] mode = "deploy-key"`, Part 8.2.3), a worker may hold a **project-scoped, read-only deploy key** under the resolved worker profile. Such a key is not a "personal" credential and does not violate this list; it must never be an account-wide personal token.

### Controller

The controller may hold:

- SSH private key(s) for worker access (per-controller keypair, Part 4.3);
- host inventory;
- optional power provider credentials.

### Remote execution

Every job is restricted to:

```text
job workspace
job target
project cache
explicit project dependencies
```

**Honesty note (new in rev. B; amended rev. G):** on Linux/macOS/Windows without additional sandboxing, this restriction is enforced by convention (per-job directories plus the selected identity's permissions), not by a kernel mechanism. A hostile job can read anything that identity can read. Dedicated mode is therefore intended to hold no personal credentials or data; current-user mode explicitly gives up that separation. See 4.5.

### Native Windows Claude (orig. §41)

Because native Windows Claude sandboxing is not currently available *(rev. A research claim — verify against current upstream docs)*, the dedicated Windows account is particularly important.

### Codex Windows

Prefer the native elevated sandbox.

### Linux/macOS Claude

Enable sandboxing where it is compatible with the project.

## 4.3 SSH key lifecycle (new in rev. B; resolves S-05)

Revision A distributed one key (`styrn_ed25519`) in every bootstrap example and never discussed rotation or revocation. Adopted policy:

1. **One keypair per controller machine, generated lazily (rev. C; S-30, tenet §0.6).** The first Styrn command that needs to connect and finds no configured identity generates `~/.ssh/styrn_<controller-name>_ed25519` automatically (equivalent to `ssh-keygen -t ed25519 -C styrn-<controller-name>`), prints the public key, and says exactly how to authorize it (`styrn setup --authorized-keys` on the worker, or `styrn host authorize-key` from an already-authorized controller). No separate init ceremony is required; `styrn controller init` exists only as an explicit way to pre-generate.
2. **Authorization follows installation scope.** In default user scope, Styrn
   idempotently updates the selected user's ordinary OpenSSH authorized-key file
   with one recognizable line per controller (`styrn-mbp-main`,
   `styrn-win-hp`). It is user-owned and is explicitly not protected from
   same-user code. In system scope, Styrn configures the protected
   account-specific `AuthorizedKeysFile` described in 15.7.1, outside the
   worker-writable profile. Options `restrict,pty` may be added later; v1 keeps
   plain entries because `styrn shell` and Herdr attach need a PTY and command
   flexibility.
3. **Authorizing a new controller** is an idempotent update performed either during setup (`[ssh] authorized_keys` or `--authorized-keys`) or later via an existing controller. It needs no elevation in user scope; protected system scope requires the operator to run an already-elevated command.
4. **Revocation:** `styrn host revoke-key <host> --controller <name>` removes the matching line from the scope-selected worker key file. When a controller machine is lost or compromised, run this against every worker from any surviving controller; because keys are per-controller, no other controller is disturbed. Tailscale device removal for the lost machine is the complementary first step.
5. **Rotation** is revoke + authorize with a fresh keypair; no shared-secret ceremony exists to coordinate.
6. Private keys should be held in the OS keychain/agent where practical (`ssh-agent` on all three platforms; macOS keychain integration; Windows OpenSSH agent service). Styrn never reads private key files itself in v1 — it delegates to `ssh`.

## 4.4 Host-key trust: pin at enrollment (new in rev. B; resolves S-05's TOFU half)

Revision A relied implicitly on OpenSSH `known_hosts` behavior. Made explicit:

1. On `styrn host enroll`, the first connection is trust-on-first-use, surfaced honestly: Styrn displays the worker's host-key fingerprint and requires interactive confirmation (or `--fingerprint <sha256:...>` for scripted enrollment, matched against a fingerprint the operator obtained out of band — printed by `styrn setup` on the worker's console as part of the enrollment card, Part 15.10).
2. On confirmation, the host key is recorded in a Styrn-managed known-hosts file: `~/.config/styrn/known_hosts` (`%APPDATA%\Styrn\known_hosts` on Windows). All subsequent non-interactive connections run with `-o UserKnownHostsFile=<that file> -o StrictHostKeyChecking=yes`.
3. A changed host key is a hard failure (exit 4, `transport.auth_failed`) with remediation text: verify the machine (reinstall? substitution?), then `styrn host trust <host> --fingerprint ...` to re-pin deliberately. Never auto-accept a changed key.
4. Tailscale provides the outer authentication layer (only tailnet devices can reach port 22 at all); host-key pinning is the second, independent layer. The design does not treat the tailnet as sufficient on its own.

## 4.5 What is and is not a security boundary (new in rev. B; resolves S-06; extends orig. §93)

Revision A's language implied two protections that do not hold as stated. This section replaces them with an honest model. The detailed consequences for MCP and workflows are in Parts 9.5 and 13.

**Claim 1 (rev. A, implicit in §81–§87): "agents can only run declared workflows."**
Not true as a security property. Workflow commands come from `.styrn.toml` **inside the repository the agent is editing**. An agent (or any commit author) can modify `.styrn.toml` on its branch to make an innocently named workflow run arbitrary commands, then request that workflow at its own revision. Since validation jobs intentionally execute the profile *at the requested revision* (Part 8.3), the declared-workflow vocabulary constrains *honest* agents' ergonomics, not hostile ones.

**Claim 2 (rev. A, §82): MCP prevents the harness from bypassing policy.**
Only when the harness has no other capabilities. A coding agent with shell access on a machine that holds controller credentials (the daily MacBook is exactly this) can ignore MCP and run `styrn` CLI commands or raw `ssh` itself. MCP tool narrowing is real and valuable — it shapes what a *well-behaved* agent does, keeps topology and credentials out of the agent's context, and gives approval UIs a meaningful vocabulary — but it is **least-privilege ergonomics, not containment**.

**The actual security boundaries, in order of strength:**

```text
1. Tailscale reachability            who can open a TCP connection at all
2. SSH key possession                which machines can authenticate as the selected worker
3. OS account separation             what a dedicated worker can read/write/damage
4. Credential placement              dedicated workers hold none; current-user inherits its user
5. Harness sandbox (where available) what a local agent process can touch
6. Worker-side enforcement           quotas, timeouts, admission — bounds resource damage
7. MCP surface + approvals           least-privilege vocabulary for honest agents
8. AGENTS.md / CLAUDE.md             guidance only (orig. §93)
```

**Design consequences adopted:**

- A job on a worker is treated as **untrusted code running as the selected worker identity**. In default user scope, the manifest, receipt, registry, locks, and authorization files are user-owned: atomic validation detects accidents and corruption but cannot prevent deliberate same-user tampering. Styrn never calls those files a security boundary. In explicit system scope, machine state is root/Administrators-owned and readable but not writable by the unprivileged worker token.
- In current-user mode, a hostile job has that user's ambient filesystem, credentials, and user-scoped Styrn state access. Styrn must state this limitation in the setup plan, manifest security posture, and doctor output; it must never describe current-user mode as credential or policy isolation. Harness sandboxes, admission, quotas, and timeouts still apply where the harness actually enforces them.
- The worker-side Styrn RPC endpoint and jobs use the same selected identity, so a hostile job could tamper with job state files of other jobs owned by that identity. v1 accepts this within a single worker identity (single-tenant fleet, one human operator); a later hardening step is per-job OS users on Linux/macOS.
- Machines where credentialed controllers run agents under current-user mode (the MacBook is the obvious case) rely on harness sandboxing, worker-side enforcement, and operator review. If that is unacceptable, use a dedicated worker identity on that host or dispatch to a dedicated-identity worker.
- Optional hardening for the workflow-tampering vector (controller-pinned profile hashes or a controller-side workflow allowlist) is specified as an opt-in in Part 9.5 and is default-off (decided in D-5).

## 4.6 Secrets storage summary (new in rev. B; part of S-19)

| Secret | Location | Notes |
|---|---|---|
| Controller SSH private keys | controller `~/.ssh` / OS agent or keychain | never in inventory or fleet-config repo |
| Worker host-key pins | controller `~/.config/styrn/known_hosts` | shareable, not secret (public keys) |
| Tailscale node identity | managed by Tailscale itself | never a reusable auth key on workers |
| `TS_AUTHKEY` for setup | operator's shell env at setup time only | one-shot pre-approved keys preferred; never persisted (15.7.2) |
| Optional deploy keys (opt-in) | selected worker profile `.ssh`, per project | read-only scope, revocable at the forge |
| Power-provider credentials | controller-only `power.toml`, mode 0600 (D-4) | never in machine manifest (orig. §18) |
| Agent-harness logins (Codex/Claude) | per-user harness config on each machine | interactive first-login; surfaced as pending_actions |

Styrn v1 deliberately has **no secret-distribution mechanism**: no command copies a secret from one machine to another. Anything that looks like that need (e.g. per-job tokens) is out of scope until a real requirement appears.

---

# Part 5 — The Styrn RPC protocol (new in rev. B; resolves S-04; supersedes the orig. §2.10 handshake)

Revision A committed to "a versioned JSON protocol over stdin/stdout" (orig. §3) and a one-blob handshake (orig. §2.10), with streaming events asserted in orig. §79 and artifact reads in orig. §120 — but specified no framing, no multiplexing, no negotiation policy, and no binary transfer. This Part is the missing specification. It is deliberately minimal: NDJSON, correlation IDs, and four stream kinds.

## 5.1 Transport and framing

- The controller runs `ssh <worker-user>@<host> styrn rpc serve --stdio`, with the enrolled worker user supplied as a separate SSH destination field rather than interpolated into a shell command. The fixed `styrn rpc serve --stdio` remote command is the *only* command string that crosses the login shell; it contains no user data and is quoting-safe on sh, PowerShell, and cmd. Everything else travels inside the protocol. (This is the keystone of the Windows quoting answer — see Part 7.10.)
- The protocol is **newline-delimited JSON (NDJSON)**: one JSON object per line, UTF-8, `\n` terminated, no pretty-printing. A frame may not exceed **4 MiB** serialized; larger payloads must be chunked (5.6).
- stdin of `styrn rpc serve` carries controller→worker frames; stdout carries worker→controller frames; **stderr of the RPC process is reserved for human-readable diagnostics and is never parsed**.
- Every frame has:

```json
{ "id": "c1", "type": "request", "...": "..." }
```

  - `id` — correlation string chosen by the sender of a `request` (controller-chosen ids are prefixed `c`, worker-initiated ids `w`, to prevent collisions). All frames belonging to one logical operation share its `id`.
  - `type` — one of `hello`, `request`, `response`, `event`, `log`, `chunk`, `cancel`, `ping`, `pong`, `error`.

## 5.2 Hello and version negotiation

The **server (worker side) speaks first**, immediately on start:

```json
{ "id": "hello", "type": "hello",
  "protocol_min": 1, "protocol_max": 1,
  "styrn_version": "0.4.0",
  "machine_id": "01991f5d-d72f-7b5e-a43d-9fcb61bd3265",
  "name": "win-mini",
  "manifest_schema_version": 1 }
```

The controller replies with its selection:

```json
{ "id": "hello", "type": "hello",
  "protocol": 1,
  "styrn_version": "0.5.0" }
```

Rules:

1. The controller picks the highest protocol in the intersection of its own supported range and `[protocol_min, protocol_max]`. If the intersection is empty, it sends an `error` frame with code `protocol.incompatible` (naming both ranges), closes stdin, and exits 8. The worker, seeing EOF before a controller hello, exits quietly.
2. Per Part 2.8, every release supports protocol N and N−1, so any two releases at most one protocol step apart interoperate.
3. `machine_id` in the hello is how enrollment (Part 6.1) verifies it is talking to the machine it thinks it is, and how the substitution check in 2.4.1 fires.
4. No other frame may precede the hello exchange in either direction.

## 5.3 Requests and responses

```json
{ "id": "c42", "type": "request", "method": "job.submit", "params": { } }
```

```json
{ "id": "c42", "type": "response", "ok": true, "data": { } }
```

```json
{ "id": "c42", "type": "response", "ok": false,
  "errors": [ { "code": "resource.disk_admission_denied", "message": "...", "details": { } } ] }
```

- Methods are dot-namespaced strings mirroring the CLI: `machine.manifest`, `machine.status`, `job.submit`, `job.get`, `job.list`, `job.cancel`, `job.logs`, `job.artifact.read`, `agent.list`, `agent.start`, `agent.read`, `agent.prompt`, `agent.wait`, `agent.stop`, `exec.run`, `clean.plan`, `clean.run`, `cache.status`, `cache.trim`, `repo.ensure`, `events.subscribe`, `host.authorize_key`, `host.revoke_key`.
- Requests are **concurrent**: a controller may issue new requests while others are outstanding; responses correlate by `id`. Workers process cheap queries concurrently but serialize mutating job-registry operations internally (Part 7.3).
- Errors use the same `{code, message, details}` shape as the CLI envelope (Part 10.2); the error-code registry (Part 10.3) is shared between CLI and RPC.

## 5.4 Streaming: `event` and `log` frames

A request whose result is a stream (e.g. `events.subscribe`, `job.logs` with `follow: true`, `exec.run` with streaming output) is answered by zero or more `event`/`log` frames carrying the request's `id`, followed by a terminal `response`:

```json
{ "id": "c7", "type": "log", "stream": "stdout", "text": "Compiling fricos-core v0.3.1\n", "ts": "2026-09-01T09:12:03+02:00" }
```

```json
{ "id": "c9", "type": "event", "schema": "styrn.event.v1",
  "kind": "agent.state_changed", "host": "win-mini",
  "agent": "fs-fix", "from": "working", "to": "blocked",
  "ts": "2026-09-01T09:14:41+02:00" }
```

- `log` frames preserve the stdout/stderr distinction via `stream`. Text is UTF-8 with lossy replacement for invalid bytes; raw bytes are always additionally on disk in the job directory (Part 7.7), so the stream is a convenience view, not the record.
- `event` frames use `styrn.event.v1`, the same line schema the CLI emits for `--jsonl` (Part 10.1), so `styrn monitor --jsonl` is a thin pass-through.
- Streams end with a normal `response` (`ok` + summary data) or an `error`-carrying response.

## 5.5 Cancellation and liveness

- `{ "id": "c7", "type": "cancel" }` asks the worker to abort the operation with that id. Cancelling `job.logs` stops the stream; cancelling `job.submit` before admission aborts it; cancelling an already-running job is *not* done via frame-cancel — it is a separate `job.cancel` request against the job id, because the job outlives any RPC session (Part 7.8).
- `ping`/`pong` frames (either direction, `id` echoed) provide liveness on top of SSH keepalives. The controller sends a ping after 30 s of silence; two missed pongs → treat the session as lost, exit 3 for interactive commands. Session loss **never** affects running jobs (Part 7.8) or Herdr-owned agents.

## 5.6 Chunked binary transfer

Artifact reads and any payload over the 4 MiB frame limit use `chunk` frames:

```json
{ "id": "c11", "type": "chunk", "seq": 0, "data": "<base64>", "eof": false }
```

- `seq` starts at 0 and increments; `eof: true` marks the final chunk (which may carry empty `data`).
- Chunk payloads are ≤ 1 MiB of raw bytes before base64. The terminal `response` carries `{ "bytes_total": n, "sha256": "..." }` so the receiver can verify integrity.
- This is knowingly base64-inefficient (+33%). Over a LAN/Tailscale link moving logs and result files, that is acceptable in v1; a side-channel (SFTP/scp) can be added behind the `Transport` trait later without protocol changes. Artifact size limits and retention are in Part 7.7 (defaults final per D-7).

## 5.7 `styrn rpc events --stdio` (orig. §79 mechanism)

Event subscription may run over the main RPC session (`events.subscribe`) or as a dedicated long-lived session per host, which is what `styrn monitor` maintains:

```text
controller
  |
  +--- ssh host1 styrn rpc serve --stdio   (events.subscribe)
  |
  +--- ssh host2 styrn rpc serve --stdio   (events.subscribe)
  |
  +--- ssh host3 styrn rpc serve --stdio   (events.subscribe)
```

The remote Styrn process subscribes to its own job registry unconditionally, and **additionally** to its local Herdr socket (Unix domain socket on Linux/macOS, named pipe on Windows) **when the host's session substrate is registered** (Part 11.0): an `active` substrate is subscribed immediately, and a `registered` substrate whose session is down is retried on the same backoff as a dropped subscription, so agent events begin flowing when the session comes up. On a substrate-`none` host the stream simply carries job and host events only — normal operation, not a warning, and `styrn monitor --notify` (14.1) consequently emits agent-transition notifications only from hosts that have a substrate, with no configuration needed. It converts everything into `styrn.event.v1` frames. Only the remote Styrn binary needs to know the platform difference (orig. §79). Dropped event sessions are reconnected by the controller with backoff; events during the gap are lost (v1 accepts at-most-once event delivery for *notifications*; authoritative state is always re-queryable).

---

# Part 6 — Enrollment, scheduling, and fleet operations

## 6.1 Enrollment workflow (orig. §22, revised)

Bootstrap a worker. Then, from any controller:

```text
styrn host enroll win-mini --user alex
```

Implementation (revised order; host-key and identity steps new in rev. B — resolves S-05):

```text
1. resolve MagicDNS name; establish SSH
2. TOFU host-key confirmation (or --fingerprint); pin key         [Part 4.4]
3. execute: styrn rpc serve --stdio; receive hello                [Part 5.2]
4. validate protocol compatibility; record machine_id
5. request machine.manifest; validate schema
6. save manifest cache (keyed by machine_id)
7. run doctor
8. add host to inventory
```

Example output:

```text
Enrolled win-mini
  OS          windows/x86_64
  RAM         16.0 GiB
  disk        447 GiB
  Herdr       installed
  Codex       installed
  Claude      installed
  Rust        installed
  heavy-test  no

Pending:
  Codex first login
  Claude first login
```

Machine output:

```text
styrn host enroll win-mini --user alex --json
```

returns one stable JSON object (standard envelope).

**Friction note (rev. C, tenet §0.6; amended rev. G):** enrollment has no
implicit SSH username. The operator supplies the hostname and selected
transport user, plus a fingerprint confirmation; `port = 22` remains the only
transport default. Setup discovers the user and prints all three facts in the
enrollment card, so normal enrollment is still one paste rather than a memory
test. The returned manifest must bind `transport.user` to the same stable
`worker_identity`; a mismatch aborts before inventory is written. If no
controller identity exists yet, enrollment triggers lazy key generation
(4.3.1) instead of failing. Enrollment remains controller-initiated (S-36).

## 6.2 `styrn host remove` semantics (new in rev. B; part of S-05)

Revision A listed the command (orig. §25) without semantics. Defined:

- `styrn host remove <host>` removes the host from **this controller's inventory and caches only**. It does not touch the worker, does not revoke keys, and does not affect running jobs. Output states this explicitly.
- `styrn host remove <host> --revoke` additionally connects first and removes *this controller's* key line from the worker's protected authorized-key file (self-deauthorization). Refused if there are jobs on that worker owned/submitted by this controller unless `--force`.
- Removing a **lost or compromised** machine is the reverse direction and is documented procedure, not a single command: remove the device from the tailnet, then `styrn host revoke-key <worker> --controller <lost>` on each worker (Part 4.3.4).
- Running jobs on a removed host keep running (the worker owns them); they simply stop being visible from this controller until re-enrollment.

## 6.3 Controller selection is symmetric (orig. §54)

Any enrolled machine with:

```toml
roles = ["controller"]
```

or:

```toml
roles = ["controller", "worker"]
```

can hold an inventory and control the rest. There is no authoritative Mac-specific control plane.

From Windows:

```powershell
styrn fleet status --json
styrn shell linux-macpro
styrn agent list --all
```

From Linux:

```bash
styrn workflow run fricos test-windows
```

From macOS:

```bash
styrn agent start win-mini --harness codex --project fricos --name fs-fix
```

## 6.4 Scheduling preferences and the selection algorithm (orig. §55, §53; algorithm new in rev. B)

Capability is mandatory. Preference is optional.

Example inventory policy:

```toml
[scheduler]
prefer_idle = true
prefer_remote_workers = true

[[scheduler.preference]]
match.os = "windows"
match.heavy_test = true
host = "win-hp"
weight = 100

[[scheduler.preference]]
match.os = "windows"
host = "win-mini"
weight = 50
```

A workflow requiring heavy Windows validation never runs on `win-mini` because capability is false.

**Selection algorithm (new in rev. B):**

```text
1. candidates = enrolled hosts where scheduler eligibility (Part 2.1) holds
                and workflow requirements match (os/arch vs [platform],
                boolean flags vs [capabilities])
2. drop candidates whose latest status query fails (unreachable)
3. drop candidates whose predictive admission fails (Part 7.2, using
   fresh machine.status + cached policy)
4. score = manifest [scheduling].priority (default 50)
         + sum of matching [[scheduler.preference]] weights
         + idle bonus (prefer_idle: +10 if jobs.running == 0)
         - self penalty (prefer_remote_workers on the dispatching host: -25 if candidate == self)
5. pick highest score; ties break on most available_memory_bytes
6. submit; if the worker's authoritative admission denies (Part 7.3),
   move to the next candidate; if none remain, exit 6
```

Scores are internal; `workflow plan` surfaces them for transparency (orig. §118 / Part 13.6).

**`--host` override semantics (rev. E; review D §6.2):** forcing a host with `workflow run --host` bypasses the *preference* machinery (steps 4–5) only. Capability matching still applies (a host that cannot satisfy the workflow's requirements is refused, exit 7), and worker-side admission remains authoritative as always (exit 6 on denial, with no silent fallback to another host — the operator named this one).

## 6.5 `doctor` is a core feature (orig. §56)

`styrn host doctor win-mini` should verify:

```text
Tailscale reachable
SSH reachable
protocol compatible
manifest valid
free disk above hard floor
session substrate consistent (11.0) — if registered: Herdr executable
  found AND session accessible, both hard findings on failure;
  if none: one informational line, and the host is healthy
Herdr present but unregistered -> informational drift note (11.0.1)
[capabilities] agent = true with substrate none -> manifest drift warning
Git found
Codex found
Claude found
Rust found if capability says Rust
sccache found if configured
native Windows, not WSL
Codex Windows sandbox configuration
Claude Windows sandbox limitation acknowledged
```

Additions in rev. B:

```text
machine_id present in manifest (self-heal if missing)         [S-25]
manifest not writable by the resolved worker principal         [4.5]
clock skew vs controller under 30s                            [2.5]
manifest cache age / version drift                            [2.8.6]
Windows: long paths enabled (registry + git core.longpaths)   [7.10]
worker sleep policy compatible with accept_jobs               [15.7.6; rev. E]
pending_actions unresolved entries                            [15.2.4]
```

JSON output should identify remediations (each finding carries `id`, `severity`, `message`, `remediation`).

**Unification (rev. D; scoped in rev. E):** doctor has two layers. The relational checks above (Tailscale reachable, SSH reachable, protocol compatible — plus clock skew and manifest-cache staleness from the additions) are **controller-side**: they run from the querying controller and are not setup probes. Every remaining entry is a **worker-local probe** shared verbatim with `styrn setup` (Part 15.2.2); for that layer, each doctor entry is backed by exactly one probe and no check may exist in one surface without the other (review D §4.3).

## 6.6 Version drift (orig. §57)

```text
styrn fleet versions
```

Human (CHANNEL and the upgrade hints are rev. E; Part 15.14):

```text
HOST            styrn    CHANNEL   herdr    codex     claude    rustc
linux-macpro    0.3.0    deb            ...      ...       ...       ...
win-mini        0.3.0    direct         ...      ...       ...       ...
win-hp          0.4.0    winget         ...      ...       ...       ...
mbp-main        0.4.0    brew           ...      ...       ...       ...

styrn drift: linux-macpro, win-mini behind 0.4.0
  linux-macpro:  styrn upgrade linux-macpro     (delegates: apt install ./styrn_0.4.0_amd64.deb)
  win-mini:      styrn upgrade win-mini         (delegates: stage-zero download + verify)
```

Do not automatically upgrade every tool without recording the change. Toolchain drift can explain test differences. The `styrn` column's channel comes from the manifest's `[install]` record (15.14.3); the binary itself is upgraded only through `styrn upgrade`'s channel delegation (15.14.4), never automatically.

## 6.7 Shared controller state (orig. §62, revised)

If you want controllers to be interchangeable, store only **non-secret fleet metadata** in a private Git repository:

```text
fleet-config/
├── hosts/
│   ├── linux-macpro.toml
│   ├── win-mini.toml
│   └── win-hp.toml
└── projects/
```

Do not commit:

- SSH private keys;
- access tokens;
- Tailscale auth keys;
- passwords.

Each controller has its own secret material. This is optional (v1 posture decided in D-2: primary controller + cold standby; the repo is convenience, never setup). A single MacBook controller can remain the normal workflow.

**Divergence rules (new in rev. B; resolves S-26 and the state half of S-03):**

- The fleet-config repo (or each controller's local inventory) is a **directory of hosts**, not a source of truth about live state. Live job/agent state is always obtained from workers.
- `styrn job list` and `styrn agent list --all` are **fan-out queries**: the controller asks every reachable inventory host and merges results, labeling unreachable hosts as such. **List-style fan-outs exit 0 with unreachable hosts in `warnings[]`** (rev. E; review D §4.8) — two of this fleet's machines are laptops that sleep, and a routine listing returning non-zero as its normal state would both fight §0.6 and train scripts to ignore exit 9. Exit 9 (`fleet.partial`) is reserved for operations where an unreachable host was a *required participant* — matrix aggregation (8.6) and targeted fleet operations — where partial genuinely means failed-in-part. A second controller sees jobs submitted by the first without any controller-to-controller synchronization.
- Each controller additionally keeps a local, append-only **submission index** (`~/.config/styrn/jobs-index.jsonl`: job id, host, project, workflow, revision, submitted-at) so `styrn job show <id>` can resolve a bare job id to a host without a fleet-wide query. A job id unknown to the local index triggers the fan-out lookup. Host-qualified artifact URIs (`job://<host>/<id>/...`, Part 7.7) need no index at all.
- Manifest caches may diverge between controllers; that is harmless because caches only feed *predictions*. `styrn host refresh` re-syncs; the staleness warnings of 2.8.6 apply per controller.

## 6.8 Maintenance policy (orig. §58)

Daily:

```text
remove successful expired jobs
remove failed targets after retention period
remove stale worktrees
rotate logs
trim cache to quota
check disk floor
```

Weekly:

```text
Git maintenance
version report
Tailscale health
SSH health
Herdr integration status
sccache statistics
```

Avoid global `cargo clean`.

**Execution locus (new in rev. B; executor specified in rev. D — resolves S-34):** maintenance runs on the **worker**, executed by the `styrnd` service installed by setup (Part 15.9) — with `styrn clean run` still invocable remotely on demand — under the same registry lock as admission, so cleanup never races job creation. If styrnd is stopped, due maintenance runs opportunistically at job admission and via `doctor` (degraded, not absent). Stale-worktree detection cross-references the job registry: a worktree without a registry entry older than 1 hour is stale.

---

# Part 7 — Jobs and resource governance

## 7.1 The governor's job (orig. §27)

The worker, not Codex or Claude, decides safe concurrency. Every job performs admission control before launching.

## 7.2 Admission formula (orig. §27, revised; resolves S-07)

Revision A's formula:

```text
cpu_budget =
    min(configured_max_jobs,
        logical_cpu_count - reserved_cpus)

memory_budget =
    floor(
        (available_memory - reserved_memory)
        / estimated_memory_per_job
    )

parallelism =
    max(1, min(cpu_budget, memory_budget))
```

Two defects, both fixed here:

**(a) Two different quantities were conflated.** "Parallelism" above is *intra-job parallelism* (what becomes `CARGO_BUILD_JOBS` / `RUST_TEST_THREADS`), while admission also has to decide *whether this job may start at all* alongside already-running jobs. Revision A computed the first and silently assumed the second.

**(b) `available_memory` is a point sample.** Two admissions racing (or one admission racing an already-admitted job that has not yet allocated its memory) both see the same free memory and double-book it.

**Revised model.** Each job, at admission, is assigned a **committed budget**:

```text
job_memory_budget = intra_job_parallelism * estimated_memory_per_job
                    + job_overhead_bytes          (default 1 GiB)
job_disk_budget   = min(project disk hint or default, policy.max_job_disk_bytes)
job_cpu_budget    = intra_job_parallelism
```

Admission (evaluated under the registry lock, 7.3) admits the job only if **both** the sampled reality and the bookkeeping allow it:

```text
committed_memory = sum(job_memory_budget of running jobs)
committed_cpus   = sum(job_cpu_budget of running jobs)
committed_disk   = sum(job_disk_budget of running jobs)

memory_ok = (available_memory_sampled - reserved_memory >= job_memory_budget)
        AND (total_memory - reserved_memory - committed_memory >= job_memory_budget)

cpu_room  = logical_cpu_count - reserved_cpus - committed_cpus
cpu_ok    = cpu_room >= 1

disk_ok   = (free_disk_sampled - reserved_disk >= job_disk_budget)
        AND (free_disk_sampled - reserved_disk - committed_disk_unwritten >= 0)

heavy_ok  = (resource_class != heavy) OR (heavy_running < max_heavy_jobs)
```

where `committed_disk_unwritten` is each running job's remaining budget (budget minus measured usage at last poll) — a conservative estimate of disk that running jobs may still consume.

Intra-job parallelism is then sized to the *remaining* room, not the raw machine:

```text
intra_job_parallelism =
    max(1, min(policy.max_parallel_compile_jobs,
               cpu_room,
               floor((total_memory - reserved_memory - committed_memory - job_overhead_bytes)
                     / estimated_memory_per_job)))
```

If `memory_ok`/`cpu_ok`/`disk_ok`/`heavy_ok` fail, the submission is denied with exit 6 and the specific code (`resource.memory_admission_denied`, `resource.cpu_admission_denied`, `resource.disk_admission_denied`) plus details (sampled, reserved, committed, required). The controller may retry another candidate (Part 6.4) or queue (7.6).

The project can provide estimates (orig. §27):

```toml
[resource_hints]
compile_memory_per_job_bytes = 2684354560
test_memory_per_job_bytes = 2147483648
peak_memory_bytes = 8589934592        # new in rev. B: expected single-process peak (linker)
disk_per_job_bytes = 21474836480      # new in rev. E: expected job-tree disk (review D §4.6)
```

**Defaults when hints are absent (rev. E; review D §4.6)** — the formula must never depend on constants an implementer invents. Profile-less or hint-less projects (both allowed by 9.1's starter on-ramp) use: `estimated_memory_per_job` = 2 GiB; `disk_per_job_bytes` = 20 GiB (always further capped by `policy.max_job_disk_bytes`); `job_overhead_bytes` = 1 GiB (as above); an interactive harness session's conservative committed budget (12.9.1) = 2 GiB memory, 1 CPU, 10 GiB disk.

Machine policy provides ceilings. The computed variables become (orig. §27, unchanged names):

```text
resources.compile_jobs
resources.test_jobs
resources.available_memory_bytes
resources.free_disk_bytes
resources.job_disk_limit_bytes
```

**Known residual risk (stated, not hidden):** admission bounds *planned* usage. A single rustc/linker invocation can spike past `estimated_memory_per_job` (that is what `peak_memory_bytes` hints at: admission additionally checks `available - reserved >= peak_memory_bytes` for heavy jobs). If reality exceeds the budget anyway, the enforcement layer (7.5 monitor: OOM-adjacent memory pressure and disk-floor kill) is the backstop, and the OS OOM behavior is the final one. The governor makes overload rare and bounded, not impossible.

## 7.3 Worker-side admission is atomic (new in rev. B; resolves S-03)

- Every worker keeps a **job registry**: `<paths.root>/jobs/registry.json` (job id → state, budgets, pids, resource class, owner-controller, timestamps).
- All registry mutations — admission, state transitions, cancellation, cleanup — are serialized by an **exclusive advisory lock** on `<paths.root>/jobs/registry.lock` (`flock` on Linux/macOS, `LockFileEx` on Windows), held only for the duration of the mutation (milliseconds; sampling `available_memory`/`free_disk` happens inside the critical section, but never any long work).
- Because every controller reaches the worker through the same registry lock, **two controllers dispatching simultaneously to the same worker cannot double-book**: one admission completes first and its committed budgets are visible to the second. This is the entire multi-controller concurrency story, and it needs no controller coordination (Part 2.1).
- Registry writes are atomic (write temp + rename). On worker restart, `styrn` reconciles the registry against reality: pids that no longer exist → job marked `failed` with `job.supervisor_lost` unless a final `result.json` exists (then its recorded outcome stands). Reconciliation also runs lazily at every lock acquisition (rev. C): entries whose recorded pids are gone are swept before the new mutation proceeds — this is also what releases an interactive harness session's budget after its exec'd agent exits (12.10).
- **Lock liveness (rev. C):** the advisory lock releases automatically when its holder dies (the OS drops it with the file handle), so no stale-lock recovery protocol exists or is needed. Acquisition waits up to 10 s, then fails the operation with `internal.error` — a wedged worker is a `doctor` case, not a retry loop.

## 7.4 Initial resource policies for the current machines (orig. §28)

These are starting values, not eternal constants.

### Ryzen 5 3550H, 16 GB, 480 GB Windows (win-mini)

```toml
[resources.policy]
reserved_memory_bytes = 5368709120      # 5 GiB
reserved_disk_bytes = 85899345920       # 80 GiB
reserved_cpus = 1
max_parallel_compile_jobs = 3
max_parallel_test_jobs = 3
max_heavy_jobs = 1
max_job_disk_bytes = 37580963840        # 35 GiB (orig. §31 value, now a schema key)
```

Capabilities:

```toml
heavy_build = false
heavy_test = false
```

Use for:

- `cargo check`;
- smoke tests;
- changed-crate tests;
- Windows-specific agent development;
- fast native-Windows validation.

### HP Windows, 32 GB, larger disk (win-hp)

```toml
[resources.policy]
reserved_memory_bytes = 8589934592      # 8 GiB
reserved_disk_percent = 15
max_parallel_compile_jobs = 8
max_parallel_test_jobs = 8
max_heavy_jobs = 1
max_job_disk_bytes = 107374182400       # 100 GiB (orig. §31)
```

Use for:

- full Windows builds;
- integration suites;
- release validation;
- feature matrices;
- heavy Windows agent work.

### Mac Pro Ubuntu, 64 GB, 1 TB (linux-macpro)

```toml
[resources.policy]
reserved_memory_bytes = 12884901888     # 12 GiB
reserved_disk_bytes = 161061273600      # 150 GiB
max_parallel_compile_jobs = 10
max_parallel_test_jobs = 10
max_heavy_jobs = 1
max_job_disk_bytes = 161061273600       # 100–150 GiB range from orig. §31; 150 GiB chosen
```

The exact Xeon model should be auto-detected. Do not hard-code a compile count based only on RAM.

## 7.5 Per-job disk quota and enforcement mechanics (orig. §31, revised; resolves S-08)

A runaway build must not fill the host. Suggested starting hard limits (now `max_job_disk_bytes`, see 7.4):

```text
win-mini       35 GiB/job
win-hp         100 GiB/job
linux-macpro   150 GiB/job
```

Revision A said the worker should "periodically measure" the job root, target directory and free filesystem space — which is a polling race: a parallel build or a test writing large fixtures can add gigabytes between polls. The honest per-OS situation:

| Mechanism | Linux | macOS | Windows | Verdict |
|---|---|---|---|---|
| Per-directory kernel quota | XFS/ext4 *project quotas* — only if the fs was provisioned for it | none practical | NTFS quotas are per-*user*; FSRM per-directory quotas are Server-SKU | not portable; not v1 |
| Dedicated per-job filesystem/volume | loopback image possible | sparse bundle possible | VHDX possible | heavy, slow, complex; not v1 |
| Polling with adaptive interval | yes | yes | yes | **v1 baseline** |

**Adopted v1 design — adaptive polling with a hard floor backstop:**

1. The job supervisor (7.8) walks the **whole `job.root` tree — workspace, target, and the job's log and artifact files** (a runaway `stdout.log` is as real a flood risk as a runaway target dir; rev. E, review D §6.2) and samples filesystem free space on an **adaptive interval**: 30 s baseline; 10 s once usage > 50% of budget; 5 s once > 80%. Directory walk results are cached per subtree mtime to keep the walk cheap on 100 GiB target dirs (a full cold walk of a large target dir is expensive; the adaptive schedule bounds how often it happens).
2. **Overshoot is expected and budgeted.** The polling race means a job can exceed `max_job_disk_bytes` by roughly (write rate × interval). `reserved_disk_bytes` is therefore the *hard host floor* and is sized generously (80–150 GiB above) precisely so quota overshoot cannot endanger the host.
3. Two triggers, two severities:
   - `job usage > max_job_disk_bytes` → kill (code `resource.job_disk_limit_exceeded`);
   - `filesystem free < reserved_disk` → kill the *largest currently-writing* job first (code `resource.host_disk_floor`), regardless of its own quota — host protection outranks job fairness.
4. On either limit (orig. §31 sequence, kept):

```text
1. terminate the job process tree
2. mark job as resource_limit_exceeded
3. preserve logs
4. delete disposable build artifacts
5. return structured failure
```

Filesystem project quotas on the Linux worker are an optional later hardening (the Mac Pro's disk could be provisioned XFS with project quotas at reinstall time); the design keeps the polling path regardless, because Windows and macOS need it.

## 7.6 Heavy-job exclusivity (orig. §32)

Two independent full Cargo builds usually produce more RAM/disk pressure than useful throughput.

Machine policy:

```toml
max_heavy_jobs = 1
```

Light agent analysis may coexist. A second heavy workflow should queue.

**Enforcement locus and queue semantics (new in rev. B):** `heavy_running < max_heavy_jobs` is checked inside worker-side admission (7.2/7.3) — a controller-side count would race. "Queue" in v1 means the **controller** polls — the worker maintains no persistent queue. A denied-for-exclusivity submission carries `resource.heavy_exclusivity_denied`; whether the controller then retries is **TTY-aware** (rev. C; S-31, tenet §0.6): an *interactive* invocation waits by default, retrying with backoff (30 s interval, 2 h cap) behind a single status line ("waiting for win-hp: heavy job slot busy") — a developer who typed the command wants it to run, not to babysit a retry loop — with `--no-wait` opting out; a *non-interactive* invocation (stdout not a TTY) fails fast with exit 6 unless `--wait` is given, keeping scripts deterministic. A worker-side queue is deliberately out of scope for v1 (it would need ordering, starvation, and multi-controller fairness policies that a 4-machine fleet does not justify).

## 7.7 Job directory, artifacts, and URIs (orig. §29, §34, §120)

### Rust/FriCOS artifact strategy (orig. §29)

Rust's `target/` directory can become very large. Rule for automated jobs:

> every job gets a private disposable `target` directory.

Example:

```text
C:\Styrn\jobs\01991...\target
```

or:

```text
/srv/styrn/jobs/01991.../target
```

Set:

```text
CARGO_TARGET_DIR=${job.root}/target
```

Do not share target directories between jobs, agents, or machines. When a successful job ends, delete the whole job directory. This is safer and more deterministic than repeatedly running `cargo clean`.

### Job directory layout (orig. §34)

```text
job.toml            submitted parameters (project, workflow, revision, budgets)
status.json         authoritative live state (written atomically by the supervisor)
stdout.log
stderr.log
resource.jsonl      periodic samples from the supervisor's monitor
result.json         final structured outcome
harness.jsonl       raw harness output when the job wraps an agent run (orig. §90)
workspace/          git worktree
target/             disposable build output
```

### Artifact references (orig. §120, revised URI form; resolves S-14)

Styrn defines stable job artifact URIs, **host-qualified** so that any controller can resolve them without a shared index:

```text
job://win-hp/0199.../stdout.log
job://win-hp/0199.../stderr.log
job://win-hp/0199.../cargo-timings.html
job://win-hp/0199.../result.json
```

CLI:

```text
styrn artifact read job://win-hp/0199.../stderr.log
styrn artifact read job://win-hp/0199.../result.json --json
```

MCP: `styrn_job_artifact_read` (Part 13). Transfer uses chunked frames (5.6). This avoids dumping large artifacts into every workflow response. Default per-read size cap 64 MiB (`--max-bytes` to raise); artifact retention follows job retention (`[cleanup]`, Part 9.1). These defaults are final (D-7): everything is tunable per project via `[cleanup]` and per call via `--max-bytes`, so adjusting later needs no design change — which is exactly why deciding now is safe.

## 7.8 Job execution model: the detached supervisor (new in rev. B; resolves S-01)

**The defect.** Revision A drove jobs through `ssh <host> styrn rpc serve --stdio` and simultaneously promised "You can close the controller" mid-validation (orig. §61). But a process started by an SSH-session child dies with the session on every platform (SIGHUP/EOF on Unix; console/job teardown on Windows) unless deliberately detached. As specified, closing the MacBook lid mid-`test-windows-heavy` would have killed the build. Nothing in revision A addressed orphaned, killed, or reattachable jobs.

**The fix.** Job submission and job execution are decoupled:

1. `job.submit` (RPC) performs admission under the registry lock (7.3). On admission, the RPC process spawns `styrn job supervise <job-id>` **detached from the SSH session**:
   - *Unix/macOS:* double-fork + `setsid()` (new session, no controlling terminal), stdio redirected to the job's log files, working directory `job.root`.
   - *Windows:* `CreateProcess` with `DETACHED_PROCESS | CREATE_NEW_PROCESS_GROUP | CREATE_BREAKAWAY_FROM_JOB`, so the supervisor escapes any Job Object that sshd/the session placed it in. (`styrn host doctor` verifies breakaway is permitted in this environment; if the sshd process tree denies breakaway, the RPC process requests the spawn from the local `styrnd` broker over its named pipe — Part 15.9 — which lives outside any sshd Job Object by construction. Rev. E notes the tension review D §4.11 flagged: Part 17's recorded Herdr claim that SSH-launched Windows processes survive logout *hints* the direct spawn may simply work, but survival-after-logout is not proof of no-Job-Object — the doctor probe on real hardware decides.)
2. The supervisor owns the job for its whole life: it creates the worktree, applies the environment, launches the workflow command — with working directory `${workspace.root}` (rev. E; review D §4.7: since 9.3 rule 5 bars variable expansion inside `command`, cwd is the only way a command finds its workspace) — inside a **new process group/session (Unix)** or an **anchored Job Object with `JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE` (Windows)**, runs the resource monitor (7.5), enforces the wall-clock timeout (7.9), writes `status.json`/`resource.jsonl`/`result.json` atomically, and performs cleanup per project policy.
3. The submitting RPC session, after spawn, merely **tails**: it streams `status.json` transitions and log growth to the controller as `log`/`event` frames. If the SSH session drops, the supervisor does not notice and does not care.
4. **Reattachment:** any controller can later run `styrn job show <id>`, `styrn job logs <id> --follow`, `styrn job cancel <id>` — all are registry/file operations against the worker, independent of the original session. There is no "job owner session"; the *worker* owns the job, the submitting controller is recorded in `job.toml` as provenance only.
5. `job.cancel` signals the supervisor (pid from the registry); the supervisor kills the process tree (group kill / Job Object termination), marks `cancelled`, cleans up, exits. If the supervisor itself has died (crash, reboot), reconciliation (7.3) marks the job `failed`/`job.supervisor_lost`, and cleanup collects the directory by retention policy.
6. **Unhappy paths at submission (new in rev. C).** `job.submit`'s success response is sent only after **spawn-ack**: the supervisor process has started and atomically written its initial `status.json` (`"state": "preparing"`). If the spawn fails or the ack does not arrive within 10 s, the registry entry and its committed budgets are rolled back under the lock and the response is an error (`internal.error` with spawn diagnostics) — no half-created jobs. If the RPC session dies *after* admission but before the response is delivered, the job exists and runs; the controller must treat `transport.session_lost` during submit as **outcome unknown — query, never resubmit blindly**. To make retries safe anyway, `job.submit` accepts an optional controller-minted `submission_id` (UUID); a resubmission carrying a `submission_id` already present in the registry returns the existing job instead of creating a twin. The submission index (6.7) records the `submission_id` alongside the job id. Dedupe consults live **and archived** registry entries; archived entries keep their `submission_id` for 24 h after archival, after which a re-used id may create a new job — a documented residual, acceptable because retries happen within minutes, not days (rev. E; review D §4.10).

This makes orig. §61's promise true: submit from the laptop, close the laptop, query from any other controller.

## 7.9 Wall-clock limits (orig. §33)

Workflows support:

```toml
timeout_seconds = 3600
```

Example policies:

```text
check              20 min
smoke              30 min
platform test      60 min
full validation   120 min
```

Terminate the **entire process tree**, especially on Windows. On Windows this uses the supervisor's Job Object (7.8); on Unix, `killpg` on the job's process group — SIGTERM, 10 s grace, SIGKILL. Timeout enforcement lives in the supervisor, so it works with no controller connected. Result code: exit 10 / `job.timeout`.

## 7.10 Windows execution semantics (new in rev. B; resolves S-09)

Revision A required native-Windows correctness throughout but never specified how commands actually execute there. Adopted rules:

1. **No shell in the job path.** Workflow `command` is an argv array in TOML (Part 9.1) and crosses the RPC boundary as a JSON array. The supervisor launches it with `std::process::Command` — direct `CreateProcessW`, no `cmd /c`, no PowerShell. Rust's standard quoting for MSVC-style argument parsing applies. Consequences, stated plainly:
   - the program must be a real executable on `PATH` or an absolute path; `.bat`/`.cmd` files are **not supported** as workflow commands (they would require `cmd.exe` semantics and its unquotable metacharacters — a project needing one wraps it in a real executable or a PowerShell file invoked as `["pwsh", "-File", "script.ps1"]`);
   - no environment-variable expansion, globbing, or redirection happens in `command` on any OS — uniformity beats convenience.
2. **`styrn exec` is the one shell-full path.** `styrn exec <host> -- <command...>` sends an argv array; the remote side executes it directly (no shell) by default, with `--shell` opting into the account's shell for humans who want pipes. Documented accordingly; agents get no exec at all (Part 13).
3. **Process-tree termination** is the Job Object (`KILL_ON_JOB_CLOSE` + explicit `TerminateJobObject`), covering grandchildren; the known escape (a child that itself requests breakaway) requires a privilege Styrn does not grant to a dedicated worker identity. In current-user mode, setup/doctor report if the selected account already holds privileges that weaken this boundary.
4. **Paths.** Variable expansion (Part 9.3) renders path-valued variables with native separators (`C:\Styrn\jobs\<id>\target` on Windows) before they reach environment variables, even though profile authors write `${job.root}/target` with forward slashes. Windows APIs largely accept forward slashes, but child tooling (MSVC, some build scripts) does not reliably, so Styrn normalizes.
5. **Long paths.** Deep Cargo target trees can exceed the legacy 260-character `MAX_PATH`. Bootstrap must set `HKLM\SYSTEM\CurrentControlSet\Control\FileSystem\LongPathsEnabled = 1` and `git config --system core.longpaths true`; job roots stay short (`C:\Styrn\jobs\<uuid>`); doctor checks both (6.5).
6. **Encoding.** The RPC and log pipeline is UTF-8 end to end; the supervisor sets the child's console code page expectations by env (`PYTHONUTF8`-style tricks are per-tool and out of scope) and stores raw bytes in log files, converting lossily only for `log` frames (5.4).

## 7.11 Job lifecycle (orig. §34, extended)

```text
created
  |
  v
admission            (worker-side, atomic — 7.3)
  |
  +-- denied
  |
  v
preparing            (worktree creation, env materialization — supervisor)
  |
  v
running
  |
  +-- timeout
  +-- cancelled
  +-- resource_limit
  +-- failed
  +-- supervisor_lost     (new in rev. B: reconciliation verdict — 7.3/7.8)
  |
  v
succeeded
  |
  v
cleanup
  |
  v
archived
```

All states are readable in `status.json` and via `job.get`; transitions are appended to the worker's audit log (Part 14.3).

## 7.12 sccache policy (orig. §30)

Use sccache as the reusable compilation cache.

Automated/ephemeral jobs:

```text
RUSTC_WRAPPER=sccache
CARGO_INCREMENTAL=0
```

Rust incremental compilation and sccache have an important interaction: incrementally compiled crates are not normally cacheable through sccache *(verify against current upstream docs)*. Therefore use two modes.

**Remote automated mode:**

```text
incremental = false
sccache = true
target = ephemeral
```

**Long-lived interactive developer worktree:**

```text
incremental = true
target = persistent-for-session
```

This can make sense on the HP or Linux heavy machine if you are repeatedly editing the same branch. Do not use that mode on the 480 GB mini-PC without a quota.

**Wiring made explicit (new in rev. B; resolves S-22):** the launcher/supervisor sets `SCCACHE_DIR=<paths.cache>/sccache` and `SCCACHE_CACHE_SIZE` from the manifest's `[caches.sccache] max_bytes` (rendered in sccache's size syntax), so the cache lives inside the governed `[paths].cache` tree and `styrn cache status/trim` (Part 10.5) can report and bound it. sccache's local server handles concurrent jobs sharing one cache directory by design; no per-job cache split.

---

# Part 8 — Source distribution and validation

## 8.1 Git workflow (orig. §35)

Do not sync active source trees with rsync. Use Git commits and worktrees.

Remote worker has a stable reference repository:

```text
repos/fricos.git        (bare; rev. B — see 8.2)
```

Job:

```text
git -C repos/fricos.git worktree add ../../jobs/<id>/workspace <commit>
```

After success:

```text
git worktree remove ...
```

Agent-created changes should become commits on a temporary branch before cross-machine validation. This gives every validator an exact SHA.

**Branch namespace (new in rev. B; refspec revised in rev. C):** Styrn-created temporary refs live under `refs/styrn/` — `refs/styrn/revisions/<sha>` for pushed job revisions (SHA-keyed, so pushes are idempotent and shared across jobs of the same commit; rev. B's `refs/styrn/jobs/<job-id>` form is superseded because the job id is only minted at admission, *after* the push — see 8.2), `refs/styrn/agents/<agent-name>` for agent working branches, and `refs/styrn/snapshots/*` (8.7). They never collide with human branches and are garbage-collected mechanically: a `refs/styrn/revisions/*` ref is pruned when no registry job references its SHA and it is older than 7 days; agent and snapshot refs prune with job retention.

## 8.2 How source reaches the worker (new in rev. B; resolves S-02)

**The contradiction in revision A:** orig. §35 requires the worker to `git fetch` before creating a job worktree, but orig. §41 forbids storing personal SSH keys or unrelated GitHub tokens on workers — and FriCOS is a private repository. As written, the worker has no way to authenticate to the remote. This was a genuine blocker, not an oversight of phrasing.

**Adopted default: controller push.** The machine that already has both the source and the credentials — the controller (or the developer/agent machine that made the commit) — *pushes* to the worker over the same SSH transport Styrn already trusts:

```text
git push ssh://styrn@win-hp/C:/Styrn/repos/fricos.git  7a3fd91:refs/styrn/revisions/7a3fd91
```

Mechanics:

1. Each worker holds a **bare** reference repository per project at `<paths.repos>/<project>.git`. `git worktree add` works from a bare repository, and bare avoids checked-out-branch push restrictions entirely.
2. `repo.ensure` (RPC) is **implicit in every submission** (rev. C; S-29, tenet §0.6): given `{project, sha?}` it creates the bare repo when absent and reports `{created: bool, have: bool}` for the SHA. No separate setup step exists; `styrn project init <host> <project>` remains only as an *optional pre-warm* (useful to push a large repository once, ahead of the first real job). First-time population is simply the first push (a full push is slower once; subsequent pushes send deltas).
3. The submission path is: plan → `repo.ensure` → push if `have: false` → `job.submit`. The controller pushes `sha:refs/styrn/revisions/<sha>` using its system `git` (git is already a controller prerequisite) over the same SSH identity and pinned host key as the RPC channel; no forge credential is involved anywhere. Pushes are idempotent (SHA-keyed refspec) and happen *outside* the registry lock — only `job.submit` takes it — so two controllers pushing the same SHA race harmlessly, and a push followed by a denied admission parks only a reusable revision ref, never job state. Push failures map to exit 5 (`remote execution failed`) with git's stderr in `errors[].details`; transport failures map to exit 3/4 as usual. After a successful push the controller re-verifies `have: true` before submitting.
4. Workers therefore need **no git-remote credentials at all** in the default mode, and validation works even when GitHub (or the internet) is unreachable — the fleet is self-contained.

**Opt-in alternative: read-only deploy key.** For projects that want workers to pull directly from the forge (e.g. huge repos where controller upload bandwidth hurts, or CI-style workers that fetch on their own):

```toml
[source]
kind = "git"
default_branch = "main"

[source.auth]                 # new in rev. B; absent = controller-push mode
mode = "deploy-key"           # "push" (default) | "deploy-key"
remote = "git@github.com:iob-dev/fricos.git"
```

In `deploy-key` mode, a per-project, read-only deploy key is provisioned under the resolved worker profile (`.ssh/deploy_<project>_ed25519` plus an SSH config alias), revocable at the forge independently of everything else. This is compatible with Part 4.2 as clarified there: project-scoped read-only ≠ personal credential. The default is decided in D-1: controller-push for every project unless that project explicitly opts into `deploy-key`.

## 8.3 Agent job versus validation job (orig. §36)

These are different trust roles.

```text
agent job
  edits source
  runs focused tests
  commits result

validation job
  clean worktree
  exact commit
  does not edit
  produces authoritative result
```

Example:

```text
Codex on win-mini
      |
      v
commit abc123
      |
      +--> HP Windows heavy validation
      |
      +--> Mac Pro Linux validation
```

This is better than letting the modifying agent certify its own workspace.

**Enforcement honesty (new in rev. B):** "does not edit" is guaranteed by *disposability*, not prevention — the validation worktree is created fresh at the exact SHA, its result is labeled with that SHA, and the worktree is deleted; nothing stops the workflow command from writing inside its own workspace, and nothing needs to. What makes the result authoritative is that the *inputs* are pinned (SHA + profile at that SHA) and the *outputs* (result.json, logs) are produced by the supervisor, not by the code under test. Note the corollary from Part 4.5: the profile at the validated SHA defines the commands, so validation certifies "this commit passes its own declared workflows," which is the correct semantic for a single-operator fleet.

## 8.4 Revision resolution (new in rev. B; resolves S-13)

Revision A used `HEAD` in examples (`styrn matrix run fricos cross-platform HEAD`, orig. §38) without saying where `HEAD` is resolved — the controller may not even have the repository. Rules adopted:

1. Every job records and executes an exact **40-hex SHA**. Symbolic names are resolved **before** submission, never on the worker.
2. Resolution order for `workflow run` / `matrix run`:
   - explicit `--revision <sha|ref>`: resolved in the project checkout the command runs in, or — if not inside one — refused for symbolic refs (`project.revision_unresolved`; a full SHA is accepted anywhere, and is pushed per 8.2 from a machine that has it, normally the invoking checkout);
   - no `--revision`, invoked inside a checkout of the project: `HEAD` of that checkout (dirtiness rules in 8.7 apply);
   - no `--revision`, outside any checkout: refused (`project.revision_unresolved`) — there is no "current revision" to guess.
3. Herdr-context invocations (orig. §98 / Part 11.8) resolve from the active pane's worktree by the same rules.
4. `result.json` and all reporting always show the resolved SHA, never the symbolic name the user typed.

## 8.5 FriCOS validation tiers (orig. §37)

**Tier 0**

```text
format/check
```

**Tier 1**

```text
workspace check
focused unit tests
affected crates
clippy
```

**Tier 2** — native platform suite:

```text
Windows-specific
Linux-specific
macOS-specific if applicable
```

**Tier 3** — heavy:

```text
full workspace
integration tests
release compilation
feature matrix
expensive fixtures
```

Only machines advertising `heavy_test=true` should be candidates for Tier 3.

## 8.6 Matrix workflow (orig. §38)

A project can define:

```toml
[matrix.cross-platform]
workflows = [
  "test-linux-heavy",
  "test-windows-heavy"
]
```

Then:

```text
styrn matrix run fricos cross-platform --revision 7a3fd91
```

(Rev. B: the positional bare `HEAD` of the original example is replaced by `--revision`, resolved per 8.4; omitting it inside a checkout still means "this checkout's HEAD".)

Human output:

```text
FriCOS 7a3fd91

                     linux-macpro    win-hp
check                   PASS          PASS
unit                    PASS          PASS
platform                PASS          PASS
integration             PASS          PASS
release                 PASS          PASS

Result: PASS
```

Machine output:

```text
styrn matrix run fricos cross-platform --revision 7a3fd91 --json
```

Matrix entries are dispatched as independent jobs (each with its own supervisor); the matrix command aggregates. A matrix where some jobs ran and some hosts were unavailable exits 9 (`fleet.partial`); any executed-and-failed workflow makes the matrix exit 12.

## 8.7 Dirty-worktree handling (orig. §98, mechanics completed in rev. B; resolves S-21)

If the current worktree is dirty, Styrn must not silently validate a different commit. Options (orig. §98):

```text
refuse and explain
```

or:

```text
offer snapshot/temp commit
```

For automation, explicit is safer. **Adopted:** default is refuse with `project.worktree_dirty`, listing the dirty paths. `--snapshot` opts into the second behavior, whose mechanics (unspecified in rev. A) are:

1. `git stash create`-style temporary commit: build a tree from the working directory (tracked files only; untracked files are *not* included — the refusal message says so, and `--snapshot-untracked` adds intent-to-add first), commit it with parent `HEAD` onto a temporary ref `refs/styrn/snapshots/<timestamp>-<n>`; the user's worktree, index, and branches are untouched.
2. The snapshot SHA is what gets pushed (8.2) and validated; reports label it `snapshot of <branch>@<HEAD-sha> + dirty` so a snapshot result is never mistaken for a branch result.
3. Snapshot refs are pruned with job retention like other `refs/styrn/*` refs (8.1).

---

# Part 9 — Project profiles and workflows

## 9.1 Generic project profile (orig. §26)

Each project can contain:

```text
.styrn.toml
```

Example generic structure:

```toml
schema_version = 1

[project]
name = "fricos"

[source]
kind = "git"
default_branch = "main"

[workspace]
strategy = "git-worktree"
ephemeral = true

[variables]
PROJECT_ROOT = "${workspace.root}"
JOB_ROOT = "${job.root}"

[workflows.check]
description = "Fast compile validation"
resource_class = "light"
command = ["cargo", "check", "--workspace"]

[workflows.check.requirements]
build = true

[workflows.check.environment]
CARGO_BUILD_JOBS = "${resources.compile_jobs}"
CARGO_TARGET_DIR = "${job.root}/target"
CARGO_INCREMENTAL = "0"
RUSTC_WRAPPER = "sccache"

[workflows.test-smoke]
resource_class = "normal"
command = ["cargo", "test", "--workspace"]

[workflows.test-smoke.environment]
CARGO_BUILD_JOBS = "${resources.compile_jobs}"
RUST_TEST_THREADS = "${resources.test_jobs}"
CARGO_TARGET_DIR = "${job.root}/target"
CARGO_INCREMENTAL = "0"
RUSTC_WRAPPER = "sccache"

[workflows.test-windows-heavy]
resource_class = "heavy"
command = ["cargo", "test", "--workspace"]

[workflows.test-windows-heavy.requirements]
os = "windows"
heavy_test = true

[workflows.test-linux-heavy]
resource_class = "heavy"
command = ["cargo", "test", "--workspace"]

[workflows.test-linux-heavy.requirements]
os = "linux"
heavy_test = true

[cleanup]
delete_successful_job_workspace = true
failed_job_retention_hours = 24
log_retention_days = 7
```

This keeps Cargo knowledge in FriCOS. Styrn only knows how to expand resource variables and execute the workflow.

The FriCOS reference profile previously shipped as a `fricos.styrn.toml` companion file, removed with the original design (§0.2). Its content (with `minimum_styrn_version = "0.1.0"`, `[resource_hints]`, per-workflow `description`/`timeout_seconds` — check 1200 s, smoke 1800 s, both heavies 7200 s — and full `[workflows.*.environment]` blocks mirroring the above, plus the same `[cleanup]` policy) is specified here and is carried forward unchanged except that it, too, may add `[source.auth]` per Part 8.2. It has been **recreated** at `examples/fricos.styrn.toml` from this section, and validates against `schemas/project-v1.schema.json`. The `examples/` and `schemas/` trees of Part 16.1 now exist; the three JSON Schemas are normative renderings of 2.4/2.4.2, 9.1, and 10.2/10.3 respectively, and are the artefacts `implementation-plan.md` T0.5, T3.1, and T0.2 validate against.

`resource_class` takes one of `light | normal | heavy` — `heavy` engages `max_heavy_jobs` exclusivity (7.6) and heavy-peak admission (7.2); `light`/`normal` differ only as scheduling metadata in v1.

**Starter on-ramp (new in rev. C; S-32, tenet §0.6):** a repository without `.styrn.toml` is not a dead end. `styrn project inspect` and `styrn workflow list` in a profile-less repo print a commented starter profile to stderr (choosing the Rust flavor above when `Cargo.toml` is present) with one line telling the developer to save it as `.styrn.toml` — instead of a bare error. A fuller `styrn project scaffold` command is deferred to a later phase.

## 9.2 Workflow requirements semantics (orig. §6, §26; consolidated)

`[workflows.<name>.requirements]` keys `os` and `arch` match `[platform]`; all other keys must be `true`-valued booleans matching `[capabilities]` flags (Part 2.3). A requirement naming a capability the manifest does not declare at all is simply unmet (not an error in the profile).

## 9.3 Variable expansion (new in rev. B; the original used `${...}` throughout without rules)

Namespace available in `[workflows.*.environment]`, `[variables]`, and alias definitions:

```text
${job.root}                      absolute job directory (native separators)
${job.id}                        job UUIDv7
${workspace.root}                absolute worktree path (native separators)
${project.name}
${revision.sha}
${resources.compile_jobs}        integers rendered as decimal strings
${resources.test_jobs}
${resources.available_memory_bytes}
${resources.free_disk_bytes}
${resources.job_disk_limit_bytes}
```

Rules:

1. Single-pass expansion; a variable's value is never re-expanded (no recursion, no injection through values).
2. Referencing an undefined variable is a **plan-time error** (`project.profile_invalid`), not silent empty-string substitution.
3. `$${` escapes a literal `${`.
4. Path-valued variables render with native separators (Part 7.10.4); profile authors always write `/`.
5. Expansion applies to environment values and `[variables]`; it does **not** apply inside `command` array elements in v1 (commands that need the paths read them from the environment) — one less injection surface, and the original examples never did so either. The command's working directory is always the workspace root (7.8), which is how `cargo check --workspace` and relative script paths resolve.

## 9.4 Project aliases for fluid CLI use (orig. §99)

From a project directory:

```text
styrn check
styrn test
styrn validate
styrn dev windows
```

can be convenience aliases resolved from `.styrn.toml`. They map to generic primitives. Example:

```toml
[aliases]
check = "check"
test = "test-smoke"
validate = "cross-platform"
```

Avoid compiling FriCOS-specific subcommands into Styrn. Alias lookup happens only when the invocation is inside a project directory and the first CLI token is not a built-in command; built-ins always win.

## 9.5 Workflow trust posture (new in rev. B; resolves the design half of S-06)

Consequence of Part 4.5, stated as policy:

- **Default posture:** workflow commands are untrusted input executed as the selected worker identity, inside a disposable worktree, under admission, quota, and timeout enforcement. Dedicated mode additionally provides a credential-free OS identity; current-user mode does not and must not advertise that guarantee. The vocabulary restriction ("only declared workflows") is an *ergonomic and review* aid, not a guarantee about what code runs.
- **Optional hardening (default off per D-5):**

```toml
# controller-side, per project, in inventory or fleet-config:
[projects.fricos.trust]
mode = "pinned"                     # "open" (default) | "pinned" | "allowlist"
profile_sha256 = "..."              # pinned: only run profiles whose hash matches
allowed_workflows = ["check", "test-smoke", "test-windows-heavy", "test-linux-heavy"]
```

  `pinned` refuses to plan/run when `.styrn.toml` at the requested revision hashes differently (the operator re-pins after reviewing profile changes); `allowlist` restricts by name regardless of content (weaker — names don't pin content — but cheap). Both are controller-side conveniences; the worker-side posture above is what actually bounds damage.

## 9.6 Suggested end-to-end command experience (orig. §100)

From any controller platform:

```text
styrn status
```

means fleet status.

From inside FriCOS:

```text
styrn check
```

runs the declared cheap local/remote check.

```text
styrn validate
```

runs the declared matrix.

```text
styrn dev windows --agent codex
```

selects a native Windows worker, creates a worktree, starts Codex inside remote Herdr, and attaches.

```text
styrn agents
```

lists agents across all machines.

```text
styrn attach fs-fix
```

attaches regardless of which OS hosts it.

The explicit long forms remain available for scripts.

---

# Part 10 — CLI surface and output contract

## 10.1 CLI output contract (orig. §23)

This is important. Every **non-interactive command that generates output** must support:

```text
--json
```

Default output is human-readable. JSON output must be stable, machine-readable and free of decorative text.

### Rules (orig. §23, unchanged)

1. JSON goes to stdout.
2. Diagnostics/progress go to stderr.
3. `--json` disables ANSI color.
4. stdout must contain exactly one valid JSON document for finite commands.
5. streaming commands should additionally support `--jsonl`.
6. field removal requires a schema-version change.
7. adding optional fields is allowed within a schema version.
8. timestamps are RFC 3339.
9. sizes are integers in bytes in JSON.
10. durations are integers in milliseconds in JSON.

**Streaming line schema (new in rev. B):** `--jsonl` emits one `styrn.event.v1` object per line — the identical shape to RPC `event` frames (Part 5.4) minus the framing fields, so `styrn monitor --jsonl` is a lossless relay.

**Environment (new in rev. B):** a small `STYRN_*` set, all optional: `STYRN_CONFIG_DIR` (override config/inventory location), `STYRN_JSON=1` (as if `--json`), `STYRN_LOG` (tracing filter for stderr diagnostics), `STYRN_SSH` (path to the ssh binary). Nothing else; flags always win over environment.

## 10.2 Standard envelope (orig. §23)

```json
{
  "schema": "styrn.command.v1",
  "ok": true,
  "command": "host status",
  "timestamp": "2026-09-01T08:35:12+02:00",
  "data": {},
  "warnings": [],
  "errors": []
}
```

Error:

```json
{
  "schema": "styrn.command.v1",
  "ok": false,
  "command": "workflow run",
  "timestamp": "2026-09-01T08:35:12+02:00",
  "data": null,
  "warnings": [],
  "errors": [
    {
      "code": "resource.disk_admission_denied",
      "message": "Free disk space is below the configured reserve.",
      "details": {
        "free_bytes": 51400000000,
        "required_free_bytes": 85899345920
      }
    }
  ]
}
```

## 10.3 Error-code registry (new in rev. B; resolves part of S-19)

Error `code` values are dot-namespaced, stable, append-only within envelope v1 (Part 2.8.5). Every code carries its coarse exit mapping (completed in rev. E; review D §4.9). Codes marked *(job outcome)* describe how a job ended: they appear in `result.json` and surface through `workflow run`/`matrix run` as exit 12 with the code in `errors[]`, while direct queries about such a job (`job show`) exit 0. Initial registry — seeded with the codes already used in rev. A's examples so none is orphaned:

```text
usage.invalid_argument          bad flags/arguments (exit 2)
usage.config_invalid            unreadable/invalid local config or inventory (exit 2)
transport.unreachable           cannot reach host (exit 3)
transport.auth_failed           SSH auth or host-key pin failure (exit 4)
transport.session_lost          RPC session dropped mid-operation (exit 3)
protocol.incompatible           version/schema window violation (exit 8)
protocol.malformed              unparseable or oversized frame (exit 8)
machine.manifest_invalid        manifest fails validation (exit 2)
resource.memory_admission_denied   (exit 6)
resource.cpu_admission_denied      (exit 6)
resource.disk_admission_denied     (exit 6; orig. §23 example code, retained verbatim)
resource.heavy_exclusivity_denied  (exit 6)
resource.job_disk_limit_exceeded   (job outcome → exit 12)
resource.host_disk_floor           (job outcome → exit 12)
capability.unsatisfied          no eligible host (exit 7)
capability.substrate_unregistered  agent-surface operation on a host with no
                                session substrate (rev. F; exit 7; Part 11.0.3)
job.not_found                   unknown job id (exit 2)
job.timeout                     (exit 10)
job.cancelled                   (job outcome → exit 12)
job.workflow_failed             wrapped command exited non-zero (exit 12)
job.supervisor_lost             reconciliation verdict (Part 7.3; job outcome → exit 12)
agent.not_found                 unknown agent name (exit 2)
agent.harness_error             (exit 11)
project.profile_invalid         (exit 2)
project.workflow_not_declared   (exit 2)
project.revision_unresolved     (exit 2)
project.worktree_dirty          (exit 2)
fleet.partial                   (exit 9)
internal.error                  (exit 1)
setup.probe_failed              (rev. D; exit 13)
setup.plan_invalid              (rev. D; exit 13)
setup.confirmation_required     (rev. D; exit 13)
setup.elevation_required        (rev. D; exit 13)
setup.apply_failed              (rev. D; exit 13)
setup.needs_human               (rev. D; warning, or exit 13 under fail_on_pending)
setup.unsupported_os            (rev. D; exit 13)
setup.receipt_conflict          (rev. D; exit 13)
setup.adopt_mismatch            (rev. D; exit 13)
```

## 10.4 Exit codes (orig. §24, revised; resolves S-11)

```text
0   success
1   unexpected internal error                (rev. B: was undefined)
2   CLI usage/configuration error
3   host unreachable
4   authentication/authorization failure
5   remote execution failed
6   resource admission denied
7   required capability unavailable
8   protocol/schema incompatibility
9   partial fleet operation
10  timeout
11  agent/harness error
12  project workflow error
13  setup action failed / setup requires input   (rev. D; Part 15.13)
```

Agent state `blocked` is normally a valid state, not a process error (orig. §24).

**Collision policy (new in rev. B):** the codes above describe *Styrn's* outcome, and they inevitably collide with codes that invoked programs use for their own meanings. Resolution:

- For `workflow run` / `matrix run`, the wrapped command's exit code is **never** propagated as Styrn's exit code; a non-zero workflow command yields Styrn exit **12** with the inner code in `data.exit_code` (and in `result.json`). Scripts that need the inner code use `--json`. This keeps `cargo test`'s 101 from masquerading as a Styrn meaning and vice versa.
- **Exception — `styrn exec` mirrors the remote command's exit code** (the `ssh` convention), because `exec` exists precisely to feel like running the command there; Styrn-level failures (unreachable, auth, protocol) then use the table above, which is ambiguous with remote codes 3/4/8 in principle — exactly as it is with plain `ssh`. Callers needing certainty use `--json`, where `data.exit_code` and `errors[]` are unambiguous. (Decided in D-6.)
- Exit codes are for coarse scripting dispatch; the JSON envelope is the authoritative outcome record.

## 10.5 Core command surface (orig. §25, with rev. B adjustments)

### Local machine (rev. E; review D §4.5 — previously specified only in Parts 2 and 4)

```text
styrn machine roles [--json]
styrn machine role add|remove controller|worker [--json]
styrn machine manifest [--json]
styrn machine init [--json]                           (machine_id minting; Part 2.4.1)
styrn controller init [--json]                        (optional keypair pre-generation; Part 4.3.1)
```

### Host management

```text
styrn host list [--json]
styrn host show <host> [--json]
styrn host status [<host>] [--json]
styrn host enroll <host> --user <user> [--fingerprint SHA256] [--json]
styrn host remove <host> [--revoke] [--json]          (semantics: Part 6.2)
styrn host doctor [<host>] [--json]
styrn host refresh [<host>] [--json]
styrn host authorize-key <host> --public-key PATH [--json]   (new: Part 4.3)
styrn host revoke-key <host> --controller NAME [--json]      (new: Part 4.3)
styrn host trust <host> --fingerprint SHA256 [--json]        (new: Part 4.4)
```

### Shell and desktop

```text
styrn shell <host>
styrn desktop open <host>
styrn admin open <host>
```

These are interactive and do not need `--json` for the interactive stream. A companion metadata command should exist:

```text
styrn desktop info <host> --json
```

### Remote command

```text
styrn exec <host> -- <command...>
styrn exec <host> --json -- <command...>
styrn exec <host> --shell -- <command...>             (rev. B: Part 7.10.2)
```

JSON result:

```json
{
  "exit_code": 0,
  "stdout": "...",
  "stderr": "...",
  "duration_ms": 1462
}
```

### Agents

```text
styrn agent list [--host HOST] [--all] [--json]
styrn agent start <host> --harness codex|claude --project NAME --name NAME [--json]
styrn agent read <agent> [--lines N] [--json]
styrn agent prompt <agent> --text TEXT [--json]
styrn agent wait <agent> [--state idle|done|blocked] [--json]
styrn agent stop <agent> [--json]
styrn agent attach <agent>
```

(Rev. B: `--harness` replaces the original `--kind`; S-20.)

### Session substrate (added to this listing in rev. F; Parts 11.0, 11.6, 11.13)

```text
styrn herdr status [<host>] [--json]                  (substrate state per host; Part 11.0.1)
styrn herdr attach <host>                             (full native remote Herdr UI; Part 11.13)
styrn herdr action <id> [...]                         (plugin plumbing, invoked by Herdr; Part 11.6)
styrn herdr event <id> [...]                          (plugin plumbing, invoked by Herdr; Part 11.6)
```

These are **vendor-named on purpose** (D-9), and they were absent from this surface until rev. F even though 10.7 and the Part 16.3 phase listings already used them — a latent breach of the rule that every command appears here. `herdr status` reports each inventory host's substrate state (`none | registered | active`), session name, and Herdr version where active; reporting `none` is its job, so it exits 0 whatever the state. `herdr attach` against a substrate-`none` host refuses per 11.0.3. The `action`/`event` subcommands are executed *by* Herdr's plugin system and so cannot run without it; they need no gating.

### Jobs

```text
styrn job list [--json]
styrn job show <id> [--json]
styrn job cancel <id> [--json]
styrn job logs <id>
styrn job logs <id> --json
styrn job logs <id> --follow --jsonl
```

### Projects/workflows

```text
styrn project list [--json]
styrn project inspect <name> [--json]
styrn project init <host> <name> [--json]             (optional pre-warm; implicit at first submission — Part 8.2)

styrn workflow list <project> [--json]
styrn workflow plan <project> <workflow> [--revision R] [--json]
styrn workflow run <project> <workflow> [--host HOST] [--revision R] [--wait|--no-wait] [--snapshot] [--json]
styrn workflow cancel <submission-id|job-id> [--json]  (rev. E; semantics in 13.3)
styrn matrix run <project> <matrix> [--revision R] [--json]
```

### Maintenance

```text
styrn clean plan <host> [--json]
styrn clean run <host> [--json]
styrn cache status <host> [--json]
styrn cache trim <host> [--json]
styrn artifact read <job-uri> [--max-bytes N] [--json]
```

### Fleet

```text
styrn fleet status [--json]
styrn fleet doctor [--json]
styrn fleet versions [--json]                         (channel + upgrade hints; Part 15.14)
styrn fleet selftest [--json]                         (added to this listing in rev. E; Part 16.6 item 6)
styrn fleet controllers
styrn fleet workers
```

### Harness (added to this listing in rev. E; Parts 12.9, 12.14)

```text
styrn harness run codex|claude [...]                  (inside a Herdr pane; Part 12.9)
styrn harness-hook claude <event>                     (hook adapter; Part 12.14)
```

### Upgrade (rev. E; Part 15.14)

```text
styrn upgrade [<host>|--all] [--json]                 (delegates to the owning channel; never self-updates)
```

### Setup (rev. D; full grammar and flags in Part 15.13)

```text
styrn setup [--role R] [--install c1,c2,...] [--config PATH] [--interactive]
            [--yes] [--dry-run] [--emit-script[=PATH]] [--uninstall] [--json]
styrn bootstrap-script --os <linux|macos|windows> [--json]
styrn env
```

### Monitoring

```text
styrn monitor [--notify] [--jsonl]                    (headless; Part 14.1)
styrn watch [--all] [--herdr]                         (ratatui TUI; Phase 8; spec: Part 14.5)
```

Do not let the TUI become the primary API.

## 10.6 Human dashboard versus API (orig. §39)

A TUI can be useful later (`styrn watch`), but it is not the control contract. The contract is the non-interactive command API with stable JSON. This means other tools can build on Styrn:

- shell scripts;
- GitHub Actions;
- Herdr plugins;
- IDE extensions;
- web dashboard;
- CI scheduler;
- ChatGPT/Codex skill;
- Claude skill.

## 10.7 JSON behavior applies to integration commands too (orig. §101)

Examples:

```text
styrn integrate status --json
styrn herdr status --json
styrn agent list --json
styrn workflow plan fricos test-windows-heavy --json
```

Finite JSON output still follows the standard envelope. Streaming:

```text
styrn monitor --jsonl
styrn job logs ID --follow --jsonl
```

Do not mix progress text with JSON stdout.

---

# Part 11 — The session substrate (Herdr)

## 11.0 The substrate is optional (new in rev. F; resolves S-40)

The operator's requirement, verbatim and binding:

> "styrn should not depend on herdr: it should be able to run independently, while leveraging herdr when present and in-use and registered."

Styrn has **two execution layers**, and only one of them is Styrn's own. Batch work — jobs, workflows, matrices — runs on the worker-owned detached supervisor (Part 7.8) and depends on nothing in this Part. Persistent *interactive* work — coding-agent sessions with lifecycle, prompt/read/wait, and attach — runs on the host's **session substrate**, which in v1 is Herdr, and which is **optional per host**.

A fleet on which no host has a substrate is a fully healthy Styrn fleet: every command in Parts 5–10 works, enrollment succeeds, doctor is green, and `fleet selftest` passes. What such a fleet lacks is exactly and only the `agent`-lifecycle surface, and it refuses that surface cleanly (11.0.3) without degrading anything else. This is §0.6 applied in both directions: a Herdr-less developer is never nagged about Herdr, and a Herdr user loses nothing specified elsewhere in this Part.

Terminology (§0.4): **"session substrate"** is always written qualified. It is unrelated to the *package substrates* of 15.2.1/15.7.6 (`SubstrateProbe{winget, brew, apt}`), and the unqualified word "substrate" is not used on its own.

### 11.0.1 Substrate state (normative)

Each host has exactly one machine-local **substrate state**, computed by the worker — which is, as everywhere else, the authority on its own condition:

```text
none         no session substrate is registered on this host
registered   registered in the manifest, but the named session is not currently live
active       registered, and the named session answers a liveness query
```

The operator's three words map onto the model as follows. **Present** = the worker-local probe finds the `herdr` executable (`ToolProbe{herdr}` → `Present`, 15.2.1). **Registered** = the manifest records it: `[herdr] installed = true` and `enabled != false` (2.4). **In use** = the session named by `[herdr] session` answers on its local socket — a worker-local liveness probe, new in rev. F, shared between doctor and setup per 15.2.2. State `active` requires all three.

Presence *without* registration is state `none`: Styrn leverages only what the operator's setup has recorded, and doctor reports the discrepancy as informational drift (6.5), never as ill health. A developer who installed Herdr by hand for their own use has not thereby volunteered it to Styrn.

### 11.0.2 Registration: one authority, three signals ranked

Three pre-existing signals touch Herdr. Their precedence is now defined:

1. **The manifest `[herdr]` table is the registration authority.** It is setup-probed output (15.3.2) plus one operator-owned key — `enabled` (optional, default `true`), the analogue of the operator-owned `[resources.policy]` region and preserved across setup re-runs. Registered ⇔ `installed = true` AND `enabled != false`. Setting `enabled = false` is how an operator keeps Herdr installed for personal use while telling Styrn not to leverage it.
2. **`[components] herdr` in `setup-config.toml` (15.3.1) is desired-state input only.** It causes installation, whose probe then registers the result in the manifest. It is never consulted at runtime.
3. **`styrn integrate herdr install` (11.16) points the other way** — it installs Styrn's plugin *into* Herdr. It requires an `active` substrate, and it neither grants nor implies registration: an unlinked plugin does not remove agent control.

**Capability tie.** Manifest generation sets `[capabilities] agent = true` only when the substrate is registered **and** at least one agent harness (`[agents.*] installed = true`) is present. Agent placement — `styrn agent start`, and host selection in MCP `styrn_agent_start` — requires that capability exactly as workflow requirements do (2.1, 9.2). Doctor flags `agent = true` alongside substrate `none` as manifest drift.

### 11.0.3 How a controller learns the state, and the degradation contract

A controller learns *registered vs. none* from the cached manifest (fetched at enrollment, refreshed by `host refresh`), and the *live* state from `machine.status`, which gains an ephemeral `substrate` field (2.5, additive within envelope v1):

```json
"substrate": { "kind": "herdr", "state": "active", "session": "fleet" }
```

The hello (5.2) is unchanged — it stays minimal by design.

> **Substrate degradation (binding contract).** Every operation whose semantics *require* a session substrate — `agent start/read/prompt/wait/stop/attach`, `styrn herdr attach`, `styrn integrate herdr install|doctor`, the MCP `styrn_agent_*` tools other than `styrn_agent_list`, and the parity machinery of 12.9.1 — when directed at a host whose substrate state is `none`, fails with **exit 7** and error code **`capability.substrate_unregistered`**, carrying `details = {host, substrate: "none"}` and a remediation naming the enabling command for that host (`styrn setup --install herdr`, run on the host). Query-shaped operations — `agent list`, `styrn_agent_list`, `styrn herdr status`, `doctor`, the 11.10 and 14.5 boards, and `fleet selftest`'s agent leg — treat `none` as a valid, healthy answer: empty data, exit 0, **no warnings**. A Herdr-less fleet is silent, never nagged (§0.6); the single permitted hint is one stderr line on an *interactive* `agent list` that is empty precisely because no host has a substrate. A substrate that is `registered` but cannot be brought up is a different failure — the integration is broken, not absent — and reports **exit 11 / `agent.harness_error`**, which doctor will already be flagging.

## 11.1 What Herdr provides as the session substrate (orig. §11)

Herdr already provides the difficult pieces *(upstream claims recorded 2026-09-01 — verify against current upstream docs; Part 17)*:

- persistent background server;
- panes;
- workspaces;
- worktrees;
- Codex/Claude detection;
- agent state;
- machine-readable CLI responses;
- detach and reattach;
- headless server mode;
- remote attach for Linux/macOS;
- native Windows persistent sessions.

Run a named session such as:

```text
fleet
```

Headless server — canonical invocation (rev. B standardization; S-23):

```text
HERDR_SESSION=fleet herdr server
```

(The alternative `herdr --session fleet server` form noted in rev. A is not used by Styrn's own materials; the Ubuntu bootstrap's systemd unit already uses the env-var form. If upstream deprecates either form, adjust at implementation time.)

### Important Windows asymmetry (orig. §11)

Current Herdr remote attach supports Windows as a **local client**, but not Windows as a `herdr --remote` **target** *(verify against current upstream docs)*. Therefore Styrn must hide the difference.

Linux/macOS interactive attach:

```text
herdr --remote linux-macpro --session fleet
```

Windows interactive attach:

```text
ssh -t win-mini "herdr --session fleet"
```

Programmatic control should not depend on `herdr --remote` at all. Instead:

```text
controller
   |
   +-- SSH --> remote `styrn rpc serve --stdio`
                       |
                       +-- local Herdr CLI/API
```

This gives identical semantics on all operating systems.

## 11.2 Herdr agent operations Styrn should wrap (orig. §12)

Styrn should expose a provider abstraction:

```rust
trait HarnessProvider {
    fn list_agents(...);
    fn start_agent(...);
    fn prompt_agent(...);
    fn read_agent(...);
    fn wait_agent(...);
    fn stop_agent(...);
    fn attach_agent(...);
}
```

`HerdrProvider` is the **only** v1 implementation, and provider resolution is substrate-gated (11.0.3): asking for a provider on a host whose substrate state is `none` yields the refusal, never a provider object with failing methods. The per-operation contract:

| Operation | substrate `active` | substrate `registered` (session down) | substrate `none` |
|---|---|---|---|
| `list_agents` | full answer | empty list, state reported | empty list, state reported (exit 0) |
| `start` / `prompt` / `read` / `wait` / `stop` / `attach` | full behavior | start the session first where `[herdr] autostart` permits an on-demand start (`on-demand`, `on-demand-ssh`; canonical invocation per 11.1 *(verify)*); if it cannot be brought up, or `autostart = "systemd-user"` reports the service down, exit 11 / `agent.harness_error` | exit 7 / `capability.substrate_unregistered` |

**There is deliberately no second, reduced provider in v1.** The considered alternative — a provider built on the detached job supervisor (7.8) — cannot honestly implement `prompt`, `read`, `wait`, or `attach`: the supervisor has no PTY, no incremental prompt channel, and no lifecycle detection, and faking them would recreate exactly the split-brain lifecycle model 11.12 forbids. The need such a provider would serve is already served: a *batch* agent run (`codex exec`, `claude -p`) is a workflow command in `.styrn.toml` like any other (§66 — harness knowledge belongs in the project profile), runs under full governance as an ordinary job, and the job layout already reserves `harness.jsonl` for precisely this (7.7, 12.5). Refusal plus the existing job path is the whole answer; a `NullProvider` would be a larger mechanism delivering less honesty (§0.7).

Relevant Herdr operations include:

```text
herdr agent list
herdr agent start ...
herdr agent prompt ...
herdr agent read ...
herdr agent wait ...
herdr workspace create ...
herdr worktree create ...
herdr pane read ...
herdr pane run ...
```

Herdr already classifies agents into lifecycle states such as:

```text
working
blocked
idle
done
unknown
```

Styrn should preserve those states rather than inventing a second incompatible lifecycle model.

## 11.3 Four integration layers (orig. §69)

Styrn should integrate at **four different layers**, each with a distinct responsibility.

```text
                         HUMAN / OPERATOR
                               |
                     Herdr Styrn plugin
                  actions / panes / keybindings
                               |
                               v
                         styrn CLI
                               |
                 +-------------+-------------+
                 |                           |
                 v                           v
        Styrn SSH/RPC             local Herdr API
         other machines              panes / agents / events
                 |
                 v
       remote styrn binary
                 |
        remote Herdr + jobs
                 |
        Codex / Claude / other
                 ^
                 |
              MCP stdio
                 |
                AGENT
```

The layers are:

1. **Herdr official agent integrations** — Codex/Claude native session identity, restore behavior, and Herdr's normal lifecycle visibility.
2. **Styrn Herdr plugin** — human-facing fleet actions and an optional fleet board inside Herdr.
3. **Styrn MCP server** — used by Codex/Claude themselves to query the fleet and request policy-controlled workflows.
4. **Styrn launcher/resource governor** — enforcement. Environment, process limits, disk admission, timeouts, worktree isolation, and cleanup cannot rely on an LLM following instructions.

This is intentionally layered. Do not make one mechanism perform all four jobs.

## 11.4 What current Herdr gives us (orig. §70)

Current Herdr exposes the primitives Styrn needs without screen scraping *(upstream claims — verify; Part 17)*:

- persistent workspaces, tabs, panes and coding-agent sessions;
- `agent list`, `agent get`, `agent read`, `agent prompt`, `agent wait`, `agent start`, and `agent attach`;
- a newline-delimited JSON socket API;
- `events.subscribe` for agent/pane lifecycle events;
- an executable plugin system;
- cross-platform plugin declarations for `linux`, `macos`, and `windows`;
- plugin actions;
- plugin event hooks;
- plugin-managed terminal panes;
- plugin-specific config/state directories;
- injected context through `HERDR_PLUGIN_CONTEXT_JSON`;
- pane metadata that changes display without stealing lifecycle authority;
- declarative agent-view filtering and sorting.

Herdr plugin commands are external processes, so the plugin implementation can simply be the existing Rust `styrn` executable. That is ideal for the dependency requirement: **no Node, Python, Bun, or separate plugin runtime is necessary.**

## 11.5 Keep Herdr's official Codex and Claude integrations installed (orig. §71)

Setup runs (as the `herdr` component's integration actions, Part 15.7.7), under the actual agent user:

```text
herdr integration install codex
herdr integration install claude
```

Do not replace these integrations with Styrn. Current behavior is useful:

- **Codex:** Herdr's Codex integration reports the native Codex session identity to Herdr so a session can be restored; Herdr derives Codex lifecycle state from its screen-manifest detection. The Herdr installer updates Codex's hook configuration and enables the hook feature when necessary.
- **Claude Code:** Herdr's Claude integration reports Claude's native session identity; lifecycle state comes from screen-manifest detection. The integration writes Herdr-managed Claude hook entries into the configured Claude directory.

**Why Styrn should not duplicate these hooks:** both harnesses have evolving hook systems (Codex hook behavior is relatively new and still changing). Styrn should avoid editing the same hook files simply to rediscover information Herdr already knows. Use:

```text
harness hook -> Herdr
Herdr -> Styrn
```

rather than:

```text
harness hook -> Herdr
harness hook -> Styrn
```

unless there is a specific event Herdr cannot expose. This reduces configuration collisions.

## 11.6 The Styrn Herdr plugin (orig. §72)

Place the plugin in the Styrn repository:

```text
styrn/
└── integrations/
    └── herdr/
        └── herdr-plugin.toml
```

The plugin is intentionally thin. Every command invokes the Styrn executable. The reference manifest ships as the companion file `styrn-herdr-plugin.toml`. Conceptually:

```toml
id = "styrn.control"
name = "Styrn"
version = "0.1.0"
min_herdr_version = "0.7.0"
description = "Control Styrn hosts, jobs and remote coding agents"
platforms = ["linux", "macos", "windows"]

[[actions]]
id = "fleet-status"
title = "Fleet status"
contexts = ["workspace"]
command = ["styrn", "herdr", "action", "fleet-status"]

[[actions]]
id = "validate-current"
title = "Validate current commit"
contexts = ["workspace"]
command = ["styrn", "herdr", "action", "validate-current"]

[[actions]]
id = "start-remote-agent"
title = "Start remote agent"
contexts = ["workspace"]
command = ["styrn", "herdr", "action", "start-remote-agent"]

[[panes]]
id = "fleet"
title = "Styrn"
placement = "tab"
command = ["styrn", "watch", "--herdr"]

[[events]]
on = "worktree.created"
command = ["styrn", "herdr", "event", "worktree-created"]
```

(The full companion file additionally declares the per-platform validate actions `validate-windows` / `validate-linux` / `validate-macos` via `["styrn", "herdr", "action", "validate-platform", "<os>"]` — carried forward unchanged.)

Herdr injects context such as:

```text
HERDR_PLUGIN_CONTEXT_JSON
HERDR_WORKSPACE_ID
HERDR_TAB_ID
HERDR_PANE_ID
HERDR_SOCKET_PATH
HERDR_BIN_PATH
HERDR_PLUGIN_CONFIG_DIR
HERDR_PLUGIN_STATE_DIR
```

Styrn should consume those values directly.

## 11.7 Why a Herdr plugin improves the developer experience (orig. §73)

Without the plugin, you type:

```text
styrn workflow run fricos windows-heavy
```

With the plugin, while focused on a FriCOS Herdr workspace, you can invoke:

```text
Validate current commit
```

Styrn can infer from Herdr context:

```text
current workspace
current pane cwd
Git repository
Git worktree
branch
HEAD SHA
project .styrn.toml
```

and submit the correct validation workflow. The operator should not need to repeatedly specify:

```text
--project fricos
--commit abc123
--host win-hp
```

when that information is already available from context and policy.

## 11.8 Current-workspace context removes repetitive arguments (orig. §98)

A Herdr plugin action receives contextual metadata. An invocation such as:

```text
Validate current commit
```

should internally become approximately:

```text
cwd        = Herdr active pane cwd
repo       = git root(cwd)
project    = repo/.styrn.toml
revision   = git rev-parse HEAD          (resolution rules: Part 8.4)
workflow   = project.default_validation
```

If the current worktree is dirty, Styrn refuses by default or snapshots on request, per Part 8.7.

## 11.9 Recommended Herdr actions (orig. §74)

The first plugin version should expose a deliberately small action set:

- **Fleet status** — opens or focuses a Styrn board.
- **Validate current commit** — reads the current Git SHA and runs the project's default validation matrix.
- **Validate on Windows** — chooses a capable Windows host.
- **Validate on Linux** — chooses a capable Linux host.
- **Validate on macOS** — chooses a capable macOS host.
- **Start remote Codex** — creates an isolated remote worktree and Herdr pane and starts Codex.
- **Start remote Claude** — same operation using Claude Code.
- **Attach remote agent** — shows selectable active/blocked/done remote agents and attaches using the correct platform transport.
- **Show job logs** — opens a Herdr pane displaying a structured remote job log.

Do not expose machine enrollment, power cycling or arbitrary root commands as normal Herdr actions.

## 11.10 Herdr fleet board (orig. §75)

`styrn watch --herdr` can run as a normal Herdr-managed terminal pane (full TUI specification: Part 14.5). Example:

```text
 Styrn                                       controller: mbp-main

 HOST             OS          CPU    RAM FREE    DISK FREE   STATE
 ------------------------------------------------------------------
 linux-macpro     linux/x64    21%     49 GiB      612 GiB    busy
 win-mini         win/x64       3%     10 GiB      118 GiB    idle
 win-hp           win/x64      68%     23 GiB      681 GiB    busy

 AGENT                 HOST             PROJECT    STATE
 ------------------------------------------------------------------
 fs-fix                win-mini         fricos     blocked
 linux-review          linux-macpro     fricos     working
 windows-validator     win-hp           fricos     working

 JOB                    HOST             WORKFLOW              STATE
 ------------------------------------------------------------------
 0199...a2             win-hp           test-windows-heavy    running
 0199...17             linux-macpro     test-linux-heavy      running
```

On a fleet where no host's substrate is registered, the AGENT section renders a single empty-state line (`no session substrate on any host — 11.0`); the HOST and JOB sections are unaffected, because neither depends on the substrate.

The TUI is optional convenience. Equivalent data remains available through:

```text
styrn fleet status --json
styrn agent list --all --json
styrn job list --json
```

Never require the TUI for automation.

## 11.11 Herdr metadata for informative panes (orig. §76)

Herdr supports display-only metadata separately from semantic lifecycle state. Styrn should report metadata such as:

```text
project = fricos
host = win-mini
job = 0199...
workflow = test-smoke
git_sha = 7a3fd91
machine_class = windows-light
```

This can make a pane appear as:

```text
Codex: FriCOS / win-mini / 7a3fd91
```

without overriding Herdr's authoritative:

```text
working
blocked
idle
done
```

This distinction matters. Styrn owns **operational metadata**. Herdr owns **agent lifecycle semantics**.

## 11.12 Do not fake remote agents into the local Herdr agent list (orig. §77)

Each Herdr server owns its own local terminal processes. Styrn should not create fake local panes merely to impersonate agents running on another machine. That would introduce:

- duplicated lifecycle state;
- synchronization races;
- confusing attach semantics;
- false process ownership.

Instead use:

```text
local Herdr built-in Agents view -> local agents (authoritative locally)
Styrn board / watch agent board  -> ALL agents, host-labelled (superset)
```

(Rev. E: the watch agent board, 14.5.1 item 4, deliberately *includes* local agents marked by host, making this a hierarchy — one cross-machine place to look — rather than two disjoint views; Herdr's native list remains the local authority.)

When the user wants the full native remote Herdr UI:

```text
styrn herdr attach linux-macpro
styrn herdr attach win-mini
```

Styrn hides the platform difference.

## 11.13 Remote Herdr attach abstraction (orig. §78)

Current Herdr remote behavior differs by target platform.

**Linux/macOS target** — Styrn can use Herdr's native remote attach where available:

```text
herdr --remote <host> --session fleet
```

**Windows target** — current Herdr remote-target support is not equivalent. Styrn should use:

```text
ssh -t <host> "herdr --session fleet"
```

The user-facing command remains:

```text
styrn herdr attach <host>
```

This transport choice belongs inside Styrn.

## 11.14 Styrn subscribes to Herdr lifecycle events (orig. §79)

Herdr exposes event subscriptions such as:

```text
pane.agent_status_changed
pane.agent_detected
pane.exited
workspace.created
workspace.closed
```

Styrn's remote RPC mode maintains an event stream per host (mechanics: Part 5.7). The remote Styrn process subscribes to its local Herdr socket and converts events into the versioned Styrn protocol. This gives cross-platform behavior even though Herdr's local socket is:

```text
Unix domain socket       Linux/macOS
named pipe               Windows
```

Only the remote Styrn binary needs to know that difference.

## 11.15 Herdr worktree events and Styrn (orig. §97)

Herdr plugin events can react to:

```text
worktree.created
```

The Styrn plugin can use this to:

- discover `.styrn.toml`;
- register project metadata;
- report Git SHA/branch metadata;
- prepare a job-local environment file;
- optionally detect missing toolchains.

Do not start expensive builds automatically on every worktree creation. Use events for lightweight preparation.

## 11.16 Herdr plugin installation UX (orig. §103)

During local development:

```text
herdr plugin link ./integrations/herdr
```

Production:

```text
styrn integrate herdr install
```

The Styrn command should locate its bundled plugin manifest. Possible deployment strategies:

**Bundle manifest as executable asset** — embed the TOML in the Styrn binary and materialize it into Styrn's config directory. Pros: truly one binary; plugin version exactly matches Styrn.

**Ship plugin directory beside executable** — simpler during development.

Recommended production approach: **embed the small manifest**. Then:

```text
styrn integrate herdr install
```

writes:

```text
<styrn-config>/integrations/herdr/herdr-plugin.toml
```

and invokes:

```text
herdr plugin link ...
```

## 11.17 Plugin state should remain disposable (orig. §104)

Herdr states that plugin config/state directories are path discovery; plugins own their contents. Styrn plugin state should contain only cache/presentation data:

```text
last selected project
last board filter
last selected host
view configuration
```

Authoritative inventory remains in Styrn's normal config. Do not create a second inventory inside Herdr plugin state.

## 11.18 Agent view projection (orig. §105)

On each machine, the plugin can optionally install a Herdr agent-view projection that shows:

```text
agents in current workspace
OR
blocked/done agents elsewhere
```

sorted by:

```text
attention
recent state transition
```

Herdr already supports this declaratively *(verify)*. This is a local-Herdr UX enhancement. It is not a substitute for Styrn's cross-machine board.

---

# Part 12 — Agent harnesses

## 12.1 Agent CLI providers (orig. §13)

Support at least:

```text
codex
claude
```

but avoid hard-coding the entire fleet around those two.

Manifest:

```toml
[agents.codex]
installed = true
command = "codex"

[agents.claude]
installed = true
command = "claude"
```

Future providers can include:

```text
opencode
cursor
copilot
aider
custom
```

## 12.2 Codex native Windows (orig. §14)

Codex has a native Windows sandbox and does not require WSL for native Windows development *(rev. A research claim — verify against current upstream docs)*.

Recommended configuration:

```toml
[windows]
sandbox = "elevated"
```

The elevated mode is preferred over the fallback unelevated sandbox. For worker automation, do not use full-access mode as the default.

Codex also supports non-interactive automation through:

```text
codex exec
```

However, when Styrn is using Herdr, interactive Codex sessions can remain inside Herdr and Styrn can control them through Herdr's API.

## 12.3 Claude Code native Windows (orig. §15)

Claude Code now runs natively on Windows and can use PowerShell. No WSL is required. Important current limitation *(verify)*:

> Claude Code's sandboxing supports macOS, Linux and WSL2; native Windows sandboxing is not currently supported.

Therefore an operator who needs OS-account separation should opt into:

```text
dedicated Windows account
+ NTFS permissions
+ Tailscale policy
+ Windows Firewall
+ Claude permission rules
+ isolated job directory
```

This is optional hardening, not a prerequisite for Styrn. In default
current-user mode the boundary instead includes that user's ambient access and
must be reported honestly; admission, quotas, job directories, Tailscale,
Firewall, and harness permissions still apply.

If using PowerShell as the primary Claude shell, configure it intentionally. (The concrete `settings.json` keys the Windows bootstrap script writes for this — `CLAUDE_CODE_USE_POWERSHELL_TOOL`, `defaultShell` — are **unverified inventions of the rev. A script**; confirm the real configuration surface against current Claude Code docs before shipping the bootstrap. Registered as part of S-18.)

## 12.4 macOS agents (orig. §16)

macOS is a first-class worker platform. Codex and Claude both run natively. Claude's sandbox uses macOS Seatbelt. Herdr supports macOS directly and can be a `herdr --remote` target.

A macOS machine manifest should record:

```toml
[capabilities]
os = "macos"        # normalized to [platform] per Part 2.3
arch = "aarch64"    # or x86_64
xcode = true
simulator = true
interactive_gui = true
```

Project profiles can then request a real Mac for:

- Xcode;
- Swift;
- macOS application tests;
- iOS Simulator;
- macOS filesystem behavior;
- Apple-specific signing or tooling.

## 12.5 MCP is also better for structured logs (orig. §90)

Both Claude Code and Codex already expose machine-readable non-interactive modes *(verify)*.

Claude supports:

```text
--output-format json
--output-format stream-json
--json-schema
```

Codex `exec` supports structured JSON/JSONL event output in current releases.

Styrn should normalize harness execution records into its own stable schema. Example:

```json
{
  "harness": "claude",
  "native_session_id": "...",
  "exit_code": 0,
  "result": "...",
  "usage": {},
  "raw_artifact": "job://win-mini/0199.../harness.jsonl"
}
```

Raw native output should remain available for debugging. Styrn's schema should not expose every upstream field as a permanent compatibility promise.

## 12.6 Canonical project instructions: AGENTS.md first (orig. §91)

Use `AGENTS.md` as the common project-level agent guidance. Codex natively understands hierarchical `AGENTS.md` files. Claude Code does not directly use `AGENTS.md` as its primary project memory, but current Claude Code explicitly supports importing it from `CLAUDE.md` *(verify)*.

Therefore use:

```text
AGENTS.md
```

as the canonical shared guidance. Then:

```markdown
# CLAUDE.md

@AGENTS.md

## Claude-specific notes

Use the Styrn MCP tools for remote validation when available.
```

This removes duplicated build/test instructions.

## 12.7 What belongs in AGENTS.md (orig. §92)

Keep it compact. Example:

```markdown
# Development execution policy

This repository uses Styrn.

Do not assume the current machine is the authoritative target platform.

Use declared Styrn workflows for builds and tests where available.

For native Windows validation, request the Windows workflow.
For native Linux validation, request the Linux workflow.
For native macOS validation, request the macOS workflow.

Do not bypass a resource-admission failure.

Do not run unrestricted parallel builds.

Do not use `cargo clean` as routine cleanup.

Automated build targets are disposable and job-scoped.

On native Windows:
- use native Windows APIs and PowerShell;
- never use WSL;
- do not assume Unix filesystem semantics.

Before claiming a cross-platform change is validated, inspect the corresponding Styrn job result.
```

Detailed resource values do **not** belong here. Those are enforced by machine/project policy.

## 12.8 Instructions guide; enforcement does not depend on them (orig. §93)

This is crucial. Claude's own documentation distinguishes instructions from hard enforcement: `CLAUDE.md` guides behavior but does not enforce it. The same general principle applies to agent instructions. Therefore:

```text
AGENTS.md          guidance
CLAUDE.md          guidance
MCP tool surface   capability restriction (least-privilege ergonomics — Part 4.5)
Styrn job          enforcement
OS account         security boundary
sandbox            additional boundary
```

Do not rely on prose such as:

```text
Please don't use too much RAM.
```

to protect a 16 GB build machine.

## 12.9 Harness launcher wrapper (orig. §94)

Styrn should provide:

```text
styrn harness run codex ...
styrn harness run claude ...
```

The command is a **resource-governed launcher**, and its governance — project identification, job context, computed limits, exported resource environment, metadata, and admission accounting — is substrate-independent. It runs in one of two contexts, which it detects for itself:

- **Pane context** — launched inside a pane of a registered session substrate (detected by the presence of Herdr's pane-identity environment, `HERDR_*` *(verify the exact variable set against current Herdr)*). This is the recommended context, and the one the parity invariant (12.9.1) governs.
- **Standalone context** — launched in any other terminal, including on a host whose substrate state is `none` (11.0). Everything below except step 7 applies identically; the registry entry records `context = "standalone"`. On Windows, standalone mode records the real exit status via the inert waiter (12.10); the Unix exec forfeit described in step 8 applies in both contexts.

It:

1. identifies the project;
2. creates/loads job context;
3. computes resource limits;
4. exports resource environment variables — *augmenting* the inherited environment, never scrubbing it (normative rules below);
5. records metadata;
6. starts the real agent;
7. preserves Herdr process detection **in pane context** — an invariant with per-OS mechanisms (below and 12.10), not a hope; in standalone context there is no observer and the step is vacuous;
8. records exit status — on Windows, via the inert waiter (12.10); on Unix/macOS, the normative exec model makes the child's exit status unrecoverable by Styrn, so the registry entry is instead closed by pid-death reconciliation with `exit_status: "unknown"` (rev. E; review D §4.1). This is acceptable because agent lifecycle truth lives in Herdr (11.2), not in the interactive session's registry entry.

For Rust projects it can export:

```text
CARGO_BUILD_JOBS
CARGO_TARGET_DIR
CARGO_INCREMENTAL=0
RUSTC_WRAPPER=sccache
RUST_TEST_THREADS
```

The important point is that these variables exist even if the agent directly invokes Cargo.

### 12.9.1 Herdr parity is an invariant, not an aspiration (new in rev. C; resolves S-33)

Revision B (and orig. §94) listed "preserves Herdr process detection" as a launcher step with no mechanism behind it. If wrapping broke Herdr's detection, the damage would cascade: Herdr's lifecycle states are the source of truth Styrn deliberately does not reimplement (orig. §12), so losing detection breaks `HarnessProvider` — `agent list/read/prompt/wait/stop/attach` — which breaks the `orchestrator` MCP profile and cross-agent delegation (13.9), and turns `styrn agent wait` into a command that never fires. The developer would experience "Styrn-launched agents are invisible and uncontrollable; manually launched ones work" — precisely the tool-fighting failure §0.6 forbids. Therefore:

> **Herdr parity (invariant — scoped in rev. F to a registered substrate).** When `styrn harness run <harness>` is launched **in pane context** (12.9) on a host whose session substrate is registered (11.0), the agent it starts MUST be indistinguishable to Herdr from the same agent started manually in a Herdr pane: same detection, same lifecycle-state transitions, same attach/prompt/read behavior. Styrn adds resource context and display metadata; it never degrades harness observability or control. If parity cannot be achieved on a platform or in a given environment, the launcher MUST refuse to wrap and instead launch the agent directly with the resource context applied via environment variables only — an unwrapped-but-governed session — rather than silently producing an undetectable one. The fallback is reported (stderr notice plus pane metadata `styrn_wrap = "env-only"`), never silent. **In standalone context the invariant is vacuous, not weakened:** the launcher uses mechanics identical to the wrapped path (exec on Unix, direct child plus inert waiter on Windows) with full resource governance, and makes no parity claim because there is no observer to be indistinguishable to. The scope condition may never be used to skip the parity probe (12.10 item 3) on a host whose substrate *is* registered.

**Environment handling (normative).** The launcher builds the child environment as *inherited environment + Styrn additions*, never from scratch. It may set only: the project resource variables (the Cargo set above and their `[workflows.*.environment]`-style equivalents), `STYRN_JOB_ID`/`STYRN_JOB_ROOT` for its own bookkeeping, and sccache wiring (7.12). Everything Herdr injected into the pane — all `HERDR_*` variables and anything Herdr's Codex/Claude integrations rely on for session/pane identity — passes through untouched. The launcher never unsets or overwrites a pre-existing `HERDR_*` variable.

**Hook coexistence (normative; the converse of 12.12–12.13).** Styrn's launcher does not read, write, disable, or reorder the hook configurations that Herdr's official Codex/Claude integrations install (11.5). Styrn's own optional hooks (12.13–12.14) are *additional* entries installed through each harness's supported merge mechanism, and `styrn integrate <harness> doctor` verifies Herdr's entries are still present after any Styrn integration change. Which specific hook entries Herdr installs is upstream-defined *(verify against current Herdr docs)*; the requirement on Styrn — leave them alone — does not depend on their contents.

**Interaction with admission (new in rev. B):** an interactive harness session started this way registers in the worker's job registry as a `light` job with a conservative committed budget (defaults: 2 GiB memory, 1 CPU, 10 GiB disk — 7.2), so admission (7.2) accounts for live agents when sizing validation jobs on the same machine. It has no wall-clock timeout (interactive sessions are human-bounded), but it *is* subject to the disk monitor and host floor.

## 12.10 Launcher implementation by OS (orig. §95)

**Unix/macOS (normative, rev. C; resolves S-33)** — the launcher prepares the job context and environment, then **replaces itself with the harness via `execvp`**. Not "where possible" — this is the specified behavior. After exec, the running process *is* `codex`/`claude`: same pid, same pane-foreground process, same process name and command line a manual launch would have — so anything Herdr observes about a manually launched agent holds identically, by construction. Exec can only fail *before* the agent starts (binary missing or not executable), which surfaces as an ordinary launch error (exit 11, `agent.harness_error`), never as a degraded wrapped session. Accepted consequence: after exec no Styrn process remains in the pane, so exit-status recording (12.9 step 8) and release of the interactive session's committed budget are handled by the worker's lazy registry reconciliation when the recorded pid dies (7.3) — not by a wrapper lingering in the process tree. The exit-status half of 12.9 step 8 is explicitly forfeited on Unix: reconciliation observes only that the pid died, so the entry closes as `exit_status: "unknown"` (rev. E; review D §4.1).

**Windows (normative, rev. C; resolves S-33)** — there is no exec. What Herdr actually observes about a pane's process tree — parent chain, image names, command lines — is upstream implementation detail this document must not guess at. (Rev. A asserted "Herdr's Windows detection already follows descendant agent processes and common wrappers"; treat that as **unverified** until probed.) The launcher therefore commits to the arrangement that minimizes its own footprint and keeps the agent a direct, visible child in the pane's tree:

1. `styrn harness run` creates a Job Object, spawns the harness as its **direct child** with the pane's inherited environment plus additions — no intermediate `cmd`/`conhost` layer of Styrn's making, no command-line rewriting: the child's image name and arguments are exactly the harness's own — assigns the child to the Job Object, and then stays **resident but inert**: one thread waiting on the process handle to record exit status. It allocates no console and touches no stdio; the agent inherits the pane's console directly, so screen-manifest-based detection (11.5) sees exactly what a manual launch produces.
2. The interactive-session Job Object is configured **without** `KILL_ON_JOB_CLOSE` — an agent must survive a launcher crash (contrast batch jobs, 7.8, where kill-on-close is the point). It exists for tree-scoped accounting and for `styrn agent stop`'s tree-kill only.
3. **Parity is verified, never assumed:** `styrn integrate herdr doctor` performs a live probe — launch a trivial wrapped process and an unwrapped control in Herdr panes, confirm Herdr's `agent list`/pane detection reports both identically. If the probe fails on a machine, the launcher on that machine downgrades to the env-only fallback of the 12.9.1 invariant and doctor reports why. The conformance test (16.6 item 7) keeps this honest in CI and in `styrn fleet selftest`. On a host whose substrate state is `none`, the probe is inapplicable: `styrn integrate herdr doctor` refuses per 11.0.3, and the launcher's standalone context (12.9) needs no probe.

The wrapper remains minimal on all platforms — now a requirement with a mechanism, not a hope.

## 12.11 Styrn launcher versus Herdr `agent start` (orig. §96)

Use both, but for different cases.

**Simple manual Herdr session** — the user can still run:

```text
codex
claude
```

normally. Herdr detects them.

**Styrn-created controlled session** — Styrn creates the worktree/pane, then launches:

```text
styrn harness run codex
```

or:

```text
styrn harness run claude
```

The launcher applies project/job resource context. Herdr still owns the terminal. This means Styrn does not become another terminal multiplexer.

## 12.12 Codex hooks: use cautiously (orig. §106)

Current Codex releases include hooks and Herdr's official integration uses them for session identity. However, the hook surface has been evolving rapidly, with recent upstream issues involving:

- async hooks;
- timeout field behavior;
- plugin-hook compatibility.

Therefore Styrn's **core policy must not depend on Codex hooks**.

Good uses:

```text
session metadata
notification glue
optional project convenience
```

Bad uses:

```text
the only mechanism stopping disk exhaustion
the only mechanism enforcing workflow use
```

Use process/job policy for hard controls.

## 12.13 Claude hooks: useful optional hardening (orig. §107)

Claude Code's hook system is currently much richer *(verify)*. It exposes events including:

```text
SessionStart
UserPromptSubmit
PreToolUse
PermissionRequest
PostToolUse
Notification
SubagentStart
SubagentStop
Stop
WorktreeCreate
WorktreeRemove
SessionEnd
```

Project hooks can be committed in `.claude/settings.json`. An optional FriCOS hardening hook could detect direct unbounded Cargo invocations and reject them. For example, deny:

```text
cargo test --workspace --all-features
```

when Styrn job context is absent.

But this should be **defense in depth**, not the universal enforcement mechanism, because Codex and other harnesses may not execute the same hook.

## 12.14 Do not require jq in harness hooks (orig. §108)

The dependency requirement suggests avoiding examples that parse hook JSON with `jq`. If Styrn supplies a Claude hook, configure the hook command as:

```text
styrn harness-hook claude pre-tool-use
```

Claude sends JSON on stdin. Styrn's Rust binary parses it with `serde_json` and returns the required JSON decision. This keeps the hook dependency-free. The same principle applies to any future Codex hook adapter.

## 12.15 Shared policy compiler (orig. §109)

A useful future component inside Styrn is:

```text
styrn project compile-integrations
```

Input:

```text
.styrn.toml
```

Output/merge targets:

```text
AGENTS.md guidance
CLAUDE.md import/glue
Claude project MCP config
Claude optional hardening hooks
Codex MCP config
Herdr metadata defaults
```

However, `.styrn.toml` remains authoritative for operational policy. Generated instruction text is only a presentation/adaptation layer.

## 12.16 Recommended project repository additions (orig. §110)

FriCOS should eventually contain:

```text
fricos/
├── .styrn.toml
├── AGENTS.md
├── CLAUDE.md
├── .mcp.json                 optional Claude project MCP registration
├── .codex/
│   └── config.toml           optional when the supported Codex version
│                              handles project-level MCP config reliably
└── ...
```

Suggested `CLAUDE.md`:

```markdown
@AGENTS.md

## Claude Code

Prefer the Styrn MCP tools for remote platform validation.
Do not bypass Styrn resource-admission failures.
```

## 12.17 Harness-native versus Herdr-native orchestration (orig. §115)

There are three useful patterns.

**Human launches remote specialist:**

```text
human
 -> Styrn
 -> remote Herdr
 -> Codex/Claude
```

**Main agent delegates remote validation:**

```text
human
 -> local Codex/Claude
 -> Styrn MCP
 -> remote Styrn job
 -> native platform build/test
```

**Main agent delegates another agent:**

```text
human
 -> local orchestrator agent
 -> Styrn MCP (orchestrator profile)
 -> remote Herdr
 -> remote specialist agent
```

Styrn can support all three without changing the underlying machine model.

## 12.18 `styrn integrate` command group (orig. §102)

Recommended:

```text
styrn integrate status [--json]

styrn integrate herdr install [--json]
styrn integrate herdr remove [--json]
styrn integrate herdr doctor [--json]

styrn integrate codex install [--scope user|project] [--json]
styrn integrate codex remove [--json]
styrn integrate codex doctor [--json]

styrn integrate claude install [--scope user|project] [--json]
styrn integrate claude remove [--json]
styrn integrate claude doctor [--json]

styrn integrate all [--json]
```

`integrate all` can:

1. detect Herdr;
2. install Herdr's official Codex integration;
3. install Herdr's official Claude integration;
4. link Styrn's Herdr plugin;
5. register Styrn MCP with supported harnesses;
6. validate configuration;
7. report pending authentication/trust actions.

On a host whose substrate state is `none` (11.0), steps 1–4 are reported as `skipped (substrate: none)` — informational, not failed — and the harness MCP registrations (step 5) proceed: they do not depend on Herdr.

## 12.19 Research conclusions on harness configuration (orig. §124)

*(Recorded from rev. A's research pass of 2026-09-01. These are external-behavior claims that cannot be re-verified from this repository — verify against current upstream docs at implementation time. The design's posture if any claim is wrong: every harness-specific behavior sits behind the `HarnessProvider` trait and the `integrate` doctor commands, so a drifted upstream surface degrades to a reported integration failure, never a silent policy hole.)*

**Claude Code** currently provides:

- native macOS/Linux/Windows;
- native Windows PowerShell support;
- rich lifecycle hooks;
- project/user/managed settings;
- project `CLAUDE.md`;
- `CLAUDE.md` import of `AGENTS.md`;
- project MCP configuration;
- JSON and streaming JSON non-interactive output;
- JSON-schema constrained non-interactive output;
- native sandboxing on macOS/Linux but not native Windows.

This makes Claude a strong fit for:

```text
Herdr session identity
+
Styrn MCP
+
AGENTS.md imported through CLAUDE.md
+
optional PreToolUse hardening
```

**Codex** currently provides:

- native macOS/Linux/Windows;
- native Windows sandbox;
- AGENTS.md hierarchy;
- MCP client support;
- `codex exec`;
- structured event output;
- hooks used by Herdr for session identity;
- an evolving plugin/MCP/hook surface.

This makes Codex a strong fit for:

```text
Herdr session identity
+
Styrn MCP
+
AGENTS.md
+
Styrn controlled launcher
```

Do not make current Codex hook details part of Styrn's hard resource-enforcement contract.

---

# Part 13 — The Styrn MCP server

## 13.1 The most useful harness integration (orig. §81)

Both Codex and Claude Code can use MCP servers. Implement:

```text
styrn mcp serve
```

as a stdio MCP server in the **same Rust executable**. This is a major developer-experience improvement.

Instead of an agent being told:

```text
SSH to win-hp and run tests.
```

the agent gets a controlled tool:

```text
styrn_workflow_run(
    project="fricos",
    workflow="test-windows-heavy",
    revision="HEAD"
)
```

(Revision strings are resolved per Part 8.4 — the MCP server resolves `HEAD` in the project root it is scoped to, and the job runs the exact SHA.)

Styrn performs:

- host selection;
- Git worktree creation;
- disk admission;
- RAM/CPU limits;
- timeout;
- Cargo environment;
- log collection;
- cleanup.

The harness never needs unrestricted SSH credentials or knowledge of the machine topology.

## 13.2 Why MCP is better than giving the harness SSH (orig. §82, reframed per Part 4.5)

Giving Codex or Claude raw SSH to every worker means the harness can:

- bypass workflow policy;
- run unbounded builds;
- manipulate unrelated workspaces;
- alter host configuration;
- fill disks;
- stop services;
- create arbitrary agent processes.

A Styrn MCP server can expose a much narrower vocabulary.

Good:

```text
plan validation
run allowed workflow
read job
read logs
list remote agents
read remote agent
```

Bad default MCP tool:

```text
ssh_exec(host, arbitrary_command)
```

Keep arbitrary remote execution a **human/controller CLI capability**, not a default agent tool.

**Reframing (rev. B; amended rev. G; resolves S-06):** the narrow vocabulary is what a *cooperating* agent uses, and it is genuinely valuable — less context, fewer footguns, reviewable approvals. It is **not containment** of a hostile agent on a machine where the same user account can run `styrn`/`ssh` directly, and it does not survive `.styrn.toml` tampering (Part 4.5, 9.5). Both residual vectors terminate at the selected posture: admission, quotas, and timeouts in both modes, plus unprivileged credential-free account separation only in dedicated mode. State the guarantee in those terms and no further.

## 13.3 MCP profiles (orig. §83; tool names normalized per §0.4)

Expose different tool surfaces according to trust.

**`readonly`** — for ordinary analysis:

```text
styrn_fleet_status
styrn_host_status
styrn_host_capabilities
styrn_agent_list
styrn_agent_read
styrn_job_list
styrn_job_get
styrn_job_logs
styrn_workflow_list
styrn_workflow_plan
```

**`developer`** — adds project-scoped operations:

```text
styrn_workflow_run
styrn_workflow_cancel
```

The server can only run workflows declared by the current project's `.styrn.toml`.

`styrn_workflow_cancel` — previously a dangling name with no underlying operation (review D §4.4) — is defined (rev. E): resolve the target by `submission_id` (7.8.6) or job id via the submission index (6.7), then issue `job.cancel` for each job that submission created. It introduces no new RPC method. The CLI twin is `styrn workflow cancel <submission-id|job-id>` (10.5). A matrix run's member jobs are individually cancelable by the ids `matrix run` prints as it dispatches; interrupting an attached `matrix run` (Ctrl-C) offers to cancel its members.

**`orchestrator`** — adds:

```text
styrn_agent_start
styrn_agent_prompt
styrn_agent_wait
styrn_agent_stop
```

Still restricted to enrolled hosts and declared projects.

**Substrate gating (rev. F; S-40):** each profile's tool surface is stable regardless of fleet substrate state — tools are **not** hidden when no host has a substrate, because fleet state changes and a vanishing tool list is worse than a clear refusal. `styrn_agent_list` answers empty-and-healthy over substrate-`none` hosts; every other `styrn_agent_*` tool directed at such a host returns a structured tool error carrying `capability.substrate_unregistered` per 11.0.3. Host selection in `styrn_agent_start` (13.9) treats the `agent` capability — which implies a registered substrate (11.0.2) — as a hard requirement, so a substrate-less fleet yields the same `capability.unsatisfied`-family refusal an unsatisfiable workflow requirement does.

**`admin`** — potentially adds machine maintenance. Do **not** expose `admin` to normal coding-agent sessions.

Example:

```text
styrn mcp serve --profile developer
```

**Profile authority (new in rev. B; part of S-06):** the `--profile` flag is client-configured (it lives in `.mcp.json`/Codex config, which the agent's user can edit), so it cannot *widen* privileges by itself. The server intersects the requested profile with the machine-level ceiling in Styrn's own config (`[mcp] max_profile = "developer"` in the controller/machine config file, which on hardened setups is not writable by the agent's account — Part 4.5). Requesting a profile above the ceiling yields the ceiling, with a warning in the server's startup diagnostics.

## 13.4 MCP tools are project-scoped by default (orig. §84)

If Styrn is launched inside FriCOS:

```text
styrn mcp serve --profile developer
```

it determines the project from:

1. MCP roots, when supplied by the client;
2. harness-provided project root environment;
3. process working directory;
4. nearest `.styrn.toml`.

Then the MCP surface should default to:

```text
this project
```

not:

```text
every project on every machine
```

An agent working on FriCOS does not need to discover unrelated repositories.

## 13.5 MCP approvals matter (orig. §87)

A workflow tool that starts a remote build spends machine time and may modify a worktree. Therefore:

```text
styrn_workflow_plan
styrn_host_status
styrn_job_logs
```

can usually be automatic. But:

```text
styrn_workflow_run
styrn_agent_start
styrn_agent_stop
styrn_workflow_cancel
```

should respect harness approval controls. Styrn should describe mutating MCP tools accurately (MCP annotations: `readOnlyHint`/`destructiveHint`) so the harness can apply its tool-approval mechanism.

It should also have an independent Styrn policy:

```toml
[mcp]
profile = "developer"

[mcp.mutations]
workflow_run = "allow-declared"
agent_start = "deny"
host_admin = "deny"
```

(`[mcp.mutations]` keys are *operation names* in Styrn's own config, deliberately unprefixed — the `styrn_` prefix belongs to the MCP tool namespace the harness sees, per §0.4; the config key `workflow_run` governs the tool `styrn_workflow_run`.)

Harness approval and Styrn authorization are separate layers.

## 13.6 Workflow plan is first-class (orig. §118)

Before mutating a remote machine, an agent should be able to call:

```text
styrn_workflow_plan
```

Example result:

```json
{
  "project": "fricos",
  "workflow": "test-windows-heavy",
  "revision": "7a3fd91",
  "candidate_hosts": [
    {
      "name": "win-hp",
      "score": 92
    }
  ],
  "selected_host": "win-hp",
  "resources": {
    "compile_jobs": 6,
    "test_jobs": 6,
    "free_disk_bytes": 731214159872,
    "admission": "pass"
  },
  "mutating": true
}
```

This improves agent reasoning and lets the user see what will happen before approval. Per Part 2.1, `"admission": "pass"` is a *prediction*; the worker re-decides at submission and the plan output says so in its human rendering.

## 13.7 Remote validation returns concise structured failure data (orig. §119)

An agent does not need 30 MB of build log in context. `styrn_job_get` should return:

```json
{
  "state": "failed",
  "workflow": "test-windows-heavy",
  "host": "win-hp",
  "exit_code": 101,
  "summary": "1 test failed",
  "failures": [
    {
      "name": "filesystem::windows::junction_test",
      "log_excerpt": "...",
      "artifact": "job://win-hp/0199.../stderr.log"
    }
  ]
}
```

Then the harness requests full logs only if needed. This controls context growth.

## 13.8 Example MCP tool model (orig. §117)

A compact v1 MCP surface could be:

```text
styrn_fleet_status
styrn_host_status
styrn_workflow_list
styrn_workflow_plan
styrn_workflow_run
styrn_job_get
styrn_job_logs
styrn_job_artifact_read
styrn_agent_list
styrn_agent_read
```

Orchestrator profile adds:

```text
styrn_agent_start
styrn_agent_prompt
styrn_agent_wait
styrn_agent_stop
```

Avoid exposing dozens of tiny tools initially. Too many MCP tools add context and tool-selection complexity.

## 13.9 Cross-agent delegation through MCP (orig. §89)

Later, an orchestrating agent can request:

```text
styrn_agent_start(
  host_selector = {
    os = "windows",
    heavy_build = false
  },
  harness = "codex",
  project = "fricos",
  revision = "feature/foo",
  task = "Investigate the native Windows failure"
)
```

That remote Codex instance lives in the remote host's Herdr server. The orchestrating agent can then:

```text
styrn_agent_read
styrn_agent_prompt
styrn_agent_wait
```

through Styrn. This creates a clean hierarchy:

```text
human
  |
main agent
  |
Styrn policy
  |
remote specialist agent
```

Do not enable this in the default `developer` MCP profile. Use `orchestrator`. Otherwise one agent can accidentally create an uncontrolled number of other agents.

**Fan-out bound (new in rev. B):** the orchestrator profile additionally enforces a numeric ceiling — `[mcp] max_agents_started_per_session` (default 3) — because "do not enable by default" is not a limit once it *is* enabled.

## 13.10 A powerful developer workflow (orig. §88)

Suppose Codex is running locally on the M1 inside the FriCOS worktree. The agent changes Windows-related code. Instead of saying:

```text
I can't validate Windows here.
```

it can call:

```text
styrn_workflow_plan("test-windows-heavy")
```

receive:

```text
selected host: win-hp
estimated compile jobs: 6
disk admission: pass
revision: 7a3fd91
```

then, with approval:

```text
styrn_workflow_run("test-windows-heavy")
```

The job executes natively on Windows. Codex can query:

```text
styrn_job_get(...)
styrn_job_logs(...)
```

and fix the resulting Windows failure without you manually copying logs. This is the primary reason MCP integration is worth implementing.

## 13.11 Claude Code MCP integration (orig. §85)

Claude Code supports local stdio MCP servers and project-scoped `.mcp.json` *(verify)*. A project can contain:

```json
{
  "mcpServers": {
    "styrn": {
      "type": "stdio",
      "command": "styrn",
      "args": [
        "mcp",
        "serve",
        "--profile",
        "developer"
      ]
    }
  }
}
```

(This is the shipped companion file `claude.mcp.example.json`, unchanged.)

Claude Code supplies a stable project-root context to local stdio MCP servers and supports project-scoped server approval/trust. Styrn should provide:

```text
styrn integrate claude --project .
```

which can:

1. detect Claude;
2. add or merge the Styrn MCP entry safely;
3. validate JSON;
4. never delete unrelated MCP servers;
5. report that the project may require first-time trust/approval.

## 13.12 Codex MCP integration (orig. §86)

Codex CLI is an MCP client and supports configured MCP servers *(verify)*. The user-level configuration form is conceptually:

```toml
[mcp_servers.styrn]
command = "styrn"
args = ["mcp", "serve", "--profile", "developer"]
```

(This is the shipped companion file `codex.styrn.example.toml`, whose header correctly instructs merging into the appropriate Codex config scope rather than overwriting.)

Codex currently has a richer and still-evolving MCP/config/plugin surface, so Styrn should not hard-code assumptions about a single future config location. Provide:

```text
styrn integrate codex
```

which:

1. detects Codex version;
2. detects supported configuration scope;
3. installs/merges the Styrn MCP registration;
4. validates using Codex's own MCP/config commands where possible;
5. records exactly what it changed;
6. leaves unrelated Codex configuration untouched.

Current Codex sources indicate both normal MCP-client configuration and newer project/plugin-scoped mechanisms exist, while parts of the project-scoping UX continue to evolve *(verify)*.

---

# Part 14 — Notifications, monitoring, and observability

## 14.1 Event monitoring and notifications (orig. §40 + §80, unified; resolves S-12)

Revision A specified this feature twice under two different commands (`styrn watch --notify` in §40, `styrn monitor --notify` in §80). Canonical form (§0.4): **`styrn monitor`** is the headless event follower; `styrn watch` is the optional TUI and has no `--notify`.

A controller can run:

```text
styrn monitor --notify
```

It keeps event streams open to inventory hosts (Part 5.7) and emits native notifications for important transitions:

```text
working -> blocked
working -> done
host online -> offline
job running -> failed
disk pressure warning
```

When a remote agent moves from `working` to `blocked`, the local controller calls the OS notification API. This is a presentation feature, not part of the remote protocol. Platform presentation adapters:

```text
macOS       UserNotifications / osascript fallback
Windows     Windows notification API
Linux       freedesktop notification
```

Keep it optional. No central server is required. Machine consumption uses:

```text
styrn monitor --jsonl
```

emitting `styrn.event.v1` lines (Part 10.1). Delivery is at-most-once (Part 5.7); anything that must be *reliable* is state, queried on demand, not an event.

## 14.2 Job records are the primary observability surface (new in rev. B; part of S-19)

v1 deliberately ships **no metrics pipeline**. The durable record is per-job:

- `status.json` — state machine truth;
- `resource.jsonl` — sampled CPU/RSS/disk of the job tree (from the supervisor's monitor, 7.5);
- `result.json` — outcome, timings, inner exit code, SHA, budgets vs. actuals.

`resource.jsonl` doubles as capacity-planning data: `styrn job show --json` surfaces peak memory/disk vs. the hints, so `[resource_hints]` can be tuned from evidence instead of folklore. A metrics exporter, if ever wanted, reads these files; nothing in v1 depends on one.

## 14.3 Audit logging (new in rev. B; resolves part of S-19)

Two append-only JSONL logs, no daemon:

1. **Worker audit log** — `<paths.logs>/audit.jsonl`: every registry mutation (job submitted/denied/started/finished/cancelled/killed, key authorized/revoked, clean run), each entry carrying timestamp, acting controller (`machine_id` from the session hello), and parameters. Written under the registry lock, rotated by the daily maintenance task.
2. **Controller audit log** — `~/.config/styrn/audit.jsonl`: every mutating command this controller issued (enroll, remove, revoke, workflow/matrix run, agent start/stop, exec), with target host and outcome.

Together they answer "who did what, from where, when" for a multi-controller fleet without any shared infrastructure. They are diagnostic records, not tamper-proof logs — consistent with the single-operator trust model (Part 4.5).

## 14.4 Backup and restore (new in rev. B; part of S-19)

- **Controller state** (`inventory.toml`, manifest caches, known_hosts pins, jobs-index, audit log) is a directory of small files: back up `~/.config/styrn` (or `%APPDATA%\Styrn`) with any file backup, or adopt the fleet-config git repo (Part 6.7) for the shareable subset. Loss of a controller is recoverable by re-enrolling hosts (TOFU re-pin with console-verified fingerprints).
- **Worker state is disposable by design**: jobs are ephemeral, reference repos are re-pushable, caches are rebuildable, the manifest is regenerable by bootstrap + `machine init` (except `machine_id` — which is why doctor backs it up into the enrollment record on every controller that enrolls the host; a reinstalled worker gets a *new* machine_id and is treated as a new machine, which is the correct security posture).
- There is deliberately no fleet-wide backup mechanism to build or operate.

## 14.5 The `styrn watch` TUI (specification; Phase 8 — new in rev. E)

`styrn watch` has been contemplated since orig. §25/§39/§75 and deliberately left last (16.3 Phase 8; orig. §59's "do not start with the TUI" stands). This section specifies it so "later" has a defined shape. It is a **ratatui** application — the one place ratatui belongs, per 15.4.2's split: prompts for setup, ratatui for watch.

### 14.5.1 Views

**Tier 1, in build order:**

1. **Matrix view** (live projection of 8.6). A workflows × hosts grid; each cell advances `queued → admitted → running → PASS/FAIL` (failure cells show the inner exit code), with job id and elapsed time; Enter on a cell opens the job view. 8.6's human table exists only at completion today — this is the most TUI-shaped surface in the design, and previously unserved.
2. **Job view with resource trace.** Running (and recent) jobs; per job: state, elapsed vs. `timeout_seconds`, and memory/CPU/disk traces drawn from the supervisor's `resource.jsonl` samples plotted **against the committed budget** (7.2) and `max_job_disk_bytes` (7.5) — the resource governor made legible in real time rather than a post-mortem file read (14.2).
3. **Fleet board.** Exactly 11.10's layout (hosts / agents / jobs), kept as drawn there.
4. **Agent board.** All agents on all hosts — **a superset that includes local agents, every row marked by host** — sorted blocked-first (attention), then by most recent transition (11.18's ordering); Enter attaches via the platform-appropriate transport (11.13). This makes 11.12's two-surface split a deliberate **hierarchy** rather than a split brain: Herdr's native Agents view stays authoritative for the local machine; the watch agent board is the single cross-machine place to look. It displays Herdr's lifecycle states and never invents its own (11.11: Styrn owns operational metadata; Herdr owns lifecycle semantics). Hosts with substrate `none` (11.0) contribute no rows and no warnings; when that leaves the board empty it shows the 11.10 empty-state line. The board is a projection of `agent list --all` (14.5.2 rule 1), which already answers empty-and-healthy on such a fleet (11.0.3).
5. **Doctor view.** `doctor` / `fleet doctor` as pass/fail rows with expandable finding detail (`id`, `severity`, `message`, `remediation` — 6.5), and a remediation trigger where the remediation is itself a safe styrn command (e.g. `host refresh`) — routed per 14.5.2 rule 2.

**Tier 2:** a **workflow-plan review pane** (13.6's plan rendered read-before-approve, feeding the same confirmation the CLI would show); a **clean-plan confirm** (`clean plan` → review → `clean run`); and a **scheduling explainer** — for a chosen workflow, each host's elimination reason (capability unmet / unreachable / predictive admission fail / final score), i.e. 6.4's algorithm made visible: "why won't this schedule?".

### 14.5.2 Constraints (normative)

1. **Projection rule — absolute (10.5/10.6):** every view renders data the JSON API already exposes (`fleet status`, `job list/show` incl. `resource.jsonl`, `agent list`, `doctor --json`, `workflow plan --json`). Nothing is reachable only through the TUI. The TUI persists nothing but view preferences (per 11.17, in Herdr plugin state when running as the plugin pane, else under `STYRN_CONFIG_DIR`).
2. **Read-only by default; mutations gated.** Attach, cancel, remediation, and plan approval invoke the same CLI/RPC paths with the same authorization and confirmation as typing the command — the TUI is never a privilege bypass (the 4.5 layer order is unchanged by presentation).
3. **Event-driven, not polling.** Subscribes to the 5.7/11.14 event streams (`styrn.event.v1`); hosts without a live event session degrade to slow refresh (≥ 10 s). Resource traces ride the job's existing status/log stream, never per-frame RPC queries.
4. **Herdr pane citizenship** (`styrn watch --herdr`, 11.6):
   - *Keybinding hygiene:* never bind Herdr's prefix or pane-navigation chords; watch bindings are plain unmodified keys with documented alternates; the pane must remain escapable at all times.
   - *Alt-screen caution:* Herdr's integrations rely on screen-manifest detection of agent panes (11.5). watch sets pane metadata `styrn_pane = "watch"` (11.11) so Herdr tooling can classify it, must not render agent-lookalike content, and its use of the alternate screen buffer must be confirmed harmless to Herdr's pane-content reading on all three OSes *(implementer confirm against current Herdr; exercised alongside the 16.6 item 7 environment)*.
   - *Narrow panes degrade by column-drop* (priority: state > name > host > detail), never horizontal scroll.
5. **Zero-argument project scoping (§0.6):** launched inside a Herdr workspace or project directory, watch resolves context per 11.8 (pane cwd → git root → `.styrn.toml`) and opens filtered to that project; `--all` widens.
6. **Terminal support:** 16-color-safe with degradation, mouse optional never required, minimum 80×24.

### 14.5.3 Explicitly not TUI (decisions preserved, not reopened)

- **`setup --interactive`** remains an `inquire` prompt sequence (15.4.2's decision): a wizard is a linear Q&A with five questions, not a monitoring surface, and prompts behave better over SSH and dumb terminals.
- **`monitor`** remains headless (14.1): it exists precisely for no-TTY contexts and notification plumbing; watch may run alongside it, consuming the same events.
- **`fleet versions`** remains a static table (6.6): nothing about it is live; terminal output plus `--json` suffice.

---

# Part 15 — Machine setup: the `styrn setup` subsystem (new in rev. D)

## 15.1 What this Part is, and what it supersedes

This Part **replaces wholesale** the rev. B/C "Bootstrap and provisioning" Part 15 and is the new home of orig. §42–§49, §60, and §111–§114. The operator's requirement, verbatim and binding:

> "the bootstrap story is very weak and cumbersome. ideally a user should be able to execute `styrn setup --install ssh,tailscale --role both`, `styrn setup --config path/to/setup-config.toml` or `styrn setup --interactive` (TUI based configuration). the styrn binary should be able to autodetect what is already installed, what can be installed, etc. and perform the required installations and configurations automatically. this is a very important part to make styrn adoptable. go deep."

> "if styrn is not able to perform bootstrap by itself, it should be able to generate platform specific bootstrap shell/powershell/etc. scripts to be executed by the user"

That CLI surface is adopted **verbatim** (15.4); script generation is specified in 15.11. The §0.6 tenet applies here harder than anywhere else in the document — setup is the surface that decides whether anyone adopts the tool.

**Evidence discipline for this Part.** The mechanics below are grounded in a dedicated research pass whose findings carry explicit evidence tags, preserved here: **[verified: Sn]** = checked against the cited primary source (source list in 15.15); **[well-established]** = standard practice not re-verified; **[judgment]** = design recommendation; **[unverified]** = must be confirmed by the implementer before this hardens, with the design stated to degrade gracefully if the claim is false. A `[judgment]` tag on a sentence means the *choice* is ours, not a claim of external fact.

## 15.2 The engine: probe → observed state → desired state → diff → plan → apply (absorbs orig. §42)

One engine, one shape:

```text
Probe layer (read-only, unprivileged, per-OS impls behind one trait)
      │  produces
ObservedState  ──┐
                 ├──> Diff ──> Plan (ordered Vec<Action>) ──> Apply (with receipt journaling)
DesiredState  ───┘
(from flags | config file | interactive answers | defaults)
```

### 15.2.1 The probe layer

One `Capability` probe per concern — `TailscaleProbe`, `SshdProbe`, `ServiceAccountProbe`, `DirTreeProbe`, `ToolProbe{git, rustup, sccache, codex, claude, herdr}`, `SubstrateProbe{winget, brew, apt}`, `ServiceProbe{styrnd}` — each returning a typed status:

```rust
enum ProbeStatus {
    Absent,
    Present { version: Option<String>, healthy: bool },
    Broken { reason: String },
    Unknowable { reason: String },
}
```

Probes **never mutate and never require elevation** [judgment]. A tool that demands admin just to *look* is the §0.6 anti-pattern.

### 15.2.2 `doctor` and `setup` are two frontends of one probe layer (amends Part 6.5)

**`doctor` = probe + render. `setup` = probe + diff + plan + apply.** Two probe codebases is exactly how the rev. A shell scripts rotted — each script re-implemented detection badly and divergently. Unification means every health check Styrn can express is automatically a setup precondition, and every setup precondition is automatically a doctor check. `nix-installer` (plan/apply with a reviewable JSON plan) and Terraform (diff/plan/apply) both validate the shape [verified: S1] [judgment on unification].

**Consequence for Part 6.5 (scoped in rev. E; review D §4.3):** doctor has two layers, and only one is this probe layer. **Controller-side checks** — Tailscale/SSH reachability, protocol compatibility, clock skew vs. the controller, manifest-cache staleness — are relational by definition (clock skew is *defined* against the querying controller) and cannot be worker-local probes; they are implemented in the controller's doctor frontend. Everything else in 6.5's checklist is a **worker-local probe**, shared verbatim with setup. The one-to-one rule binds the worker-local layer only: a worker-local doctor check may not exist without a probe, and vice versa. (6.5 carries the matching split.)

### 15.2.3 The Action model

Every planned change is a variant of one typed `Action` enum implementing:

```rust
trait ActionImpl {
    fn check(&self) -> Done | Todo;               // idempotency gate
    fn apply(&mut self) -> Result<ReceiptEntry>;  // performs the change
    fn revert(&self, e: &ReceiptEntry) -> Result<()>;  // uninstall path
    fn privilege(&self) -> None | Root | Admin;   // what apply() needs
    fn describe(&self) -> PlanLine;               // dry-run / confirm display
    fn render_posix(&self) -> String;             // script renderer (15.11)
    fn render_powershell(&self) -> String;        //   — same parameters, cannot drift
}
```

This is `nix-installer`'s action architecture [verified: S1] — typed, individually reversible, journaled — plus the two `render_*` methods that make script emission a third renderer of the same plan (15.11). `apply()` is invoked only when `check()` says `Todo`; re-running `styrn setup` on a healthy machine is a no-op that prints "nothing to do".

### 15.2.4 `NeedsHuman` is a first-class outcome (absorbs orig. §42's pending-action rule and orig. §17's examples)

Orig. §42's core rule stands verbatim: **the setup process never silently claims that an interactive step succeeded.** Actions that cannot be completed programmatically resolve to `NeedsHuman { instructions, fragment: Option<ScriptFragment> }` [judgment]: setup completes, records the item in the receipt as `pending`, prints it in a distinct final block — as a copy-pasteable command block when a runnable fragment exists, prose only when none does — and **doctor keeps nagging until the probe passes**. The pending item is also written to the manifest as a `[[pending_actions]]` table (unchanged schema; see Part 3.4's example), so enrollment output and `styrn host doctor` surface it exactly as before. The classic examples (orig. §42):

```text
Tailscale login required
Codex ChatGPT login required
Claude login required
macOS Screen Sharing consent required
Codex elevated Windows sandbox approval required
RDP password configuration required
```

### 15.2.5 Orig. §42's principles, restated as engine properties

The rev. A bootstrap principles are not dropped; they are what the engine *is*:

| Orig. §42 principle | Where the engine delivers it |
|---|---|
| idempotent / safe to rerun | `check()`-before-`apply()` gate (15.2.3); resumable-forward (15.6.3) |
| explicit about privilege | `privilege()` per action; badges in the plan display (15.4.4); one protected publisher that delegates `None` effects to the original principal (15.5) |
| native to the OS; WSL-free | per-OS action implementations (15.7); WSL never appears |
| generates the machine manifest | manifest is setup *output* (15.3.2) |
| reports incomplete interactive steps | `NeedsHuman` (15.2.4) |
| non-destructive to unrelated config | receipt-scoped ownership: uninstall removes only what Styrn created (15.6.2) |
| `--dry-run` mode "eventually" | first-class now: plan display + `--dry-run` (15.4) |

## 15.3 Three files, three jobs: config in, manifest out, receipt as journal

**Never merged** [judgment; adopted]:

| File | Direction | Role |
|---|---|---|
| `setup-config.toml` | input | desired state — human-authored or wizard-written; copy it to the next machine and run `styrn setup --config` to reproduce it |
| `machine.toml` (Part 2.4) | output | observed identity — machine_id, platform, probed component versions, roles, pending actions, last-setup timestamp. **Setup generates and refreshes the manifest; it never reads it as desired state.** |
| `receipt.json` | journal | what Styrn changed — the `--uninstall` input and the ownership authority (15.6) |

### 15.3.1 `setup-config.toml` schema (new in rev. D)

```toml
schema_version = 1

role = "worker"                        # "controller" | "worker" | "both"
name = "win-mini"                      # default: hostname

[installation]
scope = "user"                         # default; "user" | "system"

[components]                           # absent table = role defaults (15.3.3)
ssh-server = true
tailscale = true
git = true
rust = { enabled = true, toolchain = "stable" }   # optional per-component version pin
sccache = true
herdr = true
codex = true
claude = true
styrnd = true                          # worker service (15.9); default true for workers
sleep-policy = true                    # workers must not sleep (rev. E; 15.7.6, S-38)
rdp = false                            # Windows only; optional GUI access (Part 3.4)
cockpit = false                        # Linux only; optional web admin (Part 3.4)

[account]
mode = "current-user"                  # default; "current-user" | "dedicated"
# name = "styrn"                       # dedicated mode only; suggested, never required

[dirs]
root = ""                              # empty = OS default (Part 4.1 layout)

[ssh]
authorized_keys = [                    # controller public keys to authorize (Part 4.3)
  "ssh-ed25519 AAAA... styrn-mbp-main",
]

[tailscale]
mode = ""                              # macOS only: "" (default = standalone GUI) | "tailscaled"
auth_key_env = "TS_AUTHKEY"            # env var consulted for headless auth;
                                       # the key itself NEVER appears in this file [judgment]

[pending_policy]
fail_on_pending = false                # true: exit non-zero if any NeedsHuman remains
```

Layering, lowest → highest: **built-in defaults < config file < environment variables < CLI flags** — the k3s layering model [verified: S7]. The effective merged desired state is echoed into the plan header so no one has to compute precedence in their head.

### 15.3.2 Relationship to the manifest — decided

Setup **generates the manifest** (and re-generates it on every run, preserving `machine_id` per Part 2.4.1). The manifest is never desired state; a hand-edit to `machine.toml` that contradicts probing is reported by doctor as drift, not silently honored. `[resources.policy]` values (Part 7.4) are seeded by setup from detected hardware using the Part 7.4 tables and are the one manifest region setup will *not* overwrite on re-run once an operator has edited it (policy is operator-owned; identity and detection are setup-owned).

For a worker role, setup writes `[worker_identity]` from the resolved stable
uid/SID and makes `[transport].user` the same validated login name. Both fields
are setup-owned. A later name-to-id mismatch is reported as drift; neither
setup nor RPC falls back to the current process user.

### 15.3.3 Roles and component sets (absorbs orig. §43's profiles)

Orig. §43's bootstrap profiles map onto role defaults plus `--install`:

| Orig. §43 profile | Rev. D equivalent |
|---|---|
| `core` | the baseline set every role gets: tailscale, ssh (server for workers, client check for controllers), git, styrn binary, dirs, manifest |
| `developer` | `--install rust,sccache,herdr,codex,claude` (the dev-tool extras) |
| `controller` | `--role controller` (adds config dir and lazy keypair per 4.3.1; no worker runtime or styrnd) |
| `worker` | `--role worker` (selects a worker identity, adds the dir tree, styrnd, and enrollment card) |
| `both` | `--role both` |

For the initial fleet, the rev. A guidance "use `developer + worker`" becomes: `styrn setup --role worker --install rust,sccache,herdr,codex,claude`.

## 15.4 The three invocation modes, one code path (absorbs orig. §46, §113)

All three modes differ **only** in how `DesiredState` is constructed; probe/diff/plan/apply are shared:

1. **`styrn setup --install ssh,tailscale --role both`** — flags parse into a DesiredState fragment merged over defaults. `--install` selects components; everything else defaulted.
2. **`styrn setup --config path/to/setup-config.toml`** — file deserialized into DesiredState, then env/flags layered per 15.3.1.
3. **`styrn setup --interactive`** — a prompt sequence fills the same DesiredState struct **and writes the answers to `./setup-config.toml`** (telling the user where), so every interactive run is replayable non-interactively — the `gh auth login` philosophy of interactive-by-default with a scriptable twin [verified: S6].

Shared tail for all modes: print plan → confirm (skipped by `--yes`) → apply in
the already-selected scope → print manifest summary + an enrollment card when
remote transport is ready + pending-actions block. Styrn never inserts an
elevation step. `--dry-run` stops after the plan.

### 15.4.1 The zero-argument path (the §0.6 benchmark)

Bare `styrn setup` on a fresh machine [judgment; adopted]:

1. Probe everything (unprivileged, seconds), render current state.
2. DesiredState from pure defaults: **scope = `user`, role = `worker`, account mode = `current-user`** — a controller and system/dedicated installation are deliberate acts; promote later with `styrn setup --role both` or harden with `--scope system --account dedicated[:<name>]`. Components = the rootless worker baseline; missing machine-wide SSH/Tailscale/sleep-policy changes appear as optional `NeedsHuman`, never elevation requests. Dev-tool extras appear as `skipped (enable with --install rust,sccache,herdr,codex,claude)`.
3. Print the plan with privilege badges and pending-human items.
4. **Human decision 1:** one Enter to confirm the whole plan.
5. Apply. A Tailscale browser login may be a second decision only when an
   already-installed user-usable Tailscale client needs authentication.
6. If machine-wide actions are required, offer **one optional OS authorization
   decision** for their exact displayed subset. Declining leaves them pending.
7. Finish: user-scope manifest written; print Tailscale name/IP and the
   **enrollment card** only when SSH transport is actually ready; always print
   local capability and pending-action summaries.

That is **one human decision** for ordinary local setup, plus at most one native
authorization decision and optionally a browser login when those capabilities
are missing. `--yes` never grants privilege. No TTY and no `--yes` prints the
plan and exits 13 / `setup.confirmation_required`; with `--yes`, rootless work
may proceed but system actions remain pending unless the process is already
elevated or explicit authorization policy is supplied. Identity, dirs, shell,
and versions have working defaults.

### 15.4.2 `--interactive` wizard — `inquire`-style prompts, not a ratatui TUI (decided)

Adopted [judgment; libraries well-established: S26, S27]: the wizard is a **prompt sequence** (`inquire` — or `dialoguer`; inquire preferred for richer built-in select/multiselect/validation), *not* a full-screen `ratatui` application. A ratatui wizard is the wrong weight: higher maintenance, worse over-SSH/dumb-terminal behavior, no accessibility win — and it would duplicate effort with the later `styrn watch` TUI (specified in Part 14.5), which is where ratatui genuinely belongs. The user's phrase "TUI based configuration" is satisfied by a terminal-interactive wizard; the reconciliation is explicit: **prompts for setup, ratatui for `watch`.** Prompts degrade gracefully when stdin is not a TTY (fail fast with a flag hint). Wizard scope, five questions maximum: role → components (multiselect with sensible pre-checks) → identity mode (current user preselected; ask for a name only if dedicated) → Tailscale auth method → confirm.

### 15.4.3 Superseded UX (orig. §46, §113 — recorded, not silently dropped)

Orig. §46's per-machine script invocations (`sudo ./bootstrap/bootstrap-ubuntu.sh --name linux-macpro --authorized-key ... --enable-agents --enable-rust --enable-cockpit`, the `bootstrap-windows.ps1` equivalents, `bootstrap-macos.sh --headless-tailscale`) and orig. §113's intended `styrn bootstrap machine --profile rust-worker-heavy` UX are both **superseded by `styrn setup`**. Their intent survives: §46's flags map to `--install`/config keys (`--enable-cockpit` → `--install cockpit`; `--heavy` → the seeded `[resources.policy]` per 15.3.2); §113's "keep setup logic versioned with the binary and testable" is realized by this entire Part.

### 15.4.4 Plan display

Terraform-style, domain-fitted [judgment] — grouped by component, one line per action:

```text
tailscale     + install 1.86.2 (msi, 28 MB, pkgs.tailscale.com)      [admin]
              ~ set unattended mode: always                          [admin]
              ! authenticate: browser login (or pass --auth-key)
sshd          ✓ installed, running, key auth ok — nothing to do
identity      ✓ current user alex (dedicated isolation disabled)
rust          . skipped (enable with --install rust)
```

Symbols: `+` create/install, `~` reconfigure, `✓` already satisfied, `!` needs human, `.` skipped, `-` remove (uninstall mode). Every machine-wide line carries a `[sudo]`/`[admin]` badge. Interactive setup groups those lines into one optional native-authorization decision; downloads show size and origin.

## 15.5 Elevation strategy (decided)

- **Probe always runs unprivileged** (15.2.1).
- **User scope is rootless-complete first.** `Privilege::None` actions apply and
  journal as the invoking user without consulting an elevation mechanism.
  Machine-wide actions may appear in the same confirmed plan but remain pending
  until the separate authorization decision; declining them never rolls back or
  blocks independent user actions.
- **One prompt, only when necessary.** In an interactive TTY, after the exact
  privileged delta is displayed, ask once: `Authorize these N system changes?
  [y/N]`. The default is no. Consent launches the exact current Styrn binary
  through the OS-owned authorization surface: terminal `sudo` on Unix/macOS;
  verified Windows inline `sudo` when available, otherwise UAC `runas`. The OS,
  never Styrn, reads credentials. macOS TCC/FDA consent that cannot be granted
  by root remains `NeedsHuman` with a System Settings instruction.
- **The privileged runner is closed.** It accepts a versioned, size-bounded,
  short-lived request containing only closed Action variants and non-secret
  normalized parameters. It runs no project code, plugin, shell fragment,
  user PATH executable, arbitrary URL/path/argv, or setup renderer. It uses the
  absolute current executable, re-probes every action, and requires the
  recomputed privileged set to be an exact subset of the plan the user saw;
  drift that adds or changes an action aborts for re-confirmation. Results
  return over a typed local channel and are journaled by the owning scope.
- **Noninteractive behavior is deterministic.** `--yes` confirms ordinary
  actions but never implies privilege consent. Without an already-elevated
  process or an explicit future `--authorize-system` policy flag, privileged
  lines become pending and no auth UI appears. `--no-elevate` forbids even the
  interactive offer.
- **System scope is explicit.** `--scope system` (implied by
  `--account dedicated[:NAME]`) uses the same one-shot authorization path when
  interactive, or accepts a process the operator started elevated. User-level
  effects still execute through the captured original principal/token.
- An elevated process must not accidentally select root/SYSTEM for
  current-user identity. System-scope per-user effects use the captured original
  principal/token; if it cannot be established, setup refuses before mutation.

## 15.6 Receipts, idempotency, `--uninstall`, and the failure policy

### 15.6.1 The receipt

JSON, schema-versioned, one entry per applied action, modeled on `/nix/receipt.json` [verified: S1]. User-scope locations are `${XDG_STATE_HOME:-~/.local/state}/styrn/receipt.json` (Linux), `~/Library/Application Support/Styrn/receipt.json` (macOS), and `%LOCALAPPDATA%\Styrn\receipt.json` (Windows), owned and mode/ACL-restricted to the current user. System-scope locations remain `/var/lib/styrn/receipt.json`, `/Library/Application Support/Styrn/receipt.json`, and `C:\ProgramData\Styrn\receipt.json`, protected by root/Administrators. The manifest records the scope. Per entry:

- action type + parameters, timestamp, privilege used;
- files created (paths + hashes); files modified (path + before-hash + backup location);
- services, accounts, registry keys, firewall rules created;
- download provenance (URL, version, SHA-256);
- status: `applied | pending | adopted` (adopted = applied by a generated script and reconciled later; 15.11.2).

**Durable apply protocol (rev. G):** the private transaction intent is not a receipt entry and conveys no ownership. Before dispatch it is fsynced as `prepared` with the closed action and expected effect. After `apply` returns success and the finalized effect exactly matches, the intent is atomically/fsync transitioned to `succeeded`; only then may the applied receipt entry be appended. Recovery may finalize a `succeeded` intent after revalidation. A `prepared` intent whose probe remains `Todo` may retry; a `prepared` intent whose probe is already `Done`, `NeedsHuman`, or inconsistent is an explicit `setup.receipt_conflict`, never automatic ownership or adoption.

In user scope this protocol protects against crashes, concurrency, accidental
corruption, links, and malformed data; it does not prove ownership against a
malicious same-user process. In system scope it additionally enforces the
worker-nonwrite boundary. Both scopes use no-follow descriptor/handle
verification for every private intent read, not a check-then-open pathname.

### 15.6.2 `--uninstall`

`styrn setup --uninstall` reads the receipt and reverses entries newest-first via each action's `revert()`. **The receipt is the ownership authority**: uninstall removes only what Styrn created — it must NOT uninstall a Tailscale or Git that predated Styrn. Receipt-driven uninstall is the pattern that made nix-installer displace the official installer [verified: S1].

**Transport guard** [judgment; adopted]: refuse to disable or uninstall sshd/Tailscale when the current session appears to arrive over them (`SSH_CONNECTION` set; source address in the tailnet range) unless `--force` — sawing off the branch you are sitting on should require saying so.

### 15.6.3 Failure policy — resumable-forward (adopted, with the brief's argument)

Partial failure is the norm: network blips, a locked MSI, a missing FDA grant. Rollback-on-failure is the wrong default for a *setup* tool — half-configured-but-progressing beats repeatedly-reverted, and some actions (OS capability installs) are slow to redo. nix-installer attempts best-effort reversion on failed installs [verified: S1]; Styrn steals the *receipt* that makes reversal possible, **not** that behavior [judgment; adopted]. On action failure: stop (or continue independent siblings with `--keep-going`), report exactly which action failed and why (exit 13, `setup.apply_failed`, failing action named in `errors[].details`), leave the receipt accurate, and make the fix path "run `styrn setup` again" — which normally converges because of the `check()` gate. Reversal happens only via explicit `--uninstall`.

There is an unavoidable crash window between an external OS mutation and durably recording `succeeded`; those operations cannot be one filesystem transaction. If recovery sees the resource `Done` with only a `prepared` intent, it cannot distinguish Styrn's interrupted mutation from an external actor completing the same state. Because the receipt is uninstall authority, false ownership is worse than automatic recovery: stop with `setup.receipt_conflict`, retain diagnostic evidence, and require later explicit adoption/reconciliation. Never infer ownership from observed convergence alone. This is the honest boundary of the resumable-forward policy.

## 15.7 Per-OS mechanics (new in rev. D; evidence tags preserved)

### 15.7.1 Windows: OpenSSH Server [verified: S2, S3]

All machine-wide mechanics below are **system-scope actions**. In default user
scope, setup only probes the installed server and uses the selected user's
ordinary authorized-key path when the active sshd configuration permits it. A
missing/disabled server, firewall rule, account-specific override, or
administrator-group shared-key trap becomes `NeedsHuman`; it never causes UAC.
The machine remains a functioning local worker/controller while its remote-SSH
capability is unavailable.

- **Detect:** `Get-WindowsCapability -Online | Where-Object Name -like 'OpenSSH*'` → `State: NotPresent|Installed`. Requires Windows 10 1809+/Server 2019+; Server 2025 ships OpenSSH preinstalled (only service enablement needed).
- **Install:** `Add-WindowsCapability -Online -Name OpenSSH.Server~~~~0.0.1.0` (elevated); revert via `Remove-WindowsCapability`. The `~~~~0.0.1.0` suffix is the capability-name convention, matched by wildcard probe first (the rev. B S-18 brittleness fix). Newer OpenSSH builds exist as MSI/winget packages from the Win32-OpenSSH releases (winget id reportedly `Microsoft.OpenSSH.Beta` **[unverified — confirm via `winget search openssh`]**); the inbox capability path is chosen anyway — serviced by Windows Update, no third channel [judgment]. Known failure mode: `Add-WindowsCapability` can fail (0x800f0954-class) on WSUS-managed machines that block Feature-on-Demand downloads [well-established community reports]; the action's error message must name the WSUS cause and the GPO/registry remediation, and the plan degrades to `NeedsHuman` with that instruction.
- **Service:** `Start-Service sshd; Set-Service -Name sshd -StartupType 'Automatic'`.
- **Firewall:** verify rule `OpenSSH-Server-In-TCP`; create if absent (`New-NetFirewallRule ... -LocalPort 22`).
- **Config:** `%programdata%\ssh\sshd_config`; sshd regenerates a default if missing; restart the service after edits. `StrictModes`, `AuthorizedKeysCommand`, `PermitRootLogin` and others are NOT supported in the inbox build [verified: S3] — setup must not write unsupported directives.
- **The ACL trap and the safe resolution:** the inbox default sends members of
  Administrators to `%programdata%\ssh\administrators_authorized_keys`, whose
  ACL must contain only SYSTEM and Administrators or key auth silently fails
  [verified: S3]. That shared file would authorize the Styrn controller key for
  every administrator, so Styrn does not use it. Setup writes an account-specific
  protected key file under `%ProgramData%\Styrn\ssh\`, ACL'd to SYSTEM,
  Administrators, and read-only access for the selected SID, and installs a
  safely escaped `Match User <selected-name>` override pointing to it. Native
  conformance proves both administrator-member and ordinary-user key login. If
  the installed OpenSSH build cannot express or honor that account-specific
  override, setup returns `NeedsHuman` and refuses worker eligibility; it never
  broadens access through `administrators_authorized_keys`. This protected
  override is system scope only. User scope never edits `sshd_config`; if the
  inbox administrator rule blocks safe per-user authorization, remote-worker
  eligibility is pending rather than broadened.
- **DefaultShell (decided):** registry `HKLM:\SOFTWARE\OpenSSH`, string value `DefaultShell`; initial default is `cmd.exe` [verified: S3]. Setup sets it to PowerShell (`pwsh.exe` when present, else Windows PowerShell) via `New-ItemProperty ... -Force`. Rationale: every string that *does* traverse the login shell — `styrn shell`, the Herdr attach command (11.13), and git's `git-receive-pack '<path>'` invocation during controller-push (8.2) — gets one known set of quoting semantics instead of cmd.exe's. This does not change Part 7.10's convention: workflow commands and `styrn exec` never use the login shell at all; the fixed `styrn rpc serve --stdio` literal is quote-safe under any of the three shells (5.1). **Git-push interop through the chosen default shell is exercised by `styrn fleet selftest` (16.6 item 6), which pushes on every run — treat any residual quoting interaction between OpenSSH-Windows, the shell, and `git-receive-pack` as implementer-confirm rather than assumed.**

### 15.7.2 Tailscale, per OS

- **Auth model** [verified: S9]: non-interactive registration via `tailscale up --auth-key=tskey-...`; interactive via bare `tailscale up`, which prints a login URL — setup surfaces the URL and waits. Key facts: one-off vs reusable keys; ephemeral/pre-approved/tagged attributes; keys expire 1–90 days (default 90); a device registered by an expired key stays authorized until node-key expiry (default 180 days); tagged devices disable expiry by default. **Handling [judgment; adopted]:** the key is accepted ONLY via `--auth-key` or the `TS_AUTHKEY` env var, never persisted to config or receipt; one-off pre-approved keys are the documented default recommendation.
- **Footgun rule:** re-running `tailscale up` with a new flag requires re-specifying previously-set flags (modern versions error and point at `--reset`) [well-established]. Setup always issues `up` with the **complete intended flag set**, never incrementally.
- **Linux** [verified: S8]: the official one-liner (`curl ... | sh`) adds the distro repo and installs. Styrn does **not** shell out to a remote script (supply-chain bar, 15.7.6): it writes Tailscale's apt keyring to `/usr/share/keyrings/` and a sources entry itself, then `apt-get update && apt-get install -y tailscale` — exact repo/keyring URLs at pkgs.tailscale.com are **[unverified — implementer must confirm]**. Packaged installs run `tailscaled` under systemd [well-established]; probe via `systemctl is-active tailscaled` and `tailscale status --json` [verified: S10].
- **Windows** [verified: S15, S16]: silent install `msiexec.exe /i tailscale-setup-<ver>-amd64.msi /quiet /norestart`; MSI properties land as REG_SZ under `HKLM\SOFTWARE\Policies\Tailscale` — set `TS_UNATTENDEDMODE = always` so connectivity survives logout/no-login, and `TS_NOCLOSEONSIGNALIN` to suppress GUI launch during silent install. Post-install alternative: `tailscale up --unattended=true` (Windows-specific flag; Linux is system-level by default; macOS lacks unattended mode entirely [verified: S8]). The winget id `Tailscale.Tailscale` is **[unverified — confirm via `winget search`]** and only relevant to the opportunistic path (15.7.6).
- **macOS** [verified: S11, S10]: three variants — App Store (sandboxed), Standalone (Tailscale's recommended default), open-source `tailscaled`; **only `tailscaled` can run before login**, and Tailscale recommends it only for experienced-admin unattended installs. GUI-variant CLI lives at `/Applications/Tailscale.app/Contents/MacOS/Tailscale`; Standalone can install a `/usr/local/bin/tailscale` launcher. **Decision [judgment; adopted]:** default = Standalone GUI (dev Macs are interactive anyway), with the before-login gap recorded in the manifest (`[tailscale] mode = "gui", unattended = false` — Part 3.2's model, unchanged); `tailscaled`-under-launchd is the explicit opt-in headless mode (`[tailscale] mode = "tailscaled"` in setup-config). GUI variants need first-launch human approval (VPN configuration consent) — modeled as `NeedsHuman`; the exact per-version approval sequence is **[unverified — walk through on current macOS]**.

### 15.7.3 macOS Remote Login — the honest answer [verified: S11, S12]

sshd is preinstalled on macOS; this is enablement, not installation. `systemsetup -setremotelogin on` (as root) fails on macOS 10.15+ unless the calling process's context has Full Disk Access ("requires Full Disk Access privileges"), and TCC consent cannot be granted programmatically without MDM — out of scope for a personal fleet.

**Fallback chain (adopted) [judgment]:**

1. Try `systemsetup -setremotelogin on`; detect the FDA error string/exit.
2. Try the launchctl path — `launchctl load -w /System/Library/LaunchDaemons/ssh.plist` (legacy syntax; modern equivalents `launchctl bootstrap system ...` / `launchctl enable system/com.openssh.sshd`) — then probe port 22 locally to confirm. **Whether this still bypasses the FDA gate on current macOS is [unverified — the single most important pre-implementation test in this Part; the cited practitioner source is from 2020].** If the probe fails, fall through.
3. Emit `NeedsHuman`: "System Settings → General → Sharing → Remote Login → on; then re-run `styrn doctor`."

The design degrades gracefully if item 2 is dead on current macOS: the chain simply lands on item 3, and macOS worker setup costs one extra human toggle — reported, never faked (15.2.4). Optionally restrict SSH to the `com.apple.access_ssh` group via `dseditgroup` — group name and behavior **[unverified]**.

### 15.7.4 Service installation from one binary [S28, S29, S30, S17]

| OS | Mechanism | Privilege |
|---|---|---|
| Linux user | write a systemd user unit and `systemctl --user enable --now styrnd`; without linger its guarantee is the user-manager lifetime, which doctor reports | none |
| macOS user | write `~/Library/LaunchAgents/dev.styrn.styrnd.plist`; `launchctl bootstrap gui/<uid> <plist>`; login-session guarantee only | none |
| Windows user | register a per-user logon task/startup entry using the current interactive token, with no stored password; login-session guarantee only | none |
| Linux system | write `/etc/systemd/system/styrnd.service`; `systemctl daemon-reload && systemctl enable --now styrnd` | root [well-established: S28] |
| macOS system | write `/Library/LaunchDaemons/dev.styrn.styrnd.plist`; LaunchDaemon runs at boot with `UserName` set to the resolved worker principal and survives logout | root [well-established: S29] |
| Windows system | a credential-free LocalSystem SCM service implements only the narrow admission/spawn broker; selected-principal maintenance remains separate | Administrator |

**Normative content is the unit/plist/service definitions themselves** — they are files, written directly by Styrn and recorded in the receipt. The `service-manager` crate (v0.10; wraps sc.exe/launchd/systemd/OpenRC with install/uninstall/start/stop [verified: S17]) may be *evaluated* as an implementation backend, but its fitness is **[unverified — API verified from README only; prototype before committing]**; worst case Styrn vendors its own three small templates, which also keeps them receipt-visible [judgment].

**Herdr autostart carried forward:** the rev. B Linux mechanism — a systemd *user* service (`styrn-herdr.service`, `Environment=HERDR_SESSION=fleet`, `ExecStart=<herdr> server`) plus `loginctl enable-linger <worker-principal>` — is retained as the `herdr` component's Linux autostart action (`[herdr] autostart = "systemd-user"`); macOS/Windows remain `on-demand`/`on-demand-ssh` as in Part 2.4.

### 15.7.5 Worker identity modes, per OS (amended rev. G)

**Current-user mode (default):** resolve the invoking OS principal once and record its stable platform identifier plus display name. In default user scope no elevation handoff exists: setup, tools, state, PATH changes, harness configuration, services, and jobs all use that principal's standard directories/token. Authorization keys follow 4.3's user-scope rule. In explicit system scope, an already-elevated launch must recover the trustworthy original principal or refuse; Styrn never runs jobs as root/SYSTEM merely because setup began there.

**Dedicated mode (optional):** create or adopt the configured, non-administrator local account. The suggested name is `styrn`, but no platform adapter or test may assume it. Linux uses an ordinary local user with a real shell and home because workers accept SSH and may run lingering user services. macOS uses the validated native account mechanism selected by T0.14; its account-creation path remains an honest native gate until proven end to end. Windows uses native local-account APIs, generates a 32+-byte password in memory, and keeps the transient-logon and SCM behavior in 15.8. Re-running must adopt the exact configured principal without recursively taking ownership of pre-existing files.

In either mode, the worker principal is a typed value validated before native calls. Names containing NULs, separators, ambiguous domain syntax, or platform-invalid forms are rejected. Security-sensitive records prefer stable uid/SID identity and retain the display name for diagnostics. Deleting or renaming a configured OS account is drift, not a reason to silently switch users.

### 15.7.6 Package substrates and component channels

**The winget finding (S-35; the decisive one):** winget is per-user MSIX; it is not resolvable/runnable under the SYSTEM account or typical service contexts, and commonly fails in non-interactive SSH sessions [verified: S13, S14] — i.e., **exactly the contexts in which Styrn provisions Windows workers**. The rev. A `bootstrap-windows.ps1` is built entirely on a winget helper and therefore fails precisely where Styrn needs it. Consequences, adopted:

- **winget = opportunistic only** (interactive elevated console, when detected): non-interactive flags `--silent --accept-package-agreements --accept-source-agreements --disable-interactivity`, target `--id <Id> -e`, pin `--version`, scope `--scope machine`; exit codes are HRESULTs decodable via `winget error <code>` [verified: S4, S21]. Exact package ids (`Tailscale.Tailscale`, `Git.Git`, …) are **[unverified — confirm via `winget search` at implement time]**.
- **Direct download + silent MSI/EXE (`msiexec /quiet /norestart`) is the dependable path Styrn specs against** on Windows [verified: S13, S14 for the rationale].
- **Homebrew** [verified: S5]: never install brew itself (its installer wants interaction/sudo; absence = "substrate unavailable", not an error). Detect at `/opt/homebrew/bin/brew` (Apple Silicon) / `/usr/local/bin/brew` (Intel); `brew install` is non-interactive; bottles/casks need no Xcode CLT, source builds do.
- **apt (Ubuntu)** [well-established: S33]: `DEBIAN_FRONTEND=noninteractive apt-get install -y <pkg>` (use `apt-get`, not `apt`, in automation); exit 0 ok / 100 error; root required; third-party repos = keyring in `/usr/share/keyrings/` + sources entry + `apt-get update`.

**The supply-chain bar (normative for every component action) [judgment; adopted]:** (1) HTTPS-only downloads via rustls, no plaintext fallback; (2) pinned versions — a compiled-in (or styrn-repo-fetched) component table of `{version, url, sha256}` per platform, verified before execution; (3) prefer channels with built-in signing (Windows capability/MSI Authenticode, apt repo signatures) over raw binaries; (4) provenance (url, version, digest) recorded in the receipt; (5) **never pipe a remote script to a shell at runtime** — piped payloads are server-detectable and swappable [verified: S34, S35], and docker's own script tells users to read, pin, and dry-run first [verified: S36]. No sigstore/TUF machinery — disproportionate for a personal fleet. Where a vendor updater exists (Tailscale, Claude Code self-update), it owns upgrades; Styrn pins only the initial install. This bar **retires the rev. A `curl | sh` pattern for runtime installs entirely**; the sole surviving piped script is stage zero (15.11.4).

**Component channels** (each an Action bound by the bar above):

- **Git:** apt / direct installer on Windows (winget `Git.Git` opportunistically, id unverified) / on macOS via Xcode CLT — `xcode-select --install` triggers a GUI consent → `NeedsHuman` if absent [well-established].
- **Rust:** download `rustup-init` per platform from static.rust-lang.org and run `rustup-init -y --no-modify-path --default-toolchain <pin>` [verified: S22] — never pipe sh. rustup's Windows PATH mechanism (user registry env) is **[unverified from primary docs — confirm before depending on it]**; Styrn owns PATH itself regardless (below).
- **sccache:** GitHub-release static binary → styrn bin dir; `RUSTC_WRAPPER` set per-job by the launcher/supervisor (7.12), never in global shell config [well-established; judgment].
- **Claude Code:** native installers exist, no Node required [verified via secondary sources: S24 — **confirm exact official URLs at implement time**]; self-updates in background — the vendor updater owns upgrades, Styrn pins only the initial install (supply-chain bar, 15.7.6).
- **Codex CLI:** Rust binary; channels = standalone installer / Homebrew cask / GitHub-release binaries; the npm channel needs Node 22+ and is **rejected outright** — Styrn requires no language runtime for any component [verified: S24, S25; asset naming settling — pin at implement time].
- **Herdr:** project-internal, no public distribution documented — **the spec defines it**: GitHub-release per-platform binaries + SHA-256, installed by Styrn like sccache [judgment].
- **rdp** (Windows only, default off; the orig. §48 mechanics as an Action): set `HKLM:\System\CurrentControlSet\Control\Terminal Server` `fDenyTSConnections = 0` and enable the "Remote Desktop" firewall rule group `[admin]`; revert restores the prior value. Updates `[desktop]` in the manifest (Part 2.4).
- **cockpit** (Linux only, default off; the orig. §47 mechanics as an Action): `apt-get install -y cockpit` + `systemctl enable --now cockpit.socket` `[sudo]`; updates `[admin]` in the manifest (Part 2.7) and reminds about the optional tailnet grant (Part 3.1).
- **sleep-policy** (workers, default on; rev. E — resolves S-38, review D §6.2): a machine that accepts jobs must not suspend while unattended. Windows: `powercfg /change standby-timeout-ac 0` plus lid-close-on-AC action "do nothing" `[admin]`; Linux: mask `sleep.target suspend.target hibernate.target hybrid-sleep.target` `[sudo]`; macOS: `pmset -c sleep 0` [well-established in outline; exact per-OS incantations implementer-confirm]. Laptop workers (win-hp, mbp-main) are exactly why this exists: "heavy Windows validation" otherwise silently depends on an unstated the-lid-is-open assumption. Remote *wake* stays out of scope (power providers, 3.5/D-4, are recovery, not wake); doctor warns when a manifest says `accept_jobs = true` but the OS sleep policy would suspend the machine.

**PATH strategy [judgment; adopted]:** silently editing rc files across bash/zsh/fish/PowerShell is the classic tarpit (rustup maintains env files; starship instead has the user add one line [verified: S23]). Styrn uses `.local/bin` under the resolved worker profile, changes PATH only for that identity, and provides `styrn env` printing shell-appropriate export lines for other users.

### 15.7.7 Install ordering (absorbs orig. §111)

Orig. §111's ordering rule — integrations only after the tools and their user config dirs exist — becomes a **dependency edge in the plan**, not documentation: `integrate-herdr-codex` depends on `herdr` and `codex` actions (and on the user-phase context on Windows, 15.8); `integrate-claude` likewise; the Styrn Herdr plugin and MCP registrations depend on their hosts. The planner orders by dependencies; a failed prerequisite skips its dependents with an explicit `skipped: dependency failed` plan-result line. The orig. §111 sequence (install Herdr → Codex → Claude → init config dirs → Herdr integrations → Styrn plugin → MCP registrations → integration doctor) is exactly the topological order the graph produces.

## 15.8 Windows worker identity strategy (D-3 superseded by rev. G; absorbs orig. §112)

Orig. §112's diagnosis stands: Herdr, Codex, and native Claude installers are per-user, so an elevated phase must never install them into the elevating administrator's profile by accident.

**Current-user/user-scope mode is the default.** Setup runs once under the
current token, writes only user-owned paths, and never re-executes as
Administrator. No account or password is created, requested, logged, or
persisted. If a system prerequisite is missing, it records `NeedsHuman` and
continues independent user work instead of changing token or profile.

**Dedicated mode remains the hardened option.** Setup creates or adopts the configured non-administrator principal and generates a password in memory. Within that run it uses `CreateProcessWithLogonW` with profile loading to materialize and execute `styrn setup user-phase` under the selected identity. The password is zeroized after the user phase; it is never handed to the broker or SCM. No argument, output, config, receipt, manifest, Styrn-owned file, or service credential contains it.

The user phase installs per-user tools and writes selected-profile harness
configuration while journaling through the scope-selected receipt. In user
scope controller authorization keys use the selected user's OpenSSH location;
in system scope they use Part 4.3's protected account-specific location. All
paths derive from the resolved profile; neither `C:\Users\styrn` nor any other
literal profile is assumed. Transient-logon failure in optional dedicated mode
produces a `NeedsHuman` fragment and leaves current-user mode unaffected.

## 15.9 `styrnd`: the worker service (resolves S-34; reconciles orig. §58/Part 6.8 with orig. §63)

**The gap:** Part 6.8 (orig. §58) specifies daily and weekly maintenance but never says what *runs* it; workers are headless, controllers are closable, and orig. §63 rejects a central daemon. Separately, 7.8 needed a concrete home for the Windows supervisor-spawn fallback ("a pre-created scheduled task" was a placeholder). One small local service answers both.

**`styrnd`** — one binary installed first as a user service (mechanics 15.7.4).
It runs as the current principal with no password capture, performs maintenance,
and on Windows can broker supervisor spawn from a process created independently
of sshd's Job Object. Its advertised persistence is login-session scoped unless
the native user manager demonstrably survives logout. Optional system scope
uses the separate credential-free LocalSystem Windows broker and boot services;
those are never prerequisites for ordinary user-scope operation.

1. **Maintenance executor (all OSes):** an internal tick runs Part 6.8's daily and weekly task lists (`styrn clean run --local`, cache trim, log rotation, disk-floor check, git maintenance, health snapshots) under the same registry lock as admission (6.8's locus rule, unchanged), journaling each run to the worker audit log (14.3).
2. **Spawn broker (Windows only):** a scope-specific local named pipe ACL'd to
   the resolved worker SID (and SYSTEM in system scope). The ACL is not an
   authorization decision because jobs share that SID. Admission first creates
   a one-use pending-spawn record containing the job id, submission id,
   expected installed-binary identity, and requesting RPC process. The broker
   atomically consumes that record. It
   validates the named-pipe client PID/token, selected SID, installed executable
   identity, sshd ancestry, expected Job-Object condition, and exact admitted
   job before constructing the fixed argv `styrn job supervise <id>` itself.
   It rejects replay, malformed ids, arbitrary executables/argv, unadmitted jobs,
   and same-SID callers without the pending record. It has no network access and
   cannot serve as a general executor. In user scope this is functional
   hardening, not containment from malicious same-user code; that code can
   already spawn arbitrary same-user processes and alter user state. In system
   scope the record is protected and the broker remains capability-limited.
   On Linux/macOS,
   double-fork/setsid needs no broker and styrnd plays no part in job execution.

**Reconciliation with orig. §63 (explicit, so the contradiction is only
apparent):** §63 rejected a *central* server — a fleet coordination point with
TLS, a database, and upgrade coupling. `styrnd` is per-worker and local-only,
with no listening network socket, cross-machine protocol, or fleet-availability
dependency. Maintenance degrades to opportunistic execution when its executor
is absent. Windows tries direct breakaway first, but when the OS denies it the
narrow credential-free broker is required for the accepted job-durability
contract; doctor therefore marks a Windows worker ineligible if that broker is
unavailable and breakaway is denied. Part 1.4's rule now explicitly excludes
this capability-limited broker from its ban on privileged worker daemons.

## 15.10 Enrollment in one step (resolves the pass-1 deferral in 6.1; S-36; absorbs orig. §60)

**Decision: enrollment remains controller-initiated** — trust must flow from the party holding credentials, and a worker cannot insert itself into a controller's inventory without holding a shared secret, which Part 4.2 forbids. But `styrn setup` makes the worker **enrollable in one paste**, which is what the friction tenet actually demands:

1. Setup on a worker accepts controller public keys up front (`[ssh] authorized_keys` in setup-config, `--authorized-keys` flag, or baked into a generated bootstrap script, 15.11.4) and installs them (Part 4.3 semantics).
2. Setup ends by printing — and recording in the manifest — the **enrollment card**:

```text
Ready to enroll. From any controller, run:

  styrn host enroll win-mini --user alex --fingerprint sha256:Yk3…hostkey…Q0=

  (tailscale: win-mini.tail1234.ts.net · 100.101.102.103)
```

   The card carries exactly what Part 6.1's flow needs: name/address, the
   validated transport user, and the out-of-band host-key fingerprint that
   makes enrollment non-interactive and TOFU-honest (4.4). There is no implicit
   account. This replaces rev. B's "the reference scripts should be extended to
   print the fingerprint" with a guarantee. The card is **integrity-sensitive**
   (the fingerprint is the enrollment trust anchor): read it off the worker's
   own console or a session you initiated; do not relay it through channels you
   would not trust with host-key pinning (rev. E; review D §6.2).
3. On the controller, that one pasted line completes enrollment (manifest fetch, machine_id record, pin, inventory add — 6.1 unchanged).

**The fleet walkthrough (orig. §60, rewritten for rev. D).** Setting up the initial fleet is now:

```text
MacBook Pro (first controller):
  styrn setup --role controller            # config dir, lazy keypair, tailscale check
  styrn bootstrap-script --os linux   > linux.sh      # each embeds this controller's
  styrn bootstrap-script --os windows > windows.ps1   # public key + pinned binary hash

Ubuntu Mac Pro:      run linux.sh    → paste back the enrollment card line
Ryzen mini-PC:       run windows.ps1 → paste back the enrollment card line
HP laptop:           run windows.ps1 (add --install rust,sccache,herdr,codex,claude
                     and let setup seed the heavy [resources.policy]) → paste back
Future Mac worker:   styrn bootstrap-script --os macos → same dance
```

Two pastes per machine — one outbound (the script), one returning (the enrollment card) — zero credentials on any worker, and every step re-runnable. Orig. §60's per-machine checklists (Tailscale, SSH, account, toolchains, agents, manifest, enroll) are subsumed: each list item is now a probed component in the plan.

## 15.11 Script generation: the third renderer (absorbs orig. §113–§114)

### 15.11.1 `--emit-script`: the plan rendered instead of applied

The plan already has two renderers — dry-run text and `apply()`. Script emission is the third: `--emit-script[=PATH]` walks the same ordered `Vec<Action>` and concatenates each action's `render_posix()` or `render_powershell()` fragment (default output `./styrn-setup.sh` / `.ps1` by target OS; `-` for stdout). Because all three renderers consume identical Action parameters, **the script cannot drift from what `apply` would have done** [judgment; precedent: Alembic's offline `upgrade --sql` mode, which exists for exactly the operator-forbids-direct-execution case: S39]. `--target-os <os>` is permitted only together with `--config` (there is no live probe of a foreign machine), in which case every step relies on its embedded guard. Three situations, one mechanism: audit/air-gap provisioning, human-gated steps (`NeedsHuman` fragments, 15.2.4), and cross-machine emission (`styrn bootstrap-script`, 15.11.4).

### 15.11.2 The four hard breaks (specified, not hand-waved)

1. **Runtime-only secrets.** The Windows account password must be generated *at script run time*, inside the script (PowerShell crypto RNG inline), never embedded at generation time. Rule: `render_*` may reference secrets only as generate-here code or environment lookups (`$env:TS_AUTHKEY`), never as literals — **enforced structurally**: secret-bearing Action parameters are typed `Secret<T>`, and `Secret<T>` deliberately implements no renderer-visible stringification [judgment].
2. **State drift between generation and execution.** The plan was computed from a probe that may be stale when a human finally runs the script — or was never run at all (`--target-os`). Fix: every rendered fragment embeds its own guard — the script form of `Action::check()` (`Get-WindowsCapability`, `systemctl is-active`, a safely quoted lookup of the configured principal, …) — so each step is skip-if-satisfied. Alembic documents the same offline limitation and makes the operator supply the starting state [verified: S39]; Styrn is luckier — shell *can* re-probe cheaply, so rendered guards recover most of what a live probe gives [judgment].
3. **Interactive auth.** Unproblematic: the script does what setup would — honor `TS_AUTHKEY` if set, else run `tailscale up` and let it print its login URL and wait [verified: S8].
4. **The receipt.** A script cannot faithfully write Styrn's journal. Rule: every generated script's final step installs (if absent) and invokes `styrn` to re-probe and reconcile — `styrn setup --adopt` — recording receipt entries with `provenance: "script"`, status `adopted`, so `--uninstall` knows those resources are Styrn-owned by adoption. **No prior art exists for this exact loop — it needs a design spike before implementation** [judgment; flagged honestly]. A plain re-run of `styrn setup` also converges (the `check()` gate) but records nothing as Styrn-owned; `--adopt` is what claims ownership.

### 15.11.3 Generation quality bar and integrity

Every emitted script carries [judgment; shell mechanics well-established]:

- **Provenance header:** styrn version, plan hash, generation timestamp, target OS/machine, the generating invocation, and "generated — regenerate rather than hand-edit" with the regeneration command;
- **Fail-fast:** bash `set -euo pipefail`; PowerShell `Set-StrictMode -Version Latest` + `$ErrorActionPreference = 'Stop'`;
- **Echo-before-do**, steps visually separated per component; `NeedsHuman` fragments appear as clearly delimited sections that pause for confirmation rather than run silently;
- **Idempotent guards** (15.11.2.2) making partial-failure recovery "run it again" — the same resumable-forward policy as `apply` (15.6.3);
- **No secrets embedded** (15.11.2.1);
- **Terminal adoption step** (15.11.2.4).

**Integrity, proportionate bar [judgment]:** no PGP/sigstore — disproportionate for a personal fleet. At generation, Styrn prints the emitted file's SHA-256; controller→worker transfer rides Tailscale/SSH, already mutually authenticated; a human who cares compares the printed hash. Stage-zero scripts, which travel the open web, are where checksums are mandatory (15.11.4). Rendered scripts must be **CI-tested in VMs to converge to the same probe results as `apply`** (16.6 item 8) — the guard checks are a mitigation, not a proof, and the two-dialect test surface is the costliest part of this feature; it is affordable only because generation is a renderer of the existing plan, never a parallel implementation [judgment].

### 15.11.4 Stage zero (absorbs orig. §114) and `styrn bootstrap-script`

Stage zero — no `styrn` binary yet — cannot be plan-generated. It is a **short, stable, hand-maintained pair of scripts** (`install.sh`, `install.ps1`) whose only jobs are [judgment; chaining pattern verified: S38]:

1. TLS-constrained download of the pinned platform binary (`curl --proto '=https' --tlsv1.2`; the release-asset list of orig. §114 stands verbatim: the six per-target binaries + `SHA256SUMS`);
2. SHA-256 verification against a checksum **embedded in the script** — the cheap thing nix-installer and rustup don't fully do [verified: S40, S22];
3. install to a standard location;
4. pass-through of remaining arguments into `styrn setup`: `sh -c "$(curl -fsLS https://<host>/install.sh)" -- setup --role worker` (chezmoi-style chaining [verified: S38]).

The docs always publish the script's own digest beside the one-liner and document the two-step "download, read, run" form (docker's own advice [verified: S36]); the scripts stay tiny and diff-stable so reading them is realistic. Stage-zero hosting (domain, stability guarantees, release pipeline) is distribution engineering to be decided alongside the release setup — flagged, not designed here.

**`styrn bootstrap-script --os <linux|macos|windows> [--role R] [--install ...] [--config <url>] [--json]`** (controller-side) emits a customized copy of the stage-zero script for a target machine: same download+verify preamble, plus this controller's public key and the chosen setup arguments baked in, ending with the enrollment card (15.10). One self-contained file to move to the new box.

## 15.12 The reference scripts, demoted (absorbs orig. §47–§49; supersedes S-10/S-17/S-18/S-27/S-35 remediation plans)

`bootstrap-ubuntu.sh`, `bootstrap-macos.sh`, `bootstrap-windows.ps1`, and the two `install-controller-*` scripts are **superseded and removed**: they are no longer in the repository (orig. §47–§49), and are replaced by the `install.sh`/`install.ps1` shims (15.11.4) plus `styrn setup`. Their behaviour is recorded here so that nothing they did is lost with the files. What each did — Ubuntu: packages, Tailscale, SSH, account, key, dirs, rust/sccache, agents, Herdr systemd-user service, Cockpit, manifest; Windows: OpenSSH capability, firewall, account, Tailscale MSI-via-winget, Git/PowerShell, rust/MSVC, agent installers, RDP, manifest; macOS: hidden-ish account, SSH enablement attempt, Tailscale variants, rust/agents, manifest — is now all expressed as probed components of the one engine.

Their open defect registers are **superseded, not silently dropped**:

- **S-10** (admin-context user installs, profile-before-logon, `$home` shadowing, the `icacls` parse hazard, the discarded password): all four design causes are eliminated by 15.8 (transient-logon user phase, in-memory credential moment) and 15.7.1; the shell-level bugs die with the scripts.
- **S-17** (`curl | sh` supply chain): runtime installs now use pinned `{version, url, sha256}` downloads under the 15.7.6 supply-chain bar; the only piped script remaining is the stage-zero one-liner, hardened and checksum-published per 15.11.4.
- **S-18** (manifest lies, dual disk keys, versioned capability name, invented Claude keys): manifest is now engine output (15.3.2); capability probed by wildcard (15.7.1); the Claude settings keys remain flagged unverified (12.3).
- **S-27** (macOS dscl Secure-Token/FDA caveats): folded into 15.7.5's account decision and 15.7.3's fallback chain, still flagged for end-to-end testing.
- **S-35** (the winget foundation): resolved by 15.7.6 — winget demoted to opportunistic, direct MSI/EXE primary.

## 15.13 Command surface, JSON behavior, and codes (new in rev. D)

```text
styrn setup [--role controller|worker|both] [--install <c1,c2,...>]
            [--config PATH] [--interactive]
            [--scope user|system]
            [--name NAME] [--account current-user|dedicated[:NAME]]
            [--authorized-keys K...]
            [--auth-key TSKEY] [--yes] [--dry-run]
            [--authorize-system|--no-elevate] [--keep-going]
            [--emit-script[=PATH]] [--target-os linux|macos|windows]
            [--uninstall [--force]] [--adopt] [--rotate-account]
            [--json]
styrn setup user-phase                        (internal plumbing; Windows user phase, 15.8)
styrn setup privileged-phase --request PATH   (internal closed runner; 15.5)
styrn bootstrap-script --os <os> [--role R] [--install ...] [--config URL] [--json]
styrn daemon run                              (internal plumbing; the styrnd loop, 15.9)
styrn env                                     (prints shell-appropriate PATH/env lines, 15.7.6)
```

**JSON contract:** `styrn setup --json` follows the standard envelope (Part 10.2) with `data = { plan: [...], results: [...], pending: [...], manifest: <path>, receipt: <path> }`; `--dry-run --json` carries `plan` only (this is the machine-readable plan — the brief's `--plan-json` is spelled `--dry-run --json`, one flag fewer). `--emit-script` writes the script to its target and keeps stdout clean for the envelope (script path + sha256 in `data`). All finite; no `--jsonl` surface in setup.

**Exit codes:** the Part 10.4 table gains one addition (additive, allowed within v1 per 2.8):

```text
13  setup action failed / setup requires input (elevation or confirmation)
```

Success with only pending-human items remaining is exit 0 with `warnings[]` naming them (`fail_on_pending = true` flips that to 13).

**Error codes** (appended to the Part 10.3 registry): `setup.probe_failed`, `setup.plan_invalid`, `setup.confirmation_required`, `setup.elevation_required`, `setup.apply_failed`, `setup.needs_human`, `setup.unsupported_os`, `setup.receipt_conflict`, `setup.adopt_mismatch`.

## 15.14 Packaging and upgrade of the `styrn` binary (new in rev. E; resolves S-37)

Operator requirement, verbatim and binding:

> "Styrn at regime should be installable and upgradeable via the different package managers available for each platform"

The principle is the one 15.7.6 already applies to third-party components — vendor updaters own Tailscale and Claude Code; Styrn pins only initial installs — now applied to Styrn itself: **the platform package channel owns upgrades of the `styrn` binary. Styrn never self-updates.** This was the most significant absence in rev. D (review D §6.2 item 1): `fleet versions` observed drift, 2.8 tolerated mixed versions, `fleet selftest` validated "after every upgrade" — and nothing performed one.

### 15.14.1 Channels, mapped to the Part 1.5 release targets

| Channel | Platforms | Status | Notes |
|---|---|---|---|
| GitHub Releases: raw binaries + `SHA256SUMS` (orig. §114 asset list) | all six 1.5 targets | **v1 — the substrate** | consumed by stage zero, by non-interactive provisioning, and by every other channel's manifests |
| Homebrew tap: `brew install <org>/tap/styrn` | macOS (both arches); Linuxbrew where present | **v1** | tap formula generated by release CI; homebrew-core is aspirational |
| winget manifest: `winget install styrn` | Windows | **v1** | **human-present contexts only** — S-35 stands: winget is unusable from SYSTEM/service/SSH-non-interactive contexts |
| `.deb` release asset: `apt install ./styrn_<ver>_amd64.deb` | Ubuntu/Debian | **v1 (asset only)** | dpkg-native install/uninstall without hosting; a signed hosted apt *repository* is aspirational |
| `cargo install styrn --locked` | anywhere with a Rust toolchain | **v1 (universal fallback)** | slowest; builds from source |
| apt repository, Scoop, Chocolatey, homebrew-core | — | aspirational | a channel is promised only when someone will maintain it [judgment] |

These channels also carry the signing the raw-binary path lacks — Homebrew formula checksums, winget manifest hashes, dpkg integrity, Authenticode where MSI/EXE is used — satisfying 15.7.6's prefer-signed-channels rule for Styrn itself.

### 15.14.2 Stage zero prefers a package manager when a human is present (amends 15.11.4)

`install.sh` / `install.ps1` first detect a usable package channel *in the invoking context* — brew on macOS/Linux, winget in an interactive Windows console — and prefer `brew install` / `winget install`, then chain into `styrn setup` exactly as before. They fall back to the verified direct download when no channel is present **or the context is non-interactive**. The S-35 nuance is preserved intact: package-manager install is the *human-present* path; direct download remains the path for remote, non-interactive worker provisioning, and scripts emitted by `styrn bootstrap-script` always use direct download because they run unattended.

### 15.14.3 `[install]` provenance in the manifest

Setup and stage zero record how the binary arrived (a setup-owned manifest region, 15.3.2):

```toml
[install]
channel = "winget"                       # "brew" | "winget" | "deb" | "cargo" | "direct"
version = "0.4.0"
installed_at = "2026-09-01T10:00:00+02:00"
```

`styrn fleet versions` (6.6) reads this from cached manifests and renders each host's exact upgrade command; the 2.8 out-of-window refusal message uses the same record.

### 15.14.4 `styrn upgrade`: one command, channel-owned (decided)

Adopted [judgment; §0.6 — one command that does the right thing everywhere]: `styrn upgrade` exists, and it is a **delegator, never an updater**:

- **Local:** shells out to the owning channel from `[install]` — `brew upgrade styrn`; `winget upgrade styrn`; for `deb`, download the new asset and invoke `apt install ./styrn_<ver>_amd64.deb`; for `cargo`, `cargo install --locked styrn`; for `direct`, re-run the stage-zero download-verify-replace. It never bypasses or races the channel that owns the install.
- **Remote:** `styrn upgrade <host>` (or `--all` over workers) invokes each worker's own `styrn upgrade` delegator over RPC, **workers first**; it then prompts the operator to upgrade the controller last and reminds them to run `styrn fleet selftest` (16.6 item 6) — the upgrade acceptance test.

The rejected alternative — self-update machinery — would contradict channel ownership (the operator requirement), the supply-chain bar (15.7.6), and §63's no-resident-updater instincts, for no gain over delegation.

### 15.14.5 Replacement mechanics, running jobs, and ordering

- **Binary swap.** Unix: rename-over; running processes keep the old inode. Windows: a running exe cannot be deleted but can be renamed — rename `styrn.exe` → `styrn.exe.old`, move the new binary into place, clean `.old` on next start [well-established; implementer confirm behavior under the running SCM service].
- **Running jobs are unaffected**: each supervisor is an independent process executing the old image to completion (7.8); submissions after the swap use the new binary. No drain/quiesce step is required.
- **styrnd** is restarted by the upgrade delegation (explicit service restart where the channel does not do it).
- **Ordering:** workers before controller is the recommendation (the controller then talks down at most one protocol step, within the 2.8 window); either order is safe. Mixed versions between upgrade rounds are the expected steady state (2.8 rule 3).

## 15.15 Sources for this Part

The [verified: Sn] tags above cite the setup research pass (2026-09-01). Because the underlying brief is a working file, the source list is preserved here; re-verify against current upstream docs at implementation time.

- S1 github.com/DeterminateSystems/nix-installer — receipt, planner/actions, uninstall, --no-confirm
- S2 learn.microsoft.com/en-us/windows-server/administration/openssh/openssh_install_firstuse — Add/Remove-WindowsCapability, sshd service, firewall rule, Server 2025 preinstall
- S3 learn.microsoft.com/en-us/windows-server/administration/openssh/openssh_server_configuration — DefaultShell key, administrators_authorized_keys ACL, sshd_config path, unsupported directives
- S4 learn.microsoft.com/en-us/windows/package-manager/winget/install — winget install flags
- S5 docs.brew.sh/Installation — NONINTERACTIVE=1, prefixes, CLT requirement
- S6 cli.github.com/manual/gh_auth_login — browser/device-code/--with-token/GH_TOKEN
- S7 docs.k3s.io/installation/configuration — config layering, service persistence
- S8 tailscale.com/kb/1031/install-linux + tailscale.com/kb/1088/run-unattended — install script; unattended per OS
- S9 tailscale.com/kb/1085/auth-keys — key types, expiry, --auth-key, security
- S10 tailscale.com/kb/1080/cli — status --json, macOS CLI paths
- S11 tailscale.com/kb/1065/macos-variants + discussions.apple.com/thread/251833298 — variants; setremotelogin FDA error
- S12 alansiu.net (2020) — launchctl ssh.plist workaround (dated; re-test)
- S13 scriptinghouse.com (2024) — winget under SYSTEM
- S14 github.com/microsoft/winget-cli/discussions/4756 + asheroto/winget-install#40 — winget SYSTEM/service limitations
- S15 tailscale.com/docs/install/windows/msi — MSI silent install, TS_UNATTENDEDMODE
- S16 github.com/MacsInSpace/tailscale-silent-installer — field-tested silent-install patterns (secondary)
- S17 github.com/chipsenkbeil/service-manager-rs — cross-platform service crate
- S18 UCLA bookstack (dated) + Jamf community — macOS role accounts via dscl (community-sourced)
- S19/S20 Microsoft docs — virtual service accounts; service-account types (gMSA = AD-only)
- S21 winget-cli returnCodes.md — HRESULT table
- S22 rust-lang.github.io/rustup/installation/other.html — rustup-init flags
- S23 starship.rs/guide — per-shell init pattern
- S24/S25 secondary sources — Claude Code native installers; Codex CLI channels (confirm officially)
- S26/S27 crates.io — inquire; dialoguer
- S28/S29 man systemctl; Apple launchd docs — service install
- S30 crates.io/windows-service — SCM entry points
- S31/S32 man useradd; New-LocalUser docs
- S33 man apt-get — -y, exit 100
- S34/S35 curl-pipe-bash server-side detection PoCs
- S36 get.docker.com script — header warnings, --dry-run, commit pinning
- S38 chezmoi.io/install — install+init chaining
- S39 alembic offline mode — emit-for-review precedent
- S40 nix-installer README — one-liner form, TLS constraints, no script checksum

---

# Part 16 — Implementation plan

## 16.1 Repository layout (orig. §44, superseded by §123; the §123 form is canonical)

```text
styrn/
├── Cargo.toml
├── Cargo.lock
├── src/
│   ├── main.rs
│   ├── cli/
│   ├── setup/            probe/diff/plan/apply engine + renderers (rev. D; Part 15)
│   ├── config/
│   ├── manifest/
│   ├── inventory/
│   ├── transport/
│   ├── rpc/
│   ├── mcp/
│   ├── platform/
│   │   ├── linux.rs
│   │   ├── macos.rs
│   │   └── windows.rs
│   ├── resources/
│   ├── scheduler/
│   ├── jobs/
│   ├── project/
│   ├── git/
│   ├── harness/
│   │   ├── mod.rs
│   │   ├── herdr.rs
│   │   ├── codex.rs
│   │   └── claude.rs
│   ├── integrations/
│   ├── desktop/
│   ├── notification/
│   └── output/
├── integrations/
│   └── herdr/
│       └── herdr-plugin.toml
├── schemas/
│   ├── machine-v1.schema.json
│   ├── project-v1.schema.json
│   └── command-v1.schema.json
├── bootstrap/
│   ├── install.sh                  stage-zero shim (rev. D; 15.11.4)
│   └── install.ps1                 stage-zero shim (rev. D; 15.11.4)
├── examples/
│   ├── machine.toml
│   ├── fricos.styrn.toml
│   └── tailscale-grants.json
└── docs/
    └── architecture.md
```

`mcp/` is a first-class subsystem rather than an afterthought (orig. §123). The earlier §44 layout (without `bootstrap/`, `mcp/`, `integrations/` under `src/`) is subsumed by this one.

## 16.2 Rust crate choices (orig. §45)

A reasonable starting point:

```text
clap              CLI
serde             serialization
serde_json        JSON protocol/output
toml              TOML
tokio             async concurrency
thiserror         structured errors
uuid              machine/job IDs (UUIDv7 — rev. B)
chrono/time       timestamps
sysinfo           cross-platform resource discovery
tracing           structured internal logs
```

Potentially:

```text
portable-pty      only if you later need local PTY management
russh             optional future embedded SSH transport
notify-rust       optional notification adapter
fs4 / windows-rs  advisory file locks & Job Objects (rev. B: Parts 7.3, 7.8)
```

Avoid pulling in a database in v1. Inventory is small enough for TOML files. Jobs are filesystem objects.

## 16.3 Implementation phases (orig. §59; rebuilt in rev. E — review D §2.2)

The rev. B five-phase plan predated three revisions of additions: Phase 1 had silently absorbed all of Part 15, and `styrnd`, `harness run`, audit logging, `monitor`, and `fleet selftest` were placed in no phase at all. Rebuilt: **every specified component sits in exactly one phase; each phase ends in something independently useful; jobs come before agents** (deliberately inverting rev. B's integration-first ordering — the flagship scenario of 13.10/16.7 runs entirely on jobs and workflows, and `ssh -t <host> herdr` already gives crude agent access today, while nothing today gives governed cross-platform validation). Scope note: the operator declined the independent review's proposed cut line (Part 18 preamble), so these phases *order* the full rev. E surface; they do not remove any of it.

**Phase 0 — Foundations and setup core.** *A fresh machine becomes an enrollable worker.*

```text
CLI skeleton; envelope, exit codes, error registry            (Part 10)
manifest + machine_id minting                                 (2.4)
setup engine: probes, Actions, plan/apply, receipt, elevation (15.2–15.6)
worker baseline components: account, sshd, tailscale, dirs,
  git, sleep-policy; Windows hardened user phase + fallback   (15.7, 15.8)
all three setup modes, incl. --interactive; zero-arg path     (15.4)
enrollment card; stage-zero shims; GitHub Releases substrate  (15.10, 15.11.4, 15.14.1)
session-substrate registration: [herdr].enabled, capability tie,
  session-liveness probe                                      (11.0.1-11.0.2, 15.2.1-15.2.2)
```

**Phase 1 — Fleet visibility.** *See and touch every machine from one seat.*

```text
RPC: framing, hello, streams, chunks                          (Part 5)
enroll + host-key pinning; lazy controller keys               (6.1, 4.4, 4.3.1)
host list/show/status/refresh; doctor (both layers); exec     (6.5, 7.10.2)
fleet status/versions; audit logs                             (6.6, 14.3)
substrate state in machine.status + doctor rendering,
  including the two drift lines                               (11.0.3, 6.5)
```

**Phase 2 — Jobs and governance.** *One governed remote job survives a closed laptop.*

```text
registry, locked admission, committed budgets                 (7.2–7.3)
detached supervisor; spawn-ack; submission_id                 (7.8)
disk monitor, wall-clock timeouts                             (7.5, 7.9)
job list/show/logs/cancel; artifact read                      (7.7, 10.5)
controller-push + implicit repo.ensure                        (8.1–8.2)
revision resolution; dirty refusal + --snapshot               (8.4, 8.7)
```

**Phase 3 — Workflows, matrix, selftest, maintenance.** *The 16.7 flagship scenario end to end.*

```text
.styrn.toml, variables, aliases, starter on-ramp              (9.1–9.4)
workflow plan/run (TTY-aware wait, --host semantics), cancel  (6.4, 7.6, 13.3)
matrix run; fleet selftest (substrate-conditional agent leg)   (8.6, 16.6 item 6)
styrnd: maintenance executor + Windows spawn broker           (15.9)
```

**Phase 4 — Agents on the session substrate (Herdr)** *(absorbs integration phase A).* *Govern agents wherever a substrate is registered, without losing Herdr parity; refuse cleanly where none is.*

```text
substrate gating + degradation contract; HarnessProvider
  over RPC; agent list/read/prompt/wait/start/stop/attach;
  herdr status/attach (canonical in 10.5)                     (11.0–11.2, 11.13)
harness run: pane + standalone contexts, parity invariant,
  doctor probe, env-only fallback                             (12.9–12.10)
integrate herdr install/doctor; harness-hook                  (11.16, 12.14)
```

Phase 5 carries the MCP per-call substrate refusals (13.3) on its existing lines, and Phase 8 carries the board empty-states (11.10, 14.5.1) on its existing lines; neither is a new component, so the placement rule is satisfied without a new entry.

**Phase 5 — MCP** *(absorbs integration phases C–D).* *Agents validate cross-platform without SSH.*

```text
mcp serve: readonly + developer; project scoping;
  plan-first tools; max_profile ceiling                       (13.1–13.8)
integrate codex/claude                                        (13.11–13.12)
then, gated on approval-behavior maturity:
  orchestrator profile + fan-out bound; admin last            (13.9, 13.3)
```

**Phase 6 — Packaging and upgrade.** *v0.N+1 reaches four machines without ceremony.*

```text
brew tap, winget manifest, .deb asset from release CI         (15.14.1)
[install] provenance; fleet versions channel column           (15.14.3, 6.6)
styrn upgrade (local delegation + remote orchestration)       (15.14.4–15.14.5)
compatibility windows become binding (first tagged release)   (2.8)
```

**Phase 7 — Setup completions.** *The additive renderers and reversals.*

```text
--uninstall: per-action revert() + transport guard            (15.6.2)
--emit-script/--target-os: render_*, Secret<T>, guards        (15.11.1–15.11.3)
--adopt (after its design spike)                              (15.11.2)
rendered-script VM conformance                                (16.6 item 8)
deploy-key source mode; trust pinning                         (8.2, 9.5)
```

**Phase 8 — Convenience and presentation** *(absorbs integration phases B and E).*

```text
monitor --notify                                              (14.1)
Herdr plugin actions + fleet board pane; view projections     (11.6–11.10, 11.18)
watch TUI                                                     (14.5)
desktop/admin open; power providers                           (3.4, 3.5/D-4)
optional harness hardening hooks; compile-integrations        (12.13, 12.15)
```

Do not start with the TUI (orig. §59's closing rule, unchanged — it is now explicitly Phase 8). **Placement rule (rev. E):** every component this document specifies belongs to exactly one phase above; any future addition must be placed here in the same change, or it is not specified.

## 16.4 Integration implementation priority (orig. §116 — retained for traceability; absorbed into 16.3 in rev. E)

Rev. E folds these integration phases into the single 16.3 sequence: **A → Phase 4, B → Phase 8, C → Phase 5, D → Phase 5 (gated), E → Phase 8.** Rev. B's claim below that phase A "immediately improves control" remains true, but the ordering now follows the flagship scenario (13.10, 16.7), which runs on jobs and workflows before any remote-agent control — hence jobs before agents (review D §2.2). The original staging is preserved here for orig. §116 traceability:

**Integration phase A** — implement first:

```text
styrn herdr status
styrn herdr attach HOST
styrn agent list/read/prompt/wait
styrn integrate herdr install
```

This immediately improves control.

**Integration phase B** — add Herdr plugin:

```text
Fleet board
Validate current commit
Start remote agent
Attach remote agent
```

**Integration phase C** — implement MCP:

```text
styrn mcp serve --profile readonly
styrn mcp serve --profile developer
```

Tools:

```text
styrn_host_status
styrn_workflow_list
styrn_workflow_plan
styrn_workflow_run
styrn_job_get
styrn_job_logs
```

**Integration phase D** — add orchestrator MCP tools:

```text
styrn_agent_start
styrn_agent_read
styrn_agent_prompt
styrn_agent_wait
```

Only after policy/approval behavior is mature.

**Integration phase E** — optional harness hardening hooks and richer Herdr metadata.

## 16.5 Repository separation stays (orig. §122)

Keep two independent repositories.

**Styrn:**

```text
styrn/
├── Rust control binary
├── bootstrap logic
├── protocols/schemas
├── Herdr plugin
├── MCP server
├── harness adapters
├── platform adapters
└── release tooling
```

**FriCOS:**

```text
fricos/
├── product source
├── .styrn.toml
├── AGENTS.md
├── CLAUDE.md
└── optional project integration config
```

This remains the recommended boundary after considering Herdr/MCP integration.

## 16.6 Testing strategy (new in rev. B; resolves S-16)

A product whose entire value is cross-platform correctness cannot rely on "works on my Mac." The strategy, cheapest layer first:

1. **Pure unit tests** — manifest/profile parsing and validation (including the exactly-one-disk-key rule), variable expansion (undefined-variable error, `$${` escape, path rendering per OS via injected separators), admission arithmetic (budget bookkeeping tables, heavy exclusivity), exit-code/error-code mapping, revision-resolution rules against fixture repos.
2. **Protocol golden tests** — recorded NDJSON conversations (hello negotiation including version-window rejection, request/response, streams, chunk reassembly with checksum, cancel, oversized-frame rejection) replayed against both peer roles. The protocol module must be testable with in-memory pipes, no SSH.
3. **Fake-worker harness** — `styrn rpc serve --stdio` run as a *local child process* with a temp `paths.root`, exercising the full controller↔worker path (submit → detached supervisor → status/log tailing → reattach after killing the controller-side session → cancel) on whatever OS CI is running. This single harness covers S-01's fix on all three platforms.
4. **Concurrency tests** — two controller processes hammering one fake worker with simultaneous submissions; assert committed budgets never exceed policy and `max_heavy_jobs` never over-admits (S-03's regression test).
5. **Platform CI matrix** — GitHub Actions (or equivalent) on `ubuntu-latest`, `macos-latest`, `windows-latest` running layers 1–4, plus Windows-specific tests: Job-Object tree-kill actually reaps grandchildren, long-path job root, argv round-trip through `CreateProcess` for adversarial arguments (spaces, quotes, `%VAR%`, trailing backslashes).
6. **End-to-end smoke on the real fleet** — a `styrn fleet selftest` command (new): trivially small project profile (`echo`-level workflows) run as a real matrix across all enrolled machines; used after every upgrade, doubling as the acceptance test for enrollment, push, admission, supervision, and artifact retrieval. This is also the dogfooding loop: Styrn's own repository gets a `.styrn.toml` so the fleet validates Styrn. Selftest passes unchanged on a Herdr-less fleet: the enrollment, push, admission, supervision and artifact legs run on every host, and the agent/parity leg reports `skipped (substrate: none)` per host rather than failing — item 7's conformance runs only where the substrate is `active`, as it already says.
7. **Herdr parity conformance (rev. C; S-33)** — on every OS where Herdr is present in the test environment: start the same harness (or a stand-in binary with the harness's process signature) twice in Herdr panes — once manually, once via `styrn harness run` — and assert Herdr reports identical detection and an identical lifecycle-transition sequence for both, and that the wrapped child's environment is a superset of the manual one's (no `HERDR_*` variable lost or altered). Runs in CI where Herdr can be installed, and always as part of `styrn fleet selftest` (item 6). This is the check that keeps the 12.9.1 invariant from rotting.
8. **Setup and rendered-script conformance (rev. D; amended rev. G; Part 15)** — on the three-OS VM matrix: fresh-machine `styrn setup --yes` in current-user mode creates no account and converges (second run prints "nothing to do"); `--uninstall` leaves no Styrn-owned residue while sparing pre-existing tools (receipt-ownership test); an environmental dedicated-mode run uses an explicitly selected disposable account whose name is not `styrn`; Windows proves both identity modes with real SSH key login and proves that a same-SID hostile process cannot use the spawn broker; and for each OS, emitted `--emit-script` output on an identical fresh VM converges to the **same probe results** as direct `apply` — the drift check that makes the third renderer trustworthy (15.11).

Mocked-SSH transport tests (orig. §2.5) fall out of layer 3 for free: the `Transport` trait's test implementation is "spawn local child," and the ssh implementation is thin enough to be covered by layer 6.

## 16.7 A realistic daily workflow (orig. §61)

Start from any controller:

```text
styrn fleet status
```

You have a Windows-specific FriCOS issue:

```text
styrn agent start win-mini \
  --harness codex \
  --project fricos \
  --name windows-fs
```

Prompt:

```text
styrn agent prompt windows-fs \
  --text "Investigate issue #351. Use the project workflows; do not bypass resource limits."
```

Agent produces commit. Run:

```text
styrn matrix run fricos cross-platform --revision <commit>
```

Scheduler:

```text
win-hp         Windows heavy
linux-macpro   Linux heavy
```

You can close the controller. **Herdr owns the persistent agent sessions, and each job's worker-side supervisor owns the jobs** (rev. B — the original said only the first half, and its execution model would have killed the jobs; Part 7.8).

Later, from a different controller:

```text
styrn host enroll <host> --user <user>
styrn agent list --all
styrn job list
```

provided it has access to the same inventory or re-enrolls the hosts.

## 16.8 Herdr + Styrn project UX example (orig. §121)

You open FriCOS in Herdr on the M1. The Herdr Styrn plugin recognizes:

```text
project = fricos
HEAD = 7a3fd91
```

You run Codex locally. Codex has Styrn MCP. Codex changes Windows-specific code. Codex calls:

```text
styrn_workflow_plan(test-windows-heavy)
```

You approve. Styrn schedules HP Windows. Herdr fleet board shows:

```text
win-hp / test-windows-heavy / working
```

The test fails. Codex reads the structured failure through MCP and edits the code. You invoke Herdr action:

```text
Validate current commit
```

Styrn starts Linux + Windows validation. You close the MacBook. Remote jobs and remote Herdr sessions continue (Part 7.8 makes this true). Later, from another enrolled Windows/Linux/macOS controller:

```text
styrn fleet status
styrn job list
styrn agent list
```

and continue. That is the target developer experience.

## 16.9 Consolidated recommendation (orig. §126)

The architecture should now be understood as:

```text
                 Styrn
        general machine/agent control
                    |
     +--------------+---------------+
     |              |               |
   Herdr           MCP          project policy
 human UX       agent UX        enforcement map
     |              |               |
     +--------------+---------------+
                    |
               remote jobs
                    |
      macOS / Linux / native Windows
```

The key decisions are:

1. **Generalize the controller.** Styrn is not FriCOS-specific.
2. **Use one Rust binary on every platform.** No Python/Node runtime is required by Styrn itself.
3. **Run the control command from any enrolled platform.** macOS is not privileged architecturally.
4. **Use Herdr as the persistent agent/terminal runtime where its substrate is registered (11.0).** Do not reinvent its terminal/process model — and do not require it for anything outside the agent surface.
5. **Add a thin Styrn Herdr plugin.** This gives contextual actions and a fleet board.
6. **Add Styrn as an MCP server.** This gives Codex/Claude safe, structured access to remote validation.
7. **Do not give ordinary agents raw fleet SSH.** Expose project workflows rather than arbitrary remote commands — understood per Part 4.5 as least-privilege ergonomics over worker-side enforcement, not as containment.
8. **Use `AGENTS.md` as shared instructions and import it from `CLAUDE.md`.**
9. **Keep hard resource controls below the harness.** Environment, process limits, admission, quotas, timeout and cleanup are enforced by Styrn.
10. **Keep FriCOS-specific behavior in `.styrn.toml`.**
11. **Move the final bootstrap engine into Rust.** Shell/PowerShell scripts become thin stage-zero installers.
12. **Keep every finite non-interactive command human-readable by default and machine-readable with `--json`; use `--jsonl` for streams.**
13. **(rev. B) Jobs are worker-owned; controllers are stateless dispatchers.** Detached supervisors, locked worker-side admission, and controller-push source sync are what make "any controller, closable at any time" actually true.

This produces a system that should feel less like "SSH into three build boxes" and more like a single heterogeneous development fabric, while retaining native OS behavior where it matters.

---

# Part 17 — Research notes (external claims, recorded 2026-09-01)

**Standing caveat (rev. B):** everything in this Part records what revision A's author found in upstream documentation on 2026-09-01. None of it can be verified from this repository, all of it concerns fast-moving products, and every design element that depends on it is built to degrade gracefully if a claim is stale: harness behavior sits behind the `HarnessProvider` trait and `integrate … doctor`; Tailscale/OpenSSH behavior is probed by `styrn host doctor`; nothing in the enforcement path (Parts 5–8) depends on any claim below. **Re-verify each item against current upstream docs at implementation time.**

## 17.1 Research notes (orig. §67)

### Herdr

- Install and supported platforms: https://herdr.dev/docs/install/
- Persistence and remote access: https://herdr.dev/docs/persistence-remote/
- Windows support and current remote-target limitation: https://herdr.dev/docs/windows-beta/
- CLI/API and JSON-oriented automation: https://herdr.dev/docs/cli-reference/

Relevant behavior as recorded:

- stable binaries exist for Linux, macOS and Windows;
- Herdr servers/panes are persistent;
- `herdr server` is explicitly intended for supervised/headless use;
- Windows local persistent sessions are supported;
- Windows processes launched through OpenSSH can survive SSH logout;
- Windows is not currently supported as a `herdr --remote` target;
- most CLI automation commands produce deterministic JSON.

### Tailscale

- Unattended operation: https://tailscale.com/docs/how-to/run-unattended
- macOS variants: https://tailscale.com/docs/concepts/macos-variants
- tailscaled daemon: https://tailscale.com/docs/reference/tailscaled
- grants: https://tailscale.com/docs/features/access-control/grants

Relevant behavior as recorded:

- Linux Tailscale normally runs as a system service;
- Windows supports `--unattended`;
- normal macOS GUI variants do not provide equivalent before-login unattended behavior;
- the open-source macOS `tailscaled` variant can run before login;
- grants are the recommended modern access-control mechanism.

### Windows OpenSSH

Microsoft documentation: https://learn.microsoft.com/en-us/windows-server/administration/openssh/openssh_install_firstuse

### macOS Remote Login and Screen Sharing

- Remote Login / SSH: https://support.apple.com/guide/mac-help/mchlp1066/mac
- Screen Sharing: https://support.apple.com/guide/mac-help/mh11848/mac
- Apple Remote Management: https://support.apple.com/en-us/102024

Relevant behavior as recorded:

- macOS supports SSH through Remote Login;
- Screen Sharing can provide full GUI control;
- Screen Sharing and Remote Management cannot be enabled simultaneously;
- modern macOS restricts fully automated remote-management enablement without appropriate management/consent.

### Codex

- Codex CLI: https://developers.openai.com/codex/cli
- Windows sandbox: https://developers.openai.com/codex/windows/windows-sandbox
- open-source CLI repository/install notes: https://github.com/openai/codex

Relevant behavior as recorded:

- native Windows Codex is supported;
- a native Windows sandbox exists;
- `elevated` is the preferred Windows sandbox implementation;
- `codex exec` supports repeatable non-interactive automation;
- official standalone installers exist for current platforms.

### Claude Code

- installation and native Windows: https://code.claude.com/docs/en/setup
- sandboxing: https://code.claude.com/docs/en/sandboxing
- programmatic/headless mode: https://code.claude.com/docs/en/headless
- PowerShell tool: https://code.claude.com/docs/en/tools-reference

Relevant behavior as recorded:

- Claude Code supports native Windows;
- PowerShell can be used;
- `claude -p` supports non-interactive operation;
- `--output-format json` and streaming JSON are supported;
- native Windows sandboxing is not currently supported.

### Rust / Cargo / sccache

- Cargo configuration: https://doc.rust-lang.org/cargo/reference/config.html
- Cargo environment variables: https://doc.rust-lang.org/cargo/reference/environment-variables.html
- Cargo build cache: https://doc.rust-lang.org/cargo/reference/build-cache.html
- sccache: https://github.com/mozilla/sccache
- sccache Rust notes: https://github.com/mozilla/sccache/blob/main/docs/Rust.md
- Rust static/runtime linkage: https://doc.rust-lang.org/reference/linkage.html

Relevant behavior as recorded:

- Cargo supports explicit parallel job limits;
- Cargo target/build directories can be redirected;
- sccache can wrap rustc through `RUSTC_WRAPPER`;
- Rust incremental compilation should be disabled for sccacheable Rust jobs;
- Linux musl targets are suitable for portable Styrn release binaries.

## 17.2 Source list for the integration research (orig. §125)

Verified (by rev. A) around 2026-09-01.

### Herdr

- Install: https://herdr.dev/docs/install/
- Integrations: https://herdr.dev/docs/integrations/
- Agent automation: https://herdr.dev/docs/agent-automation/
- CLI reference: https://herdr.dev/docs/cli-reference/
- Socket and plugin API: https://herdr.dev/docs/socket-api/
- Windows support: https://herdr.dev/docs/windows-beta/
- Configuration/keybindings: https://herdr.dev/docs/configuration/

### Claude Code

- Advanced setup / native Windows: https://code.claude.com/docs/en/setup
- Project memory and AGENTS.md import: https://code.claude.com/docs/en/memory
- Hooks: https://code.claude.com/docs/en/hooks
- MCP: https://code.claude.com/docs/en/mcp
- Programmatic/headless mode: https://code.claude.com/docs/en/headless
- Settings: https://code.claude.com/docs/en/settings

### Codex

- Repository / installation: https://github.com/openai/codex
- Codex Rust CLI/MCP overview: https://github.com/openai/codex/blob/main/codex-rs/README.md
- AGENTS.md implementation notes: https://github.com/openai/codex/blob/main/codex-rs/core/src/agents_md.rs
- Configuration schema: https://github.com/openai/codex/blob/main/codex-rs/core/config.schema.json
- Experimental MCP server interface: https://github.com/openai/codex/blob/main/codex-rs/docs/codex_mcp_interface.md

---

# Part 18 — Issues register

**Independent review (rev. E note):** `docs/design-review-D.md` (2026-09-01) records a fresh adversarial review of rev. D: a proportionality assessment proposing a v1 cut line (defer `styrnd`, script generation, `--uninstall`, RPC multiplexing, the N/N−1 promise, the orchestrator/admin MCP profiles, among others) together with correctness findings. The operator's decision on scope: **correctness only, cut nothing** — every mechanism remains in scope and fully specified, and the proportionality analysis is consciously *not adopted*, retained there as context for a later decision. The review's correctness findings (§4) and gap list (§6.2) are fixed in rev. E and consolidated as S-37–S-39 below.

Severity legend: **blocker** = the design as written could not have been implemented or would fail its own stated promises; **major** = a real production failure mode, security gap, or missing mechanism that implementation would have had to invent ad hoc; **minor** = internal inconsistency, prototype bug, or gap with contained impact.

Every issue cites the original section(s) it derives from; resolutions name the Part of this document where the fix is normative.

---

**S-01 · blocker · orig. §3, §34, §61**
**Problem:** jobs were driven through the controller's `ssh … styrn rpc serve --stdio` session with no ownership model for transport loss; a dropped SSH session (or closing the laptop, which §61 explicitly promises is fine) kills the remote process tree on every OS. No orphan, kill, or reattach semantics existed.
**Impact:** heavy validation jobs die mid-build whenever the controller sleeps or roams; §61's headline workflow is false as specified.
**Resolution:** worker-owned detached supervisor per job; RPC session only submits and tails; reattach/cancel from any controller; reconciliation state `supervisor_lost`. Part 7.8, states in 7.11, protocol liveness in 5.5.

**S-02 · blocker · orig. §35 vs §41**
**Problem:** §35 requires `git fetch` on workers before creating job worktrees; §41 forbids personal SSH keys and unrelated GitHub tokens on workers. For a private repository these are jointly unsatisfiable — a genuine contradiction, not a wording issue.
**Impact:** the core job pipeline cannot obtain source on any worker.
**Resolution:** controller-push model over the existing SSH transport into per-project bare repos (workers hold zero forge credentials; fleet works offline from the forge); explicit opt-in `[source.auth] mode = "deploy-key"` for project-scoped read-only keys. Parts 8.1–8.2, 4.2. Default confirmed in D-1.

**S-03 · blocker · orig. §27, §32, §54, §62**
**Problem:** the "no master / any controller" model plus "shared controller state" never says what happens when two controllers dispatch to the same worker simultaneously; admission was described as a formula, not an atomic operation; heavy-exclusivity counting had no home; inventories can diverge with no reconciliation story.
**Impact:** double-booked memory/disk, two "exclusive" heavy jobs, divergent fleet views.
**Resolution:** worker-side authoritative admission serialized by a registry lock with committed-budget bookkeeping; controllers only predict; fan-out queries + per-controller submission index for state; caches declared caches. Parts 7.2–7.3, 2.1, 6.7.

**S-04 · blocker · orig. §2.10, §3, §79, §120**
**Problem:** "a versioned JSON protocol" with a single-blob handshake; no framing, no request multiplexing, no streaming/response interleaving rules, no binary transfer, no negotiation or compatibility policy (who speaks first; what happens on mismatch).
**Impact:** unimplementable as specified; every implementer choice would have been protocol-breaking later.
**Resolution:** full NDJSON frame spec: hello with `[protocol_min, protocol_max]` (server first), correlation-ID multiplexing, `event`/`log` streams, chunked base64 artifacts with checksums, cancel/ping, N/N−1 support window. Part 5; policy in 2.8.

**S-05 · major · orig. §9, §21, §22, §25, §41**
**Problem:** single shared SSH key in all examples; host-key trust left to implicit OpenSSH TOFU; no rotation; `styrn host remove` listed with no semantics; no revocation path for a lost/compromised controller.
**Impact:** one lost laptop compromises every worker with no clean recovery; first-connection MITM window unacknowledged.
**Resolution:** per-controller keypairs; enrollment TOFU made explicit with fingerprint confirmation and pinning in a Styrn-managed known_hosts; `authorize-key`/`revoke-key`/`trust` commands; `host remove` semantics defined (local-only vs `--revoke`); lost-controller procedure. Parts 4.3, 4.4, 6.1, 6.2.

**S-06 · blocker · orig. §26, §81–§87, §93**
**Problem:** two implied security properties do not hold: (a) workflow commands come from `.styrn.toml` in the repo the agent edits, so "agents can only run declared workflows" is defeated by editing the profile on the agent's own branch; (b) MCP tool narrowing does not contain an agent that has shell access on a machine holding controller credentials — it can invoke `styrn`/`ssh` directly.
**Impact:** the design's security story overstated what it delivers; readers would provision credentials and trust boundaries based on false assumptions.
**Resolution:** honest boundary model (Part 4.5): jobs are untrusted code as the resolved worker identity; user/current-user mode explicitly cannot promise account, credential, or same-user Styrn-state separation; optional system/dedicated mode protects machine state and can be credential-free. MCP remains least-privilege ergonomics; server-side profile ceiling and optional controller-side profile pinning remain. Parts 4.5, 9.5, 13.2, 13.3.

**S-07 · major · orig. §27, §28, §32**
**Problem:** the admission formula conflates intra-job parallelism with job-count admission; `available_memory` is a point sample, so concurrent admissions (or admitted-but-not-yet-allocating jobs) double-count the same free memory; linker/sccache peak spikes exceed the per-job constant; no accounting of already-committed budgets.
**Impact:** over-admission under exactly the loads the governor exists to prevent (16 GB mini-PC).
**Resolution:** committed-budget bookkeeping under the registry lock; both sampled-reality and bookkeeping checks must pass; intra-job parallelism sized against *remaining* room; `peak_memory_bytes` hint for heavy jobs; residual risk stated with the enforcement backstop. Part 7.2.

**S-08 · major · orig. §31 (with §27, §28)**
**Problem:** "periodically measure" is a polling race against a runaway build; no per-OS mechanism analysis (Linux project quotas, NTFS/FSRM limitations, macOS's lack of per-directory quotas); walking a 100 GiB target dir is itself costly; the quota value had no schema key (S-28).
**Impact:** disk-full incidents on the 480 GB worker; or naive fixed-interval polling that is both racy and expensive.
**Resolution:** adaptive-interval polling (30/10/5 s) with cached directory walks as the portable baseline; overshoot explicitly budgeted by the reserved-disk hard floor; two-trigger kill policy (job quota vs host floor, floor wins); kernel quotas noted as optional Linux hardening only. Part 7.5.

**S-09 · major · orig. §25, §33, §48 (Windows execution generally)**
**Problem:** no specification of command quoting/escaping through the Windows exec path, shell vs no-shell semantics, process-tree termination mechanics, path-separator normalization for expanded variables, or long-path handling — for a design whose selling point is native-Windows correctness.
**Impact:** quoting bugs, orphaned build trees, MAX_PATH failures deep in Cargo target dirs.
**Resolution:** no-shell argv execution end to end (RPC carries arrays; `.bat` unsupported; `--shell` opt-in for humans on `exec` only); supervisor-anchored Job Objects with kill-on-close; native separator rendering at variable expansion; LongPathsEnabled + `core.longpaths` + short job roots, doctor-checked. Part 7.10; framing keystone in 5.1.

**S-10 · major · orig. §48, §112 + `bootstrap-windows.ps1`**
**Problem:** the script installs per-user agent tools from the elevated admin context while writing their config to `C:\Users\styrn` (the very defect §112 diagnoses, unfixed in the shipped script); writes into a profile directory that does not exist before the account's first logon; shadows `$home`; and `"$WorkerUser:(OI)(CI)F"` in the `icacls` call is a probable PowerShell scope-qualified-variable parse failure (**verify by execution** — if real, the script never ran end-to-end as shipped). The generated worker password is discarded, foreclosing the scheduled-task user phase hardened mode needs.
**Impact:** Windows workers that pass bootstrap but cannot start agents; possibly a script that fails outright.
**Resolution (superseded in rev. D):** the scripts are demoted to historical prototypes (15.12); all four design causes are eliminated by the setup engine — transient-logon user phase and in-memory credential moment (15.8), profile materialization before any profile write, per-user key file with probed ACLs (15.7.1). Hardened mode is now the Windows default (D-3).

**S-11 · major · orig. §24**
**Problem:** exit code 1 undefined; no policy for collisions between Styrn's codes and the exit codes of invoked workflow commands (`cargo test` → 101) or `exec`'d remote commands; scripts could not distinguish "styrn failed" from "the build failed".
**Impact:** ambiguous automation behavior at the primary integration surface.
**Resolution:** 1 = internal error; `workflow run` never propagates inner codes (always 12 + `data.exit_code` in JSON); `exec` alone mirrors the remote code (ssh convention, ambiguity documented, `--json` authoritative). Part 10.4; exec convention decided in D-6.

**S-12 · minor · orig. §40 vs §80, §101**
**Problem:** the same notification feature is specified under two different commands (`styrn watch --notify` and `styrn monitor --notify`).
**Impact:** contradictory CLI surface.
**Resolution:** `monitor` = headless events (+`--notify`/`--jsonl`); `watch` = TUI only. §0.4; Part 14.1.

**S-13 · major · orig. §25, §38, §73, §98**
**Problem:** `HEAD` and symbolic revisions appear in dispatch examples with no rule about *where* they resolve; a controller may not even have the repository; matrix runs took a bare positional `HEAD`.
**Impact:** "validated HEAD" could silently mean different commits on different machines — the exact failure the SHA-pinning philosophy (§35–§36) exists to prevent.
**Resolution:** resolution always happens before submission, in a defined order, never on the worker; symbolic refs refused outside a checkout; all reporting shows the SHA. Part 8.4; matrix syntax updated in 8.6.

**S-14 · major · orig. §25, §62, §120**
**Problem:** `job://<id>/…` URIs and bare job IDs have no host binding, and with independent per-controller inventories there is no shared index to resolve them; a second controller cannot dereference the first controller's artifact URIs.
**Impact:** artifact retrieval and `job show` break in exactly the multi-controller scenario the design advertises.
**Resolution:** host-qualified `job://<host>/<job-id>/<path>` URIs; per-controller submission index plus fan-out fallback for bare IDs. Parts 7.7, 6.7; §0.4.

**S-15 · major · orig. §2.7, §2.10, §19, §23, §26, §57**
**Problem:** four version fields (`schema_version` ×2, envelope, protocol) with no compatibility policy: no support window, no unknown-field rule, no defined failure on mismatch, no cache-staleness handling.
**Impact:** the first controller/worker version skew becomes an undebuggable field incident.
**Resolution:** must-ignore for additions; version bump semantics; N/N−1 support window for schemas and protocol; `minimum_styrn_version` enforcement point; manifest-cache staleness warnings. Part 2.8.

**S-16 · major · orig. §2.5 (absence elsewhere)**
**Problem:** a one-line aspiration ("mocked SSH transport tests, scheduling tests…") was the entire testing story for a product whose value is cross-platform behavioral correctness.
**Impact:** the riskiest subsystems (protocol, detached supervision, Windows process control, concurrent admission) had no planned verification.
**Resolution:** eight-layer strategy: unit, protocol golden, local fake-worker harness, concurrency hammering, three-OS CI matrix with Windows-specific process/path tests, `styrn fleet selftest` on the real fleet, Herdr-parity conformance, and setup/rendered-script conformance. Part 16.6.

**S-17 · major · bootstrap scripts (orig. §47–§49)**
**Problem:** all agent/tool installation is unpinned `curl | sh` / `irm | iex` from six different vendors, with no checksum or version pinning, running partly as root.
**Impact:** supply-chain exposure at the machines' most trusting moment.
**Resolution (superseded in rev. D):** runtime installs use pinned `{version, url, sha256}` component tables under the 15.7.6 supply-chain bar; the only remaining piped script is the stage-zero shim, kept tiny, checksum-embedding, and digest-published (15.11.4).

**S-18 · minor · scripts + orig. §7, §15, §28/§51**
**Problem:** assorted prototype bugs and inconsistencies: macOS manifest hardcodes `[tailscale] installed = false` even after installing it; the grants example bundles RDP+Cockpit to all workers against §7's own advice; dual `reserved_disk_bytes`/`reserved_disk_percent` keys with undefined precedence; version-pinned Windows OpenSSH capability name; invented Claude Windows settings keys.
**Impact:** contained — wrong metadata, over-broad network policy, schema ambiguity.
**Resolution:** exactly-one-disk-key validation rule (2.4.2); grants example corrected (3.1); the script-level items are superseded in rev. D by the engine (manifest as probed output 15.3.2, wildcard capability probe 15.7.1, scripts demoted 15.12); Claude keys remain flagged unverified (12.3).

**S-19 · major · absent from rev. A**
**Problem:** no audit logging (who dispatched what across multiple controllers), no error-code registry or stability rule, no metrics stance, no backup/restore story, no secrets-location summary.
**Impact:** operational dead-ends the first time something needs post-hoc explanation or a controller dies.
**Resolution:** worker + controller append-only audit JSONL; error-code registry with append-only stability; job records as the deliberate v1 observability surface (no metrics daemon); backup/restore by directory copy + re-enrollment, worker state disposable; secrets table. Parts 14.2–14.4, 10.3, 4.6.

**S-20 · minor · orig. §19/§25, §83/§117, §89**
**Problem:** naming drift: `--kind` vs `harness`; MCP tools with and without `styrn_` prefix; unexplained `machine` vs `host` command split.
**Impact:** would have fossilized into incompatible surfaces.
**Resolution:** frozen vocabulary (§0.4): `--harness`, always-prefixed MCP tools, machine=local/host=remote defined.

**S-21 · minor · orig. §98**
**Problem:** the "offer snapshot/temp commit" option for dirty worktrees had no mechanics (what is committed, where the ref lives, how results are labeled, untracked files).
**Impact:** ambiguity at a correctness-sensitive spot (validating something other than what the user sees).
**Resolution:** stash-create-style snapshot onto `refs/styrn/snapshots/*`, tracked-only by default, labeled results, pruned with retention. Part 8.7.

**S-22 · minor · orig. §30, §19**
**Problem:** sccache is mandated and quota'd in the manifest (`[caches.sccache] max_bytes`) but nothing wires the quota or cache location to the actual processes.
**Resolution:** supervisor exports `SCCACHE_DIR` under `[paths].cache` and `SCCACHE_CACHE_SIZE` from the manifest; `cache status/trim` operate on it. Part 7.12.

**S-23 · minor · orig. §11**
**Problem:** two alternative Herdr invocation styles left explicitly unstandardized.
**Resolution:** env-var form (`HERDR_SESSION=fleet herdr server`), matching the shipped systemd unit. §0.4; Part 11.1.

**S-24 · minor · orig. §23 (implication)**
**Problem:** RFC 3339 timestamps from independently clocked machines, with no stated assumption or check.
**Resolution:** NTP assumption stated; timestamps never used for ordering decisions; doctor warns at >30 s skew. Part 2.5.

**S-25 · major · orig. §19 vs §50 + all bootstrap scripts**
**Problem:** the canonical manifest requires `machine_id`, but no bootstrap script generates one and §50's bootstrap-output example omits it — while enrollment, caching, job indexing, and substitution detection all need stable machine identity.
**Impact:** every real machine would have violated the manifest schema on day one.
**Resolution:** UUIDv7 minted by `styrn machine init`, self-healed by any manifest-reading command, immutable thereafter, name→machine_id substitution check. Part 2.4.1.

**S-26 · minor · orig. §21, §22, §62**
**Problem:** manifest caches and inventories on multiple controllers drift with no staleness or reconciliation policy.
**Resolution:** caches feed predictions only; authoritative state always queried from workers; refresh command + 7-day/version-change staleness warnings. Parts 2.8.6, 6.7.

**S-27 · minor · `bootstrap-macos.sh` (orig. §49)**
**Problem:** `dscl`-created service users lack a Secure Token on modern macOS, and `systemsetup -setremotelogin on` can require Full Disk Access; either can silently degrade a "successful" bootstrap. (**Verify against the target macOS version.**)
**Resolution (superseded in rev. D):** folded into the setup engine's macOS account decision and Remote Login fallback chain (15.7.5, 15.7.3), both still flagged for end-to-end testing.

**S-28 · minor · orig. §28, §31**
**Problem:** §31's per-job disk limits (35/100/100–150 GiB) exist only as prose; no `[resources.policy]` key carries them, so the governor has nothing to enforce.
**Resolution:** `max_job_disk_bytes` added to the policy schema and to every per-machine policy example. §0.4; Parts 2.4, 7.4.

**S-29 · minor · rev. B Part 8.2, 10.5 (rev. C friction audit)**
**Problem:** `styrn project init <host> <project>` was a required manual step before the first dispatch to a host — a documented sequence where one command should suffice (§0.6).
**Resolution:** `repo.ensure` is implicit in every submission (creates the bare repo when absent); `project init` retained only as an optional pre-warm for large repositories. Parts 8.2, 10.5.

**S-30 · minor · rev. B Part 4.3 (rev. C friction audit)**
**Problem:** per-controller keypair generation was a documented prerequisite (`styrn controller init` or manual `ssh-keygen`) before anything worked.
**Resolution:** lazy generation — the first command needing an identity creates it, prints the public key, and says how to authorize it; `controller init` is optional pre-generation only. Part 4.3.1.

**S-31 · minor · rev. B Part 7.6, 10.5 (rev. C friction audit)**
**Problem:** queue-on-heavy-exclusivity required remembering an explicit `--wait`; the default interactive experience was an opaque exit-6 failure for a job that would have run a minute later.
**Resolution:** TTY-aware default — interactive invocations wait with a visible status line (`--no-wait` opts out); non-interactive invocations fail fast unless `--wait`. Deterministic for scripts, frictionless for humans. Parts 7.6, 10.5; new code `resource.heavy_exclusivity_denied` retained.

**S-32 · minor · rev. B Part 9.1 (rev. C friction audit)**
**Problem:** a repository without `.styrn.toml` produced only errors — no on-ramp, violating "never make a developer supply what the tool can draft" (§0.6).
**Resolution:** profile-less repos get a commented starter profile printed by `project inspect`/`workflow list` (Rust flavor when `Cargo.toml` is detected); a full `styrn project scaffold` is deferred to a later phase. Part 9.1.

**S-33 · blocker · orig. §94–§95 / rev. B Parts 12.9–12.10 (raised in rev. C)**
**Problem:** "preserves Herdr process detection" was asserted as a launcher step with no mechanism; Unix exec was hedged ("where possible"); the Windows story rested entirely on an unverified upstream claim that Herdr's detection follows descendant processes and wrappers.
**Impact:** if wrapping breaks Herdr detection, the cascade is total for Styrn-launched agents: `HarnessProvider` (`agent list/read/prompt/wait/stop/attach`), the `orchestrator` MCP profile, cross-agent delegation (13.9), and `styrn agent wait` all silently fail — "wrapped agents invisible, manual agents fine," breaching orig. §12's promise to preserve Herdr's lifecycle model and the §0.6 tenet at once.
**Resolution:** named **Herdr parity** invariant with a refusal-over-degradation fallback (env-only launch, reported not silent); normative `execvp` replacement on Unix/macOS with defined failure surface and reaper-based budget release; minimal-footprint direct-child + inert-waiter + no-kill-on-close Job Object arrangement on Windows with a live doctor probe instead of assumed upstream behavior; augment-never-scrub environment rule protecting `HERDR_*` identity variables; hook-coexistence rule (Styrn never touches Herdr-installed hooks); conformance test. Parts 12.9.1, 12.10, 16.6 item 7.

**S-34 · major · orig. §58/§63, rev. B Parts 6.8 and 7.8 (raised in rev. D)**
**Problem:** Part 6.8 specifies daily and weekly maintenance but never says what *runs* it — workers are headless, controllers are closable, and orig. §63 rejects a central daemon; separately, 7.8's Windows spawn fallback was a placeholder ("a pre-created scheduled task") with no owner. An apparent contradiction (needs a resident executor vs. "no daemon") was left standing.
**Impact:** retention, cache quotas, log rotation, and disk-floor protection silently never run; Windows supervisors have no spawn path when sshd denies Job-Object breakaway.
**Resolution:** `styrnd` — per-worker and local-only (no network listener), installed rootlessly as a user service by default; optional system scope supplies boot/logout persistence and a separate credential-free, capability-limited LocalSystem Windows broker. Maintenance degrades opportunistically; worker eligibility reports the actual login-session/boot and direct/broker capabilities rather than pretending durability. Part 15.9.

**S-35 · major · orig. §48 + `bootstrap-windows.ps1` (raised in rev. D)**
**Problem:** the entire rev. A Windows bootstrap rests on a winget helper, but winget is per-user MSIX and is not resolvable/runnable under SYSTEM/service contexts and commonly fails in non-interactive SSH sessions [verified: S13, S14] — precisely the contexts in which Styrn provisions Windows workers.
**Impact:** Windows provisioning that works in a demo (interactive admin console) and fails in production use (remote, non-interactive).
**Resolution:** winget demoted to an opportunistic substrate for interactive elevated consoles only; direct download + silent MSI/EXE with pinned versions and checksums is the dependable Windows channel the spec is written against. Part 15.7.6.

**S-36 · minor · rev. C Parts 6.1/15 seam (raised in rev. D)**
**Problem:** enrollment ergonomics straddled two Parts — pass 1 left 6.1 "light" pending the setup redesign, with no decision on whether a worker becomes enrollable in one step or how, given that no credential may live on the worker.
**Resolution:** enrollment stays controller-initiated (trust flows from the credential holder); `styrn setup` closes the loop by installing controller keys up front and ending with the **enrollment card** (name/address + explicit transport user + host-key fingerprint), making enrollment one pasted line per direction — script out, card back. Parts 15.10, 6.1.

**S-37 · major · rev. D Parts 2.8/6.6/16.6 (raised by review D §6.2 item 1; resolved via a new operator requirement)**
**Problem:** the document engineered *around* mixed versions — the 2.8 compatibility window, `fleet versions` drift reporting, `fleet selftest` "after every upgrade" — while specifying **no mechanism that upgrades the `styrn` binary on any machine**. Ad-hoc replacement would interact undefined with running jobs, styrnd, and the window.
**Impact:** after v0.2 ships, four machines have no stated path to v0.3 — the operation the compatibility machinery exists for was missing.
**Resolution:** the platform package channel owns upgrades ("installable and upgradeable via the different package managers available for each platform" — operator, verbatim): channel table with an honest v1/aspirational split; stage zero prefers a package manager when human-present (S-35 nuance intact); `[install]` provenance; `fleet versions` channel column + per-host upgrade commands; `styrn upgrade` as a pure channel delegator; swap mechanics safe under running supervisors; workers-first ordering; N/N−1 declared load-bearing with out-of-window refusals naming the exact upgrade command. Parts 15.14, 2.8, 6.6, 10.5.

**S-38 · minor · rev. D fleet reality (review D §6.2 item 2)**
**Problem:** two of the four machines are laptops, and nothing prevented OS sleep from suspending a worker that the scheduler considers eligible — "heavy Windows validation" silently assumed the HP's lid stays open. No wake mechanism, no sleep-policy setup, no doctor check.
**Resolution:** `sleep-policy` setup component (default on for workers; per-OS mechanics, macOS incantation implementer-confirm) plus a doctor check pairing `accept_jobs` with the OS sleep policy; remote *wake* explicitly out of scope (power providers are recovery, not wake). Parts 15.7.6, 15.3.1, 6.5.

**S-39 · minor · rev. D internal consistency (review D §4 and §6.2 items 3–5; consolidated)**
**Problem:** thirteen fit-and-finish defects survived three passes: 12.9 step 8 vs. the normative exec model (§4.1); styrnd's LSA credential vs. "the password goes nowhere" (§4.2); the doctor/probe one-to-one rule over-claimed for controller-side checks (§4.3); `styrn_workflow_cancel` dangling with no operation (§4.4); Part 10.5 missing the machine/controller/harness/selftest command groups (§4.5); admission-formula inputs with no defaults and no disk-hint key (§4.6); workflow-command cwd never stated (§4.7); exit 9 as the *normal* result of listing a fleet with sleeping laptops (§4.8); half the error registry without exit mappings and the envelope without a compatibility window (§4.9); `submission_id` dedupe undefined across job cleanup (§4.10); `--host` override semantics, log files' inclusion in the quota walk, and enrollment-card channel sensitivity unstated (§6.2 items 3–5).
**Resolution:** each fixed in place in rev. E, annotated "(rev. E; review D §…)" at the site. Parts 12.9–12.10, 15.7.5/15.9, 15.2.2/6.5, 13.3, 10.5, 7.2, 7.8, 6.7, 10.3, 2.8, 6.4, 7.5, 15.10.

---

**S-40 · major · rev. E Parts 1, 5.7, 6.5, 10.5, 11–13, 14.5, 16.3/16.6 (raised by a new operator requirement)**
**Problem:** the design treated Herdr as unconditionally required while almost nothing in it actually depended on Herdr. Part 11.1's title asserted it *is* the persistent execution substrate; the Part 1 dependency tables listed it flat; 6.5's doctor checklist made a Herdr-less host read as unhealthy; 5.7 subscribed to the Herdr socket unconditionally; 16.6 item 6's selftest would have failed a Herdr-less fleet; `HarnessProvider` (11.2) had no defined behavior when Herdr is absent, leaving every `styrn agent` command and `styrn_agent_*` tool undefined; `styrn harness run` (12.9) — whose actual value (resource environment, budget registration, admission accounting) is entirely Herdr-independent — was specified only "inside a Herdr pane", and the S-33 parity invariant assumed Herdr always exists; `styrn herdr status/attach` appeared in 10.7 and the Phase-4 listings but were never added to the 10.5 canonical surface; and the operator's condition "present and in-use and registered" had no counterpart — three unrelated signals (manifest `[herdr]`, setup `[components] herdr`, `integrate herdr install`) with no precedence and no single authoritative state. The strings "without Herdr" and "Herdr absent" appeared nowhere in the document.
**Impact:** a Herdr-less machine — a perfectly good validation worker — would enroll unhealthy, fail selftest, and produce undefined behavior across the whole agent surface; the tool would appear to require a component most of its machinery never touches, contradicting the operator requirement and §0.6.
**Resolution:** the **session substrate** model (11.0): per-host state `none | registered | active`, with the manifest `[herdr]` table (plus operator-owned `enabled`) as the registration authority and the other two signals ranked beneath it; the binding **substrate degradation contract** (11.0.3) — exit 7 / `capability.substrate_unregistered` for substrate-requiring operations, empty-and-healthy for queries, exit 11 for registered-but-broken; `HerdrProvider` as the only provider with substrate-gated resolution, an explicit per-operation matrix, and a reasoned rejection of a reduced supervisor-backed provider (11.2 — batch agent runs are already ordinary workflows, 7.7/12.5); `harness run` pane and standalone contexts with S-33 rescoped to pane context at full force (12.9–12.10); conditionalized doctor (6.5), events (5.7), boards (11.10, 14.5.1), selftest (16.6 item 6), `integrate all` (12.18) and MCP agent tools (13.3); `styrn herdr status/attach` kept vendor-named and added to 10.5; dependency framing corrected in Parts 1, 11 and 16.9. Decision recorded in D-9; phases per 16.3 — registration and probe in 0, state reporting in 1, selftest conditionality in 3, gating and the standalone launcher in 4, MCP refusals in 5, board empty-states in 8.

---

**Register totals: 6 blockers, 17 major, 17 minor — 40 issues** (S-29–S-33 added in rev. C; S-34–S-36 in rev. D; S-37–S-39 in rev. E; S-40 in rev. F).

---

# Part 19 — Decision log (formerly "Open questions"; decided in rev. C–D)

Every question revision B left open is now decided. D-n preserves the former OQ-n numbering, so earlier discussion still resolves. Each entry records the decision, the rationale — invoking the §0.6 tenet where it applies — and how to reverse it if the operator disagrees. As of rev. D nothing remains deferred: D-3, held for the setup redesign, is decided in place below.

**D-1 (was OQ-1) — Source sync: controller-push is the default, everywhere.**
*Decision:* every project uses controller-push (8.2) unless it explicitly opts into `[source.auth] mode = "deploy-key"`. No worker ever receives a forge credential by default.
*Rationale:* zero credential provisioning is the frictionless default (§0.6) — there is literally nothing to set up on a worker — and the fleet stays self-contained (validation works with the forge unreachable). The one scenario that favors deploy keys — a worker fetching with no controller online — does not exist in v1's execution model: jobs receive their source at submission and nothing fetches mid-job.
*Reversal:* add the `[source.auth]` block to that project's `.styrn.toml`; nothing else changes.

**D-2 (was OQ-2) — Multi-controller: safe always, ceremonial never.**
*Decision:* v1's operating posture is "primary controller + cold standby": the fleet-config git repo (6.7) is documented but **not** part of setup, and nothing requires it. Correctness under concurrent controllers is guaranteed by worker-side authority (7.3) regardless, which costs nothing at setup time.
*Rationale:* §0.6 — day-one interchangeability ceremony buys little when promoting any machine to a working controller is one `styrn host enroll` per worker plus key authorization. Safety is by construction; convenience is on demand.
*Reversal:* adopt the 6.7 fleet-config repo whenever wanted; no design change.

**D-3 (was OQ-3) — Windows worker identity: REVISED (rev. G) — current-user is the default.**
*Decision:* `styrn setup` defaults to the invoking non-elevated identity and creates no account. `--account dedicated[:<name>]` opts into the transient-logon hardened path from Part 15.8; `styrn` is only its suggested name.
*Rationale:* requiring a dedicated account is setup friction and is not necessary for Styrn's core job, transport, receipt, or admission behavior. The optional path remains valuable when the operator wants Part 4.5's OS-account separation. Current-user mode discloses that it has the user's ambient access rather than pretending otherwise.
*Reversal:* select dedicated mode per machine; no other subsystem changes because all consume the resolved `WorkerPrincipal`.

**D-4 (was OQ-4) — Power control: local-API hardware; credentials in a 0600 file.**
*Decision:* select power hardware by criterion, not brand: any smart plug or PDU controllable via a **local-network API with no cloud round-trip** (Tasmota-class firmware or a lab PDU with a local REST endpoint are the archetypes). Configuration and credentials live in a controller-only file — `~/.config/styrn/power.toml`, mode 0600 (`%APPDATA%\Styrn\power.toml` on Windows) — one `[[power]]` entry per worker:

```toml
[[power]]
host = "linux-macpro"           # the worker this outlet controls
provider = "http"
on = { method = "POST", url = "http://plug-macpro.lan/power/on" }
off = { method = "POST", url = "http://plug-macpro.lan/power/off" }
cycle = { method = "POST", url = "http://plug-macpro.lan/power/cycle" }
username = "admin"              # optional basic auth
password = "..."                # optional; the 0600 file is the store
```

*Rationale:* a file the developer can read and edit beats keychain ceremony (§0.6), works on headless Linux controllers with no keychain service, and the local-API criterion makes the credential LAN-scoped and low-value — a 0600 file is proportionate to it.
*What would change it:* choosing cloud-managed plugs (long-lived OAuth tokens) upgrades storage to the OS keychain via a `password = "keychain:<entry>"` indirection — additive; schema unchanged.
*Reversal:* swap hardware and/or add the keychain indirection; the `PowerProvider` trait (3.5) is untouched either way.

**D-5 (was OQ-5) — Workflow trust: `open` by default; pinning is opt-in.**
*Decision:* default `mode = "open"` (9.5). Workflow commands are untrusted input bounded by the worker posture (4.5); `pinned`/`allowlist` stay one config block away.
*Rationale:* single-operator fleet — the operator authored or reviews the profiles being run, and a pinning gate would interrupt every agent-driven profile evolution to defend against a threat the worker posture already bounds. §0.6: opt-in hardening, never opt-out friction.
*Reversal:* add `[projects.<name>.trust] mode = "pinned"` in controller config the day agents start proposing `.styrn.toml` changes you want gated.

**D-6 (was OQ-6) — `styrn exec` mirrors the remote exit code.**
*Decision:* the ssh convention is confirmed (10.4): `exec` returns the remote command's code; Styrn-level failures use the standard table; `--json` is the authoritative record.
*Rationale:* least surprise (§0.6) — `styrn exec` is a drop-in for `ssh host cmd` and must honor shell muscle memory; the residual exit-code ambiguity is identical to ssh's own and equally acceptable.
*Reversal:* if uniformity is ever needed, add an opt-in `--table-exit-codes` flag; the default never changes.

**D-7 (was OQ-7) — Artifact and retention defaults are final.**
*Decision:* 64 MiB per artifact read (`--max-bytes` overrides); successful job workspaces deleted immediately; failed jobs retained 24 h; logs 7 days; `refs/styrn/*` pruned per 8.1. These are the shipped defaults.
*Rationale:* they restate orig. §26/§34 policy, and every value is a per-project `[cleanup]` key or per-call flag — fully adjustable without design change, so deferring the decision bought nothing (§0.6: defaults over configuration).
*Reversal:* edit `[cleanup]` in the affected project or pass `--max-bytes`; use `resource.jsonl` peaks (14.2) to retune the 480 GB worker if heavy-job logs ever crowd it.

**D-8 (was OQ-8) — `mbp-main` accepts jobs.**
*Decision:* the MacBook enrolls `controller+worker`, `accept_jobs = true`, `priority = 20`, `prefer_remote_workers = true` (2.7).
*Rationale:* §0.6 — when a macOS-requiring workflow appears it must just run, not demand reconfiguration. Daily-driver impact is bounded by scoring (priority 20 + self-dispatch penalty + idle bonus, 6.4) and by interactive-session budget registration (12.9).
*Reversal:* `styrn machine role remove worker`, or set `accept_jobs = false` in the manifest.

**D-9 — The session substrate is optional; its absence refuses the agent surface and nothing else.**
*Decision:* Herdr is an optional, per-host **session substrate** with a single machine-local state (`none | registered | active`), whose registration authority is the manifest `[herdr]` table plus the operator-owned `enabled` key (11.0). Substrate-requiring operations against a `none` host refuse with exit 7 / `capability.substrate_unregistered`; query-shaped operations answer empty-and-healthy with no warnings; registered-but-broken stays exit 11. There is **no** second `HarnessProvider`: batch agent runs are ordinary workflows (`codex exec` declared in `.styrn.toml`, §66; the job layout already reserves `harness.jsonl`, 7.7/12.5), and a supervisor-backed provider could not honestly implement `prompt`/`read`/`wait`/`attach`. `styrn harness run` works standalone with full governance, and the S-33 parity invariant applies at full force in pane context while being vacuous — not weakened — outside it. `styrn herdr status|attach` stay vendor-named.
*Rationale:* the operator requirement is verbatim and binding, and §0.6 cuts both ways here — a Herdr-less user must never be nagged, and a Herdr user must lose nothing. §0.7 forbids both descoping the agent surface and inventing a `NullProvider` where one state, one error code, and a set of conditionals suffice. Exit 7 already means "required capability unavailable", and substrate absence *is* exactly that, so no new exit code was created. Keeping the command group vendor-named follows §0.4's preference for one precise form over a generic one: the only person who ever types `styrn herdr attach` is a Herdr user, and the name states honestly whose UI appears.
*Reversal:* if a second substrate ever ships, 11.0's state model and the provider gating are already substrate-shaped — add a provider and a manifest table, and the vendor-named group gains a sibling exactly as `integrate codex|claude` sit beside `integrate herdr`. If the operator instead decides Herdr should be mandatory on workers, flip the default: add `herdr` to the worker baseline set (15.3.3) and demote 6.5's `none` line to a warning. The degradation contract keeps working unchanged underneath either move.

---

# Appendix A — Traceability: original sections → this document

Every numbered section of the original design, revision A (`styrn-complete-design.md`), and its unnumbered role-model chapter (§RM) maps as follows. "→" names the section(s) of this document where the material now lives. The original file has been removed from the repository (§0.2); this table is the surviving record that its content was carried forward in full, not a set of links to anything readable.

| Orig. | → Here | Orig. | → Here | Orig. | → Here |
|---|---|---|---|---|---|
| §RM | 2.1 | §43 | 15.3 | §85 | 13.11 |
| §1 | 1.1 | §44 | 16.1 | §86 | 13.12 |
| §2, 2.1–2.6 | 1.2 | §45 | 16.2 | §87 | 13.5 |
| §2.7 | 1.3.1 | §46 | 15.4 | §88 | 13.10 |
| §2.8 | 1.3.2 | §47 | 15.12 | §89 | 13.9 |
| §2.9 | 1.3.3 | §48 | 15.12 | §90 | 12.5 |
| §2.10 | 1.3.4, 5.2 | §49 | 15.12 | §91 | 12.6 |
| §3 | 1.4, 5.1 | §50 | 2.7 | §92 | 12.7 |
| §4 | 1.5 | §51 | 2.7 | §93 | 12.8, 4.5 |
| §5 | 2.2 | §52 | 2.7 | §94 | 12.9 |
| §6 | 2.3, 9.2 | §53 | 2.7 | §95 | 12.10 |
| §7 | 3.1 | §54 | 6.3 | §96 | 12.11 |
| §8 | 3.2 | §55 | 6.4 | §97 | 11.15 |
| §9 | 3.3 | §56 | 6.5 | §98 | 8.7, 11.8 |
| §10 | 4.1 | §57 | 6.6, 2.8 | §99 | 9.4 |
| §11 | 11.1 | §58 | 6.8 | §100 | 9.6 |
| §12 | 11.2 | §59 | 16.3 | §101 | 10.7 |
| §13 | 12.1 | §60 | 15.10 | §102 | 12.18 |
| §14 | 12.2 | §61 | 16.7 | §103 | 11.16 |
| §15 | 12.3 | §62 | 6.7 | §104 | 11.17 |
| §16 | 12.4 | §63 | 1.6 | §105 | 11.18 |
| §17 | 3.4, 15.2.4 | §64 | 1.7 | §106 | 12.12 |
| §18 | 3.5 | §65 | 1.8 | §107 | 12.13 |
| §19 | 2.4 | §66 | 1.9 | §108 | 12.14 |
| §20 | 2.5 | §67 | 17.1 | §109 | 12.15 |
| §21 | 2.6 | §68 | 1.10 | §110 | 12.16 |
| §22 | 6.1 | §69 | 11.3 | §111 | 15.7 |
| §23 | 10.1, 10.2 | §70 | 11.4 | §112 | 15.8 |
| §24 | 10.4 | §71 | 11.5 | §113 | 15.1, 15.4, 15.11 |
| §25 | 10.5 | §72 | 11.6 | §114 | 15.11 |
| §26 | 9.1 | §73 | 11.7 | §115 | 12.17 |
| §27 | 7.1, 7.2 | §74 | 11.9 | §116 | 16.4 |
| §28 | 7.4 | §75 | 11.10 | §117 | 13.8 |
| §29 | 7.7 | §76 | 11.11 | §118 | 13.6 |
| §30 | 7.12 | §77 | 11.12 | §119 | 13.7 |
| §31 | 7.5 | §78 | 11.13 | §120 | 7.7 |
| §32 | 7.6 | §79 | 11.14, 5.7 | §121 | 16.8 |
| §33 | 7.9 | §80 | 14.1 | §122 | 16.5 |
| §34 | 7.7, 7.11 | §81 | 13.1 | §123 | 16.1 |
| §35 | 8.1 | §82 | 13.2 | §124 | 12.19 |
| §36 | 8.3 | §83 | 13.3 | §125 | 17.2 |
| §37 | 8.5 | §84 | 13.4 | §126 | 16.9 |
| §38 | 8.6 | — | — | — | — |
| §39 | 10.6 | — | — | — | — |
| §40 | 14.1 | — | — | — | — |
| §41 | 4.2 | — | — | — | — |
| §42 | 15.2 | — | — | — | — |

Sections of this document with **no** original counterpart (reviewer's additions): 0.4–0.5, 1.6 consequence paragraph, 2.4.1–2.4.2, 2.8, 3.3 hardening addendum, 4.3–4.6, all of Part 5, 6.2, 6.4 algorithm, 6.7 divergence rules, 7.2 revision, 7.3, 7.5 mechanics, 7.8, 7.10, 8.2, 8.4, 8.7 mechanics, 9.2–9.3, 9.5, 10.3, 13.3 profile authority, 13.9 fan-out bound, 14.2–14.4, the rev. B Part 15 additions (superseded wholesale by the rev. D Part 15), 16.6, Parts 18–19, and this appendix.

Rev. C additions (pass 1): §0.6–0.7, the Part 19 decision log (D-1…D-8), the Herdr parity invariant (12.9.1, 12.10, 16.6 item 7), submission unhappy paths and `submission_id` idempotency (7.8 item 6), SHA-keyed revision refs (8.1–8.2), implicit `repo.ensure` (8.2), lazy controller keys (4.3.1), TTY-aware queueing (7.6), the starter-profile on-ramp (9.1), and register entries S-29–S-33.

Rev. D additions (pass 2): §0.8, the whole `styrn setup` subsystem (Part 15: engine, config schema, elevation, receipts/uninstall, per-OS mechanics, hardened-Windows default, `styrnd`, enrollment card, script generation, stage zero, command surface), exit code 13 and the `setup.*` error family (10.3–10.4), the 6.5 doctor unification note, the 6.8/7.8 styrnd wiring, 16.6 item 8, and register entries S-34–S-36.

Rev. E additions (pass 3): §0.9, the Part 18 preamble's independent-review pointer, packaging and upgrade (15.14, with sources renumbered to 15.15), the `styrn watch` specification (14.5), the rebuilt phase plan (16.3, absorbing 16.4), the `sleep-policy` component, admission defaults and the completed error/exit mapping (7.2, 10.3), the fan-out exit-code change (6.7), `styrn workflow cancel` and the 10.5 command-surface completion, and register entries S-37–S-39.

*End of consolidated design.*
