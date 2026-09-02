# Styrn implementation plan

Derived from `docs/design.md` revision H (Part 16.3 phases, Part 16.6 testing strategy, Part 16.1 layout).
Every task cites the design Part that specifies it. If a task and the design disagree, **the design wins** — fix the plan.

## How to use this document

Each task carries three checkboxes:

```
- [ ] **T0.0** — Task title (Part X.Y)
      Implementation note.
  - [ ] + positive: the behaviour works on the happy path
  - [ ] − negative: the behaviour correctly refuses, errors, or degrades
```

**Do not tick the parent box until both children are ticked.** A task is "done" only when it works *and*
when it has been proven to fail correctly. Most of Styrn's value is in the negative cases — admission
denial, protocol refusal, dirty-worktree refusal, parity fallback. Code that only works on the happy path
has not implemented this design; it has implemented an optimistic sketch of it.

Negative tests must assert the **specific** failure: the exit code from Part 10.4, the `errors[].code`
from the Part 10.6 registry, and that no partial state was left behind. "It returned non-zero" is not a
passing negative test.

### Conventions binding on every task

- Every non-interactive command supports `--json`; JSON on stdout, diagnostics on stderr, never mixed (10.1–10.3).
- Envelope is `styrn.command.v1`; timestamps RFC 3339; sizes integer bytes; durations integer ms.
- Exit codes come from the Part 10.4 table (0–13). Error codes come from the Part 10.6 registry.
- No secret ever enters a machine manifest, a receipt, a log, or a JSON payload (4.2, 4.6, 2.4).
- Every new command is added to the Part 10.5 canonical surface in the same change.

### Phase status

| Phase | Outcome | Done |
|---|---|---|
| 0 | A fresh machine becomes an enrollable worker | ☐ |
| 1 | See and touch every machine from one seat | ☐ |
| 2 | One governed remote job survives a closed laptop | ☐ |
| 3 | The 16.7 flagship scenario, end to end | ☐ |
| 4 | Govern agents wherever a substrate is registered, without losing Herdr parity | ☐ |
| 5 | Agents validate cross-platform without SSH | ☐ |
| 6 | v0.N+1 reaches four machines without ceremony | ☐ |
| 7 | Setup completions: renderers and reversals | ☐ |
| 8 | Convenience and presentation | ☐ |

---

# Phase 0 — Foundations and setup core

**Exit criterion:** a fresh machine, given only the stage-zero one-liner, becomes a worker that a controller can enroll.

## 0.A Skeleton and output contract

- [ ] **T0.1** — Cargo workspace and module skeleton (16.1)
      Create the module tree: `cli/ setup/ config/ manifest/ inventory/ transport/ rpc/ mcp/ platform/{linux,macos,windows} resources/ scheduler/ jobs/ project/ git/ harness/ integrations/ desktop/ notification/ output/`. Crates per 16.2; no database (16.2).
  - [ ] + positive: `cargo build` succeeds on all three host OSes; `cargo test` runs an empty suite.
  - [ ] − negative: CI fails the build if a `platform/` module is referenced from generic code outside a `cfg` boundary.

- [ ] **T0.2** — JSON envelope `styrn.command.v1` (10.1–10.3)
      One serializer used by every command: `{schema, ok, command, timestamp, data, warnings, errors}`.
  - [ ] + positive: a finite command emits exactly one valid JSON document on stdout; validates against `schemas/command-v1.schema.json`.
  - [ ] − negative: progress/diagnostic output written during the command appears on stderr only; stdout still parses as a single document. Asserted by piping stdout to a strict parser while stderr is non-empty.

- [ ] **T0.3** — Exit-code table and error-code registry (10.4, 10.6)
      Codes 0–13 exactly as tabulated. `workflow run` never propagates an inner code (always 12 + `data.exit_code`); `exec` mirrors the remote code per D-6.
  - [ ] + positive: each code is produced by at least one integration test; every `errors[].code` maps to a documented registry entry. The registry includes `capability.substrate_unregistered` (11.0.3), first *produced* by Phase-4 tests like other late-phase codes.
  - [ ] − negative: a workflow command exiting 101 yields Styrn exit 12 with `data.exit_code == 101` — **not** exit 101. An unmapped internal panic yields exit 1, not a masquerading domain code.

- [ ] **T0.4** — CLI skeleton, global flags, TTY detection (10.5)
      clap-based; global `--json`, `--jsonl` where streaming; `--json` disables ANSI colour.
  - [ ] + positive: `--help` lists only commands specified in 10.5; `--json` output contains no ANSI escapes.
  - [ ] − negative: an unknown flag or malformed argument exits 2 with a usage error, and emits no partial JSON envelope.
  - [ ] − **rev. F amendment:** 10.5 gained the `styrn herdr status|attach|action|event` group (Part 11.0, D-9). Per C9 the parser must cover it, so re-verify the "`--help` lists exactly 10.5" assertion against the amended surface; behavior for `status`/`attach` lands in T4.0.

## 0.B Manifest

- [ ] **T0.5** — Machine manifest: schema, parse, validate, `machine_id` minting (2.4)
      TOML canonical, JSON renderable via `styrn machine manifest --json`. Mint a UUID at first write. Manifests record required `installation.scope = user|system` plus schema-backed stable worker identity (mode, uid/SID, login name, isolation posture).
  - [ ] + positive: a manifest round-trips/validates; machine/principal IDs remain stable; a non-admin user-scope manifest uses the native standard path, while current-user accepts any valid invoking principal.
  - [ ] − negative: missing scope/machine/schema/required worker identity is rejected. Scope/path mismatch, transport/name mismatch, or renamed/deleted uid/SID is drift, never cross-scope fallback or account switching. A second setup run does not mint a new id.

- [ ] **T0.6** — Manifest secret rejection (2.4, 4.2)
      No private key, API key, auth key, token, or password may be serialized into a manifest.
  - [ ] + positive: a manifest with the full capability/policy surface serializes cleanly.
  - [ ] − negative: attempting to write a manifest containing a field from the forbidden set fails at serialization time (a deny-list test over key names plus a heuristic scan for PEM/JWT-shaped values), rather than being caught by review.

- [ ] **T0.7** — Manifest ownership and permissions (4.5)
      Scope-aware secure storage with no literal account assumption. Default user scope is current-user owned/restricted and requires no privilege; optional system scope is root/Administrator-owned and read-only to the resolved worker principal.
  - [ ] + positive: an ordinary non-admin user can create/read/atomically replace the user manifest in the native standard config directory; explicit system scope has the protected mode/ACL on each OS.
  - [ ] − negative: user scope rejects links, special files, insecure cross-user paths, and malformed state but does not claim same-user non-writability. In system scope an explicitly selected real worker principal cannot modify/replace/delete the manifest.

## 0.C Setup engine

- [ ] **T0.8** — Capability probe layer, shared with doctor (15.2, 6.5)
      One probe implementation; `doctor` renders it, `setup` diffs against it. Note the 6.5 split: controller-side checks vs. worker-local probes are distinct layers; the one-to-one rule applies to the latter.
  - [ ] + positive: every worker-local doctor check is expressible as a probe result; adding a probe automatically surfaces in both commands.
  - [ ] − negative: a probe that cannot run (tool absent, permission denied) yields `Unknown` rather than `false` — the plan must never silently treat "could not determine" as "not installed".

- [ ] **T0.9** — `Action` trait (15.2.3)
      `check() -> Done|Todo|NeedsHuman`, `apply()`, `revert()`, `privilege()`, `describe()`. `revert` and the two `render_*` methods may be `unimplemented!()` until Phase 7, but the slots exist now.
  - [ ] + positive: an action reports `Done` when its effect is already present, `Todo` otherwise.
  - [ ] − negative: `apply()` on an action whose `check()` returns `Done` is a no-op, not a repeat mutation (idempotency is per-action, not just per-run).

- [ ] **T0.10** — Plan computation and `--dry-run` rendering (15.2)
      Diff observed vs. desired; render with privilege badges.
  - [ ] + positive: `--dry-run` prints the ordered action list with privilege annotations and mutates nothing.
  - [ ] − negative: after `--dry-run`, a subsequent probe shows byte-identical system state; no receipt entry was written.

- [ ] **T0.11** — Receipt journal (15.6)
      Scope-aware append-only record of every applied action with provenance. User scope is the no-elevation default and provides crash/concurrency integrity, not same-user containment; system scope preserves worker non-writability.
  - [ ] + positive: a non-admin user completes a journaled run in the native user-state directory; a second converged run prints "nothing to do". System scope retains protected ACLs. `NeedsHuman` is reported distinctly, never as a no-op.
  - [ ] − negative: interruption leaves exactly the durably acknowledged prefix. `succeeded`-before-append recovers from its stored finalized entry even when pre-state cannot be recomputed or the action left the current plan; `prepared` plus already-`Done` refuses ownership. Private intent reads are opened no-follow and verified by handle.

- [ ] **T0.12** — Elevation strategy (15.5)
      Rootless user work never needs privilege. When displayed machine-wide actions are necessary, interactive setup offers exactly one optional OS-owned authorization; system/dedicated scope uses the same closed runner.
  - [ ] + positive: a non-admin completes all user actions with zero auth calls. If the user accepts the one grouped system delta, sudo/UAC—not Styrn—collects credentials and only the displayed closed actions run; user-level effects remain under the original principal.
  - [ ] − negative: declining/`--no-elevate` still completes independent user work and preserves system actions as pending. `--yes` never grants privilege. The runner rejects arbitrary commands/paths/URLs, secrets, tampered/expired/replayed requests, action drift, missing original principal, and wrong token before privileged mutation.

- [ ] **T0.13** — `NeedsHuman` pending actions (15.2.4, 3.4)
      Non-automatable residue (macOS Sharing toggle, Tailscale login, Codex/Claude first login) reported as structured pending actions, never as false success.
  - [ ] + positive: a machine needing consent completes setup with `pending_actions[]` populated and a zero-or-13 exit per the specified semantics.
  - [ ] − negative: setup **never** reports success for a step it could not perform. Test: revoke the ability to enable Remote Login and assert the run reports `NeedsHuman`, not `Done`.

## 0.D Component actions

- [ ] **T0.14** — Directory tree and worker identity (15.7, 4.1)
      `repos/ jobs/ cache/ artifacts/ logs/` under the scope-selected per-OS root. User/current-user is the no-account, no-elevation default; optional dedicated mode accepts a configurable non-administrator account and implies system scope.
  - [ ] + positive: an ordinary user gets the tree in XDG data / Application Support / LocalAppData without privilege or account creation; system/dedicated mode creates or adopts the configured account and owns only the intended tree.
  - [ ] − negative: no implementation or native test requires a literal username. Dedicated mode cannot read controller key material or write outside `paths.root`; current-user mode reports that it provides no such OS-account isolation. Re-running never recursively resets ownership of pre-existing files.

- [ ] **T0.15** — sshd component (15.7)
      User scope probes existing sshd and uses the ordinary per-user key path without elevation; missing machine configuration is `NeedsHuman`. System scope owns OpenSSH install/service/config plus protected account-specific key files.
  - [ ] + positive: a non-admin user with working sshd can authorize and log in without privilege. System scope succeeds for ordinary and Administrators-member Windows principals without authorizing any other account.
  - [ ] − negative: user scope never edits machine sshd/firewall/service config or shared `administrators_authorized_keys`; it reports the exact missing capability. System scope detects/corrects protected-key ACLs, and a same-identity unprivileged job cannot modify them. Password auth is refused where Styrn manages configuration.

- [ ] **T0.16** — Tailscale component (15.7)
      Per-OS unattended operation; interactive browser flow vs. `--auth-key`/`TS_AUTHKEY` chosen by interactivity.
  - [ ] + positive: node joins the tailnet and survives reboot/logout on Linux and Windows.
  - [ ] − negative: a machine marked `headless = true` whose Tailscale cannot run before login is flagged by doctor rather than silently accepted (3.2). An auth key is never written to the manifest or receipt.

- [ ] **T0.17** — git, sleep-policy, and remaining baseline components (15.7, S-38)
      Including the sleep-policy component and its doctor check.
  - [ ] + positive: components install and report `Done` on re-run.
  - [ ] − negative: a worker configured to sleep is flagged by doctor with the remediation command for that OS — the failure mode this prevents is a worker that is "unreachable" only because it is asleep.

- [ ] **T0.18** — Windows worker identity modes: current-user + hardened transient logon (15.8, rev. G)
      Current-user is the no-account-creation default. Optional dedicated mode accepts a configurable account, generates its password in memory, uses it for the profile-materializing user phase via `CreateProcessWithLogonW`, then discards it.
  - [ ] + positive: per-user tools land in the resolved worker profile, never an incidental elevating administrator's profile (this was S-10); SSH key login as that identity works afterwards in both modes.
  - [ ] − negative: the generated password appears in no log, no receipt, no manifest, and no process argument list. If the transient logon fails, the run degrades to the specified `NeedsHuman` fallback rather than leaving a half-created account.

## 0.E Invocation surface

- [ ] **T0.19** — `setup-config.toml` schema and its relation to the manifest (15.3)
      Config in, manifest out, receipt as journal — the three-files model.
  - [ ] + positive: `styrn setup --config <file>` reproduces an identical machine state on a fresh box.
  - [ ] − negative: an unknown key or type error in the config fails fast with exit 2 naming the offending key and line; no partial apply.

- [ ] **T0.20** — Three invocation modes and the zero-argument path (15.4, 15.4.1)
      `--scope user|system`, `--install a,b --role both`, `--account current-user|dedicated[:NAME]`, config, interactive, and bare setup. Zero-arg = rootless user-scope probe → plan → one confirmation → apply.
  - [ ] + positive: bare setup as a non-admin creates no account and yields a useful local worker; it asks for native authorization at most once and only when missing system capabilities are needed. Declining remains supported. The dedicated flag accepts a non-literal configured name.
  - [ ] − negative: with no TTY and no `--yes`, it prints the plan and exits 13 rather than guessing consent. `--install` naming an unknown component exits 2 listing valid components.

- [ ] **T0.21** — `--interactive` wizard (15.4.2)
      `inquire`-style prompt sequence, five questions maximum. **Not** ratatui — decision recorded, do not reopen.
  - [ ] + positive: the five-question flow produces the same plan as the equivalent flag invocation.
  - [ ] − negative: with stdin not a TTY, the wizard fails fast with a flag hint rather than hanging or consuming EOF as a default answer.

- [ ] **T0.22** — Enrollment card (15.10)
      Emits name/address, resolved transport user, and host-key fingerprint for the controller-side paste.
  - [ ] + positive: the card contains an explicit `--user` and everything else `host enroll` needs; the fingerprint matches the machine's actual host key.
  - [ ] − negative: the card contains no private key material and no auth key.

- [ ] **T0.23** — Stage-zero shims and release substrate (15.11.4, 15.14.1)
      Hand-maintained `bootstrap/install.sh` and `install.ps1`: verify a pinned SHA-256, install the binary, chain into `styrn setup` with pass-through args. Prefer a package manager when one is present and a human is at the keyboard (15.14.1); direct verified download otherwise.
  - [ ] + positive: on a fresh VM per OS, the one-liner yields an enrolled-ready worker.
  - [ ] − negative: a tampered payload (wrong digest) aborts before execution and leaves nothing installed. The script never pipes a remote script to a shell at runtime (15.7.6 bar).

---

# Phase 1 — Fleet visibility

**Exit criterion:** from one seat, every machine is listed, health-checked, and reachable for ad-hoc commands.

## 1.A Transport and protocol

- [ ] **T1.1** — `Transport` trait with a local-child test implementation (1.5, 16.6 layer 3)
      `rpc`, `exec`, `interactive_shell`. The test impl spawns `styrn rpc serve --stdio` as a local child — this is what makes layers 3 and 4 possible without SSH.
  - [ ] + positive: the same test suite passes against both the local-child and SSH implementations.
  - [ ] − negative: a transport error is distinguishable from a remote application error — unreachable is exit 3, auth failure exit 4, never conflated with exit 5.

- [ ] **T1.2** — NDJSON framing (5.1)
      One frame per line; the module must be testable over in-memory pipes.
  - [ ] + positive: golden recorded conversations replay identically against both peer roles.
  - [ ] − negative: an oversized frame, a truncated line, or invalid UTF-8 is rejected with a protocol error and terminates the session cleanly — it does not desynchronize the stream or block forever.

- [ ] **T1.3** — `hello` and version negotiation, N/N−1 window (5.2, 2.8)
      Load-bearing, not speculative: package-manager upgrades are non-atomic across a fleet, so mixed versions are the expected steady state (15.14, S-37).
  - [ ] + positive: N↔N and N↔N−1 negotiate successfully and agree a feature set.
  - [ ] − negative: N↔N−2 is **refused** with exit 8 and a message naming the exact upgrade command for that worker's platform (15.14.4). Neither peer proceeds with a degraded guess.

- [ ] **T1.4** — Request/response with correlation IDs (5.3)
  - [ ] + positive: concurrent in-flight requests resolve to their own responses.
  - [ ] − negative: a response bearing an unknown correlation ID is discarded with a protocol warning, never matched to the wrong request.

- [ ] **T1.5** — Streams: `event` and `log` frames (5.4)
  - [ ] + positive: `job logs --follow --jsonl` interleaves with concurrent request/response on one channel.
  - [ ] − negative: a slow consumer applies backpressure without deadlocking the control channel; stream data never leaks into the finite-command stdout document.

- [ ] **T1.6** — Cancellation and liveness (5.5)
  - [ ] + positive: a cancel request stops the stream and is acknowledged.
  - [ ] − negative: a peer that stops responding is detected within the specified liveness bound and the session is torn down — not left hanging until an OS timeout.

- [ ] **T1.7** — Chunked binary transfer with checksum (5.6)
  - [ ] + positive: an artifact round-trips byte-identically; per-chunk checksums verified.
  - [ ] − negative: a corrupted chunk fails the transfer with a checksum error rather than writing a truncated or corrupt artifact to disk.

- [ ] **T1.8** — SSH transport implementation
      System OpenSSH per 1.5; identity is controller-local and never copied to a worker (2.6).
  - [ ] + positive: RPC over SSH to each of the three worker OSes.
  - [ ] − negative: host-key mismatch aborts the connection (exit 4) and does not fall back to trust-on-first-use after enrollment.

## 1.B Enrollment and inventory

- [ ] **T1.9** — Lazy controller key generation (4.3.1, S-30)
      Keys minted on first need, not demanded up front.
  - [ ] + positive: a controller with no prior key material enrolls a host without a separate keygen step.
  - [ ] − negative: an existing key is never overwritten or regenerated silently.

- [ ] **T1.10** — `host enroll` with host-key pinning (6.1, 4.4)
      Require `--user`, pin the host key at enrollment, and bound TOFU to that moment. The setup card supplies the complete paste.
  - [ ] + positive: enroll connects as the explicit transport user, validates protocol, fetches and schema-checks a matching stable worker identity, runs doctor, and writes the inventory entry and manifest cache.
  - [ ] − negative: a missing user, transport/identity mismatch, changed host key, or incompatible protocol aborts without an inventory entry. A later key change is refused (exit 4), never re-pinned.

- [ ] **T1.11** — Inventory storage (2.6)
      `~/.config/styrn/inventory.toml`; `%APPDATA%\Styrn\inventory.toml` on Windows.
  - [ ] + positive: round-trips; the identity path stays controller-local.
  - [ ] − negative: a corrupt inventory file fails with a clear parse error naming the file — it is never silently reinitialized, which would drop the fleet.

- [ ] **T1.12** — `host remove` semantics (6.2)
      Specify and test exactly what is revoked.
  - [ ] + positive: removal drops the inventory entry and cached manifest.
  - [ ] − negative: removal does not leave the controller's key authorized on the worker without saying so — the command reports the residue it cannot reach.

## 1.C Visibility commands

- [ ] **T1.13** — `host list / show / status / refresh` (10.5, 2.5)
      Status is ephemeral and must not rewrite the static manifest (2.5).
  - [ ] + positive: status returns live CPU/memory/disk/job counts, including the ephemeral `substrate` field (11.0.3); refresh updates the manifest cache.
  - [ ] − negative: repeated `status` calls leave the manifest file's mtime unchanged.

- [ ] **T1.14** — `doctor`, both layers (6.5)
      Controller-side checks and worker-local probes, kept distinct.
  - [ ] + positive: doctor verifies the full 6.5 checklist and emits remediations in JSON.
  - [ ] − negative: each check has a test that makes it *fail* and asserts the remediation text names the concrete fix — a doctor that only ever passes has never been tested.
  - [ ] − negative: a substrate-`none` worker reads **healthy** — the substrate line is informational (6.5). Then deliberately register the substrate, stop the session, and assert doctor fails the two hard checks. Also assert the two drift lines: Herdr present but unregistered, and `[capabilities] agent = true` with substrate `none`.

- [ ] **T1.15** — `exec` (10.5, D-6)
      Mirrors the remote command's exit code, ssh-convention.
  - [ ] + positive: `exec` returns the remote code and `data.{exit_code,stdout,stderr,duration_ms}` under `--json`.
  - [ ] − negative: argv crosses the RPC boundary without shell re-interpretation — adversarial arguments (spaces, quotes, `%VAR%`, trailing backslashes) arrive verbatim on Windows (16.6 layer 5).

- [ ] **T1.16** — `fleet status / versions` (6.6)
  - [ ] + positive: aggregates all enrolled hosts; roles render as JSON arrays, not comma strings (2.1).
  - [ ] − negative: one unreachable host does **not** fail the whole command — list fan-outs exit 0 with warnings; exit 9 is reserved for required participants. A sleeping laptop is an expected condition, not a partial-fleet error.

- [ ] **T1.17** — Audit logging (14.3)
  - [ ] + positive: mutating operations are journaled with actor, host, timestamp, outcome.
  - [ ] − negative: no secret, key, or auth token is ever written to the audit log; asserted by a scanning test over generated log fixtures.

---

# Phase 2 — Jobs and governance

**Exit criterion:** a governed remote job survives the controller's laptop closing, and a runaway build cannot fill the host.

## 2.A Registry and admission

- [ ] **T2.1** — Job registry with a lock (7.3)
      Worker-side and authoritative. Controller plans are predictions only.
  - [ ] + positive: registry state survives worker restart; entries reconcile against live pids.
  - [ ] − negative: a stale entry whose pid is dead is reclaimed by the lazy sweep rather than permanently reserving budget.

- [ ] **T2.2** — Admission arithmetic (7.2)
      CPU budget, memory budget, `parallelism = max(1, min(...))`, with the rev.-C correction separating intra-job parallelism from job admission.
  - [ ] + positive: table-driven unit tests over the specified budget scenarios (16.6 layer 1).
  - [ ] + positive edge: pinned defaults apply when a project supplies no hints (2 GiB/job memory, 20 GiB disk).
  - [ ] − negative: admission **denies** with exit 6 and `resource.*_admission_denied` when memory or disk is below reserve; the denial names free vs. required bytes.

- [ ] **T2.3** — Committed budgets and heavy exclusivity (7.3, 7.6)
  - [ ] + positive: concurrent light jobs admit up to policy; `max_heavy_jobs` is honoured.
  - [ ] − negative: **the S-03 regression test** — two controller processes submitting simultaneously to one fake worker never over-admit committed memory and never exceed `max_heavy_jobs` (16.6 layer 4). Run it under load, repeatedly.

- [ ] **T2.4** — Lock liveness (7.3)
      Auto-release on holder death, acquisition timeout.
  - [ ] + positive: a lock held by a live process blocks a second acquirer until release.
  - [ ] − negative: killing the lock holder mid-hold releases the lock within the specified bound — a crashed controller must not wedge the worker permanently.

## 2.B Supervision

- [ ] **T2.5** — Detached job supervisor (7.8)
      **The S-01 fix.** The worker owns the job; the SSH session is a control channel, not an execution container.
  - [ ] + positive: submit a long job, kill the controller-side SSH session, reattach, and observe it still running; collect its result.
  - [ ] − negative: killing the *supervisor* marks the job failed with logs preserved — it does not orphan a running process tree with no registry entry.

- [ ] **T2.6** — Spawn-ack and registry rollback (7.8)
  - [ ] + positive: submission returns only after the supervisor confirms spawn.
  - [ ] − negative: a spawn that fails rolls the registry entry back — no committed budget is leaked to a job that never started.

- [ ] **T2.7** — `submission_id` idempotency (7.8)
  - [ ] + positive: resubmitting after a lost session returns the existing job, not a duplicate.
  - [ ] − negative: two distinct submissions with different ids both run; the idempotency key never collapses genuinely different work.

- [ ] **T2.8** — Windows process ownership (7.8, 7.10)
      Job Object, `CREATE_BREAKAWAY_FROM_JOB`, and the styrnd broker path when breakaway is denied.
  - [ ] + positive: tree-kill reaps grandchildren (16.6 layer 5); long-path job roots work; current-user mode survives session close without storing that user's password.
  - [ ] − negative: when breakaway is denied under sshd's Job Object, the credential-free broker path is taken and the job still survives session close — the fallback is exercised in CI, not assumed. If direct breakaway and the broker are both unavailable, doctor marks the worker ineligible rather than accepting a job it cannot own durably.

## 2.C Limits and lifecycle

- [ ] **T2.9** — Disk monitor and per-job quota (7.5)
      Adaptive polling plus the hard-floor backstop.
  - [ ] + positive: normal jobs run untouched; usage is reported in `resource.jsonl`.
  - [ ] − negative: a deliberately runaway job is terminated at the quota, marked `resource_limit_exceeded`, logs preserved, artifacts cleaned. Also assert the host floor triggers independently of the per-job quota.

- [ ] **T2.10** — Wall-clock timeouts (7.9)
  - [ ] + positive: a job within its timeout completes normally.
  - [ ] − negative: an over-running job is killed at the limit with exit 10 and its tree fully reaped on every OS.

- [ ] **T2.11** — Job directory, `result.json`, artifacts, URIs (7.7)
  - [ ] + positive: the specified layout is produced; `result.json` is schema-valid.
  - [ ] − negative: an artifact read beyond the 64 MiB default cap is refused with a clear error and the `--max-bytes` hint (D-7), not silently truncated.

- [ ] **T2.12** — `job list / show / logs / cancel` (10.5)
  - [ ] + positive: `logs --follow --jsonl` streams; `cancel` stops the tree.
  - [ ] − negative: cancelling an already-finished job is a well-defined no-op with a warning, not an error or a double-free of budget.

## 2.D Source delivery

- [ ] **T2.13** — Controller-push into bare repos, `repo.ensure` implicit (8.1–8.2, D-1)
      **The S-02 fix.** Workers hold zero forge credentials. Refs are SHA-keyed `refs/styrn/revisions/<sha>` — the rev.-C fix for the ordering bug where the refspec needed a job id minted later.
  - [ ] + positive: submission pushes only when the worker lacks the SHA; the fleet validates with the forge unreachable (unplug the internet and prove it).
  - [ ] − negative: two controllers pushing the same SHA race harmlessly (idempotent refspec). A push failure maps to exit 5 with git's stderr in `errors[].details` and leaves no job state.

- [ ] **T2.14** — Revision resolution (8.4)
  - [ ] + positive: branch, tag, and SHA forms resolve to an exact commit recorded in the job record.
  - [ ] − negative: an ambiguous or non-existent revision is refused before any push or admission occurs.

- [ ] **T2.15** — Dirty-worktree refusal and `--snapshot` (8.7)
      A dirty tree must never masquerade as a clean commit — the §0.6 tenet's stated boundary.
  - [ ] + positive: `--snapshot` creates the temp commit and validates exactly that SHA.
  - [ ] − negative: a dirty worktree without `--snapshot` **refuses**, and the refusal message names the one-flag remedy. Assert it does not silently validate HEAD.

- [ ] **T2.16** — Worktree lifecycle and cleanup (8.1, 9.1 `[cleanup]`)
  - [ ] + positive: successful jobs remove their worktree and job tree; retention honours the project policy.
  - [ ] − negative: a failed job's tree is retained for the configured window and then reclaimed; `refs/styrn/revisions/*` prune only when no registry job references the SHA.

---

# Phase 3 — Workflows, matrix, selftest, maintenance

**Exit criterion:** the Part 16.7 flagship scenario runs end to end — edit on the Mac, validate natively on Windows and Linux, read structured failures.

## 3.A Project profiles

- [ ] **T3.1** — `.styrn.toml` parse and validate (9.1)
      Including the exactly-one-disk-key rule (16.6 layer 1).
  - [ ] + positive: `examples/fricos.styrn.toml` validates against `schemas/project-v1.schema.json` (both exist; the loader must agree with the schema, which is the normative rendering of 9.1).
  - [ ] − negative: both disk keys present, or an unknown `resource_class`, fails with a specific error naming the key. `minimum_styrn_version` above the running binary refuses (exit 8).

- [ ] **T3.2** — Variable expansion (9.3)
      `${resources.*}`, `${job.*}`, `${workspace.*}`; `$${` escape; per-OS path rendering via injected separators.
  - [ ] + positive: expansion produces correct env for a Cargo workflow on each OS.
  - [ ] − negative: an undefined variable is a hard error naming the variable — never an empty string substitution, which would silently produce `CARGO_BUILD_JOBS=`.

- [ ] **T3.3** — Requirements matching and capability gating (9.2, 2.3)
  - [ ] + positive: `os = "windows", heavy_test = true` selects only eligible hosts.
  - [ ] − negative: when no host satisfies the requirements, the command fails with exit 7 naming the unmet capability — it must not fall back to a "close enough" host. Also assert a controller-only host is never selected even with ample resources (2.1).

- [ ] **T3.4** — Aliases and starter on-ramp (9.4, 9.1/S-32)
  - [ ] + positive: `styrn check` in a project directory resolves via `[aliases]`; a project with no profile gets the starter template.
  - [ ] − negative: an alias naming a non-existent workflow fails with the list of declared workflows.

## 3.B Execution

- [ ] **T3.5** — Host selection algorithm (6.4)
      Static capabilities + dynamic status + project requirements + scheduling policy.
  - [ ] + positive: deterministic, explainable selection; `plan` reports why a host was chosen.
  - [ ] − negative: every rejection reason is reportable (capability, admission, policy, unreachable) — "no eligible host" must be able to say *why* for each candidate.

- [ ] **T3.6** — `workflow plan` (13.6)
      Plan-first: selection, admission prediction, revision, estimated jobs.
  - [ ] + positive: plan output matches what run subsequently does on an idle fleet.
  - [ ] − negative: plan is read-only — it creates no worktree, pushes no ref, reserves no budget. Assert by diffing worker state before and after.

- [ ] **T3.7** — `workflow run`, TTY-aware wait (7.6, S-31)
  - [ ] + positive: runs to completion, streams logs, returns structured result.
  - [ ] − negative: when the worker is busy, an interactive caller waits with feedback while a non-TTY caller gets the specified immediate outcome — never a silent indefinite hang in a script.

- [ ] **T3.8** — `workflow cancel` (10.5)
      Submission-index resolution fanning out to `job.cancel`.
  - [ ] + positive: cancels every job of a submission across hosts.
  - [ ] − negative: cancelling an unknown submission id errors clearly; a partially-cancelled fan-out reports which hosts refused.

- [ ] **T3.9** — `matrix run` (8.6)
  - [ ] + positive: N workflows × M hosts execute, results aggregate into one record.
  - [ ] − negative: one cell failing does not abort the others; the aggregate reports per-cell outcomes and the overall exit reflects the specified rule, not the first failure encountered.

- [ ] **T3.10** — Agent-job vs. validation-job separation (8.3)
      The design's load-bearing trust split.
  - [ ] + positive: a validation job runs on a clean worktree at an exact SHA and produces the authoritative result.
  - [ ] − negative: a validation job **cannot** mutate its source tree; assert the worktree is unchanged after a run that attempts writes.

## 3.C Fleet operations

- [ ] **T3.11** — `fleet selftest` (16.6 item 6)
      Trivial `echo`-level project run as a real matrix across all machines; the acceptance test for enrollment, push, admission, supervision, artifact retrieval, and (from Phase 4) Herdr parity.
  - [ ] + positive: green across the real fleet; Styrn's own repo carries a `.styrn.toml` so the fleet validates Styrn (dogfooding loop).
  - [ ] − negative: selftest **fails loudly** when a machine is misconfigured — deliberately break one worker (stop sshd, fill disk, downgrade the binary) and assert each is caught and named.
  - [ ] − negative: on a Herdr-less fleet selftest **passes**, with the agent leg reported `skipped (substrate: none)` per host. Absence is never a selftest failure (16.6 item 6).

- [ ] **T3.12** — `styrnd`: service install and maintenance executor (15.9)
      Per-worker, no network socket. Default installs a rootless systemd user unit / LaunchAgent / per-user Windows logon task. Optional system scope adds boot/logout guarantees and keeps Windows maintenance distinct from the LocalSystem broker.
  - [ ] + positive: a non-admin installs and runs ticks under the current principal with no password capture; manifest/doctor accurately reports login-session versus boot persistence.
  - [ ] − negative: logout-survival is never claimed when the user manager cannot provide it. With maintenance stopped/unavailable, work degrades opportunistically; every context opens no network listener and the system broker cannot execute maintenance.

- [ ] **T3.13** — `styrnd`: Windows spawn broker (15.9)
      User scope uses a credential-free per-user broker with login-session guarantees; optional system scope uses the LocalSystem broker and protected one-use admission. Neither performs general execution or literal account lookup.
  - [ ] + positive: each broker validates client PID/token, installed-binary identity, expected ancestry/Job-Object condition, and one-use admitted job before constructing fixed `styrn job supervise <id>` argv. Capabilities distinguish login-session from boot persistence.
  - [ ] − negative: replay, malformed ids, arbitrary executable/argv, and unadmitted requests are rejected. System scope rejects unauthorized and same-SID callers lacking the protected pending record. User scope makes no containment claim against malicious same-user code, which already has equivalent process authority.

- [ ] **T3.14** — Maintenance commands: `clean plan/run`, `cache status/trim` (10.5, 6.8)
  - [ ] + positive: plan lists exactly what run will delete; trim honours the cache quota.
  - [ ] − negative: `clean run` never deletes a live job's tree or a ref a registry job still references; prove with a running job present.

---

# Phase 4 — Agents on the session substrate (Herdr)

**Exit criterion:** agents on every substrate-registered machine are listed and controlled; a Styrn-launched agent is indistinguishable to Herdr from a manual one; and a host with no substrate refuses the agent surface cleanly (exit 7) while everything else stays green.

- [ ] **T4.0** — Substrate state, gated provider resolution, degradation contract (11.0)
      State `none | registered | active` computed worker-side; registration = manifest `[herdr]`
      `installed && enabled` (11.0.2); `machine.status.substrate`; provider resolution refuses on `none`.
      **Sequenced deliberately before T4.1: `HerdrProvider` is an implementation of a gated abstraction, not the definition of it.**
  - [ ] + positive: `styrn herdr status` reports the correct state through all three values on one host (uninstalled / installed-not-running / running), and `machine.status` carries the field.
  - [ ] − negative: `agent start/read/prompt/wait/stop/attach` and `herdr attach` against a substrate-`none` host exit 7 with `capability.substrate_unregistered`, naming the host and the remediation; `agent list --all` over a fully substrate-less fleet exits 0 with empty data and **no warnings**; a `registered` host whose session cannot be started exits 11 `agent.harness_error`, never 7.

- [ ] **T4.1** — `HarnessProvider` trait over RPC (11.1, 12.2)
      Herdr's lifecycle states (`working|blocked|idle|done|unknown`) are preserved, never re-invented (12.2). Provider resolution is substrate-gated per T4.0.
  - [ ] + positive: the same trait drives Linux, macOS, and Windows targets through `styrn rpc serve --stdio` → local Herdr CLI.
  - [ ] − negative: an unknown Herdr state maps to `unknown` rather than being coerced into a Styrn-invented state.
  - [ ] − negative: resolving a provider for a substrate-`none` host yields the 11.0.3 refusal, not a provider object whose methods fail one by one.

- [ ] **T4.2** — `agent list / read / prompt / wait / stop` (11.2, 10.5)
  - [ ] + positive: cross-host agent control works uniformly, including Windows targets.
  - [ ] − negative: `agent wait --state idle` on an agent that is `blocked` returns per spec — `blocked` is a valid state, not a process error (10.4). Asserted explicitly, since treating it as failure is the obvious wrong implementation.

- [ ] **T4.3** — `agent start` and `agent attach`; `herdr attach` abstraction (11.13)
      Linux/macOS via `herdr --remote`; Windows via `ssh -t <host> "herdr --session fleet"`. The platform difference lives inside Styrn.
  - [ ] + positive: `styrn agent attach <name>` works regardless of which OS hosts the agent.
  - [ ] − negative: programmatic control never depends on `herdr --remote` (11.1) — assert the RPC path is used for all non-interactive operations, including against Windows.

- [ ] **T4.4** — Do not fake remote agents into the local Herdr list (11.12)
  - [ ] + positive: local Herdr shows local agents; the Styrn board shows cross-host agents.
  - [ ] − negative: no code path injects a synthetic entry into another machine's Herdr agent list.

- [ ] **T4.5** — `harness run`: Unix `execvp` (12.10, S-33)
      Normative, not "where possible". After exec the process *is* the agent.
  - [ ] + positive: pid, process name, and command line match a manual launch exactly.
  - [ ] − negative: exec failure (missing/non-executable binary) surfaces as exit 11 `agent.harness_error` **before** the agent starts — never as a degraded wrapped session. Exit-status recording correctly reports `unknown` via reconciliation (the documented forfeit).
  - [ ] + positive (standalone, 12.9): launched outside any Herdr pane — including on a substrate-`none` host — the launcher still exports the resource environment, registers the interactive-session budget (7.2 defaults), and execs the harness; the registry records `context = "standalone"`.
  - [ ] − negative (standalone): no parity probe is consulted and no refusal occurs. Standalone launch must not be conflated with the env-only *fallback*, which exists only in pane context (12.9.1).

- [ ] **T4.6** — `harness run`: Windows direct child (12.10, S-33)
      Job Object without `KILL_ON_JOB_CLOSE`; launcher resident but inert; no `cmd`/`conhost` layer; no command-line rewriting; no console allocation.
  - [ ] + positive: the agent inherits the pane's console; image name and argv are exactly the harness's own.
  - [ ] − negative: killing the launcher does **not** kill the agent (the deliberate contrast with batch jobs, where kill-on-close is the point).

- [ ] **T4.7** — Environment: augment, never scrub (12.9.1)
  - [ ] + positive: the wrapped child's environment is a strict superset of the manual launch's.
  - [ ] − negative: **no `HERDR_*` variable is lost or altered** — the failure mode that would silently break Herdr's session identity. Asserted by diffing full environment blocks.

- [ ] **T4.8** — Herdr parity probe and refusal fallback (12.10, S-33)
      `integrate herdr doctor` launches a wrapped and an unwrapped control in Herdr panes and compares what Herdr reports.
  - [ ] + positive: the probe passes on each OS where Herdr is present.
  - [ ] − negative: **when the probe fails, the launcher refuses to wrap** and falls back to env-only direct launch, with doctor reporting why. Simulate a probe failure and assert no undetectable session is ever produced.
  - [ ] − negative: on a substrate-`none` host, `integrate herdr doctor` refuses per 11.0.3 (exit 7) rather than reporting a failed probe (12.10 item 3).

- [ ] **T4.9** — Parity conformance test in CI and selftest (16.6 item 7)
  - [ ] + positive: identical detection and identical lifecycle-transition sequence for both launch paths.
  - [ ] − negative: the test genuinely fails when parity is broken — verify by deliberately introducing a wrapper layer and confirming red.

- [ ] **T4.10** — Herdr lifecycle event subscription (11.14)
  - [ ] + positive: agent state changes propagate without polling.
  - [ ] − negative: event-stream loss degrades to periodic reconciliation rather than a permanently stale view.

- [ ] **T4.11** — `integrate herdr install / doctor / remove` (11.16, 15.x)
      Embedded plugin manifest materialized into the config directory.
  - [ ] + positive: install links the plugin; doctor reports status; remove is clean.
  - [ ] − negative: install never deletes or overwrites unrelated Herdr configuration; assert against a populated config.

---

# Phase 5 — MCP

**Exit criterion:** an agent validates cross-platform through a narrow tool vocabulary, holding no SSH credentials.

- [ ] **T5.1** — `mcp serve --stdio` (13.1)
  - [ ] + positive: Claude Code and Codex both connect and enumerate tools.
  - [ ] − negative: **no `ssh_exec`-equivalent tool exists in any profile** (13.2). Arbitrary remote execution stays a human CLI capability — assert by enumerating the full tool list per profile.

- [ ] **T5.2** — `readonly` profile (13.3)
  - [ ] + positive: the specified read tools work.
  - [ ] − negative: every mutating tool is absent, not merely rejected at call time.
  - [ ] − negative: the tool list is **identical** on a substrate-less fleet — tools are never hidden by fleet state (13.3) — and `styrn_agent_list` answers empty-and-healthy rather than erroring.

- [ ] **T5.3** — `developer` profile (13.3)
  - [ ] + positive: `workflow_run`/`workflow_cancel` limited to workflows declared by the current project.
  - [ ] − negative: a request naming an undeclared workflow, or a project outside scope, is refused with a structured error.

- [ ] **T5.4** — Project scoping (13.4)
      MCP roots → harness project root env → cwd → nearest `.styrn.toml`.
  - [ ] + positive: launched inside a project, the surface defaults to that project.
  - [ ] − negative: an agent cannot enumerate or act on unrelated projects on other machines.

- [ ] **T5.5** — `max_profile` server-side ceiling (13.3, 4.5)
  - [ ] + positive: the effective profile is the minimum of requested and ceiling.
  - [ ] − negative: a client requesting `admin` against a `developer` ceiling gets `developer` — client configuration cannot widen the surface. This is the S-06 fix; test it directly.

- [ ] **T5.6** — Mutation policy `[mcp.mutations]` (13.5)
  - [ ] + positive: mutating tools are described accurately so the harness can apply its approval controls.
  - [ ] − negative: a tool set to `deny` is refused by Styrn even if the harness approves it — the two layers are independent, and Styrn's own policy is authoritative.

- [ ] **T5.7** — Structured failure data (13.7)
  - [ ] + positive: a failed remote validation returns concise structured failure data, not a raw log dump.
  - [ ] − negative: oversized output is bounded per the artifact caps rather than flooding the agent's context.

- [ ] **T5.8** — `integrate claude` / `integrate codex` (13.11–13.12)
  - [ ] + positive: merges the Styrn MCP entry, validates the result, records exactly what changed.
  - [ ] − negative: **never deletes or reorders unrelated MCP servers**; assert against a config containing several. Invalid JSON/TOML aborts without writing.

- [ ] **T5.9** — `orchestrator` profile and fan-out bound (13.9) — *gated on approval-behaviour maturity*
  - [ ] + positive: agent_start/prompt/wait/stop restricted to enrolled hosts and declared projects.
  - [ ] − negative: the fan-out bound is enforced — an orchestrating agent cannot spawn unbounded remote agents. Not enabled in the `developer` profile by default.
  - [ ] − negative: `styrn_agent_prompt/wait/stop` against a substrate-`none` host return a structured tool error carrying `capability.substrate_unregistered`, and `styrn_agent_start` host selection on a substrate-less fleet yields the capability refusal — the `agent` capability implies a registered substrate (11.0.2, 13.3).

- [ ] **T5.10** — `admin` profile — *last, and never default for coding-agent sessions* (13.3)
  - [ ] + positive: exists and is reachable only by explicit operator configuration.
  - [ ] − negative: no default configuration path yields `admin`; assert across all shipped integration templates.

---

# Phase 6 — Packaging and upgrade

**Exit criterion:** a new version reaches all four machines through their own platform channels, without ceremony.

- [ ] **T6.1** — Release CI: multi-target builds (1.5)
      `aarch64-apple-darwin`, `x86_64-apple-darwin`, `x86_64-unknown-linux-musl`, `aarch64-unknown-linux-musl`, `x86_64-pc-windows-msvc`.
  - [ ] + positive: a tagged commit produces every artifact reproducibly.
  - [ ] − negative: a target that fails to build fails the release — no partial release is ever published.

- [ ] **T6.2** — GitHub Releases substrate with checksums (15.14.1)
  - [ ] + positive: artifacts and a checksum manifest published per release.
  - [ ] − negative: stage-zero refuses a payload whose digest does not match (re-assert T0.23 against the real channel).

- [ ] **T6.3** — Homebrew tap (15.14.1)
  - [ ] + positive: `brew install styrn` yields a working binary on macOS (and Linuxbrew if adopted).
  - [ ] − negative: the formula pins a version and digest; a mismatched bottle is rejected.

- [ ] **T6.4** — winget manifest — *human-present path only* (15.14.1, S-35)
      winget is unusable from SYSTEM/service/SSH-non-interactive contexts. This is a documented boundary, not a bug to work around.
  - [ ] + positive: `winget install styrn` works in an interactive session.
  - [ ] − negative: remote non-interactive provisioning does **not** route through winget; it uses verified direct download. Assert the code path chosen over SSH.

- [ ] **T6.5** — `.deb` asset, and `cargo install` fallback (15.14.1)
  - [ ] + positive: `apt install ./styrn_*.deb` works on Ubuntu; `cargo install` builds from source.
  - [ ] − negative: the `.deb` does not overwrite operator-managed files outside its manifest.

- [ ] **T6.6** — `[install]` provenance in the manifest (15.14.3)
      Records which channel installed this binary.
  - [ ] + positive: provenance is written at install and read back by `fleet versions`.
  - [ ] − negative: an unknown or hand-placed binary reports `unknown` provenance rather than guessing a channel — guessing would produce a wrong upgrade command.

- [ ] **T6.7** — `fleet versions` channel column (6.6, 15.14.3)
  - [ ] + positive: reports per-host version *and* the upgrade command for that host's platform and channel.
  - [ ] − negative: a host outside the N/N−1 window is flagged prominently, with the exact command to fix it.

- [ ] **T6.8** — `styrn upgrade`: local delegation (15.14.4)
      A pure delegator to the owning package manager. **Never self-update.**
  - [ ] + positive: delegates correctly per channel (`brew upgrade`, `apt install`, stage-zero download+verify).
  - [ ] − negative: the binary never rewrites itself in place; assert no self-replacement code path exists.

- [ ] **T6.9** — `styrn upgrade <host>`: remote orchestration (15.14.5)
  - [ ] + positive: upgrades a remote worker through its recorded channel and re-verifies the version.
  - [ ] − negative: upgrade is refused while that worker has running jobs (or handled per the specified replacement mechanics) — a binary swap must not orphan a supervisor.

- [ ] **T6.10** — Compatibility windows become binding (2.8)
      Contracts bind from the first tagged release.
  - [ ] + positive: a CI check asserts no field was removed without a schema-version bump.
  - [ ] − negative: a deliberate breaking change fails CI rather than shipping silently.

---

# Phase 7 — Setup completions

**Exit criterion:** setup is reversible, and its plan can be emitted as a script that provably converges to the same state.

- [ ] **T7.1** — Per-action `revert()` (15.6.2)
  - [ ] + positive: each action's revert undoes exactly its own effect.
  - [ ] − negative: revert on an action that never applied is a no-op, not an error or a deletion of pre-existing state.

- [ ] **T7.2** — `--uninstall` with transport guard and ownership rule (15.6.2)
      Removes only what Styrn created, per the receipt.
  - [ ] + positive: uninstall leaves no styrn-owned residue (16.6 item 8).
  - [ ] − negative: **pre-existing tools are spared** — install git manually, run setup, uninstall, and assert git survives. The transport guard prevents uninstalling the sshd you are connected over.

- [ ] **T7.3** — `render_posix` / `render_powershell` on every Action (15.11.1)
  - [ ] + positive: every action renders to both dialects.
  - [ ] − negative: an action that cannot be faithfully rendered fails generation loudly rather than emitting a subtly wrong script.

- [ ] **T7.4** — `Secret<T>` anti-stringification (15.11.2.1)
  - [ ] + positive: secrets flow through the engine without leaking into rendered output.
  - [ ] − negative: `Debug`/`Display`/serde on a `Secret<T>` cannot produce the plaintext; a compile-time or test-time assertion, since review will not catch every call site.

- [ ] **T7.5** — Embedded guard generation (15.11.2.2)
      Each emitted script re-implements its action's `check()` as a guard, so re-running is safe.
  - [ ] + positive: running an emitted script twice is idempotent.
  - [ ] − negative: a guard whose condition is already satisfied skips its action; assert no double-mutation.

- [ ] **T7.6** — `--emit-script` / `--target-os` (15.11)
  - [ ] + positive: emits a readable, reviewable, `set -euo pipefail` / `$ErrorActionPreference` script with provenance (styrn version, plan id, timestamp).
  - [ ] − negative: no secret is embedded; the script refuses to run on a mismatched OS or against an unexpected pre-existing state.

- [ ] **T7.7** — `--adopt` — *after its design spike* (15.11.2.4)
      The document itself records that no prior art exists for this loop. Do not implement before the spike concludes.
  - [ ] + positive: a state produced by a rendered script is adopted into a receipt Styrn can subsequently manage.
  - [ ] − negative: adoption refuses when observed state does not match what the script claims to have done.

- [ ] **T7.8** — Rendered-script VM conformance (16.6 item 8)
      **The drift check that makes the third renderer trustworthy.**
  - [ ] + positive: on identical fresh VMs per OS, emitted-script and direct-`apply` converge to the same probe results.
  - [ ] − negative: a deliberately divergent renderer is caught by the test — verify the check can actually fail.

- [ ] **T7.9** — Deploy-key source mode (8.2, D-1)
      Per-project, read-only, opt-in.
  - [ ] + positive: a project configured for `deploy-key` fetches directly from the forge.
  - [ ] − negative: the default remains controller-push; a deploy key is scoped to one project and revocable independently.

- [ ] **T7.10** — Workflow trust pinning (9.5, D-5)
      Default `open`; `pinned`/`allowlist` opt-in.
  - [ ] + positive: pinning rejects a `.styrn.toml` whose hash is not approved.
  - [ ] − negative: with pinning off (the default), behaviour is unchanged — the hardening must not leak friction into the default path.

---

# Phase 8 — Convenience and presentation

**Exit criterion:** ambient awareness and comfort features, none of which automation depends on.

- [ ] **T8.1** — `monitor` with `--notify` / `--jsonl` (14.1)
      Headless event follower. `watch` has no `--notify` (the S-12 de-duplication).
  - [ ] + positive: streams fleet events as JSONL; notifications fire per OS adapter.
  - [ ] − negative: `monitor` never requires a TTY; progress text never contaminates the JSONL stream.

- [ ] **T8.2** — Herdr plugin actions and events (11.6–11.9, 11.15)
      Fleet status, validate current/windows/linux/macos, start remote agent; `worktree.created` event.
  - [ ] + positive: actions resolve project and revision from Herdr pane context (12.x / orig. §98).
  - [ ] − negative: a dirty worktree action refuses per T2.15 rather than validating a different commit — the friction path must not bypass the correctness rule.

- [ ] **T8.3** — Fleet board pane and view projections (11.10, 11.18)
  - [ ] + positive: renders hosts, agents, jobs as specified.
  - [ ] − negative: equivalent data remains available via `--json`; the board is never required for automation (10.5).

- [ ] **T8.4** — `watch` TUI: fleet board view (14.5.1)
  - [ ] + positive: live host/agent/job state in a Herdr pane.
  - [ ] − negative: degrades by column-drop in a narrow pane, never horizontal scroll (14.5.2).

- [ ] **T8.5** — `watch`: matrix grid view (14.5.1)
      Workflows × hosts, cells transitioning queued → admitted → running → pass/fail.
  - [ ] + positive: a live matrix run renders cell-by-cell.
  - [ ] − negative: a failed cell is visually distinct and does not stall the grid.

- [ ] **T8.6** — `watch`: live job view with resource trace (14.5.1)
      Reads `resource.jsonl`; shows usage against the admitted budget.
  - [ ] + positive: memory/CPU trace renders for a running job.
  - [ ] − negative: a job killed at its quota shows the terminal state and the reason, making the governor legible rather than mysterious.

- [ ] **T8.7** — `watch`: agent board as a superset (14.5.1)
      All agents, all hosts, local included and marked by host; `blocked` surfaced for attention.
  - [ ] + positive: one place to see every agent; attach from the row. With no host registered, the board renders the 11.10 empty-state line rather than an error or a blank pane.
  - [ ] − negative: local rows are labelled as local and Herdr's native list remains authoritative for them — the board must not become a competing source of truth (11.12).

- [ ] **T8.8** — `watch`: doctor view with triggerable remediations (14.5.1)
  - [ ] + positive: pass/fail rows expand to detail; remediation runs from the row.
  - [ ] − negative: remediation routes through the same approval path as the CLI — the TUI is never a privilege bypass (14.5.2).

- [ ] **T8.9** — `watch`: Herdr citizenship constraints (14.5.2)
      All seven normative constraints.
  - [ ] + positive: runs as a Herdr pane using workspace context with zero arguments; updates from lifecycle events, not polling.
  - [ ] − negative: never binds Herdr's prefix or pane-navigation chords; does not interfere with Part 11.5 screen-manifest detection. Assert by running parity checks (T4.9) with a `watch` pane open.

- [ ] **T8.10** — `desktop open` / `admin open` / `desktop info` (3.4)
  - [ ] + positive: opens the configured client per platform; `desktop info --json` returns metadata.
  - [ ] − negative: RDP/Screen Sharing is never required for normal build or agent control (3.4).

- [ ] **T8.11** — Power providers (3.5, D-4)
      Local-network API only, no cloud round-trip; credentials in controller-only `power.toml` (0600).
  - [ ] + positive: power on/off/cycle against the chosen hardware.
  - [ ] − negative: credentials never enter a machine manifest (3.5); a provider requiring a cloud token is rejected by the selection criterion.

- [ ] **T8.12** — Optional harness hardening hooks; `project compile-integrations` (12.13, 12.15)
  - [ ] + positive: hooks install when requested.
  - [ ] − negative: **core policy never depends on Codex or Claude hooks** (12.12) — disable every hook and assert enforcement still holds. Styrn's launcher must not disturb Herdr's own hooks (12.9.1).

---

# Continuous obligations

These are not phase tasks; they must hold at every commit from Phase 0 onward (16.6).

- [ ] **C1** — Unit test layer: manifest/profile parsing, variable expansion, admission arithmetic, exit/error mapping, revision resolution (16.6 layer 1).
- [ ] **C2** — Protocol golden tests over in-memory pipes, both peer roles, including version-window rejection and oversized-frame handling (layer 2).
- [ ] **C3** — Fake-worker harness: local-child `rpc serve --stdio` exercising submit → supervise → tail → reattach → cancel (layer 3).
- [ ] **C4** — Concurrency tests: two controllers, one worker, budgets never exceeded (layer 4; the S-03 regression).
- [ ] **C5** — Platform CI matrix on ubuntu/macos/windows latest, including Windows argv round-trip, Job-Object tree-kill, long paths (layer 5).
- [ ] **C6** — `fleet selftest` green on the real fleet after every upgrade (layer 6).
- [ ] **C7** — Herdr parity conformance wherever Herdr is installable, i.e. wherever the substrate is `active` (layer 7; 11.0.1).
- [ ] **C8** — Setup and rendered-script conformance on the three-OS VM matrix (layer 8; Phase 7 gate).
- [ ] **C9** — Every new command added to the Part 10.5 canonical surface in the same change.
- [ ] **C10** — Every new component placed in exactly one Part 16.3 phase in the same change (the 16.3 placement rule).
- [ ] **C11** — Secret-scanning test over generated manifests, receipts, logs, audit entries, and rendered scripts.

---

# Open items carried from the design

- [ ] **O1** — Verify whether `launchctl` loading `ssh.plist` still bypasses Full Disk Access on current macOS (15.7, marked `[unverified]`; the source is 2020-era). This decides whether macOS Remote Login is automatable or must remain a `NeedsHuman` action. **Test on a real Sequoia+ machine before Phase 0's macOS path hardens.**
- [ ] **O2** — Confirm official Codex/Claude Code native installer URLs at implement time (15.7, `[verified via secondary sources]`).
- [ ] **O3** — Probe Herdr's actual Windows detection behaviour (12.10 records rev. A's claim as unverified). T4.8's live probe is the mechanism; run it early, since a negative result changes the Windows launcher design.
- [ ] **O4** — `--adopt` design spike (15.11.2.4) before T7.7.
- [ ] **O5** — Revisit `docs/design-review-D.md`'s proposed v1 cut line once Phases 0–2 exist. Its proportionality argument was consciously not adopted; real usage is the evidence that should settle it.
