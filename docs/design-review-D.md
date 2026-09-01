# Adversarial review of `design.md` revision D — complexity audit

**Reviewer posture:** fresh, no prior involvement, no stake in the document. Primary question, per the operator: is this over-engineered for the actual deployment — four machines (one M1 MacBook controller+worker, one Ubuntu box, two Windows machines) and one developer?

**Scope read:** the full 5,950 lines of `docs/design.md` rev. D. The superseded original was not read, per instruction. All Part/section citations below refer to rev. D.

---

## 1. Verdict

**Yes, revision D is over-engineered — but heterogeneously, and the diagnosis matters more than the label.** The core architecture is sound and mostly proportionate: worker-owned detached jobs (7.8), controller-push source distribution (8.2), locked worker-side admission (7.3), SSH-over-Tailscale with no daemon and no PKI (Parts 3–5), and the honest security model (4.5) are all either essential complexity or cheap. The overgrowth is concentrated in a specific stratum: the mechanisms added in the later passes that nobody then audited for proportionality — the `styrnd` service (15.9), the script-generation third renderer and its `--adopt` reconciliation loop (15.11), `--uninstall` with per-action `revert()` (15.6.2), the RPC protocol's request multiplexing and N/N−1 support windows (5.3, 2.8), the three-layer MCP authorization stack (13.3, 13.5), and — most of all — the specification itself, which at ~6,000 lines with zero code is now a larger artifact than the v1 it describes needs.

Two things must be said in the document's favor, because they make the cuts below more credible, not less:

- **The document repeatedly refuses things, and its refusals are good.** No database (16.2), no metrics pipeline (14.2), no worker-side queue (7.6), no secret-distribution mechanism (4.6), no central server (1.6), no consensus or controller coordination (2.1), no sigstore/TUF (15.7.6), prompts instead of a ratatui wizard (15.4.2), no fleet-wide backup mechanism (14.4). This is not a document that says yes to everything.
- **The three prior passes fixed genuine blockers.** S-01 (jobs died with the SSH session), S-02 (workers couldn't fetch private source at all), S-03 (admission had no atomicity), S-04 (the protocol was unimplementable as described) were real. The review process worked.

The failure mode is second-order: **each individual mechanism carries a plausible local justification, but the sum was never priced.** Every pass had an incentive to add — a reviewer closes an issue by specifying a mechanism, never by deleting the issue — and after three passes the document specifies, for one developer and four machines: a per-worker service with an LSA-stored credential, a two-dialect script renderer with its own VM CI matrix, an installer-framework Action trait with seven methods, receipt-driven uninstall, protocol version windows, four MCP profiles plus a machine ceiling plus a per-operation mutations table, and an eight-layer test strategy. The document's own restraint principles — orig. §2.8 ("avoid an extensible enterprise scheduler in v1"), Part 1.6 ("do not build it now"), §0.6 (complexity reaching the user is friction) — are honored in the *architecture* and violated in the *accretion*.

### The complexity budget, priced against the fleet

Count the moving parts the single operator must keep healthy under full rev. D: the `styrn` binary on four machines; `styrnd` on three workers (with a Windows service credential and a `--rotate-account` ceremony); Herdr, sshd, and Tailscale on four machines; per-worker job registries, receipts, and audit logs; per-controller inventories, manifest caches, known-hosts pins, submission indexes, and a second audit log; MCP registrations for two harnesses; a Herdr plugin; optional hooks. The support burden of all of it lands on the same one person the tool exists to serve. Honestly estimated, full rev. D is a multi-month, tens-of-thousands-of-lines Rust project across three operating systems — before the first remote `cargo test` runs. A v1 that is genuinely useful to this operator should be reachable in weeks, and the design already contains that v1; it just doesn't draw the line around it.

One further structural risk deserves naming: **contracts are being frozen before any code exists.** The N/N−1 protocol and schema support windows (2.8 rule 3), the append-only error-code registry (10.3), and the frozen vocabulary (§0.4) are compatibility promises of the kind one makes *after* a surface has survived contact with implementation. Made now, they constrain the first implementation for the benefit of hypothetical old versions that will never exist (there is nothing to be compatible *with*). Recommendation: mark every such contract explicitly as "binding from the first tagged release, not before" — the recommendation in §5 expands on this.

---

## 2. Proposed v1 cut line

### 2.1 The smallest coherent Styrn

The test applied: what does one developer with four machines need so that the flagship scenario of 13.10 / 16.7 — *edit on the Mac, validate natively on Windows and Linux, close the laptop, results survive* — works end to end? That scenario needs jobs, not agents; enforcement, not frameworks.

**Slice 0 — install and setup (subset of Part 15).**
Hand-maintained stage-zero shims (`install.sh` / `install.ps1`, 15.11.4) plus `styrn setup` with: the probe→diff→plan→apply engine (15.2), `check()` idempotency, flags and `--config` modes (15.4 modes 1–2), the plan display (15.4.4), the elevation strategy (15.5), the receipt as a journal (15.6.1), resumable-forward failure policy (15.6.3), per-OS component actions (15.7), the enrollment card (15.10), and `styrn bootstrap-script` implemented as stage-zero-shim-plus-baked-arguments (which is all 15.11.4 actually requires of it — see finding 3.4).
**Cut from slice 0:** `--emit-script`/`--target-os`/`--adopt` and the `render_posix`/`render_powershell` Action methods (3.4); `--uninstall` and per-action `revert()` (3.5); `--interactive` wizard (last, not first — it is the lowest-value of the three modes and the operator's zero-argument path already serves the newcomer case, 15.4.1); `styrnd` (3.1). Windows hardened mode stays the default (15.8) but ships fallback-first: if the transient-logon user phase (flagged implementer-confirm in 15.8) resists early implementation, the specified `NeedsHuman`-plus-fragment fallback *is* the v1 behavior, and `CreateProcessWithLogonW` is polish.

**Slice 1 — see the fleet.**
Enroll with host-key pinning (4.4, 6.1), `host list/status/doctor`, `exec`, `--json` envelope and exit codes (Part 10), the simplified RPC of finding 3.2 (hello + one logical request per session + streams + chunks; no multiplexing).

**Slice 2 — the core loop: remote validation.**
`.styrn.toml` parsing and variable expansion (9.1–9.3), revision resolution and dirty-refusal with `--snapshot` (8.4, 8.7), controller-push into bare repos with implicit `repo.ensure` (8.2), worker-side locked admission with committed budgets (7.2–7.3), the detached supervisor with Job Objects / setsid (7.8), disk polling and timeouts (7.5, 7.9), `workflow plan/run`, `job list/show/logs/cancel`, `artifact read` (7.7). This slice is where the design's genuinely hard, load-bearing work lives, and none of it should be cut.

**Slice 3 — matrix + selftest.**
`matrix run` (8.6) — it is thin aggregation over slice 2 — and `styrn fleet selftest` (16.6 item 6), which doubles as the upgrade acceptance test the fleet otherwise lacks.

**Slice 4 — Herdr agents.**
`agent list/read/prompt/wait/attach` via the local-Herdr-through-RPC pattern (11.1–11.2), `styrn harness run` with the parity invariant and the live doctor probe (12.9.1, 12.10), `integrate herdr install`.

**Slice 5 — MCP, two profiles.**
`styrn mcp serve` with `readonly` and `developer` only (13.3), plan/run/get/logs tools (13.8), project scoping (13.4). No `orchestrator`, no `admin`, no `[mcp.mutations]` table in v1 (3.6).

**Deferred beyond the cut line** (ordered path back to full rev. D): `styrnd` and scheduled maintenance (3.1); `monitor --notify` and `watch` TUI (already Phase 5); the Herdr plugin board (11.6–11.10); `orchestrator` MCP profile and fan-out bound (13.9); `--uninstall`; `--emit-script`/`--adopt`; `--interactive`; deploy-key source mode (8.2.3 — D-1 itself argues its motivating scenario "does not exist in v1's execution model"); trust pinning (9.5 — default-off per D-5, so deferring the *spec work* costs nothing); power providers (3.5/D-4); `project compile-integrations` (12.15); Codex/Claude hardening hooks (12.13–12.14); Cockpit/RDP components beyond the registry flip.

### 2.2 Does Part 16.3's phase plan still reflect rev. D? No.

The phases predate two revisions of additions and now misrepresent the work:

- **Phase 1 has silently ballooned.** Rev. D appended "setup engine core" to Phase 1 (16.3), but Part 15 is on the order of a quarter of the whole document — per-OS mechanics, elevation, receipts, hardened Windows account, enrollment card. A "Phase 1" containing the RPC layer *and* the setup subsystem is no longer a phase; it is most of the project. Slice 0/1 above splits it.
- **Rev. C/D mechanisms are unplaced.** `styrnd` (15.9), `styrn harness run` and the parity conformance machinery (12.9–12.10), audit logging (14.3), `monitor` (14.1), and `fleet selftest` (16.6) appear in no phase of 16.3. An implementer following 16.3 literally would not know when to build them.
- **Two parallel tracks with no cross-ordering.** 16.3 (phases 1–5) and 16.4 (integration phases A–E) are independent sequences with no statement of how they interleave — e.g., integration phase A (Herdr control) plausibly precedes or follows phase 3 (jobs), and the document never says which.
- **Ordering judgment: jobs before agents.** 16.4 puts Herdr control first ("this immediately improves control"). For this operator, the document's own flagship scenario (13.10: local agent delegates native Windows validation; 16.7: close the laptop mid-matrix) runs entirely on jobs and workflows, not on remote agent control. I recommend inverting: slices 2–3 before slice 4. This overrides 16.4's claim deliberately: `ssh -t win-mini herdr` already gives crude agent access today, but nothing today gives governed cross-platform validation.

---

## 3. Proportionality findings

Each finding names the mechanism, its cost, what breaks if cut, and a recommendation.

### 3.1 `styrnd` (15.9) — **DEFER to post-v1**

**What it is:** a per-worker service, installed by setup on all three OSes (15.7.4), running as the `styrn` account, doing two jobs: executing the 6.8 maintenance ticks, and brokering detached supervisor spawns on Windows over an ACL'd named pipe when `CREATE_BREAKAWAY_FROM_JOB` is denied.

**What it costs:** service installation and lifecycle on three OSes; on Windows, an SCM service credential set from the in-memory account password and stored by Windows in LSA (15.9), plus the `--rotate-account` ceremony that must refresh it; a new failure mode ("styrnd stopped") with doctor probes and degraded-mode logic; uninstall surface; and a permanent line in the operator's mental model of every worker.

**What breaks if cut:** almost nothing, by the document's own account. 15.9 specifies the degraded mode itself: "if styrnd is stopped, due maintenance runs opportunistically at job admission and via `doctor` (degraded, not absent)" — and 6.8 repeats it. For a four-machine fleet operated interactively, maintenance-at-admission plus on-demand `styrn clean run` plus a doctor nag *is* an adequate maintenance story: retention and cache trimming only accumulate debt when jobs run, and jobs running means admissions happening. The Windows spawn broker, meanwhile, exists for a trigger condition the document never establishes occurs: 7.8 hedges ("doctor verifies breakaway is permitted in this environment"), and Part 17's own recorded research claims "Windows processes launched through OpenSSH can survive SSH logout" — an internal signal (not proof; survival-after-logout is not the same as no-Job-Object) that the direct detached spawn may simply work on these machines. The broker is a speculative fallback promoted to a v1 subsystem.

**Recommendation:** DEFER. v1 ships the degraded mode as *the* mode: opportunistic maintenance at admission + `clean run` + doctor. On Windows, v1 attempts the direct `DETACHED_PROCESS | CREATE_BREAKAWAY_FROM_JOB` spawn and the doctor probe verifies, on each real worker, that a spawned supervisor survives session close. Build the broker only if a real machine fails that probe. Bonus: deferring styrnd removes the only consumer of a *persisted* credential in the whole design (the LSA entry), restoring 15.7.5's "the password goes nowhere" claim to full truth — see finding 4.2.

### 3.2 The RPC protocol (Part 5) — **SIMPLIFY: one logical request per session; keep framing, hello, streams, chunks**

**What it is:** NDJSON framing, correlation-ID multiplexing of concurrent requests, four stream kinds, per-frame `cancel`, ping/pong liveness, chunked base64 transfer, negotiated hello with N/N−1 windows.

**What it buys, honestly assessed.** The keystone property (5.1) — one fixed, quoting-safe command line (`styrn rpc serve --stdio`) crossing the remote login shell, everything else inside the protocol — is genuinely valuable on Windows and should be kept. The hello (machine identity, version check) is cheap and load-bearing for enrollment (5.2, 6.1). Streams and chunks serve real needs (log follow, artifact read). What buys almost nothing is **request multiplexing**: examining the document's own usage, every long-lived interaction is single-request-per-session — `events.subscribe` runs on a *dedicated* session per host by design (5.7), submit-then-tail is one request plus its stream (7.8.3), and running-job cancellation deliberately does *not* use frame-cancel but a separate `job.cancel` request (5.5). Concurrent cheap queries are the only multiplexing customer, and at four machines over a tailnet, per-operation session establishment is acceptable — the `Transport` trait (1.5.1) leaves the optimization door open.

**What breaks if simplified:** per-operation latency rises modestly for query bursts; nothing else. Correlation IDs become vestigial (a single fixed id), frame-`cancel` disappears (kill the session; `job.cancel` already covers the case that matters), and the worker's concurrent-request handling — with its cheap-query-vs-mutating-op internal scheduling (5.3) — is deleted.

**Do not simplify further to raw `ssh <host> styrn <cmd> --json` per operation:** that would put every command's arguments back through the remote login shell, forfeiting the 5.1 quoting keystone that Part 7.10's whole Windows story leans on. The stdio-single-request shape keeps it.

**On N/N−1 (2.8 rule 3, 5.2 rule 2):** SIMPLIFY with a stated trade-off. Mixed controller/worker versions exist, in this fleet, only transiently mid-upgrade — and 16.6's `fleet selftest` is specified to run after every upgrade. A hard version-match requirement with a clear "upgrade the worker: <command>" remediation is one-developer-appropriate; the N/N−1 engineering commitment (dual-version readers for manifests, profiles, and protocol, forever) is fleet-of-dozens machinery. Keep the `protocol_min`/`protocol_max` hello *fields* (cheap, future-proof); drop the *promise*.

### 3.3 Worker-side atomic admission (7.2–7.3) — **KEEP (justified), with one trim**

The operator's question invites a cut via D-2 ("primary controller + cold standby — concurrent controllers rare-to-never"). The invitation should be declined, because **multi-controller racing is not what the lock is for in practice.** Concurrency at a worker exists under a *single* controller: `matrix run` dispatches independent jobs concurrently (8.6); an MCP-driven submission from a local agent races a human's CLI invocation as two separate `styrn` processes on the same machine; and cleanup is explicitly serialized against admission under the same lock (6.8's locus rule). Remove the lock and the committed-budget bookkeeping and you re-open S-03/S-07 (double-booked memory on the 16 GB mini-PC, two "exclusive" heavy jobs) without any multi-controller scenario at all.

The mechanism is also cheap relative to its appearance: an advisory file lock (`flock`/`LockFileEx`) held for milliseconds, atomic temp-file-rename writes, and lock liveness that is a *property of the OS* (auto-release on holder death, 7.3), not code. The pid-sweep reconciliation is needed regardless for crash recovery and for releasing interactive-session budgets after the Unix `execvp` launcher (12.10) — it is shared infrastructure, not lock overhead.

**One trim:** 7.2's `committed_disk_unwritten` refinement (budget minus measured usage at last poll) is a second-order estimate feeding a check that the reserved-disk hard floor (7.5.2) backstops anyway. v1 can use full budgets for committed disk and lose nothing but a little admission pessimism.

### 3.4 Script generation, the third renderer (15.11) — **CUT from v1** (`--emit-script`, `--target-os`, `--adopt`, `render_posix`/`render_powershell`)

This is the clearest disproportion in the document, and it can be cut without violating the operator's verbatim requirement, because that requirement is **conditional**: "*if styrn is not able to perform bootstrap by itself*, it should be able to generate platform specific bootstrap … scripts" (15.1). Rev. D's own achievement — a setup engine that *can* perform bootstrap by itself, with a `NeedsHuman` outcome for the genuinely non-automatable residue (15.2.4) — dissolves the condition.

**What it costs:** two additional renderer methods on every Action forever (15.2.3); the `Secret<T>` structural-no-stringification machinery (15.11.2.1); embedded guard generation — a shell re-implementation of every `check()` (15.11.2.2); and, by 15.11.3's *own admission*, "the two-dialect test surface is the costliest part of this feature" — CI VMs proving that emitted bash and PowerShell converge to the same probe results as `apply` (16.6 item 8). Plus `--adopt`, about which 15.11.2.4 says, verbatim: "**no prior art exists for this exact loop — it needs a design spike before implementation**." A v1 feature that needs a design spike is not a v1 feature.

**What breaks if cut:** nothing user-visible in the flagship flow. I verified this against the document: the two-paste fleet walkthrough (15.10) runs on `styrn bootstrap-script`, and 15.11.4 defines that command as emitting "a customized copy of the **stage-zero script**" — the hand-maintained shim — "plus this controller's public key and the chosen setup arguments baked in." That is string substitution into a hand-written template; it requires none of the Action-renderer machinery. The `NeedsHuman` fragments (15.2.4) degrade from generated fragments to hand-written per-action instruction strings — which is what most of them (Tailscale login, Codex login, macOS Sharing toggle) already are. The losers are audit/air-gap provisioning and operator-forbids-direct-execution environments (15.11.1's Alembic analogy) — neither exists in this deployment.

**Recommendation:** CUT from v1; keep the two `render_*` slots in the trait design as documented future extension points if desired, unimplemented. Revisit only if a real need (air-gapped machine, policy-restricted host) appears.

### 3.5 Receipts and `--uninstall` (15.6) — **KEEP the receipt; DEFER `--uninstall`**

The receipt itself is a cheap append-journal that also feeds the ownership rule ("uninstall removes only what Styrn created") and download provenance — keep it; it costs one struct and some writes. `--uninstall`, however, doubles the setup implementation surface: every Action needs a tested `revert()`, plus the transport guard (15.6.2), plus the receipt-ownership conformance test (16.6 item 8). For four machines owned by their operator, the realistic uninstall path in year one is "reimage the box" or "delete the styrn tree by hand using the receipt as a checklist" — which the receipt already enables *as data* without any code. What breaks if deferred: nothing until someone wants a clean automated removal, at which point the receipt has been accumulating the necessary information all along. DEFER; implement `revert()` lazily, per-action, when uninstall ships.

### 3.6 The MCP authorization stack (13.3, 13.5, 13.9) — **SIMPLIFY: two profiles, one policy layer, in v1**

Rev. D governs a single MCP mutation through **three stacked mechanisms**: the client-requested profile, the machine-level `max_profile` ceiling (13.3), and the per-operation `[mcp.mutations]` table (13.5) — on top of the harness's own approval system, which 13.5 correctly says is a separate layer. But 4.5 has already conceded, honestly and at length, that MCP narrowing is "least-privilege ergonomics, not containment" against an agent with shell access on a credentialed controller. Three Styrn-side layers of non-boundary is two too many for v1. **Recommendation:** ship `readonly` and `developer` profiles only (matching 16.4 phase C, which already stages it this way); defer `orchestrator` (+ its fan-out bound, 13.9) and `admin` to the phase where cross-agent delegation is actually built; fold `[mcp.mutations]` into the profile definition (a profile *is* a set of allowed operations) and drop the separate table; keep `max_profile` as the single server-side ceiling since it is one config key and closes the client-edits-its-own-config hole cheaply. What breaks: nothing — no v1 scenario in the document uses `orchestrator` or per-operation overrides.

### 3.7 Windows-specific machinery (7.8, 7.10, 12.10, 15.7, 15.8) — **mostly KEEP; two deferrals**

Cross-platform correctness on native Windows is the design's stated reason to exist, and most of this stratum is essential complexity:

- **Job Objects with `KILL_ON_JOB_CLOSE` for batch jobs (7.8, 7.9, 7.10.3): KEEP.** Windows has no process groups; reliable build-tree termination genuinely requires this. It is the difference between a resource governor and a suggestion.
- **No-shell argv execution, long paths, native separator rendering (7.10): KEEP.** Each item traces to a concrete, well-known failure class; the `.bat`-unsupported rule is the right hard line.
- **The interactive-session Job Object *without* kill-on-close + inert-waiter launcher (12.10): KEEP.** It is the minimum arrangement that satisfies the parity invariant (12.9.1), and the live doctor probe (verify parity, never assume it) is one of the document's best ideas.
- **`CREATE_BREAKAWAY_FROM_JOB` fallback broker: DEFER with styrnd (3.1).** Attempt direct spawn; probe on real hardware; build the fallback only on demonstrated need.
- **`CreateProcessWithLogonW` transient logon (15.8): KEEP the design, sequence the implementation.** Hardened-by-default (D-3) is the right call — the credential separation of 4.5 is what makes "workers hold nothing worth stealing" true, and the dedicated account also sidesteps the administrators_authorized_keys ACL trap (15.7.1). But the transient-logon mechanism is flagged implementer-confirm, and 15.8 already specifies the honest fallback (`NeedsHuman` + a run-once-as-styrn fragment). v1 may ship with the fallback as the working path and the transient logon as a fast follow; the design needs no change for that sequencing.

### 3.8 The setup engine core (15.2–15.7, 15.10) — **KEEP**

Distinct from the renderer/uninstall accretions above, the core — typed probes, `check()`-gated idempotent actions, plan display with privilege badges, one-elevation apply, `NeedsHuman`, doctor/setup sharing the probe layer, the enrollment card — is proportionate *and* is the part the operator explicitly demanded ("this is a very important part to make styrn adoptable"). Setup is not a run-once cost: the same engine is the repair loop (re-run to converge, doctor to nag), and four machines × three OSes × years of drift is exactly the workload that killed the shell scripts (S-10, S-17, S-18, S-35). The winget demotion (15.7.6) and the supply-chain bar are well-judged. Two internal-consistency problems with the probe-unification claim are in finding 4.3.

### 3.9 Remaining mechanisms, briefly

- **Matrix workflows (8.6): KEEP.** Thin aggregation over independent jobs; it is the "validate everywhere" flagship, and it introduces no new machinery beyond exit-code aggregation.
- **Host-qualified artifact URIs (7.7): KEEP.** A naming convention, near-zero cost, and it deletes the shared-index problem (S-14) rather than solving it.
- **Audit logging (14.3): KEEP.** Two append-only JSONL files with no daemon; the worker log rides the existing registry lock. Cheap enough that cutting it saves nothing.
- **Backup/restore (14.4): KEEP.** It specifies the *absence* of a mechanism (copy a directory; worker state disposable). This is a model refusal, not a feature.
- **`styrn watch` TUI, `monitor --notify` (14.1, 10.5): already correctly deferred** to Phase 5; no change.
- **Deploy-key source mode (8.2.3): DEFER.** D-1 itself states the scenario favoring it "does not exist in v1's execution model." Specifying a second credential-bearing source path for v1 contradicts the document's own decision log. Keep the `[source.auth]` schema reservation; implement nothing.
- **Trust pinning / allowlist (9.5): DEFER** — default-off per D-5, single-operator rationale is sound; it is pure spec-forward work today.
- **`submission_id` idempotency, spawn-ack, TTY-aware wait (7.8.6, 7.6): KEEP.** Each is small, addresses a real unhappy path (unknown-outcome resubmission; opaque exit-6 on a busy host), and costs little.
- **Interactive-session budget registration (12.9.1): KEEP.** On the 16 GB mini-PC, an unaccounted live agent plus an admitted validation job is a real OOM path; the mechanism reuses the registry and reconciliation it needs anyway.
- **Starter-profile on-ramp, aliases (9.1, 9.4): KEEP.** Cheap, and directly serve §0.6.

---

## 4. New correctness findings

What three prior passes appear to have missed. Where I am not certain something is a defect rather than an editorial gap, it is labeled as underspecification.

### 4.1 12.9 step 8 contradicts the 12.10 Unix launcher (internal contradiction)

12.9 lists "records exit status" as launcher step 8. 12.10 then makes `execvp` replacement **normative** on Unix/macOS — "not 'where possible'" — and correctly notes that after exec no Styrn process remains, delegating *budget release* to pid-death reconciliation (7.3). But reconciliation observes only that a pid died; it cannot recover an exit status. Step 8 is therefore unachievable on Unix as specified, and 12.10 reconciles the budget-release half but not the exit-status half. Either step 8 needs a Unix caveat (exit status recorded only where a waiter exists, i.e. Windows), or the reconciliation entry needs an explicit "exit status unknown" outcome. Small, but an implementer will hit it in slice 4.

**This also answers the operator's named question:** 7.8 (batch supervisor: detached, Job Object *with* kill-on-close), 15.9 (styrnd: spawn broker only, never owner), and 12.10 (interactive launcher: direct child, Job Object *without* kill-on-close, inert waiter) otherwise tell a **consistent** story about Windows process ownership — the batch/interactive kill-on-close asymmetry is deliberate and correctly reasoned in both places. The exit-status gap above is the one seam.

### 4.2 `styrnd`'s LSA credential quietly weakens 15.7.5's password claim (drift between sections)

15.7.5 (Windows account): the password is generated in memory, used transiently, zeroized, discarded — "never written to receipt, config, console, or script output"; "nothing ever needs the password again." 15.9 then sets the styrnd SCM service credential *from that password*, "stored by Windows in LSA." The parenthetical defense ("the OS-designed mechanism, distinct from Styrn writing a password anywhere") is arguable, but the two sections' claims have drifted: something *does* need the password again, and it *is* persisted, just not by Styrn's own hand. LSA secrets are Administrator-extractable, which matters exactly on the machines 4.5 calls out as needing credential hygiene. Not a security hole within the stated threat model (a hostile job runs as `styrn`, not Administrator) — but the "goes nowhere" language should be qualified, or (per finding 3.1) styrnd deferred, which resolves it outright.

### 4.3 The doctor/setup probe unification is over-claimed (15.2.2 / 6.5)

15.2.2 declares "doctor = probe + render" with a hard rule: "a check may not be added to doctor without a probe, and vice versa." But the probe layer is defined as **local, read-only, unprivileged** (15.2.1), while several 6.5 doctor checks are irreducibly **controller-side and remote**: "Tailscale reachable," "SSH reachable," "protocol compatible," "clock skew vs controller under 30s," "manifest cache age / version drift." None of these can be a worker-local probe — clock skew is *defined* relative to the controller. So either `styrn host doctor` is really two layers (remote transport/session checks + relayed local probes) — plausible, but then 15.2.2's one-to-one rule is false as stated — or the rule silently applies only to the local subset. The distinction matters to the implementer building the shared probe layer first. Recommendation: split doctor's contract into "controller-side checks" and "worker-local probes (shared with setup)" and scope the one-to-one rule to the latter.

### 4.4 `styrn_workflow_cancel` has no underlying operation (dangling surface)

13.3's `developer` profile includes `styrn_workflow_cancel`. No corresponding CLI command exists (10.5 has only `job cancel`), and the RPC method list (5.3) has `job.cancel` but no `workflow.cancel`. A matrix/workflow run maps to one or more jobs, so cancellation-by-workflow needs a defined resolution (cancel all jobs of the submission? the submission_id?) that nothing specifies. Either drop the tool or define the mapping.

### 4.5 Part 10.5's "core command surface" is materially incomplete (spec-vs-spec drift)

Commands specified as normative elsewhere but absent from 10.5: the entire `styrn machine` group (`machine roles`, `machine manifest`, `machine init` — 2.1, 2.4.1); `styrn controller init` (4.3.1); `styrn harness run` (12.9); `styrn harness-hook` (12.14); `styrn fleet selftest` (16.6 item 6, introduced as "a … command (new)"). `styrn herdr …` and `styrn integrate …` live only in 10.7/12.18, defensibly, but the machine group and `fleet selftest` are core by any definition. An implementer generating the CLI from 10.5 ships an incomplete binary.

### 4.6 The admission formula has undefined inputs (underspecification)

7.2 computes `job_disk_budget = min(project disk hint or default, policy.max_job_disk_bytes)` — but `[resource_hints]` (7.2) defines only `compile_memory_per_job_bytes`, `test_memory_per_job_bytes`, `peak_memory_bytes`. **No disk-hint key exists in any schema, and the "default" is never given a value.** Likewise `estimated_memory_per_job` has per-project hints but no stated default for profile-less or hint-less projects (which 9.1's starter on-ramp explicitly supports), and the "conservative committed budget" of an interactive harness session (12.9.1) is never quantified. Three constants an implementer must invent inside the most safety-critical formula in the document.

### 4.7 Workflow-command working directory is never stated (underspecification)

7.8.1 sets the *supervisor's* working directory to `job.root`. Nothing states the cwd of the workflow command itself. Every example implies the workspace root (`cargo check --workspace`; `["pwsh", "-File", "script.ps1"]` resolving a relative path), but implied is not specified — and 9.3 rule 5 (no variable expansion in `command` elements) makes cwd the *only* way a command finds its workspace. One sentence fixes it.

### 4.8 Exit 9 on fan-out queries fights §0.6 in this exact fleet (design tension)

6.7: `styrn job list` / `agent list --all` fan out to every inventory host and **exit 9 (`fleet.partial`) if any host could not be queried**. Two of the four machines (win-hp, mbp-main) are laptops that sleep. Routine status queries will therefore return non-zero as the *normal* state of this fleet, which both violates the frictionless tenet and trains scripts to ignore exit 9. Suggest: partial results exit 0 with unreachable hosts in `warnings[]` (they are already labeled in output), reserving 9 for operations where the unreachable host was a *required* participant (matrix aggregation, 8.6, where it is correct).

### 4.9 The error-code → exit-code mapping is partial (underspecification)

10.3 annotates some codes with exit codes (`transport.unreachable` → 3, `job.timeout` → 10, …) but leaves many unmapped: `machine.manifest_invalid`, `job.not_found`, `agent.not_found`, `job.cancelled`, all four `project.*` codes, `usage.*`. Presumably `project.worktree_dirty` → 12 and `usage.*` → 2, but the envelope is supposed to be the authoritative contract (10.4) and half its registry has no defined coarse outcome. Also minor: 2.8 rule 3's N/N−1 window names manifests, profiles, and protocol — the command envelope has no stated window at all.

### 4.10 `submission_id` deduplication across job cleanup (underspecification, small)

7.8.6: a resubmission carrying a known `submission_id` returns the existing job. Registry entries are swept/archived by reconciliation and retention (7.3, 7.11). Whether the dedupe check consults archived/cleaned entries — i.e., whether a delayed retry after a *completed and cleaned* job creates a twin — is unstated. The window is small; a retention rule for submission_ids (e.g., dedupe against the submission index or archived registry for N hours) closes it.

### 4.11 Cross-cutting conventions: checked, and they hold

For completeness, the conventions the operator asked about were checked and pass: RFC 3339 timestamps, integer bytes, integer milliseconds are used consistently across the envelope (10.1), status (2.5), manifests (2.4), and protocol examples (5.4); the exit-code table (10.4) is internally consistent with its uses in 6.4, 7.2, 7.6, 8.2, 8.6, 15.13; TOML key naming is consistent (snake_case, `*_bytes`/`*_seconds` suffixes); the §0.4 frozen vocabulary is adhered to throughout (I found no surviving `--kind`, unprefixed MCP tool, or host-less `job://` URI). The Windows spawn-trigger question (whether sshd contexts actually deny breakaway) is treated as a proportionality matter in finding 3.1; as a correctness matter, note only that Part 17's recorded Herdr claim about SSH-spawned process survival sits in unacknowledged tension with 7.8's premise.

---

## 5. Document usability assessment

**Is the spec itself disproportionate? Yes.** ~6,000 lines for an unstarted project, of which roughly 1,200 (Parts 18–19, Appendix A, the §0 apparatus) are historiography, and much of the remainder interleaves normative rules with revision archaeology ("new in rev. B", "(orig. §N)", superseded-mechanism narrations like 1.3.4 and 15.4.3) in every section. The traceability discipline is genuinely excellent *as an audit record* — this review leaned on it — but it actively taxes the other audience. An implementer reading Part 7 must repeatedly distinguish "what to build" from "why rev. A was wrong," and the operative content of the document is perhaps a third of its mass.

Specific usability defects:

1. **Reading order.** The protocol (Part 5) precedes the job model (Part 7) it exists to carry; setup (Part 15) — Phase 1 work — comes last of the operative Parts; the phase plan that should organize a reader's priorities (16.3) is stale (§2.2). There is no implementer's reading order.
2. **Multi-site specification with drift.** The command surface is scattered across 10.5, 10.7, 12.18, 15.13, 2.1, and 4.3, with the omissions of finding 4.5. Doctor's contract lives in both 6.5 and 15.2.2, with the inconsistency of finding 4.3. Cleanup defaults live in 9.1 and again in D-7.
3. **Normative and informative are not marked.** Part 11's eighteen sections mix hard rules (11.1's transport asymmetry) with pre-implementation UX advice (11.17 plugin-state hygiene, 11.18 view projections) at equal apparent weight. The document has RFC-style vocabulary in exactly one place (12.9.1's MUST); everywhere else, bindingness must be inferred.

**Recommendation:** freeze `design.md` rev. D as the design record it has become, and extract a short implementation contract for the v1 cut line (§2) — on the order of 10–15 pages: schemas, wire format, admission rules, exit/error codes, per-OS process rules, setup component list — each section carrying a back-pointer into rev. D for rationale. Additionally mark which contracts (2.8 windows, 10.3 append-only, §0.4 vocabulary) become binding only at the first tagged release. The alternative — implementing directly from a 6,000-line document whose phase plan is stale — is how implementations quietly diverge from their specs.

---

## 6. What remains unverified or missing

### 6.1 Unverified load-bearing external claims

To its credit, the document flags nearly all of these itself (Part 17 standing caveat; 15.1's evidence tags). Listed here by how much weight rests on them — these are flags, not corrections; none can be verified from this repository:

1. **Herdr — the design's largest single external bet, and its softest.** Parts 11–12 build the entire agent story on recorded upstream claims (persistent sessions, JSON socket API, event subscriptions, plugin system, lifecycle detection, the Windows remote-target asymmetry — 11.1, 11.4, 11.14). 15.7.6 then reveals that Herdr has "no public distribution documented — the spec defines it," i.e. Styrn's design is inventing its substrate's release channel. Every Herdr claim funnels through `HarnessProvider` and the parity probe (12.10.3), which is the right degradation posture, but the concentration risk deserves a top-level statement: if Herdr's API surface shifts materially, Parts 11–12 and slice 4 re-open.
2. **Windows sshd Job-Object/breakaway behavior** (7.8.1) — the trigger for the styrnd broker; never established, and in tension with Part 17's recorded claim (findings 3.1, 4.11). The doctor probe is specified; run it on real hardware before building anything.
3. **`CreateProcessWithLogonW` profile materialization** (15.8) — flagged implementer-confirm; the hardened-Windows default rests on it, with a specified fallback.
4. **macOS `launchctl` Remote Login enablement bypassing the FDA gate** (15.7.3) — the document's own words: "the single most important pre-implementation test in this Part."
5. **Herdr's Windows pane-process detection** (12.10) — correctly downgraded from rev. A's assertion to a live probe.
6. Codex/Claude MCP config surfaces and hook systems (12.3's invented settings keys remain flagged; 12.12–12.13, 13.11–13.12); Tailscale repo/keyring URLs and macOS variant behavior (15.7.2); winget package IDs (15.7.6); git-push interop through `DefaultShell=pwsh` (15.7.1, selftest-covered); sccache/incremental interaction (7.12); `service-manager` crate fitness (15.7.4).

### 6.2 Missing entirely

1. **A binary upgrade path — the most significant absence in the document.** `styrn fleet versions` (6.6) observes version drift; 2.8 spends a page on tolerating mixed versions; `fleet selftest` validates after "every upgrade" (16.6) — and **no mechanism anywhere upgrades a worker's `styrn` binary.** Setup installs it once via stage zero (15.11.4). After v0.2 ships, how do four machines get v0.3? Re-running the stage-zero shim by hand on each box is presumably the answer, but it is nowhere stated, and it interacts with running jobs (replace the binary under a live supervisor?), with `styrnd` if built (restart the service), and with the N/N−1 window that exists precisely for this moment. One section — `styrn host upgrade <host>` or an explicit "re-run stage zero; here is the ordering" — would close it. Its absence is also an argument for the version-window simplification in 3.2: the document engineered for mixed versions while omitting the operation that creates them.
2. **Worker sleep/wake.** Two of four machines are laptops. Scheduling drops unreachable candidates (6.4 step 2) and fan-out queries mark them (6.7 — see finding 4.8), but nothing wakes a sleeping worker (no Wake-on-LAN anywhere; power providers, 3.5/D-4, are about recovery, not wake) and nothing in setup addresses OS sleep policy for a machine expected to accept jobs (e.g., win-hp lid-closed behavior, Ubuntu suspend defaults). For this specific fleet, "heavy Windows validation" (the HP laptop) silently depends on an unstated "the laptop is awake and configured never to sleep" assumption. A setup component (power/sleep policy for workers) or at least a doctor check is missing.
3. **`--host` override semantics on `workflow run`** (10.5). Does forcing a host bypass capability matching (surely not), scheduling preference (surely), or admission (surely not)? Unstated; one sentence needed.
4. **Log/artifact size bounds during a job.** `max_job_disk_bytes` governs the job tree via polling (7.5), which implicitly covers `stdout.log` growth — but only if the walk includes the log files, which 7.5.1 ("workspace + target") suggests it may not. If logs are outside the walked set, a pathological workflow can flood the disk within the floor margin. Clarify that `job.root` walking includes logs.
5. **Enrollment-card transport integrity is procedural only.** The card (15.10) travels back to the controller by human paste; the design correctly treats the fingerprint as out-of-band. Fine at this scale — noted only because nothing says the card must not be relayed through an untrusted channel. A sentence in 15.10 would do.

---

## Closing

The architecture is better than its length. The load-bearing decisions — worker-owned jobs, controller-push source, locked admission, honest boundaries, one binary, no daemon — survive adversarial reading and should be built as specified. What should not be built, yet, is the accretion layer that three improvement passes deposited on top: a service, a script compiler, an uninstaller, a multiplexer, and a compatibility regime, all serving futures this fleet does not have. Cut to the line in §2, implement the slices in order, and let the first month of real use — not a fourth review pass — decide what, from beyond the line, earns its way back in.
