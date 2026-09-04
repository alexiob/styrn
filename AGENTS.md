# Styrn development guide

Styrn is one cross-platform Rust CLI/control plane for development machines,
remote jobs, and coding agents. It deliberately uses native macOS, Linux, and
Windows facilities; do not add a WSL, container-orchestrator, database, or
project-build-system dependency to the core design.

## Authority and scope

Work from the most specific applicable source, in this order:

1. The user's request and security constraints.
2. [`docs/design.md`](docs/design.md), revision I: the canonical, binding
   architecture and protocol specification. Cite its Part numbers in design
   discussions. If it conflicts with the plan, the design wins.
3. [`docs/implementation-plan.md`](docs/implementation-plan.md): ordered work,
   positive/negative tests, and continuous obligations. Put every new component
   in exactly one Part 16.3 phase in the same change; add every command to the
   Part 10.5 surface in the same change.
4. `schemas/*-v1.schema.json` and `examples/`: normative renderings of the
   design. Keep schemas, examples, and implementation synchronized.
5. `README.md`: public-facing status and usage. Keep it truthful as the product
   evolves. `docs/design-review-D.md` is historical review material, not a
   replacement specification.

Prefer the frictionless default only when it preserves correctness and does not
weaken a security boundary. Keep Styrn generic: it schedules and runs declared
project workflows; project-specific build knowledge belongs in `.styrn.toml`.

## Rust, dependencies, and layout

- `rust-toolchain.toml` is authoritative and pins the current exact toolchain
  (`1.98.0`, with `rustfmt` and `clippy`); `Cargo.toml` declares Rust `1.98`.
  Never downgrade Rust. Each update must use the then-current latest stable
  release, never below Rust 1.94, and update the local pin, `rust-version`, CI
  selector, lockfile, and toolchain-contract tests together.
- Build with the pinned toolchain; do not select `stable`, `beta`, nightly, or
  a second toolchain in CI.
- Before adding or updating a dependency, check the design's Part 16.2 and the
  existing `Cargo.toml`/`Cargo.lock`. Prefer the existing crate set and current
  supported APIs; make API migrations complete (all call sites, tests, docs,
  lockfile), rather than retaining obsolete compatibility shims. No database in
  v1: inventory is TOML and jobs are filesystem objects.
- Keep host-specific code behind the private `platform` adapter boundary:
  `src/platform/{linux,macos,windows}.rs` owns OS mechanics and generic siblings
  must use its narrow interface. Use native Windows APIs/PowerShell on Windows,
  never WSL or assumed Unix filesystem/process semantics.

## Contracts that must not drift

- Non-interactive commands support `--json`; finite commands emit exactly one
  `styrn.command.v1` envelope on stdout, diagnostics only on stderr, and no
  ANSI in JSON. Preserve typed error codes and the documented exit mapping;
  never substitute an inner workflow exit for Styrn's typed exit.
- Machine IDs are canonical UUIDv7 values minted once and stable thereafter.
  Manifest writes must remain validated, locked, temporary-file based,
  hardened, atomically replaced, and verified after replacement. Reject unsafe
  paths, links, special files, and insecure ownership/permission chains.
- Never serialize, log, return, or include in manifests, receipts, audit logs,
  generated/rendered setup scripts, command payloads/envelopes, or diagnostics
  a private key, auth/API key, token, password, or secret-shaped value. Secret
  rejection must occur before a write and must not echo the secret in an error.
- Default user-scope core runs entirely without root/Administrator and writes
  only the invoking user's standard directories. If missing machine-wide
  capabilities matter, interactive setup may offer exactly one optional,
  itemized OS-owned sudo/UAC authorization; declining must leave a useful
  rootless installation, and `--yes` never implies privilege consent. Its
  manifest, receipt, registry, locks, and authorized
  keys are user-owned and therefore **not** a containment boundary against
  hostile same-user code; preserve atomic/no-follow/corruption checks without
  claiming worker non-writability. Explicit system scope retains root/Admin-
  owned state readable but not writable by an unprivileged worker principal.
  Never require an account named `styrn`: current-user is the default and a
  configurable dedicated account is optional system-scope hardening.
- A controller role is not job eligibility, and a worker role is not admin
  authority. The worker makes atomic resource-admission decisions. Agent jobs
  may modify source; validation runs use a clean worktree at an exact commit and
  must not certify the agent's modifying workspace.

## Implementation and tests

- Treat plan tasks as a dependency and coverage map, not as delivery-sized
  units. Work in the largest reviewable vertical slice that ends in an
  executable user journey; an internal parser, trait, provider, or receipt
  layer is not progress by itself. The current priority is ordinary user
  setup -> enrollment card -> controller enrollment -> status/doctor/exec.
  Defer daemons, streaming, multiplexing, retries, fanout, and generic
  installer/provider frameworks until a current journey consumes them.
- Every new abstraction must either serve a consumer in the current slice or
  close a concrete privilege, identity, secret, durability, concurrency, or
  data-loss hazard. Otherwise keep the implementation local and concrete until
  a second real consumer demonstrates the shared shape.
- Use strict TDD: first add or adjust a focused test that fails for the intended
  reason, implement the smallest correct change, then refactor with the suite
  green. Each plan task needs both a positive behavior test and a negative test
  that asserts the exact exit code, structured error code, and absence of
  partial state—not merely a nonzero status.
- Favor typed data and errors, explicit ownership/lifetimes at system boundaries,
  small platform adapters, and deterministic serialization. Keep public output
  additive and versioned; preserve fields unless a schema-version change is
  deliberately specified.
- Test the cheapest truthful layer first (unit, protocol, local fake worker),
  then the required real-platform behavior. Cross-platform acceptance means the
  Ubuntu, macOS, and native Windows CI/host gates actually ran; cross-compiling
  or mocking is not a substitute. If a required OS, VM, hardware account, or
  integration is unavailable, leave the test honestly unavailable/ignored with
  its prerequisite and report the exact unrun gate. Never call it passed.
- Do not bypass resource admission, run unrestricted parallel builds, or use
  `cargo clean` as routine cleanup. Build targets and job directories are
  disposable and job-scoped.

## Verification and handoff

Run the relevant gates before claiming completion; for a normal Rust change the
minimum local suite is:

```console
cargo fmt --all -- --check
cargo build --locked
cargo test --locked
cargo clippy --workspace --all-targets --all-features -- -D warnings
git diff --check
```

Also run the applicable cross-target/platform gate and preserve the three-OS CI
matrix (`ubuntu-latest`, `macos-latest`, `windows-latest`). Platform-sensitive
changes need native verification on every affected OS, or an explicit honest
status as above. Inspect `git diff` as well as test output; report commands
executed, results, and any unavailable validation. Evidence comes before a
claim that code is fixed, complete, or cross-platform.

## Working-tree and review discipline

- This greenfield repository normally works directly on `main`; do not create a
  worktree unless the user requests isolation or changes that preference.
- Start by checking `git status`. Treat all existing uncommitted changes as
  another contributor's work: preserve them, do not stage them, and avoid
  overlapping edits without coordination.
- Keep changes focused and commits small, imperative, and reviewable. Stage
  exact paths, review the staged diff and `git diff --check`, then commit only
  the files owned by the task. Request/review changes against the binding
  contracts and their tests, not just compilation.
- Never use destructive Git operations (`reset --hard`, force checkout, clean,
  or history rewriting) to resolve a dirty tree. Do not discard or overwrite
  user changes; ask when the correct target or authority is unclear.
