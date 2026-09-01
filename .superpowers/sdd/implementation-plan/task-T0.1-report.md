# Task T0.1 Report — Cargo workspace and module skeleton

## Implementation summary

Created the single `styrn` Rust binary workspace foundation with the complete requested `src/` module tree, harness submodules, and target-gated private platform modules. Added the planned architecture's starting dependencies (with compatible versions recorded in `Cargo.lock`), no database, and a GitHub Actions Ubuntu/macOS/Windows matrix covering format, build, and test checks.

Added a real compile-fail boundary integration test. It invokes `rustc` on an external-consumer fixture that attempts to access the private platform module and asserts the compiler rejects it.

## Files changed

- `Cargo.toml`, `Cargo.lock`
- `.github/workflows/ci.yml`
- `src/main.rs`
- `src/{cli,setup,config,manifest,inventory,transport,rpc,mcp,resources,scheduler,jobs,project,git,integrations,desktop,notification,output}/mod.rs`
- `src/harness/{mod.rs,herdr.rs,codex.rs,claude.rs}`
- `src/platform/{mod.rs,linux.rs,macos.rs,windows.rs}`
- `tests/platform_boundary.rs`
- `tests/fixtures/platform_consumer.rs`

## TDD RED

Command:

```text
cargo test --test platform_boundary
```

Observed failure:

```text
error: couldn't read src/main.rs: No such file or directory (os error 2)
error: could not compile `styrn` (bin "styrn") due to 1 previous error
```

This was expected: the compile-fail test existed before production code, so the referenced crate/module API was not yet present.

## TDD GREEN

Command:

```text
cargo test --test platform_boundary
```

Observed result after the skeleton was added:

```text
running 1 test
test generic_consumer_cannot_access_platform_module ... ok
test result: ok. 1 passed; 0 failed
```

## Exact verification results

- `cargo fmt --all -- --check` — passed.
- `cargo test --test platform_boundary` — passed, 1 test.
- `cargo build --locked` — passed, no warnings.
- `cargo test --locked` — passed; 0 unit tests and 1 integration test, 0 failures.
- `git diff --cached --check` — passed.

## Self-review

- Every requested module exists.
- `src/platform/mod.rs` uses compile-time `cfg(target_os = ...)` boundaries.
- Platform modules are private; the real rustc compile-fail test verifies generic/external access is rejected.
- `src/harness/` contains exactly `mod.rs`, `herdr.rs`, `codex.rs`, and `claude.rs`.
- Existing `docs/`, `examples/`, and `schemas/` were left intact.
- No database dependency or later-task runtime behavior was added.
- CI defines Ubuntu, macOS, and Windows matrix entries and runs format/build/test checks.

## Concerns

Local verification ran on the current host only; the three-host positive claim is gated by the added CI matrix and was not emulated locally.

## Fix Round 1

Changed files:

- `tests/platform_boundary.rs`
- `tests/fixtures/platform_consumer.rs`

The fixture now compiles the real `src/platform/mod.rs` as a crate-root module and defines a sibling `generic` module. A target-selected `generic::misuse` function attempts to reach the host-specific child module. This is rejected by Rust privacy on Linux, macOS, and Windows; making the host module public would make the fixture compile and fail the test.

Covering command:

```text
cargo test --test platform_boundary
```

Relevant output:

```text
running 1 test
test generic_sibling_cannot_access_host_platform_module ... ok
test result: ok. 1 passed; 0 failed
```
