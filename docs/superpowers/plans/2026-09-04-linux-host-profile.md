# Native Linux Host Profile Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Detect native Linux distributions and their independently verified package and systemd capabilities, reject WSL before setup state is touched, plan closed apt-get/DNF/Pacman actions safely, and validate the behavior on native ARM64 Linux without adding a runtime container dependency.

**Architecture:** Linux-only parsing and OS mechanics live in private children of `src/platform/linux.rs`. Generic setup holds only an opaque host-profile handle and closed native package action/effect values. Distribution, package, system-service, and user-service evidence degrade independently; only an unknowable native-versus-WSL decision blocks all platform setup. Podman remains a repository test harness, while real systemd lifecycle checks remain explicit VM gates.

**Tech Stack:** Rust 1.98.0, existing `libc`/`serde`/`sha2` dependencies, JSON Schema, POSIX shell, Podman AppleHV with native `linux/arm64` images.

**Spec:** `docs/superpowers/specs/2026-09-04-linux-host-profile-design.md`

## Global Constraints

- Work directly on `main`; preserve every path reported by the initial and each subsequent `git status`. Never rely on a hard-coded dirty-file list, and do not stage another contributor's path until its owner has committed or explicitly handed it off.
- Follow `docs/design.md` revision H until Task 1 atomically canonicalizes revision I. Where the approved supporting spec is ambiguous, preserve revision H's independent-capability and fail-safe rules.
- Use strict TDD for every behavior: focused red test, smallest green implementation, refactor with the focused suite green, then exact-path commit.
- Never use `PATH`, shell evaluation, WSL environment variables, caller-provided package names, or mutable image tags as authority.
- Never claim container success for systemd start/enable, user-manager, linger, reboot, ssh login, Tailscale TUN, sudo handoff, or dedicated-account acceptance.
- Do not add a crate. If implementation proves one necessary, stop and update Part 16.2, `Cargo.toml`, `Cargo.lock`, and dependency-contract tests together before use.
- A macOS `cargo test` filter for `platform::linux` is not evidence: it can select zero tests. Starting in Task 2, every Linux-only red/green command runs through `scripts/test-linux-arm64-cargo.sh`, whose preflight asserts the AppleHV VM, image, child kernel, Rust target, and non-root mapped UID are ARM64/correct and whose test-filter mode fails when it selects zero tests. Pure document/schema tests may continue to run directly on macOS.

---

### Task 0: Capture the collaboration and test baseline

**Files:**

- Do not modify tracked files.
- Record: `/private/tmp/styrn-linux-host-profile-baseline.txt`

- [ ] **Step 1: Record repository ownership before edits**

Run `git status --short --branch`, `git log -3 --oneline`, and `git diff --name-only` and record their output in the untracked baseline artifact. Notify the other active contributor that platform/setup/docs/harness paths are being claimed and request notice before any overlap.

- [ ] **Step 2: Record the existing macOS gate state**

Run `cargo test --locked` once on the macOS host. Record every pass/failure/ignored test name and command. The known baseline currently includes three setup failures; verify rather than assume that list before comparing the final suite. Capture the Linux baseline in Task 2 only after the attesting wrapper exists.

- [ ] **Step 3: Recheck status**

Run `git status --short`; expected: no new tracked change from baseline capture.

### Task 1: Close the supporting spec and canonical design contracts

**Files:**

- Modify: `docs/superpowers/specs/2026-09-04-linux-host-profile-design.md`
- Modify: `docs/design.md`
- Modify: `docs/implementation-plan.md`
- Create: `tests/linux_design_contract.rs`

- [ ] **Step 1: Add a failing documentation contract test**

Create `tests/linux_design_contract.rs` with section-scoped assertions that the three documents contain one exact Part 16.3 Phase 0 ownership bullet, the supported families/backends, WSL refusal, independent capability degradation, package receipt fields, and the container/VM boundary. Parse the `## 16.3`, `## 16.6`, T0.8, T0.11, and C5/C8 sections rather than counting a phrase across changelogs. Assert that the supporting spec no longer says “pending review” or incorrectly cites Part 7.10.

```rust
#[test]
fn canonical_design_owns_linux_host_profiles_once() {
    let design = include_str!("../docs/design.md");
    let plan = include_str!("../docs/implementation-plan.md");
    let phase = section(design, "## 16.3", "## 16.5");
    assert_eq!(phase.matches("Linux host profile, WSL refusal, and package-backend adaptation").count(), 1);
    for required in ["apt-get", "dnf5", "pacman", "setup.unsupported_os"] {
        assert!(design.contains(required), "missing {required}");
        assert!(plan.contains(required), "plan missing {required}");
    }
}
```

- [ ] **Step 2: Run the focused test and observe the intended failure**

Run: `cargo test --locked --test linux_design_contract -- --nocapture`

Expected: FAIL because revision H and the implementation plan do not yet own the Linux host-profile contract.

- [ ] **Step 3: Resolve the audited ambiguities in the supporting spec**

Define:

- only kernel disposition as globally blocking;
- independent `LinuxCapability` values for distribution, package, system-service, and user-service evidence;
- a `LinuxExecutableIdentity` containing canonical path, device, inode, owner UID, file type, mode, size, and modification/change timestamps, revalidated immediately before mutation;
- `/etc/os-release` fallback only on `ENOENT`, 16 KiB whole-file and 255-byte per classification-field ceilings, ASCII `[a-z0-9._-]+` ID tokens, and exact accepted `\\`, `\"`, `\'`, `\$`, and ``\` `` escapes without expansion;
- exact-ID authority with contradictory cross-family `ID_LIKE` rejected;
- system-manager query `/usr/bin/systemctl show --property=Version --value` with a nonempty single bounded UTF-8 line; user-manager query using the recovered original-user token and the same shape;
- WSL rejection for setup/apply/dry-run and worker eligibility, while help/version/controller-side rendering remain available;
- stock repository mappings: SSH (`openssh-server` on apt/DNF, `openssh` on Pacman), Git (`git` everywhere), Cockpit (`cockpit` on apt/DNF, unsupported on Pacman), and Tailscale unsupported until a separately specified repository action exists;
- installed queries: `/usr/bin/dpkg-query --show --showformat=${Status} <package>`, verified DNF executable `list --installed <package>`, and `/usr/bin/pacman -Q <package>`; query contradictions are unknowable;
- dependency-scoped `NeedsHuman` for unsupported capabilities and dependency-scoped probe failure for unknowable required evidence.

- [ ] **Step 4: Canonicalize revision I atomically**

Update revision metadata, terminology, change register, issue register, Parts 0.4, 10.3, 11.0, 15.2, 15.5, 15.6, 15.7.2, 15.7.4–15.7.7, 15.12–15.15, 16.2, 16.3 Phase 0, and 16.6. Correct Part 15.14's existing `brew`/`deb` prose to schema-backed `homebrew`/`apt`; do not add DNF or Pacman as Styrn binary installation channels.

- [ ] **Step 5: Synchronize implementation-plan ownership**

Amend T0.3, T0.8–T0.17, T0.20, C1, C5, and C8. Keep Linux account-policy generalization in T0.14 and record real Omarchy ARM64, user-manager/linger, and service lifecycle gates as unavailable until run.

- [ ] **Step 6: Verify and commit**

Run:

```console
cargo test --locked --test linux_design_contract
rg -n "Part 7\.10|pending review|package substrate|\bbrew\b|\bdeb\b" docs/superpowers/specs/2026-09-04-linux-host-profile-design.md docs/design.md
git diff --check
```

Expected: test PASS; searches contain no stale supporting-spec status/reference or incorrect install-channel vocabulary.

Commit: `Canonicalize native Linux host profiles`

### Task 2: Parse bounded Linux metadata and classify families

**Files:**

- Create: `scripts/test-linux-arm64-cargo.sh`
- Create: `tests/linux_cargo_harness_contract.rs`
- Create: `src/platform/linux/host.rs`
- Create: `tests/fixtures/linux-host/os-release/{ubuntu-24.04,debian-bookworm,fedora,rhel-9,rocky-9,alma-9,oracle-9,arch,omarchy,omarchy-future,other,conflicting,duplicate-id,unterminated-quote,literal-substitution}`
- Modify: `src/platform/linux.rs`

- [ ] **Step 1: Write a failing native-cargo harness contract**

Assert that the script pins `docker.io/library/rust:1.98-bookworm@sha256:56bfc6a715db852bdafd5e4bdf68ef7abceb791e77c47e5d87c7e861702a9ca6`, rejects a non-ARM64 Podman host/image/child, uses `--userns=keep-id:uid=1000,gid=1000` with explicit `--user 1000:1000`, asserts `id -u` is exactly 1000 and nonzero, mounts the source read-only, and uses Podman-native registry/target volumes. A dedicated initialization container may chown only those exact new volumes before the non-root runner starts. Contract-test three modes: `target-attestation`, `cargo -- <cargo-args>` pass-through, and `test-filter <substring>`; the last obtains `cargo test -- --list`, fails unless at least one exact matching test is listed, then runs that filter.

- [ ] **Step 2: Prove the harness contract is red, then implement the wrapper**

Run: `cargo test --locked --test linux_cargo_harness_contract -- --nocapture`

Expected first: FAIL because the wrapper does not exist. Implement the smallest wrapper, rerun, and expect PASS. Verify live preflight with `scripts/test-linux-arm64-cargo.sh target-attestation`; expect Podman `arm64`, image `linux/arm64`, child `aarch64`, Rust host `aarch64-unknown-linux-gnu`, and effective UID/GID `1000:1000` with writable native target/registry volumes.

- [ ] **Step 3: Capture the native Linux baseline**

Run `scripts/test-linux-arm64-cargo.sh cargo -- test --locked` before adding parser tests. Append the full pass/failure/ignored names to `/private/tmp/styrn-linux-host-profile-baseline.txt`; this is the Linux comparison authority for final verification.

- [ ] **Step 4: Write pure parser/classifier tests first**

Cover supported fixtures, exact-ID precedence, ordered `ID_LIKE`, Other, duplicate classification keys, invalid tokens, conflicting ancestry, quotes/escapes, literal command substitution, NUL, non-UTF-8, and 16 KiB overflow.

```rust
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum LinuxFamily { Debian, RedHat, Arch, Other }

#[derive(Clone, Debug, Eq, PartialEq)]
struct LinuxDistribution {
    id: Box<str>,
    id_like: Box<[Box<str>]>,
    version_id: Option<Box<str>>,
    family: LinuxFamily,
}
```

- [ ] **Step 5: Prove tests are red on native ARM64 Linux**

Run: `scripts/test-linux-arm64-cargo.sh test-filter platform::linux::host::tests::os_release`

Expected: compile/test failure because the private host module and parser do not exist.

- [ ] **Step 6: Implement a no-execution parser**

Implement `parse_os_release(bytes: &[u8]) -> Result<LinuxDistribution, LinuxObservationError>` with explicit byte-state parsing. Unknown keys are skipped after syntactic validation; classification keys are unique and bounded. Do not call a shell or environment expansion API.

- [ ] **Step 7: Verify positive and negative suites on native ARM64 Linux**

Run:

```console
scripts/test-linux-arm64-cargo.sh test-filter platform::linux::host::tests::os_release
scripts/test-linux-arm64-cargo.sh test-filter platform::linux::host::tests::rejects_
```

Expected: all focused tests PASS, including failure categories that contain no fixture contents.

- [ ] **Step 8: Commit**

Commit: `Parse bounded Linux distribution metadata`

### Task 3: Detect WSL and refuse before any setup state access

**Files:**

- Modify: `src/platform/linux/host.rs`
- Modify: `src/platform/linux.rs`
- Modify: `src/platform/mod.rs`
- Modify: `src/setup/orchestrator.rs`
- Create: `tests/setup_wsl_cli.rs`
- Create: `tests/fixtures/linux-host/kernel-release/{native,wsl1,wsl2}`

- [ ] **Step 1: Write kernel disposition and preflight tests**

Test case-insensitive `microsoft` in `uname(2)` release, the WSLInterop marker, unreadable kernel evidence, and ignored `WSL_*` variables. Add an orchestrator seam that injects a capture result and proves Unsupported WSL returns before directory planning, receipt lookup, manifest lookup, intent, or locks. Add a compile-time-only `cfg(styrn_wsl_fixture)` observation seam and integration test that builds the production binary into an isolated target with that cfg; the cfg is registered in Cargo's `unexpected_cfgs` check and cannot be selected by runtime input.

```rust
pub(crate) enum SetupExecutionContextError {
    UnsupportedOs,
    ProbeFailed,
}

pub(super) enum LinuxDisposition {
    Native(LinuxHostProfile),
    UnsupportedWsl,
    Unknowable(LinuxObservationError),
}
```

- [ ] **Step 2: Run red tests**

Run: `scripts/test-linux-arm64-cargo.sh test-filter wsl`

Expected: FAIL because WSL is currently treated as ordinary Linux and capture returns `io::Result`.

- [ ] **Step 3: Implement fixed kernel observation and typed capture mapping**

Use `libc::uname`, inspect fixed `/proc/sys/fs/binfmt_misc/WSLInterop`, and map `UnsupportedWsl` to `RootlessSetupError::UnsupportedOs`. Add that orchestrator variant and map it through the existing `setup.unsupported_os`/exit-13 output registry without editing `src/main.rs`.

- [ ] **Step 4: Verify CLI surfaces and exact no-state failure**

In the fixture build, run setup dry-run and apply with `--json`: each must emit exactly one `styrn.command.v1` envelope, exit 13, carry `setup.unsupported_os`, write diagnostics only to stderr, and leave manifest, receipt, pending intent, lock, and action roots absent. Verify help and version still exit 0. Do not use `WSL_*` environment variables as the fixture seam. Worker-doctor propagation follows after the shared profile/catalog plumbing in Task 5.

Run:

```console
scripts/test-linux-arm64-cargo.sh test-filter wsl
scripts/test-linux-arm64-cargo.sh test-filter setup::orchestrator::tests::unsupported_os
scripts/test-linux-arm64-cargo.sh cargo -- test --locked --test setup_wsl_cli
```

Expected: exact typed error; filesystem snapshot before/after identical.

- [ ] **Step 5: Commit**

Commit: `Reject WSL before setup state access`

### Task 4: Securely observe os-release and fixed executables

**Files:**

- Modify: `src/platform/linux/host.rs`
- Modify: `src/platform/linux.rs`

- [ ] **Step 1: Add descriptor-relative security tests**

Use an injected metadata/syscall backend for deterministic ordinary-user tests and a real descriptor backend for native positive tests. Production always expects owner UID 0. Test `/etc` precedence, `/usr/lib` fallback only when the `/etc` entry itself is absent with `ENOENT`, standard relative symlink acceptance, absolute/escaping/dangling links (a present dangling link must not trigger fallback), non-root ownership, writable ancestry, special files, replacement through deterministic pre-read/post-read hooks, and executable mode/type/identity drift.

```rust
#[derive(Clone, Debug, Eq, PartialEq)]
struct LinuxExecutableIdentity {
    canonical_path: PathBuf,
    device: u64,
    inode: u64,
    owner_uid: u32,
    file_type: LinuxFileType,
    mode: u32,
    size: u64,
    modified_seconds: i64,
    modified_nanoseconds: i64,
    changed_seconds: i64,
    changed_nanoseconds: i64,
}
```

Retain the same identity shape for the selected `os-release` evidence so “revalidate the host profile” is enforceable rather than a fresh best-effort re-detection.

- [ ] **Step 2: Run red tests**

Run: `scripts/test-linux-arm64-cargo.sh test-filter platform::linux::host::tests::secure_`

Expected: FAIL because production observation is not descriptor-relative or identity-carrying.

- [ ] **Step 3: Implement no-follow reads and executable verification**

Open from a trusted root with `openat`/`O_NOFOLLOW` at each component, validate UID/mode/type on each descriptor, read with the 16 KiB cap, and compare `fstat` identity before and after. Accept only the documented `/etc/os-release` relative symlink arrangement after resolving it under the same root.

- [ ] **Step 4: Verify**

Run: `scripts/test-linux-arm64-cargo.sh test-filter platform::linux::host::tests::secure_`

Expected: all positive/negative security tests PASS and errors reveal only categorical causes.

- [ ] **Step 5: Commit**

Commit: `Verify Linux host evidence without following unsafe paths`

### Task 5: Build independent package and systemd capabilities

**Files:**

- Modify: `src/platform/linux/host.rs`
- Modify: `src/platform/linux.rs`
- Modify: `src/platform/mod.rs`
- Modify: `src/setup/probe/baseline.rs`
- Modify: `src/setup/mod.rs`
- Modify: `src/rpc/server.rs`

- [ ] **Step 1: Add capability-composition tests**

Test apt plus its independent `/usr/bin/dpkg-query` identity, DNF then DNF5 fallback, Pacman, expected-manager/query absence, unsafe expected manager/query, unrelated managers, Other family, systemctl-without-runtime, runtime-without-systemctl, malformed manager query, and independent user-manager absence. For apt, a missing secure `dpkg-query` is `Unsupported`; unsafe or contradictory query evidence is `Unknowable`.

```rust
enum LinuxCapability<T> { Available(T), Unsupported, Unknowable(LinuxObservationError) }

struct LinuxHostProfile {
    distribution: LinuxCapability<LinuxDistribution>,
    package_backend: LinuxCapability<LinuxPackageBackend>,
    system_service_backend: LinuxCapability<LinuxServiceBackend>,
    user_service_backend: LinuxCapability<LinuxUserServiceBackend>,
}
```

- [ ] **Step 2: Run red tests**

Run: `scripts/test-linux-arm64-cargo.sh test-filter platform::linux::host::tests::capability_`

Expected: FAIL because no composite profile exists.

- [ ] **Step 3: Implement capability observation**

Verify only `/usr/bin/apt-get`, `/usr/bin/dpkg-query`, `/usr/bin/dnf`, `/usr/bin/dnf5`, `/usr/bin/pacman`, and `/usr/bin/systemctl`. The apt capability retains both apt-get and dpkg-query identities. Run the bounded fixed system-manager query; observe the original user's manager separately only after identity/token recovery, through a narrow opaque-token API that runs only the fixed `systemctl --user show --property=Version --value` request.

- [ ] **Step 4: Bind one opaque profile to setup and probes**

Add cloneable `SetupHostProfile` to `SetupExecutionContext`, pass it through both `production_rootless_catalog` and `production_worker_doctor_catalog` (prefer one shared host-local constructor), and change `baseline_probe_snapshot` to accept `&SetupHostProfile`. macOS and Windows construct/ignore an empty platform-native handle; no distro values cross `platform/mod.rs`. Add a test proving doctor and setup observe identical evidence from the same captured profile. Map conclusive WSL in the host-doctor/worker-eligibility RPC path to `setup.unsupported_os` instead of the current generic `remote.execution_failed`, while an unknowable native disposition maps to `setup.probe_failed`.

- [ ] **Step 5: Verify boundary and behavior**

Run:

```console
scripts/test-linux-arm64-cargo.sh test-filter platform::linux::host::tests::capability_
scripts/test-linux-arm64-cargo.sh cargo -- test --locked --test platform_boundary
scripts/test-linux-arm64-cargo.sh test-filter setup::probe::baseline::tests
scripts/test-linux-arm64-cargo.sh test-filter worker_doctor_wsl_
```

Expected: capabilities degrade independently and private Linux types cannot be named by generic consumers.

- [ ] **Step 6: Commit**

Commit: `Bind verified Linux capabilities to setup`

### Task 6: Route Linux service probes through the captured systemd capability

**Files:**

- Modify: `src/platform/linux.rs`
- Modify: `src/platform/linux/host.rs`

- [ ] **Step 1: Extend existing SSH, Tailscale, and sleep tests**

Add cases for unsupported system manager, unknowable manager evidence, verified executable replacement, and valid captured systemctl. Preserve the strict state/status contradiction tests from commit `97d9422`.

- [ ] **Step 2: Run red tests**

Run: `scripts/test-linux-arm64-cargo.sh test-filter platform::linux::tests::systemd_`

Expected: at least one test FAIL because probes still hard-code `/usr/bin/systemctl`.

- [ ] **Step 3: Consume the capability**

SSH, Tailscale, and sleep obtain systemctl only from the captured profile, revalidate its identity before each observation, and preserve `Unknowable` for operational/malformed/contradictory results. An unsupported service capability makes only the dependent probe absent/unsupported for planning; it does not invalidate Git or directory work.

- [ ] **Step 4: Verify**

Run:

```console
scripts/test-linux-arm64-cargo.sh test-filter platform::linux::tests::systemd_
scripts/test-linux-arm64-cargo.sh test-filter platform::linux::tests::ssh_
scripts/test-linux-arm64-cargo.sh test-filter platform::linux::tests::tailscale_
scripts/test-linux-arm64-cargo.sh test-filter platform::linux::tests::sleep_
```

Expected: PASS with no regression to strict state handling.

- [ ] **Step 5: Commit**

Commit: `Use captured systemd capability in Linux probes`

### Task 7: Construct and revalidate closed package operations

**Files:**

- Create: `src/platform/linux/packages.rs`
- Modify: `src/platform/linux.rs`
- Modify: `src/platform/mod.rs`

- [ ] **Step 1: Write fake-executor tests**

Cover exact installed-query and install argv, environment, privilege, unsupported table cells, wrong-family managers, PATH injection, identity drift, command failure, and Pacman's forbidden partial-sync sequence. Installed-state tests include exact valid stdout/exit pairs and contradictions for dpkg-query, DNF/DNF5, and Pacman; apt revalidates both apt-get and dpkg-query identities.

```rust
enum LinuxPackageComponent { SshServer, Git, Cockpit, Tailscale }

enum LinuxPackagePlan {
    Install(LinuxPackageInstall),
    Unsupported,
    Unknowable(LinuxObservationError),
}
```

Expected installs:

```text
/usr/bin/apt-get install -y git
/usr/bin/dnf install -y git
/usr/bin/dnf5 install -y git
/usr/bin/pacman -S --needed --noconfirm git
```

- [ ] **Step 2: Run red tests**

Run: `scripts/test-linux-arm64-cargo.sh test-filter platform::linux::packages::tests`

Expected: compile failure because the package module does not exist.

- [ ] **Step 3: Implement closed query/install construction**

Expose only opaque `NativePackageInstall`, `NativePackageEffect`, and `NativePackagePlan` wrappers from `platform/mod.rs`. Do not expose a string package constructor. Revalidate executable identity and host profile before mutation. Use a cleared/minimal fixed environment, including `DEBIAN_FRONTEND=noninteractive` only for apt.

- [ ] **Step 4: Verify exact negative behavior**

Run:

```console
scripts/test-linux-arm64-cargo.sh test-filter platform::linux::packages::tests
rg -n -- "pacman.*-Sy|-Sy.*pacman|Command::new\([^)]*PATH" src/platform
```

Expected: tests PASS; search finds no partial-upgrade command or PATH-selected package executor.

- [ ] **Step 5: Commit**

Commit: `Construct closed Linux package operations`

### Task 8: Add typed package actions, authorization, receipts, and recovery

**Files:**

- Create: `src/setup/action/package.rs`
- Modify: `src/setup/action/mod.rs`
- Modify: `src/setup/action/authorization/mod.rs`
- Modify: `src/setup/orchestrator.rs`
- Modify: `src/setup/receipt/mod.rs`
- Modify: `schemas/setup-receipt-v1.schema.json`
- Modify: `examples/setup-receipt.json`

- [ ] **Step 1: Add a failing privilege-gate test before adding package actions**

Construct a test `Privilege::Root` action and pass it to the current rootless apply entry. Assert the engine refuses before prepare, intent creation, or mutation. Add a non-forgeable execution capability accepted only from the verified authorization coordinator; make the closed action executor require it for `Root`/`Admin` actions. Rootless setup passes user authority and can execute only `Privilege::None`.

```rust
pub(in crate::setup) enum ActionExecutionAuthority<'a> {
    User,
    Authorized(&'a VerifiedAuthorizationCapability),
}
```

The `Authorized` constructor remains private to authorization verification. The capability is non-cloneable, non-serializable, lifetime-bound to one verified request, and structurally bound to the request SHA-256, privilege class, exact action parameters, and expected effect. Execution consumes it only while dispatching the recomputed approved action set and compares every binding again. Add a defense-in-depth check inside execution and atomically partition privileged actions out of the rootless mutation vector in the orchestrator; a future caller cannot accidentally make `--yes` equivalent to privilege consent. Tests prove a capability for action A, altered parameters, altered effect, or a different digest cannot authorize action B.

- [ ] **Step 2: Add failing lifecycle and schema tests**

Test check/done, prepared intent before mutation, successful install effect, backend drift before mutation, manager failure after intent, exact requested/recomputed-plan equality, recovery round trip, unknown fields, invalid package/backend combinations, and secret-shaped rejection. Negative tests assert exit 13 mapping at the orchestrator seam and no package/service mutation.

```rust
pub(crate) enum Action {
    // existing variants
    PackageInstall(package::PackageInstallAction),
}

pub(crate) enum ActionParameters {
    // existing variants
    PackageInstall(PackageInstallParameters),
}
```

- [ ] **Step 3: Run red tests**

Run:

```console
scripts/test-linux-arm64-cargo.sh test-filter setup::action::package::tests
cargo test --locked setup::receipt::tests::package_ -- --nocapture
```

Expected: compile/test failures because package resources are not part of the closed action/receipt enums.

- [ ] **Step 4: Implement the closed action chain**

Extend `Action`, `ActionParameters`, `RequestedAction`, structural authorization comparison, `ActionEffect`, `ReceiptAction`, serialization, schema, and example. Receipt data contains backend, verified executable identity, component, closed package ID, installation scope, and finalized typed effect—never a shell command.

- [ ] **Step 5: Verify schema/example and recovery**

Run:

```console
scripts/test-linux-arm64-cargo.sh test-filter setup::action::package::tests
cargo test --locked setup::action::authorization::tests
cargo test --locked setup::receipt::tests
cargo test --locked --test schema_examples
```

Expected: PASS; failed apply retains only the durable prepared/acknowledged prefix required by Part 15.6.

- [ ] **Step 6: Commit**

Commit: `Journal typed Linux package actions`

### Task 9: Plan dependency-scoped package remediation

**Files:**

- Modify: `src/setup/probe/baseline.rs`
- Modify: `src/setup/orchestrator.rs`
- Modify: `src/setup/action/package.rs`
- Modify after contributor handoff: `src/cli/mod.rs`
- Modify after contributor handoff: `src/main.rs`
- Modify: `src/setup/action/authorization/mod.rs`
- Modify: `tests/setup_cli.rs`

- [ ] **Step 1: Add positive and negative planning tests**

For missing Git/SSH/Cockpit, assert a supported stock package creates a privileged package proposal; Tailscale and unsupported Pacman Cockpit become exact `NeedsHuman`; unknowable dependent evidence returns `setup.probe_failed`; unrelated directory/rootless actions remain planable. In rootless production setup, partition every privileged proposal into pending authorization before `apply_plan_with_journal`; it must never enter the rootless mutation vector. Assert `--yes`, declined authorization, and `--no-elevate` never authorize or mutate a package/service.

- [ ] **Step 2: Run red tests**

Run: `scripts/test-linux-arm64-cargo.sh test-filter setup::probe::baseline::tests::linux_package_`

Expected: FAIL because baseline desired state is still exclusively adopt-or-defer.

- [ ] **Step 3: Add profile-aware desired actions**

Request closed components from the platform adapter. Convert `Install` to a typed package proposal, `Unsupported` to dependency-scoped `NeedsHuman`, and `Unknowable` to pre-mutation `ProbeFailed`. Only the existing explicit authorization coordinator may turn a proposal into an executable privileged action. Rootless noninteractive setup converts that proposal to pending instructions without dispatch; `--yes` and `--no-elevate` remain non-authority inputs.

- [ ] **Step 4: Coordinate and wire the production authorization journey**

Wait until the contributor owning `src/cli/mod.rs` and `src/main.rs` has committed or handed off those paths. Then connect the existing request-digest/recomputed-plan authorization coordinator to interactive Linux setup: display the exact privileged delta, request one explicit OS-owned sudo authorization, write the typed prepared request before handoff, recapture/revalidate profile and executable identities in the elevated child, execute only the structurally identical authorized set, and return to the original-user phase. Decline, `--no-elevate`, EOF, and `--yes` without an explicit interactive privilege answer all publish precise pending actions while leaving a useful rootless installation. An already-root invocation still must recover the trustworthy original principal and bind the same request.

- [ ] **Step 5: Verify exact outcomes**

Run:

```console
scripts/test-linux-arm64-cargo.sh test-filter setup::probe::baseline::tests::linux_package_
scripts/test-linux-arm64-cargo.sh test-filter setup::orchestrator::tests::linux_package_
scripts/test-linux-arm64-cargo.sh cargo -- test --locked --test setup_cli -- package_privilege
```

Expected: exact operations/privileges/errors and zero partial state on negative cases.

Add a disposable native Linux integration test with a fake OS authorization executor proving the one-prompt journey, exact digest binding, durable-prefix recovery on package-manager failure, return to user phase, and no mutation for `--yes`, decline, or `--no-elevate`. A real sudo transaction remains an explicit VM gate in Task 11.

- [ ] **Step 6: Commit**

Commit: `Plan Linux package remediation by capability`

### Task 10: Build a digest-locked native ARM64 Podman harness

**Files:**

- Create: `scripts/test-linux-arm64-podman.sh`
- Create: `tests/linux-containers/images.lock`
- Create: `tests/linux-containers/Containerfile.builder`
- Create: `tests/linux-containers/archlinuxarm/Containerfile`
- Create: `tests/linux-containers/archlinuxarm/rootfs.lock`
- Create: `tests/linux-containers/README.md`
- Create: `tests/linux-containers/unavailable-gates.json`
- Create: `tests/linux_harness_contract.rs`

- [ ] **Step 1: Add a failing static harness contract**

Parse `images.lock` without adding a crate (a strict line-oriented test format is sufficient) and assert every image is a fully qualified `tag@sha256:<64 lowercase hex>` with `linux/arm64`, each required family/backend exists, the shell script never uses `--privileged`, Podman socket mounts, host networking, floating tags, or x86 emulation, and VM-only claims are absent.

- [ ] **Step 2: Run red test**

Run: `cargo test --locked --test linux_harness_contract -- --nocapture`

Expected: FAIL because harness files do not exist.

- [ ] **Step 3: Resolve and attest native image inputs**

Require the named `styrn-linux` AppleHV VM, Fedora CoreOS image `42.20250818.3.0`, and Podman server `5.8.6` (or update the lock and contract deliberately). Inspect each manifest list for Ubuntu 24.04, Debian Bookworm, Fedora stable, UBI 9, and Rust 1.98 Bookworm, select and record the child `linux/arm64` manifest digest, then run only `tag@<arm64-child-digest>`. Record both list and child digests so `podman image inspect` ambiguity cannot substitute the amd64 digest. Download the official Arch Linux ARM AArch64 rootfs, record its HTTPS URL and upstream SHA-256, normalize build timestamp/labels with a locked `SOURCE_DATE_EPOCH` and `podman build --timestamp`, and record/verify the resulting image digest. Never record a digest from an amd64 manifest.

- [ ] **Step 4: Implement fail-fast orchestration**

The script verifies the locked VM/version, VM `arm64`, selected child manifest `linux/arm64`, child `uname -m=aarch64`, and binary target AArch64. Build once in the pinned builder, use a read-only source mount plus Podman-native artifact/target/scratch volumes, run mapped non-root with `--read-only`, `--cap-drop=ALL`, `no-new-privileges`, and `--network=none`, and remove only uniquely named owned volumes in a trap. “Dry-run” means Styrn's own plan-only path plus read-only installed-state queries; it does not invoke package-manager transaction simulations that depend on mutable repository metadata.

- [ ] **Step 5: Run contract and live harness**

Run:

```console
cargo test --locked --test linux_harness_contract
scripts/test-linux-arm64-podman.sh
```

Expected: static contract PASS; all five live images attest ARM64 and pass metadata/backend/Styrn-dry-run plus native-volume XDG/ACL tests. If the official Arch rootfs is unavailable, record that gate in `unavailable-gates.json` and do not report it passed.

- [ ] **Step 6: Commit**

Commit: `Test Linux profiles on native ARM64 images`

### Task 11: Add CI scheduling and explicit real-VM gates

**Files:**

- Create: `.github/workflows/linux-arm64-podman.yml`
- Modify: `src/platform/linux.rs`
- Modify: `tests/linux-containers/README.md`

- [ ] **Step 1: Add failing CI contract assertions**

Extend `tests/linux_harness_contract.rs` to require `workflow_dispatch`, a schedule, an ARM64 self-hosted label, exactly one harness invocation, locked runner prerequisites, and publication of `unavailable-gates.json` as an artifact. Preserve the current Ubuntu/macOS/Windows job and exact Rust selector contract unchanged.

- [ ] **Step 2: Run red test**

Run: `cargo test --locked --test linux_harness_contract`

Expected: FAIL because the workflow does not exist.

- [ ] **Step 3: Add the dedicated workflow and ignored native gates**

The workflow checks out and invokes only `scripts/test-linux-arm64-podman.sh`, then publishes its machine-readable availability inventory. Add ignored tests with precise prerequisite names for systemd start/enable, user manager, linger/logout/reboot, ssh login, Tailscale TUN, sleep policy, package transactions, sudo handoff, dedicated account, and real Omarchy ARM64. Each gate is enabled only by its own explicit prerequisite environment variable; the script runs filters only for variables proven/provisioned by that runner and records all others as unavailable.

- [ ] **Step 4: Verify**

Run:

```console
cargo test --locked --test linux_harness_contract
STYRN_TEST_NATIVE_SYSTEMD=1 scripts/test-linux-arm64-cargo.sh test-filter native_linux_systemd_
```

Expected: workflow contract PASS; only the explicitly provisioned systemd filter runs. Plain `cargo test --locked` leaves every other native gate ignored, and `unavailable-gates.json` lists its exact prerequisite.

- [ ] **Step 5: Commit**

Commit: `Schedule native ARM64 Linux verification`

### Task 12: Generalize Linux account policy independently of distro logic

**Files:**

- Modify: `src/platform/linux.rs`
- Modify: `src/platform/mod.rs`
- Modify: `docs/design.md`
- Modify: `docs/implementation-plan.md`

- [ ] **Step 1: Add identity-policy regression tests**

Cover legitimate native NSS users with UID below 1000, non-`/home` homes, non-Bash interactive shells, directory-service names, and sudo-origin identity agreement. A low UID/nonstandard home is accepted only with all affirmative proofs: UID is nonzero, account is not a known daemon/service identity, primary/supplementary groups confer no administrator authority, the shell is executable and not nologin/false, the home is unique to the account and securely owned, NSS UID↔name↔GID round trips agree, and sudo origin agrees exactly. Negative cases remain root, daemon/service/nologin/shared-home accounts, admin groups/capability posture, mismatched UID/GID/name, unsafe home, noncanonical IDs, and ambiguous names. Distribution metadata must not influence identity acceptance.

- [ ] **Step 2: Run red tests**

Run: `scripts/test-linux-arm64-cargo.sh test-filter platform::linux::tests::account_policy_`

Expected: at least the low-UID/nonstandard-home/shell cases FAIL under existing assumptions.

- [ ] **Step 3: Replace convention checks with native identity proofs**

Use the affirmative proofs above rather than numeric/path/shell conventions alone. Retain current-user no-root behavior and exact sudo-origin agreement. Do not require an account named `styrn` or infer policy from distro family.

- [ ] **Step 4: Verify**

Run:

```console
scripts/test-linux-arm64-cargo.sh test-filter platform::linux::tests::account_policy_
scripts/test-linux-arm64-cargo.sh test-filter platform::tests::unix_
```

Expected: legitimate identities PASS; all mismatch/unsafe-path cases remain rejected.

- [ ] **Step 5: Commit**

Commit: `Generalize native Linux account identity checks`

### Task 13: Update public status and run full verification

**Files:**

- Modify: `README.md`
- Modify: any files above only for defects revealed by verification

- [ ] **Step 1: Update README to the implemented truth**

Document supported Debian/Red Hat/Arch family detection, stock package action coverage, dependency-scoped degradation on Other/non-systemd systems, WSL rejection, native ARM64 container coverage, and every unavailable real-host gate. Distinguish component package backends from Styrn binary install channels.

- [ ] **Step 2: Run source/privacy/schema/security searches**

Run:

```console
rg -n -- "pacman.*-Sy|-Sy.*pacman|WSL_DISTRO_NAME|WSL_INTEROP|Command::new\([^)]*apt|Command::new\([^)]*dnf|Command::new\([^)]*pacman" src tests
cargo test --locked --test platform_boundary
cargo test --locked --test schema_examples
cargo test --locked --test linux_design_contract
cargo test --locked --test linux_harness_contract
```

Expected: no unsafe production authority or forbidden command; all contracts PASS.

- [ ] **Step 3: Run the required local gates**

Run:

```console
cargo fmt --all -- --check
cargo build --locked
cargo test --locked
cargo clippy --workspace --all-targets --all-features -- -D warnings
git diff --check
```

Expected: all new tests PASS. Record separately any pre-existing failures with exact names and confirm they are unchanged from the baseline.

- [ ] **Step 4: Run native affected-platform gates**

Run the ARM64 Podman harness, then every provisioned ignored real-VM test. Confirm the existing macOS native suite and the repository's Windows CI status; never substitute cross-compilation for native validation.

- [ ] **Step 5: Inspect scope and commit documentation**

Run:

```console
git status --short
git diff --stat
git diff --check
```

Verify no other-contributor file was staged or overwritten.

Commit: `Document native Linux host support`

- [ ] **Step 6: Request code review and resolve findings**

Use `superpowers:requesting-code-review`; review against design revision I, exact negative outcomes, receipt recovery, platform privacy, and truthful native-gate evidence. Apply review feedback with `superpowers:receiving-code-review`, rerun affected gates, and only then report completion.
