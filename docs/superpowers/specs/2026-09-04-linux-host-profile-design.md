# Native Linux host profiles and distribution adaptation

Status: approved supporting design; canonical contracts incorporated into
`docs/design.md` revision I on 2026-09-04.

## Purpose

Styrn must adapt safely to native Linux distributions in the Debian, Red Hat,
and Arch families without teaching generic code about distro-specific commands.
The first supported package backends are `apt-get`, DNF (`dnf` or `dnf5`), and `pacman`.
Systemd is the only service backend in this first slice. Omarchy is treated as
an Arch-family system. WSL is detected only so Styrn can reject it; it is not a
platform backend.

This design extends the native-platform and probe contracts in
`docs/design.md` Parts 15.2, 15.5–15.7, and 16. It keeps Podman and container
images in the test harness and adds no container dependency to Styrn itself.

## Scope

The work has four related outcomes:

1. A private Linux host profile identifies whether the kernel is native Linux
   or WSL, parses bounded distro metadata, and observes package and service
   capabilities independently.
2. Existing Linux probes and setup planning consume typed capabilities instead
   of assuming Ubuntu and `/usr/bin/systemctl` everywhere.
3. Package-backed actions choose a closed backend-specific executable, package
   name, and argument vector. No raw distro value becomes a command or URL.
4. Deterministic parser tests and native ARM64 Podman gates cover the supported
   families while real service lifecycle tests remain VM/host gates.

The first slice does not add OpenRC, runit, s6, or another service backend. A
native non-systemd host remains useful for portable/rootless operations, but a
system-service action becomes an explicit unsupported capability or
`NeedsHuman`; Styrn never pretends the action succeeded.

The first slice also does not add RPM, Pacman, or DNF as channels for installing
or upgrading the Styrn binary. Part 15.14's `[install].channel` records how
Styrn itself arrived and is separate from the package backend used to provision
components.

## Architecture

All new OS mechanics remain private to the Linux platform adapter. Generic
setup code receives only closed capability results or existing sanitized probe
snapshots.

```rust
enum LinuxDisposition {
    Native(LinuxHostProfile),
    UnsupportedWsl,
    Unknowable(LinuxObservationError),
}

struct LinuxHostProfile {
    distribution: LinuxCapability<LinuxDistribution>,
    package_backend: LinuxCapability<LinuxPackageBackend>,
    system_service_backend: LinuxCapability<LinuxServiceBackend>,
    user_service_backend: LinuxCapability<LinuxUserServiceBackend>,
}

enum LinuxFamily {
    Debian,
    RedHat,
    Arch,
    Other,
}

enum LinuxPackageBackend {
    AptGet {
        apt_get: LinuxExecutableIdentity,
        dpkg_query: LinuxExecutableIdentity,
    },
    Dnf { executable: LinuxExecutableIdentity },
    Pacman { executable: LinuxExecutableIdentity },
}

enum LinuxServiceBackend {
    Systemd { executable: VerifiedExecutable },
}

enum LinuxCapability<T> {
    Available(T),
    Unsupported,
    Unknowable(LinuxObservationError),
}

struct LinuxExecutableIdentity {
    canonical_path: PathBuf,
    device: u64,
    inode: u64,
    owner_uid: u32,
    file_type: FileType,
    mode: u32,
    size: u64,
    modified_at: SystemTime,
    changed_at: SystemTime,
}
```

`LinuxDistribution` retains bounded `ID`, `ID_LIKE`, and `VERSION_ID` values
for classification and diagnostics. It is not serialized into the machine
manifest or RPC protocol in this slice. The capability types carry verified
fixed paths, not executable names resolved through `PATH`.

Only inability to distinguish native Linux from WSL is globally blocking.
Distribution, package, system-service, and user-service evidence are separate
`LinuxCapability` values and degrade independently: a failure to classify the
distribution does not erase already proved service evidence, and unavailable
user services do not disable portable/rootless work.

Every `LinuxExecutableIdentity` contains canonical path, device, inode, owner
UID, file type, mode, size, and modification/change timestamps. It is compared
against a fresh handle-derived identity immediately before every mutation; any
change is `Unknowable` and stops that dependent action.

The profile should live in a small private child module owned by
`src/platform/linux.rs`, such as `src/platform/linux/host.rs`. Package command
construction may later move to `src/platform/linux/packages.rs`; the public
platform boundary remains `src/platform/mod.rs`.

## Detection flow

### 1. Reject WSL before distro classification

The adapter obtains the kernel release through `uname(2)`, not a shell command.
A case-insensitive `microsoft` marker in the kernel release is conclusive WSL.
The kernel-owned `/proc/sys/fs/binfmt_misc/WSLInterop` entry, when present, is
also conclusive. Caller-controlled `WSL_*` environment variables are ignored:
they may be recorded by a diagnostic test, but they can neither select a
backend nor force a production authorization decision.

Conclusive WSL produces `LinuxDisposition::UnsupportedWsl`. Every local
`styrn setup` mode, including apply and `--dry-run`, and worker eligibility fail
before creating a manifest, receipt, intent, lock, or action with exit 13 and
`setup.unsupported_os`, explaining that native Windows or native Linux is
required. Help, version, and controller-side rendering remain available because
they do not make this host a worker or rely on native Linux mutations.

An unreadable kernel observation is `Unknowable`, not native by default.

### 2. Read and parse `os-release`

The production reader uses fixed paths:

1. `/etc/os-release`;
2. `/usr/lib/os-release` only when opening the first path returns `ENOENT`.

It never combines the files and never sources either file through a shell. The
reader accepts the standard relative symlink arrangement only when the final
target is a regular, root-owned file whose target and directory chain are not
group/world writable. It rejects special files, unsafe links, oversized input,
NUL bytes, non-UTF-8 input, and replacement detected across inspection/read.
The byte limit is 16 KiB.

The parser implements only the `os-release` assignment grammar needed to read
values safely: comments, blank lines, unquoted values, single/double quotes,
and only the exact `\\`, `\"`, `\'`, `\$`, and ``\` `` backslash escapes. It
performs no expansion, substitution, or execution. The reader accepts at most
16 KiB for the whole file and at most 255 bytes for each classification field.
`ID` and each `ID_LIKE` token must be ASCII and match `[a-z0-9._-]+`.
Duplicate classification keys, unterminated quoting, invalid key syntax,
unknown escapes, and invalid `ID`/`ID_LIKE` tokens make distribution evidence
`Unknowable`. Unknown unrelated keys are ignored.

Classification gives exact `ID` authority and consults ordered `ID_LIKE`
ancestry only for an otherwise unknown exact ID:

- Debian family: `debian`, `ubuntu`, or a derivative whose `ID_LIKE` contains
  `debian`;
- Red Hat family: `fedora`, `rhel`, `centos`, or a derivative whose
  `ID_LIKE` contains one of those identifiers;
- Arch family: `arch`, `omarchy`, or a derivative whose `ID_LIKE` contains
  `arch`;
- otherwise `Other`.

An exact supported-family ID combined with contradictory cross-family
`ID_LIKE`, or ancestry that names more than one supported family, is
`Unknowable`; ancestry never overrides the exact ID. Omarchy must work both
when it exposes ordinary Arch metadata and if it later exposes `ID=omarchy`
with `ID_LIKE=arch`.

### 3. Corroborate package capabilities

Distro identity narrows the allowed backend; it never proves the backend is
usable. The adapter then inspects only closed absolute candidates:

- Debian: both `/usr/bin/apt-get` and `/usr/bin/dpkg-query`;
- Red Hat: `/usr/bin/dnf`, with `/usr/bin/dnf5` as a separately recognized
  implementation when the canonical `dnf` entry is absent;
- Arch: `/usr/bin/pacman`.

A package capability is available only when every executable required by its
backend is verified, so apt requires both `apt-get` and `dpkg-query`. A
candidate must resolve to a regular executable with a secure root-owned
path/target chain. A caller-controlled `PATH`, alias, wrapper in a home
directory, or unrelated installed package manager is ignored. If the expected
backend is absent, the capability is `Unsupported`. Conflicting or unsafe
evidence is `Unknowable`. Styrn never switches a Fedora-family host to apt or a
Debian-family host to DNF merely because that binary happens to be installed.

An `Other` family does not receive an automatic privileged package action in
this slice. Portable verified downloads and unrelated rootless work remain
available; package provisioning becomes a precise `NeedsHuman`. Adding a new
family later means adding one family mapping, backend implementation, closed
package table, fixtures, and a truthful native gate.

### 4. Detect the service backend independently

The system-service systemd capability is available only when all of these
observations agree:

- `/run/systemd/system` is a directory;
- `/usr/bin/systemctl` is a verified executable;
- `/usr/bin/systemctl show --property=Version --value` succeeds and returns a
  nonempty single bounded UTF-8 line.

The existing strict `systemctl is-active`/`is-enabled` state parsers remain the
boundary for unit observations. An installed `systemctl` in a container or on
a non-systemd host is not sufficient. Operational errors, malformed state,
and status/state contradictions remain `Unknowable` under Part 15.2.1.

System and user service capabilities are separate because a running system
manager does not prove that the current user's manager or login session is
available. The user-manager query has the same `show --property=Version
--value` shape, uses `--user`, and runs only under the recovered original-user
token, never the elevated identity or a reconstructed environment.
User-service persistence and linger remain real-host gates.

## Package actions

The generic planner requests a closed component, not a package name. The Linux
adapter maps that component to a backend-specific package identifier and exact
argv. Backend implementations never accept arbitrary package strings.

The stock-repository component table is closed and exact:

| Component | apt | DNF | Pacman |
|---|---|---|---|
| SSH | `openssh-server` | `openssh-server` | `openssh` |
| Git | `git` | `git` | `git` |
| Cockpit | `cockpit` | `cockpit` | unsupported |
| Tailscale | unsupported | unsupported | unsupported |

Tailscale package provisioning remains unsupported until a separately
specified vendor-repository action defines the repository URL, signing key,
supported distribution/version set, rollback, and receipt effect. The fact
that some distribution or third-party repository happens to contain a package
does not extend this table. Likewise, the Pacman decision for Cockpit is an
explicit v1 support boundary, not a claim that no Arch package exists.

Initial install command shapes are:

- apt: `/usr/bin/apt-get install -y <closed-package>` with the existing
  noninteractive environment contract;
- DNF: the verified DNF executable with `install -y <closed-package>`;
- Pacman: `/usr/bin/pacman -S --needed --noconfirm <closed-package>`.

Styrn must never emit `pacman -Sy <package>` because Arch partial upgrades are
unsupported. Refreshing or upgrading the whole system is a distinct broad
action that is not authorized by a component-install request. Vendor repository
configuration, URLs, signing keys, package identifiers, and supported distro
versions stay in a compiled closed table and must satisfy Part 15.7.6's
supply-chain bar.

Each action records the selected backend, verified executable identity, closed
component/package identifier, scope, and finalized receipt effect. Recovery
replays the typed action; it never stores or reconstructs a raw shell command.

Installed-state queries are equally closed: apt uses `/usr/bin/dpkg-query
--show --showformat=${Status} <package>` and accepts only the exact installed
status; DNF uses the verified DNF executable with `list --installed <package>`;
Pacman uses `/usr/bin/pacman -Q <package>`. Exit/output contradictions,
malformed output, or a query executable whose identity changed are
`Unknowable`, never absent.

## Probe and planning behavior

The host profile is captured once during setup preflight and bound to the setup
execution context. It is revalidated before any privileged package or service
mutation. Backend or executable drift stops before mutation.

Privilege approval returns a non-cloneable, non-serializable, lifetime-bound
authorization capability. It is structurally bound to the request digest,
privilege, exact parameters, and expected effect. The privileged runner accepts
the capability plus its typed action, revalidates both profile and
`LinuxExecutableIdentity`, consumes the capability once, and cannot accept an arbitrary argv,
package, path, URL, or caller-constructed token.

Existing Linux SSH, Tailscale, and sleep-policy probes consume the system
service capability. Existing Git/tool probes remain executable probes, but
their remediation plan uses the package capability when a verified user/direct
channel is unavailable. This provides an immediate consumer for the profile
instead of leaving an unused detector abstraction.

Outcomes are closed and fail-safe:

- WSL: `setup.unsupported_os`, exit 13, no partial state;
- observation failure or contradictory evidence: `Unknowable`; only an action
  that requires that evidence becomes `setup.probe_failed`, exit 13, before
  mutation, while independent capabilities and actions continue;
- conclusively unsupported package/service backend: unrelated rootless actions
  continue and only the dependent system action becomes `NeedsHuman`;
- package-manager failure after authorization: `setup.apply_failed`, exit 13,
  preserving only the durable acknowledged receipt prefix.

`--yes` does not consent to privilege, select a guessed backend, or convert
`NeedsHuman` into success.

## Test strategy

### Pure and boundary tests

TDD starts with byte fixtures under `tests/fixtures/linux-host/` for:

- Ubuntu and Debian -> Debian/apt;
- Fedora, RHEL, Rocky/Alma/Oracle-style ancestry -> Red Hat/DNF;
- Arch, current Omarchy-as-Arch, and future `omarchy`/`ID_LIKE=arch` ->
  Arch/Pacman;
- unknown valid distro -> `Other` with no automatic package backend;
- `/etc` precedence over `/usr/lib`;
- WSL1 and WSL2 kernel releases overriding Ubuntu-looking metadata;
- malformed quoting, duplicate classification keys, invalid UTF-8, NUL,
  oversize input, cross-family ancestry, unsafe file types/links/permissions,
  and inspection/read replacement;
- correct family with missing, unsafe, or contradictory manager evidence;
- fake managers earlier in `PATH` and multiple unrelated installed managers.

Fake-executor tests assert exact executable, argv, sanitized environment,
privilege, receipt effect, typed exit/error, and absence of partial state. WSL
integration tests assert exactly one JSON envelope, exit 13,
`setup.unsupported_os`, and no manifest, receipt, pending intent, or action.

### ARM64 Podman matrix

Podman is a test harness only. Every matrix run verifies all four facts rather
than trusting `--platform` alone:

1. Podman machine architecture is `arm64`;
2. the selected image manifest contains `linux/arm64`;
3. `uname -m` inside the container is `aarch64`;
4. the Styrn test binary reports the AArch64 target.

The initial matrix uses pinned image digests for Ubuntu 24.04, Debian Bookworm,
a stable Fedora image, and Red Hat UBI 9 after manifest inspection. Arch-family
coverage uses an internally built image from a checksummed Arch Linux ARM
rootfs; mutable third-party `latest` images are not accepted. Omarchy receives
deterministic Arch-family fixtures plus a real ARM64 host/VM gate when such a
host is available. Until that gate runs, the handoff reports it as unavailable,
not passed.

Build Styrn once with the pinned Rust 1.98.0 toolchain in a native ARM64 builder
and copy the binary/test harness into distro images. Run as a mapped non-root
UID with read-only source and a native Linux writable volume. Do not grant
privileged mode, host sockets, or TUN for parser/package planning tests.

Containers truthfully cover distro metadata, backend discovery, pure planning,
package query/dry-run behavior, rootless XDG behavior, and native Linux
filesystem/ACL semantics. Containers do not certify service lifecycle. A real
systemd VM/host is still required for service
enable/start, user managers, linger/logout/reboot persistence, sshd login,
Tailscale TUN, sleep policy, sudo handoff, and dedicated-account acceptance.

### CI

The existing Ubuntu/macOS/Windows CI matrix remains mandatory. Parser,
classifier, fake-executor, and WSL-refusal tests run on every PR. The ARM64
distro harness initially runs locally and on any available Apple-Silicon
self-hosted runner; it must not be represented by x86 emulation. Real package
transactions can run scheduled against disposable images. Real VM service
gates run scheduled/release and report unavailable prerequisites honestly.

## Documentation, phases, and compatibility

Revision I of canonical `docs/design.md` owns **Linux host profile, WSL refusal,
and package-backend adaptation** in Part 16.3 Phase 0. Its synchronized contract
is:

- Part 15.2.1: replace the apt-only backend list with the typed Linux host
  profile and capability rules;
- Parts 15.7.2 and 15.7.4-15.7.6: define family-specific package handling,
  systemd-first service behavior, WSL rejection, and exact failure semantics;
- Part 16.3 Phase 0: place host profiling, backend probes, and baseline package
  adaptation exactly once;
- Part 16.6: add the truthful distro/ARM64 and WSL-rejection gates;
- Part 15.14 remains limited to its schema-backed Styrn binary channels;
  component package backends do not extend `[install].channel`.

The implementation plan receives corresponding Phase 0 tasks and positive and
negative tests. The first vertical slice is host-profile parsing plus WSL
refusal and consumption by existing SSH/Tailscale/sleep probes. Package-backed
baseline actions follow in the same Phase 0 workstream. Linux account-policy
generalization is a separate security-sensitive Phase 0 task because current
UID/home/shell assumptions are not package-manager concerns.

No dependency or machine-schema change is required for the first slice. If a
new crate becomes necessary, Part 16.2, `Cargo.toml`, `Cargo.lock`, and the
toolchain/dependency contract tests change together. If distro/backend data is
ever serialized, schemas, examples, manifest types, and protocol documentation
must change atomically; the default is to keep the profile private.

## Alternatives considered

### Distro strategy objects

One object per Ubuntu/Fedora/Arch derivative is simpler initially, but it
couples package, service, and account assumptions and grows a brittle list of
brand names. A derivative can carry a familiar label while changing one
backend. Rejected.

### Universal direct downloads

Static verified downloads avoid package-manager differences, but make Styrn
own update and service integration that native signed channels already handle.
They remain a scoped fallback under Part 15.7.6, not the primary design.

### Capability-first composite profile

The selected approach treats distro metadata as a bounded classification hint
and separately proves every executable/service capability before use. It costs
more typed states and tests, but handles derivatives safely, keeps generic code
portable, and extends one backend at a time without weakening security.
