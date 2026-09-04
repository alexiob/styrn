use super::{
    ManifestOwner, PrincipalKind, PrivateFileIdentity, SetupExecutionContext, SetupHostPrivilege,
    UnixCallerIds, WorkerAccountPolicy, WorkerPrincipal,
};
use std::ffi::{c_void, CString, OsString};
use std::fs;
use std::io::{self, Read};
use std::os::fd::{AsRawFd, FromRawFd};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::ffi::OsStringExt;
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt};
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};

use sha2::{Digest, Sha256};

#[allow(dead_code)] // Source-inclusion tests omit current-user SSH setup actions.
pub(super) fn current_user_ssh_directory() -> io::Result<PathBuf> {
    let account =
        account_details_for_uid(unsafe { libc::getuid() }, WorkerAccountPolicy::CurrentUser)?;
    Ok(PathBuf::from(account.home).join(".ssh"))
}

#[allow(dead_code)] // Source-inclusion contract tests omit enrollment-card discovery.
pub(super) fn native_ssh_keyscan_path() -> PathBuf {
    PathBuf::from("/usr/bin/ssh-keyscan")
}

pub(super) fn baseline_probe_snapshot(
    kind: super::BaselineProbeKind,
    authorized_public_keys: &[String],
    tailscale_mode: &str,
) -> super::BaselineProbeSnapshot {
    match kind {
        super::BaselineProbeKind::SshServer => ssh_server_snapshot(authorized_public_keys, true),
        super::BaselineProbeKind::Tailscale => tailscale_snapshot(tailscale_mode),
        super::BaselineProbeKind::Git => git_snapshot(),
        super::BaselineProbeKind::SleepPolicy => sleep_snapshot(),
        super::BaselineProbeKind::Styrnd | super::BaselineProbeKind::Deferred => {
            super::BaselineProbeSnapshot::Unknowable
        }
    }
}

pub(super) fn ssh_server_transport_snapshot() -> super::BaselineProbeSnapshot {
    ssh_server_snapshot(&[], false)
}

fn ssh_server_snapshot(
    authorized_public_keys: &[String],
    require_authorized_keys: bool,
) -> super::BaselineProbeSnapshot {
    let sshd = Path::new("/usr/sbin/sshd");
    if !sshd.is_file() {
        return super::BaselineProbeSnapshot::Absent;
    }
    let service = match super::run_fixed_baseline_command(
        Path::new("/bin/launchctl"),
        &["print", "system/com.openssh.sshd"],
    ) {
        Ok(output) => output.success,
        Err(_) => return super::BaselineProbeSnapshot::Unknowable,
    };
    let account = match account_details_for_uid(
        unsafe { libc::getuid() },
        WorkerAccountPolicy::CurrentUser,
    ) {
        Ok(account) => account,
        Err(_) => return super::BaselineProbeSnapshot::Unknowable,
    };
    let match_context = format!(
        "user={},host=localhost,addr=127.0.0.1",
        account.principal.name()
    );
    let config = match super::run_fixed_baseline_command(sshd, &["-T", "-C", &match_context]) {
        Ok(output) if output.success => super::parse_effective_sshd_config(&output.stdout),
        Ok(_) | Err(_) => return super::BaselineProbeSnapshot::Unknowable,
    };
    let Some(config) = config else {
        return super::BaselineProbeSnapshot::Unknowable;
    };
    let transport_healthy = service && config.public_key_authentication();
    if !require_authorized_keys {
        return super::BaselineProbeSnapshot::Present {
            version: None,
            healthy: transport_healthy,
        };
    }
    let home = PathBuf::from(account.home);
    super::BaselineProbeSnapshot::Present {
        version: None,
        healthy: transport_healthy
            && authorized_keys_are_ready(
                &home,
                unsafe { libc::getuid() },
                config.authorized_keys_files(),
                authorized_public_keys,
            ),
    }
}

fn tailscale_snapshot(requested_mode: &str) -> super::BaselineProbeSnapshot {
    let daemon_program = [
        Path::new("/opt/homebrew/bin/tailscale"),
        Path::new("/usr/local/bin/tailscale"),
    ]
    .into_iter()
    .find(|path| path.is_file());
    let gui_program = Path::new("/Applications/Tailscale.app/Contents/MacOS/Tailscale")
        .is_file()
        .then_some(Path::new(
            "/Applications/Tailscale.app/Contents/MacOS/Tailscale",
        ));
    let gui_persistent = tailscale_service_is_persistent(super::BaselineTailscaleMode::Gui);
    let daemon_persistent =
        tailscale_service_is_persistent(super::BaselineTailscaleMode::Tailscaled);
    let (mode, persistent) = match select_tailscale_mode(
        daemon_program.is_some(),
        gui_program.is_some(),
        daemon_persistent,
        gui_persistent,
    ) {
        Some(selection) => selection,
        None if daemon_program.is_none() && gui_program.is_none() => {
            return super::BaselineProbeSnapshot::Absent;
        }
        None => return super::BaselineProbeSnapshot::Unknowable,
    };
    let (program, unattended, environment): (&Path, bool, &[(&str, &str)]) = match mode {
        super::BaselineTailscaleMode::Tailscaled => (daemon_program.unwrap(), true, &[]),
        super::BaselineTailscaleMode::Gui => {
            (gui_program.unwrap(), false, &[("TAILSCALE_BE_CLI", "1")])
        }
        super::BaselineTailscaleMode::Service => unreachable!(),
    };
    match super::run_fixed_baseline_command_with_env(program, &["status", "--json"], environment) {
        Ok(output) if output.success => {
            parse_tailscale_status(&output.stdout, mode, persistent, unattended, requested_mode)
                .unwrap_or(super::BaselineProbeSnapshot::Unknowable)
        }
        Ok(_) => super::BaselineProbeSnapshot::Unknowable,
        Err(_) => super::BaselineProbeSnapshot::Unknowable,
    }
}

fn select_tailscale_mode(
    daemon_present: bool,
    gui_present: bool,
    daemon_persistent: bool,
    gui_persistent: bool,
) -> Option<(super::BaselineTailscaleMode, bool)> {
    use super::BaselineTailscaleMode::{Gui, Tailscaled};

    match (daemon_present, gui_present) {
        (false, false) => None,
        (true, false) => Some((Tailscaled, daemon_persistent)),
        (false, true) => Some((Gui, gui_persistent)),
        (true, true) => match (daemon_persistent, gui_persistent) {
            (false, true) => Some((Gui, true)),
            (true, false) => Some((Tailscaled, true)),
            (false, false) | (true, true) => None,
        },
    }
}

fn tailscale_service_is_persistent(mode: super::BaselineTailscaleMode) -> bool {
    let uid = unsafe { libc::getuid() };
    let labels = match mode {
        super::BaselineTailscaleMode::Gui => vec![
            format!("gui/{uid}/io.tailscale.ipn.macsys"),
            format!("gui/{uid}/io.tailscale.ipn.macos"),
        ],
        super::BaselineTailscaleMode::Tailscaled => vec![
            "system/com.tailscale.tailscaled".to_owned(),
            "system/homebrew.mxcl.tailscale".to_owned(),
        ],
        super::BaselineTailscaleMode::Service => return false,
    };
    labels.iter().any(|label| {
        super::run_fixed_baseline_command(Path::new("/bin/launchctl"), &["print", label])
            .is_ok_and(|output| output.success)
    })
}

fn git_snapshot() -> super::BaselineProbeSnapshot {
    let (program, arguments) = git_invocation();
    if !program.is_file() {
        return super::BaselineProbeSnapshot::Absent;
    }
    match super::run_fixed_baseline_command(program, &arguments) {
        Ok(output) if output.success => parse_git_version(&output.stdout)
            .map(|version| super::BaselineProbeSnapshot::Present {
                version: Some(version),
                healthy: true,
            })
            .unwrap_or(super::BaselineProbeSnapshot::Unknowable),
        Ok(_) => super::BaselineProbeSnapshot::Broken,
        Err(_) => super::BaselineProbeSnapshot::Unknowable,
    }
}

fn sleep_snapshot() -> super::BaselineProbeSnapshot {
    match super::run_fixed_baseline_command(Path::new("/usr/bin/pmset"), &["-g", "custom"]) {
        Ok(output) if output.success => parse_sleep_posture(&output.stdout)
            .map(|healthy| super::BaselineProbeSnapshot::Present {
                version: None,
                healthy,
            })
            .unwrap_or(super::BaselineProbeSnapshot::Unknowable),
        Ok(_) | Err(_) => super::BaselineProbeSnapshot::Unknowable,
    }
}

fn git_invocation() -> (&'static Path, [&'static str; 1]) {
    (Path::new("/usr/bin/git"), ["--version"])
}

fn parse_git_version(bytes: &[u8]) -> Option<String> {
    if bytes.len() > 256 {
        return None;
    }
    let output = std::str::from_utf8(bytes).ok()?.trim();
    let version = output.strip_prefix("git version ")?;
    (!version.is_empty()
        && version.len() <= 96
        && version.bytes().all(|byte| {
            byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-' | b'+' | b'(' | b')' | b' ')
        }))
    .then(|| version.to_owned())
}

fn parse_tailscale_status(
    bytes: &[u8],
    mode: super::BaselineTailscaleMode,
    persistent: bool,
    unattended: bool,
    requested_mode: &str,
) -> Option<super::BaselineProbeSnapshot> {
    super::tailscale_status_snapshot(
        bytes,
        mode,
        persistent,
        unattended,
        requested_mode,
        super::BaselineTailscaleMode::Gui,
    )
}

fn parse_sleep_posture(bytes: &[u8]) -> Option<bool> {
    let output = std::str::from_utf8(bytes).ok()?;
    let mut section_count = 0_usize;
    let mut sleep_values = Vec::new();
    let mut section_has_sleep = false;
    for line in output.lines() {
        let trimmed = line.trim();
        if trimmed.ends_with(" Power:") {
            if section_count != 0 && !section_has_sleep {
                return None;
            }
            section_count += 1;
            section_has_sleep = false;
            continue;
        }
        let mut fields = trimmed.split_ascii_whitespace();
        if fields.next() == Some("sleep") {
            if section_count == 0 || section_has_sleep {
                return None;
            }
            let value = fields.next()?;
            if fields.next().is_some() || !value.bytes().all(|byte| byte.is_ascii_digit()) {
                return None;
            }
            sleep_values.push(value == "0");
            section_has_sleep = true;
        }
    }
    (section_count != 0 && section_has_sleep && sleep_values.len() == section_count)
        .then(|| sleep_values.into_iter().all(|value| value))
}

fn authorized_keys_are_ready(
    home: &Path,
    uid: u32,
    configured: &[String],
    required: &[String],
) -> bool {
    let Ok(home_metadata) = fs::symlink_metadata(home) else {
        return false;
    };
    if !secure_ssh_path_metadata(&home_metadata, uid, true) {
        return false;
    }
    let ssh = home.join(".ssh");
    let Ok(ssh_metadata) = fs::symlink_metadata(&ssh) else {
        return false;
    };
    if !secure_ssh_path_metadata(&ssh_metadata, uid, true) {
        return false;
    }
    configured.iter().any(|configured| {
        let Some(path) = canonical_authorized_keys_path(home, configured) else {
            return false;
        };
        authorized_keys_file_is_ready(&path, uid, required)
    })
}

fn canonical_authorized_keys_path(home: &Path, configured: &str) -> Option<PathBuf> {
    let relative = configured
        .strip_prefix("%h/")
        .or_else(|| configured.strip_prefix("./"))
        .unwrap_or(configured);
    if !matches!(relative, ".ssh/authorized_keys" | ".ssh/authorized_keys2") {
        return None;
    }
    Some(home.join(relative))
}

fn authorized_keys_file_is_ready(path: &Path, uid: u32, required: &[String]) -> bool {
    let Ok(mut file) = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)
    else {
        return false;
    };
    let Ok(metadata) = file.metadata() else {
        return false;
    };
    if !secure_ssh_path_metadata(&metadata, uid, false) || metadata.len() > 1024 * 1024 {
        return false;
    }
    let mut bytes = Vec::with_capacity(metadata.len() as usize);
    if std::io::Read::by_ref(&mut file)
        .take(1024 * 1024 + 1)
        .read_to_end(&mut bytes)
        .is_err()
        || bytes.len() > 1024 * 1024
    {
        return false;
    }
    let Ok(contents) = std::str::from_utf8(&bytes) else {
        return false;
    };
    let keys = contents
        .lines()
        .map(str::trim)
        .filter_map(super::parse_authorized_key_line)
        .collect::<Vec<_>>();
    if required.is_empty() {
        !keys.is_empty()
    } else {
        required.iter().all(|required| {
            super::parse_authorized_key_line(required)
                .is_some_and(|required| keys.contains(&required))
        })
    }
}

fn secure_ssh_path_metadata(metadata: &fs::Metadata, uid: u32, directory: bool) -> bool {
    !metadata.file_type().is_symlink()
        && if directory {
            metadata.is_dir()
        } else {
            metadata.is_file()
        }
        && matches!(metadata.uid(), owner if owner == uid || owner == 0)
        && metadata.mode() & 0o022 == 0
}

#[cfg(test)]
mod baseline_probe_tests {
    use super::super::{
        run_baseline_readonly_command, BaselineCommandFailure, BaselineProbeKind,
        BaselineProbeSnapshot,
    };
    use super::{
        authorized_keys_are_ready, git_invocation, parse_git_version, parse_sleep_posture,
        parse_tailscale_status, select_tailscale_mode,
    };
    use std::fs;
    use std::os::unix::fs::PermissionsExt;
    use std::path::Path;
    use std::time::{Duration, Instant};

    #[test]
    fn baseline_probe_timeout_kills_and_reaps_child_without_partial_output() {
        let started = Instant::now();
        let error = run_baseline_readonly_command(
            Path::new("/usr/bin/tail"),
            &["-f", "/dev/null"],
            Duration::from_millis(40),
        )
        .unwrap_err();

        assert_eq!(error, BaselineCommandFailure::TimedOut);
        assert!(started.elapsed() < Duration::from_secs(2));
    }

    #[test]
    fn rootless_ssh_probe_never_uses_shared_admin_keys_or_mutates_user_or_machine_state() {
        let home = std::env::temp_dir().join(format!(
            "styrn-baseline-ssh-{}-{}",
            std::process::id(),
            uuid::Uuid::now_v7()
        ));
        fs::create_dir(&home).unwrap();
        let shared = home.join("administrators_authorized_keys");
        let key = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIE9Hc3R5cm5UZXN0S2V5T25seQ test";
        fs::write(&shared, format!("{key}\n")).unwrap();
        let before = fs::read(&shared).unwrap();

        assert!(!authorized_keys_are_ready(
            &home,
            unsafe { libc::getuid() },
            &[".ssh/authorized_keys".to_owned()],
            &[],
        ));
        assert_eq!(fs::read(&shared).unwrap(), before);
        assert!(!home.join(".ssh").exists());

        fs::remove_dir_all(home).unwrap();
    }

    #[test]
    fn rootless_ssh_probe_requires_secure_modes_and_valid_openssh_key_blobs() {
        let home = std::env::temp_dir().join(format!(
            "styrn-baseline-ssh-security-{}-{}",
            std::process::id(),
            uuid::Uuid::now_v7()
        ));
        let ssh = home.join(".ssh");
        fs::create_dir_all(&ssh).unwrap();
        fs::set_permissions(&home, fs::Permissions::from_mode(0o700)).unwrap();
        fs::set_permissions(&ssh, fs::Permissions::from_mode(0o700)).unwrap();
        let authorized_keys = ssh.join("authorized_keys");
        let valid = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIAABAgMEBQYHCAkKCwwNDg8QERITFBUWFxgZGhscHR4f fixture";
        fs::write(&authorized_keys, format!("{valid}\n")).unwrap();
        fs::set_permissions(&authorized_keys, fs::Permissions::from_mode(0o600)).unwrap();
        let configured = [".ssh/authorized_keys".to_owned()];

        assert!(authorized_keys_are_ready(
            &home,
            unsafe { libc::getuid() },
            &configured,
            &[valid.to_owned()],
        ));

        fs::set_permissions(&authorized_keys, fs::Permissions::from_mode(0o666)).unwrap();
        assert!(!authorized_keys_are_ready(
            &home,
            unsafe { libc::getuid() },
            &configured,
            &[],
        ));

        fs::set_permissions(&authorized_keys, fs::Permissions::from_mode(0o600)).unwrap();
        fs::write(
            &authorized_keys,
            "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIE9Hc3R5cm5UZXN0S2V5T25seQ malformed\n",
        )
        .unwrap();
        assert!(!authorized_keys_are_ready(
            &home,
            unsafe { libc::getuid() },
            &configured,
            &[],
        ));

        fs::remove_dir_all(home).unwrap();
    }

    #[test]
    fn tailscale_probe_discards_raw_identity_address_login_and_error_output() {
        let raw = br#"{"BackendState":"Running","Self":{"Online":true,"HostName":"private-node","TailscaleIPs":["100.64.0.1"]},"AuthURL":"https://login.example/secret"}"#;
        let status = parse_tailscale_status(
            raw,
            super::super::BaselineTailscaleMode::Gui,
            true,
            false,
            "",
        );

        assert_eq!(
            status,
            Some(BaselineProbeSnapshot::TailscalePresent {
                version: None,
                healthy: true,
                posture: super::super::BaselineTailscalePosture {
                    mode: super::super::BaselineTailscaleMode::Gui,
                    persistent: true,
                    unattended: false,
                },
            })
        );
        let rendered = format!("{status:?}");
        for secret in ["private-node", "100.64.0.1", "login.example"] {
            assert!(!rendered.contains(secret));
        }
    }

    #[test]
    fn tailscale_probe_requires_requested_mode_and_persistence_proof() {
        let raw = br#"{"BackendState":"Running","Self":{"Online":true}}"#;
        let mismatch = parse_tailscale_status(
            raw,
            super::super::BaselineTailscaleMode::Gui,
            true,
            false,
            "tailscaled",
        );
        let unpersisted = parse_tailscale_status(
            raw,
            super::super::BaselineTailscaleMode::Gui,
            false,
            false,
            "",
        );

        assert!(matches!(
            mismatch,
            Some(BaselineProbeSnapshot::TailscalePresent {
                healthy: false,
                posture: super::super::BaselineTailscalePosture {
                    mode: super::super::BaselineTailscaleMode::Gui,
                    persistent: true,
                    unattended: false,
                },
                ..
            })
        ));
        assert!(matches!(
            unpersisted,
            Some(BaselineProbeSnapshot::TailscalePresent {
                healthy: false,
                posture: super::super::BaselineTailscalePosture {
                    persistent: false,
                    ..
                },
                ..
            })
        ));
    }

    #[test]
    fn tailscale_variant_selection_uses_the_matching_launchd_service() {
        use super::super::BaselineTailscaleMode::{Gui, Tailscaled};

        assert_eq!(
            select_tailscale_mode(true, true, false, true),
            Some((Gui, true))
        );
        assert_eq!(
            select_tailscale_mode(true, true, true, false),
            Some((Tailscaled, true))
        );
        assert_eq!(select_tailscale_mode(true, true, false, false), None);
        assert_eq!(select_tailscale_mode(true, true, true, true), None);
    }

    #[test]
    fn git_probe_uses_fixed_argv_and_rejects_malformed_or_unbounded_output() {
        let (program, arguments) = git_invocation();
        assert_eq!(program, Path::new("/usr/bin/git"));
        assert_eq!(arguments, ["--version"]);
        assert_eq!(
            parse_git_version(b"git version 2.51.0\n"),
            Some("2.51.0".to_owned())
        );
        assert_eq!(
            parse_git_version(b"git version 2.50.1 (Apple Git-155)\n"),
            Some("2.50.1 (Apple Git-155)".to_owned())
        );
        assert_eq!(parse_git_version(b"git release secret\n"), None);
        assert_eq!(parse_git_version(&vec![b'1'; 65 * 1024]), None);
    }

    #[test]
    fn sleep_probe_never_guesses_healthy_when_native_state_cannot_be_proven() {
        assert_eq!(
            parse_sleep_posture(b"Battery Power:\n sleep 0\nAC Power:\n sleep 0\n"),
            Some(true)
        );
        assert_eq!(
            parse_sleep_posture(b"Battery Power:\n sleep 15\nAC Power:\n sleep 0\n"),
            Some(false)
        );
        assert_eq!(parse_sleep_posture(b"localized unknown state\n"), None);
        assert_eq!(
            parse_sleep_posture(b"Battery Power:\n sleep 0\n sleep 10\n"),
            None
        );
        assert_eq!(
            parse_sleep_posture(b"Battery Power:\n sleep 0\nAC Power:\n"),
            None
        );
    }

    #[test]
    #[ignore = "requires a disposable macOS user with running sshd and Tailscale, valid per-user authorized_keys, Git, and sleep=0"]
    fn native_rootless_baseline_positive_requires_disposable_configured_host() {
        for kind in [
            BaselineProbeKind::SshServer,
            BaselineProbeKind::Tailscale,
            BaselineProbeKind::Git,
            BaselineProbeKind::SleepPolicy,
        ] {
            assert!(matches!(
                super::baseline_probe_snapshot(kind, &[], ""),
                BaselineProbeSnapshot::Present { healthy: true, .. }
                    | BaselineProbeSnapshot::TailscalePresent { healthy: true, .. }
            ));
        }
    }

    #[test]
    #[ignore = "requires a disposable macOS user with deliberately denied, malformed, and timeout-injected native probe state"]
    fn native_rootless_baseline_negative_requires_disposable_faulted_host() {
        assert!(matches!(
            super::baseline_probe_snapshot(BaselineProbeKind::SleepPolicy, &[], ""),
            BaselineProbeSnapshot::Unknowable
        ));
    }
}

#[cfg(test)]
type PostWorkerMkdirHook = fn(i32, &std::ffi::CStr);

#[derive(Clone, Copy, Eq, PartialEq)]
enum WorkerPublicationInterruption {
    AfterProvenance,
    AfterRootOwnership,
}

#[cfg(test)]
thread_local! {
    static POST_WORKER_MKDIR_HOOK: std::cell::Cell<Option<PostWorkerMkdirHook>> = const {
        std::cell::Cell::new(None)
    };
    static WORKER_MKDIR_INTERRUPT_AFTER: std::cell::Cell<Option<usize>> = const {
        std::cell::Cell::new(None)
    };
    static WORKER_PUBLICATION_INTERRUPT: std::cell::Cell<Option<WorkerPublicationInterruption>> = const {
        std::cell::Cell::new(None)
    };
    static WORKER_RECOVERY_IDENTITY_OVERRIDE: std::cell::RefCell<Option<(Vec<u8>, super::WorkerDirectoryIdentity)>> =
        const { std::cell::RefCell::new(None) };
    static WORKER_NODE_POST_PUBLISH_FAILURE: std::cell::Cell<bool> = const {
        std::cell::Cell::new(false)
    };
    static WORKER_NODE_POST_PUBLISH_FAULT: std::cell::Cell<Option<super::WorkerNodePostPublishFault>> = const {
        std::cell::Cell::new(None)
    };
    static WORKER_NODE_PRINCIPAL_DRIFT: std::cell::Cell<bool> = const {
        std::cell::Cell::new(false)
    };
    static WORKER_PROVENANCE_RETIREMENT_FAULT: std::cell::Cell<Option<super::WorkerProvenanceRetirementFault>> = const {
        std::cell::Cell::new(None)
    };
}

#[cfg(test)]
fn set_post_worker_mkdir_hook(hook: PostWorkerMkdirHook) {
    POST_WORKER_MKDIR_HOOK.with(|slot| slot.set(Some(hook)));
}

#[cfg(test)]
fn set_worker_mkdir_interrupt_after(remaining: Option<usize>) {
    WORKER_MKDIR_INTERRUPT_AFTER.with(|slot| slot.set(remaining));
}

#[cfg(test)]
fn set_worker_publication_interrupt(interruption: Option<WorkerPublicationInterruption>) {
    WORKER_PUBLICATION_INTERRUPT.with(|slot| slot.set(interruption));
}

#[cfg(test)]
fn set_worker_recovery_identity_override(
    override_value: Option<(Vec<u8>, super::WorkerDirectoryIdentity)>,
) {
    WORKER_RECOVERY_IDENTITY_OVERRIDE.with(|slot| *slot.borrow_mut() = override_value);
}

#[cfg(test)]
pub(super) fn set_worker_node_post_publish_failure_for_test(fail: bool) {
    WORKER_NODE_POST_PUBLISH_FAILURE.with(|slot| slot.set(fail));
}

#[cfg(test)]
pub(super) fn set_worker_node_post_publish_fault_for_test(
    fault: Option<super::WorkerNodePostPublishFault>,
) {
    WORKER_NODE_POST_PUBLISH_FAULT.with(|slot| slot.set(fault));
}

#[cfg(test)]
pub(super) fn set_worker_node_principal_drift_for_test(drift: bool) {
    WORKER_NODE_PRINCIPAL_DRIFT.with(|slot| slot.set(drift));
}

#[cfg(test)]
pub(super) fn set_worker_provenance_retirement_fault_for_test(
    fault: Option<super::WorkerProvenanceRetirementFault>,
) {
    WORKER_PROVENANCE_RETIREMENT_FAULT.with(|slot| slot.set(fault));
}

#[cfg(test)]
fn fail_worker_provenance_retirement_at(
    phase: super::WorkerProvenanceRetirementFault,
) -> io::Result<()> {
    WORKER_PROVENANCE_RETIREMENT_FAULT.with(|slot| {
        if slot.get() == Some(phase) {
            slot.set(None);
            Err(io::Error::other(format!(
                "injected worker provenance retirement failure at {phase:?}"
            )))
        } else {
            Ok(())
        }
    })
}

#[cfg(test)]
fn fail_worker_node_post_publish_at(phase: super::WorkerNodePostPublishFault) -> io::Result<()> {
    WORKER_NODE_POST_PUBLISH_FAULT.with(|slot| {
        if slot.get() == Some(phase) {
            slot.set(None);
            Err(io::Error::other(format!(
                "injected worker node publication failure at {phase:?}"
            )))
        } else {
            Ok(())
        }
    })
}

fn worker_recovery_candidate_identity(
    _name: &[u8],
    directory: &std::fs::File,
) -> io::Result<super::WorkerDirectoryIdentity> {
    #[cfg(test)]
    if let Some((_, identity)) = WORKER_RECOVERY_IDENTITY_OVERRIDE.with(|slot| {
        slot.borrow()
            .as_ref()
            .filter(|(candidate, _)| candidate.as_slice() == _name)
            .cloned()
    }) {
        return Ok(identity);
    }
    worker_directory_identity(directory)
}

type Acl = *mut std::ffi::c_void;
type AclEntry = *mut std::ffi::c_void;
#[cfg(test)]
type AclPermset = *mut std::ffi::c_void;
#[cfg(test)]
type AclFlagset = *mut std::ffi::c_void;

const ACL_TYPE_EXTENDED: i32 = 0x100;
const ACL_FIRST_ENTRY: i32 = 0;
const ACL_NEXT_ENTRY: i32 = -1;
const ACL_EXTENDED_ALLOW: i32 = 1;
const ACL_EXTENDED_DENY: i32 = 2;
#[cfg(test)]
const ACL_WRITE_DATA: i32 = 1 << 2;
#[cfg(test)]
const ACL_DELETE: i32 = 1 << 4;
#[cfg(test)]
const ACL_DELETE_CHILD: i32 = 1 << 6;
#[cfg(test)]
const ACL_ENTRY_FILE_INHERIT: i32 = 1 << 5;
#[cfg(test)]
const ACL_ENTRY_DIRECTORY_INHERIT: i32 = 1 << 6;

unsafe extern "C" {
    fn renamex_np(old: *const i8, new: *const i8, flags: u32) -> i32;
    fn acl_init(count: i32) -> Acl;
    fn acl_free(object: *mut std::ffi::c_void) -> i32;
    fn acl_get_file(path: *const i8, kind: i32) -> Acl;
    #[allow(dead_code)]
    fn acl_get_fd_np(fd: i32, kind: i32) -> Acl;
    fn acl_set_fd_np(fd: i32, acl: Acl, kind: i32) -> i32;
    fn acl_set_file(path: *const i8, kind: i32, acl: Acl) -> i32;
    fn acl_get_entry(acl: Acl, entry_id: i32, entry: *mut AclEntry) -> i32;
    fn acl_get_tag_type(entry: AclEntry, tag: *mut i32) -> i32;
    #[cfg(test)]
    fn acl_create_entry(acl: *mut Acl, entry: *mut AclEntry) -> i32;
    #[cfg(test)]
    fn acl_set_tag_type(entry: AclEntry, tag: i32) -> i32;
    #[cfg(test)]
    fn acl_set_qualifier(entry: AclEntry, qualifier: *const std::ffi::c_void) -> i32;
    #[cfg(test)]
    fn acl_get_permset(entry: AclEntry, permset: *mut AclPermset) -> i32;
    #[cfg(test)]
    fn acl_add_perm(permset: AclPermset, permission: i32) -> i32;
    #[cfg(test)]
    fn acl_get_flagset_np(entry: AclEntry, flagset: *mut AclFlagset) -> i32;
    #[cfg(test)]
    fn acl_add_flag_np(flagset: AclFlagset, flag: i32) -> i32;
    #[cfg(test)]
    fn acl_set_flagset_np(entry: AclEntry, flagset: AclFlagset) -> i32;
    #[cfg(test)]
    fn mbr_uid_to_uuid(uid: u32, uuid: *mut u8) -> i32;
}

#[allow(dead_code)]
pub(crate) fn platform_name() -> &'static str {
    "macos"
}

pub(super) fn resolve_current_worker_principal() -> io::Result<WorkerPrincipal> {
    let real_uid = unsafe { libc::getuid() };
    let effective_uid = unsafe { libc::geteuid() };
    principal_for_uid(
        super::validate_unix_caller_ids(real_uid, effective_uid)?,
        WorkerAccountPolicy::CurrentUser,
    )
}

#[allow(dead_code)] // Consumed by the T0.14 setup action integration follow-up.
pub(super) fn default_worker_root(
    scope: super::InstallationScope,
    principal: &WorkerPrincipal,
) -> io::Result<(PathBuf, super::WorkerRootCreationPolicy)> {
    validate_worker_root_principal(scope, principal)?;
    match scope {
        super::InstallationScope::System => Ok((
            PathBuf::from("/Users/Shared/Styrn"),
            super::WorkerRootCreationPolicy::ExistingParent {
                allow_untrusted_parent_create: false,
            },
        )),
        super::InstallationScope::User => {
            let current = resolve_current_worker_principal()?;
            super::validate_user_scope_principal(principal, &current)?;
            let account =
                account_details_for_uid(principal.unix_uid()?, principal.account_policy())?;
            let home = PathBuf::from(account.home);
            Ok((
                home.join("Library/Application Support/Styrn"),
                super::WorkerRootCreationPolicy::CreateMissingFrom(home),
            ))
        }
    }
}

#[allow(dead_code)] // Consumed by the T0.14 setup action integration follow-up.
pub(super) fn validate_worker_root_principal(
    scope: super::InstallationScope,
    principal: &WorkerPrincipal,
) -> io::Result<()> {
    verify_worker_principal(principal)?;
    if scope == super::InstallationScope::User {
        let current = resolve_current_worker_principal()?;
        super::validate_user_scope_principal(principal, &current)?;
    }
    Ok(())
}

fn revalidate_worker_root_principal(
    layout: &super::WorkerDirectoryLayout,
) -> io::Result<WorkerPrincipal> {
    #[cfg(test)]
    if WORKER_NODE_PRINCIPAL_DRIFT.with(std::cell::Cell::get) {
        return Err(permission_denied(
            "injected worker principal drift before retained binding",
        ));
    }
    #[cfg(test)]
    if let Some(revalidation) = &layout.principal_revalidation {
        let (resolved, current) = match revalidation {
            super::WorkerPrincipalRevalidationTest::Resolved { principal, current } => {
                (Ok(principal.clone()), current.as_ref())
            }
            super::WorkerPrincipalRevalidationTest::Deleted => (
                Err(io::Error::new(io::ErrorKind::NotFound, "worker deleted")),
                None,
            ),
        };
        return super::validate_revalidated_worker_principal(
            layout.scope,
            &layout.principal,
            resolved,
            current,
        );
    }
    let scope = layout.scope;
    let principal = &layout.principal;
    let resolved = principal_for_uid(principal.unix_uid()?, principal.account_policy());
    let current = if scope == super::InstallationScope::User {
        Some(resolve_current_worker_principal()?)
    } else {
        None
    };
    super::validate_revalidated_worker_principal(scope, principal, resolved, current.as_ref())
}

#[allow(dead_code)] // Consumed by the T0.14 setup action integration follow-up.
pub(super) fn worker_root_path_is_normalized(path: &Path) -> bool {
    let bytes = path.as_os_str().as_bytes();
    !bytes.contains(&0)
        && !bytes.ends_with(b"/")
        && !bytes.windows(2).any(|pair| pair == b"//")
        && !bytes
            .split(|byte| *byte == b'/')
            .any(|component| component == b"." || component == b"..")
}

#[allow(dead_code)] // Consumed by the T0.14 setup action integration follow-up.
pub(super) fn create_worker_directory_layout(
    layout: &super::WorkerDirectoryLayout,
) -> io::Result<super::WorkerDirectoryCreation> {
    let root_components = absolute_worker_components(layout.root())?;
    let expected_uid = layout.principal.unix_uid()?;
    let first_creatable = match &layout.creation_policy {
        super::WorkerRootCreationPolicy::ExistingParent { .. } => root_components
            .len()
            .checked_sub(1)
            .ok_or_else(|| invalid_data("worker root has no leaf component"))?,
        super::WorkerRootCreationPolicy::CreateMissingFrom(anchor) => {
            let anchor_components = absolute_worker_components(anchor)?;
            if !root_components.starts_with(&anchor_components)
                || root_components.len() == anchor_components.len()
            {
                return Err(permission_denied(
                    "worker standard root escapes its native profile anchor",
                ));
            }
            anchor_components.len()
        }
    };

    let mut directory = open_worker_filesystem_root()?;
    verify_worker_creation_ancestor(&directory, expected_uid)?;
    for component in &root_components[..first_creatable] {
        directory = open_worker_directory_at(&directory, component)?;
        verify_worker_creation_ancestor(&directory, expected_uid)?;
    }
    let creation_lock = directory;
    if unsafe { libc::flock(creation_lock.as_raw_fd(), libc::LOCK_EX) } == -1 {
        return Err(io::Error::last_os_error());
    }
    let verified_principal = revalidate_worker_root_principal(layout)?;
    let expected_uid = verified_principal.unix_uid()?;
    let mut root_parent = creation_lock.try_clone()?;
    let mut creation_provenance = Vec::new();
    let mut pending_ownership = Vec::new();
    for component in &root_components[first_creatable..root_components.len() - 1] {
        let opened = open_or_create_worker_directory_at(
            &root_parent,
            &root_parent,
            component,
            true,
            expected_uid,
            false,
            None,
        )
        .map_err(|error| {
            io::Error::new(
                error.kind(),
                format!("creating worker root ancestor failed: {error}"),
            )
        })?;
        if let Some(provenance) = opened.provenance {
            creation_provenance.push(provenance);
        }
        if opened.disposition == super::WorkerDirectoryNodeDisposition::Created {
            pending_ownership.push((root_parent.try_clone()?, opened.directory.try_clone()?));
        }
        root_parent = opened.directory;
    }
    let root_name = root_components
        .last()
        .expect("the normalized worker root has a leaf component");
    let (root, staged_children) =
        create_or_open_complete_worker_root(&root_parent, root_name, expected_uid).map_err(
            |error| {
                io::Error::new(
                    error.kind(),
                    format!("creating complete worker root failed: {error}"),
                )
            },
        )?;
    let root_disposition = root.disposition;
    if let Some(provenance) = root.provenance {
        creation_provenance.push(provenance);
    }
    let directory = root.directory;
    let root_identity = worker_directory_identity(&directory)?;
    let root_observation = super::WorkerDirectoryNodeObservation::new(
        layout.root().to_path_buf(),
        root_disposition,
        root_identity,
    );

    let children = match staged_children {
        Some(children) => children,
        None => {
            open_or_create_worker_children(&root_parent, &directory, expected_uid, false, None)?
        }
    };

    for (parent, intermediate) in pending_ownership {
        harden_new_worker_directory(&intermediate, expected_uid)?;
        intermediate.sync_all()?;
        parent.sync_all()?;
    }
    if root_disposition == super::WorkerDirectoryNodeDisposition::Created {
        harden_new_worker_directory(&directory, expected_uid)?;
        directory.sync_all()?;
        root_parent.sync_all()?;
        maybe_interrupt_worker_publication(true, WorkerPublicationInterruption::AfterRootOwnership);
    }

    if worker_directory_identity(&directory)? != root_identity {
        return Err(permission_denied(
            "worker root identity changed during layout creation",
        ));
    }
    verify_worker_path_identity(layout.root(), root_identity)?;
    let mut child_observations = Vec::with_capacity(children.len());
    let mut child_handles = Vec::with_capacity(children.len());
    for (name, child) in super::WorkerDirectoryLayout::child_names()
        .into_iter()
        .zip(children)
    {
        let child = child.expect("every fixed worker child was opened or created");
        let reopened = open_worker_directory_at(&directory, name.as_bytes())?;
        let identity = worker_directory_identity(&child.directory)?;
        if worker_directory_identity(&reopened)? != identity {
            return Err(permission_denied(
                "worker layout child identity changed during creation",
            ));
        }
        child_observations.push(super::WorkerDirectoryNodeObservation::new(
            layout.root().join(name),
            child.disposition,
            identity,
        ));
        if let Some(provenance) = child.provenance {
            creation_provenance.push(provenance);
        }
        child_handles.push(child.directory);
    }
    let [repos, jobs, cache, artifacts, logs] = child_handles
        .try_into()
        .unwrap_or_else(|_| unreachable!("the worker layout always has exactly five children"));
    let lease = WorkerDirectoryLease {
        _creation_lock: creation_lock,
        layout: layout.clone(),
        nodes: [directory, repos, jobs, cache, artifacts, logs],
        creation_provenance,
    };
    Ok(super::WorkerDirectoryCreation::new(
        root_observation,
        child_observations
            .try_into()
            .unwrap_or_else(|_| unreachable!("the worker layout always has exactly five children")),
        lease,
    ))
}

pub(super) fn inspect_worker_directory_node(
    layout: &super::WorkerDirectoryLayout,
    node: super::WorkerDirectoryNode,
) -> super::WorkerDirectoryNodeInspection {
    let verified_principal = match revalidate_worker_root_principal(layout) {
        Ok(principal) => principal,
        Err(_) => {
            return super::WorkerDirectoryNodeInspection::Unknowable(
                super::WorkerDirectoryInspectionIssue::PrincipalDrift,
            );
        }
    };
    let Some(path) = layout.path_for_node(node) else {
        return super::WorkerDirectoryNodeInspection::Conflict(
            super::WorkerDirectoryInspectionIssue::UnsafeOrConflictingState,
        );
    };
    let expected_uid = match verified_principal.unix_uid() {
        Ok(uid) => uid,
        Err(_) => {
            return super::WorkerDirectoryNodeInspection::Unknowable(
                super::WorkerDirectoryInspectionIssue::PrincipalDrift,
            );
        }
    };
    match worker_node_has_reserved_evidence(layout, node, expected_uid) {
        Ok(true) => {
            return super::WorkerDirectoryNodeInspection::Conflict(
                super::WorkerDirectoryInspectionIssue::UnsafeOrConflictingState,
            );
        }
        Ok(false) => {}
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            return super::WorkerDirectoryNodeInspection::Absent;
        }
        Err(error) => return classify_worker_directory_inspection_error(error),
    }
    let directory = match open_existing_worker_path(&path) {
        Ok(directory) => directory,
        Err(error) => return classify_worker_directory_inspection_error(error),
    };
    let verified = match node {
        super::WorkerDirectoryNode::Support { .. } => {
            verify_worker_creation_ancestor(&directory, expected_uid)
        }
        _ => verify_worker_directory_security(&directory, expected_uid),
    }
    .and_then(|()| {
        let identity = worker_directory_identity(&directory)?;
        verify_worker_path_identity(&path, identity)
    });
    match verified {
        Ok(()) => super::WorkerDirectoryNodeInspection::Healthy,
        Err(error) => classify_worker_directory_inspection_error(error),
    }
}

fn worker_node_has_reserved_evidence(
    layout: &super::WorkerDirectoryLayout,
    node: super::WorkerDirectoryNode,
    expected_uid: u32,
) -> io::Result<bool> {
    let root_components = absolute_worker_components(layout.root())?;
    let first_creatable = worker_first_creatable_component(layout, &root_components)?;
    let anchor = open_worker_creation_anchor(&root_components, first_creatable, expected_uid)?;
    let (staging_parent, destination_parent, name, _, _) = worker_node_location(
        layout,
        node,
        &anchor,
        &root_components,
        first_creatable,
        expected_uid,
    )?;
    let staging = worker_staging_name(&destination_parent, name)?;
    let provenance = worker_creation_provenance_name(&destination_parent, name)?;
    if worker_parent_entry_exists(&staging_parent, &staging)?
        || worker_parent_entry_exists(&staging_parent, &provenance)?
    {
        return Ok(true);
    }
    let retired = worker_creation_retired_provenance_name(&destination_parent, name)?;
    if !worker_parent_entry_exists(&staging_parent, &retired)? {
        return Ok(false);
    }
    let directory = open_worker_directory_at(&destination_parent, name).map_err(|_| {
        permission_denied("retired worker provenance has no exact destination directory")
    })?;
    let identity = worker_recovery_candidate_identity(name, &directory)?;
    open_retired_worker_creation_provenance(
        &staging_parent,
        &destination_parent,
        name,
        identity,
        expected_uid,
    )?
    .ok_or_else(|| permission_denied("retired worker provenance marker disappeared"))?;
    Ok(false)
}

fn worker_parent_entry_exists(parent: &std::fs::File, name: &std::ffi::CStr) -> io::Result<bool> {
    let mut status = unsafe { std::mem::zeroed::<libc::stat>() };
    if unsafe {
        libc::fstatat(
            parent.as_raw_fd(),
            name.as_ptr(),
            &mut status,
            libc::AT_SYMLINK_NOFOLLOW,
        )
    } == 0
    {
        return Ok(true);
    }
    let error = io::Error::last_os_error();
    if error.kind() == io::ErrorKind::NotFound {
        Ok(false)
    } else {
        Err(error)
    }
}

fn classify_worker_directory_inspection_error(
    error: io::Error,
) -> super::WorkerDirectoryNodeInspection {
    if error.kind() == io::ErrorKind::NotFound {
        super::WorkerDirectoryNodeInspection::Absent
    } else if error.kind() == io::ErrorKind::PermissionDenied && error.raw_os_error().is_none() {
        super::WorkerDirectoryNodeInspection::Conflict(
            super::WorkerDirectoryInspectionIssue::UnsafeOrConflictingState,
        )
    } else {
        super::WorkerDirectoryNodeInspection::Unknowable(
            super::WorkerDirectoryInspectionIssue::ObservationUnavailable,
        )
    }
}

pub(super) fn create_worker_directory_node(
    layout: &super::WorkerDirectoryLayout,
    node: super::WorkerDirectoryNode,
) -> Result<super::WorkerDirectoryNodeCreateOutcome, super::WorkerDirectoryNodeCreationError> {
    let (
        creation_lock,
        lock_anchor_path,
        lock_anchor_identity,
        parent,
        destination_parent,
        destination_name,
        path,
        expected_uid,
        opened,
    ) = (|| -> Result<_, super::WorkerDirectoryNodeCreationError> {
        let root_components = absolute_worker_components(layout.root())?;
        let first_creatable = worker_first_creatable_component(layout, &root_components)?;
        let lock_anchor_path = worker_creation_anchor_path(layout)?;
        let initial_uid = layout.principal.unix_uid()?;
        let creation_lock =
            open_worker_creation_anchor(&root_components, first_creatable, initial_uid)?;
        let lock_anchor_identity = worker_directory_identity(&creation_lock)?;
        #[cfg(test)]
        probe_worker_layout_lock_contention_for_action_test(&creation_lock)?;
        if unsafe { libc::flock(creation_lock.as_raw_fd(), libc::LOCK_EX) } == -1 {
            return Err(io::Error::last_os_error().into());
        }
        #[cfg(test)]
        super::notify_worker_layout_lock_probe_for_action_test(
            super::WorkerLayoutLockProbeEvent::Acquired,
        );
        verify_worker_path_identity(&lock_anchor_path, lock_anchor_identity)?;
        let expected_uid = revalidate_worker_root_principal(layout)?.unix_uid()?;
        let (staging_parent, parent, name, path, canonical) = worker_node_location(
            layout,
            node,
            &creation_lock,
            &root_components,
            first_creatable,
            expected_uid,
        )?;
        let destination_parent = parent.try_clone()?;
        let destination_name = CString::new(name)
            .map_err(|_| invalid_data("worker directory component contains a NUL byte"))?;
        let opened = match open_or_create_worker_directory_at(
            &staging_parent,
            &parent,
            destination_name.to_bytes(),
            true,
            expected_uid,
            canonical,
            None,
        ) {
            Ok(opened) => opened,
            Err(error) => {
                let (primary, published) = error.into_parts();
                let Some(opened) = published else {
                    return Err(primary.into());
                };
                let mut creation_provenance = Vec::new();
                if let Some(provenance) = opened.provenance {
                    creation_provenance.push(provenance);
                }
                let evidence = WorkerDirectoryNodeFailureEvidence {
                    lease: WorkerDirectoryNodeLease {
                        creation_lock,
                        lock_anchor_path,
                        lock_anchor_identity,
                        layout: layout.clone(),
                        node: opened.directory,
                        destination_parent,
                        destination_name,
                        path,
                        creation_provenance,
                    },
                };
                return Err(
                    super::WorkerDirectoryNodeCreationError::with_retained_evidence(
                        primary, evidence,
                    ),
                );
            }
        };
        Ok((
            creation_lock,
            lock_anchor_path,
            lock_anchor_identity,
            parent,
            destination_parent,
            destination_name,
            path,
            expected_uid,
            opened,
        ))
    })()?;
    if opened.disposition == super::WorkerDirectoryNodeDisposition::Existing {
        return Ok(super::WorkerDirectoryNodeCreateOutcome::Existing);
    }
    let mut creation_provenance = Vec::new();
    if let Some(provenance) = opened.provenance {
        creation_provenance.push(provenance);
    }
    let evidence = WorkerDirectoryNodeFailureEvidence {
        lease: WorkerDirectoryNodeLease {
            creation_lock,
            lock_anchor_path,
            lock_anchor_identity,
            layout: layout.clone(),
            node: opened.directory,
            destination_parent,
            destination_name,
            path,
            creation_provenance,
        },
    };
    let operation = (|| -> io::Result<super::WorkerDirectoryNodeObservation> {
        harden_new_worker_directory(&evidence.lease.node, expected_uid)?;
        evidence.lease.node.sync_all()?;
        parent.sync_all()?;
        let identity = worker_directory_identity(&evidence.lease.node)?;
        verify_worker_path_identity(&evidence.lease.path, identity)?;
        #[cfg(test)]
        if WORKER_NODE_POST_PUBLISH_FAILURE.with(std::cell::Cell::get) {
            return Err(io::Error::other(
                "injected worker node post-publication failure",
            ));
        }
        Ok(super::WorkerDirectoryNodeObservation::new(
            evidence.lease.path.clone(),
            super::WorkerDirectoryNodeDisposition::Created,
            identity,
        ))
    })();
    let observation = match operation {
        Ok(observation) => observation,
        Err(error) => {
            return Err(
                super::WorkerDirectoryNodeCreationError::with_retained_evidence(error, evidence),
            );
        }
    };
    Ok(super::WorkerDirectoryNodeCreateOutcome::Created(
        super::WorkerDirectoryNodeCreation::new(observation, evidence.lease),
    ))
}

#[cfg(test)]
fn probe_worker_layout_lock_contention_for_action_test(lock: &std::fs::File) -> io::Result<()> {
    if !super::worker_layout_lock_probe_is_enabled_for_action_test() {
        return Ok(());
    }
    if unsafe { libc::flock(lock.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } == 0 {
        if unsafe { libc::flock(lock.as_raw_fd(), libc::LOCK_UN) } == -1 {
            return Err(io::Error::last_os_error());
        }
        super::notify_worker_layout_lock_probe_for_action_test(
            super::WorkerLayoutLockProbeEvent::UnexpectedlyAvailable,
        );
        return Ok(());
    }
    let error = io::Error::last_os_error();
    if error
        .raw_os_error()
        .is_some_and(|raw| raw == libc::EWOULDBLOCK || raw == libc::EAGAIN)
    {
        super::notify_worker_layout_lock_probe_for_action_test(
            super::WorkerLayoutLockProbeEvent::Contended,
        );
        Ok(())
    } else {
        Err(error)
    }
}

fn worker_node_location<'component>(
    layout: &super::WorkerDirectoryLayout,
    node: super::WorkerDirectoryNode,
    creation_lock: &std::fs::File,
    root_components: &[&'component [u8]],
    first_creatable: usize,
    expected_uid: u32,
) -> io::Result<(
    std::fs::File,
    std::fs::File,
    &'component [u8],
    PathBuf,
    bool,
)> {
    let root_index = root_components
        .len()
        .checked_sub(1)
        .ok_or_else(|| invalid_data("worker root has no leaf component"))?;
    let (target_index, child_name) = match node {
        super::WorkerDirectoryNode::Support { ordinal } => {
            let index = first_creatable
                .checked_add(usize::from(ordinal))
                .ok_or_else(|| invalid_data("worker support ordinal overflows"))?;
            if index >= root_index {
                return Err(permission_denied(
                    "worker support node is outside the closed materialization set",
                ));
            }
            (index, None)
        }
        super::WorkerDirectoryNode::Root => (root_index, None),
        super::WorkerDirectoryNode::Repos => (root_index, Some(b"repos".as_slice())),
        super::WorkerDirectoryNode::Jobs => (root_index, Some(b"jobs".as_slice())),
        super::WorkerDirectoryNode::Cache => (root_index, Some(b"cache".as_slice())),
        super::WorkerDirectoryNode::Artifacts => (root_index, Some(b"artifacts".as_slice())),
        super::WorkerDirectoryNode::Logs => (root_index, Some(b"logs".as_slice())),
    };
    let mut parent = creation_lock.try_clone()?;
    for component in &root_components[first_creatable..target_index] {
        parent = open_worker_directory_at(&parent, component)?;
        verify_worker_creation_ancestor(&parent, expected_uid)?;
    }
    if let Some(child_name) = child_name {
        let staging_parent = parent.try_clone()?;
        let root = open_worker_directory_at(&parent, root_components[root_index])?;
        verify_worker_directory_security(&root, expected_uid)?;
        return Ok((
            staging_parent,
            root,
            child_name,
            layout
                .path_for_node(node)
                .ok_or_else(|| invalid_data("worker node has no closed path"))?,
            true,
        ));
    }
    Ok((
        parent.try_clone()?,
        parent,
        root_components[target_index],
        layout
            .path_for_node(node)
            .ok_or_else(|| invalid_data("worker node has no closed path"))?,
        node == super::WorkerDirectoryNode::Root,
    ))
}

#[allow(dead_code)] // Retained by the T0.14 per-node Action receipt binder.
pub(super) struct WorkerDirectoryNodeLease {
    creation_lock: std::fs::File,
    lock_anchor_path: PathBuf,
    lock_anchor_identity: super::WorkerDirectoryIdentity,
    layout: super::WorkerDirectoryLayout,
    node: std::fs::File,
    destination_parent: std::fs::File,
    destination_name: CString,
    path: PathBuf,
    creation_provenance: Vec<WorkerCreationProvenance>,
}

#[allow(dead_code)] // Retained by the T0.14 per-node failure receipt binder.
pub(super) struct WorkerDirectoryNodeFailureEvidence {
    lease: WorkerDirectoryNodeLease,
}

#[allow(dead_code)] // Consumed by the T0.14 per-node failure receipt binder.
impl WorkerDirectoryNodeFailureEvidence {
    pub(super) const fn retained_count(&self) -> usize {
        1
    }
}

#[allow(dead_code)] // Consumed by the T0.14 per-node failure receipt binder.
pub(super) fn reverify_worker_directory_node_failure_evidence(
    evidence: &WorkerDirectoryNodeFailureEvidence,
) -> io::Result<super::WorkerDirectoryNodeObservation> {
    let identity = reverify_worker_directory_node_authority(&evidence.lease)?;
    Ok(super::WorkerDirectoryNodeObservation::new(
        evidence.lease.path.clone(),
        super::WorkerDirectoryNodeDisposition::Created,
        identity,
    ))
}

#[allow(dead_code)] // Consumed by the T0.14 per-node failure receipt binder.
pub(super) fn retire_worker_directory_node_failure_authority(
    evidence: &WorkerDirectoryNodeFailureEvidence,
) -> io::Result<()> {
    retire_worker_directory_node_authority(&evidence.lease)
}

#[allow(dead_code)] // Consumed by the T0.14 per-node Action receipt binder.
pub(super) fn reverify_worker_directory_node_lease(
    lease: &WorkerDirectoryNodeLease,
    observation: &super::WorkerDirectoryNodeObservation,
) -> io::Result<()> {
    let identity = reverify_worker_directory_node_authority(lease)?;
    if observation.path() != lease.path || identity != observation.identity() {
        return Err(permission_denied(
            "retained worker directory observation changed before release",
        ));
    }
    Ok(())
}

fn reverify_worker_directory_node_authority(
    lease: &WorkerDirectoryNodeLease,
) -> io::Result<super::WorkerDirectoryIdentity> {
    let principal = revalidate_worker_root_principal(&lease.layout)?;
    let expected_uid = principal.unix_uid()?;
    if worker_directory_identity(&lease.creation_lock)? != lease.lock_anchor_identity {
        return Err(permission_denied(
            "worker creation lock identity changed before retained evidence release",
        ));
    }
    verify_worker_path_identity(&lease.lock_anchor_path, lease.lock_anchor_identity)?;
    lease.node.sync_all()?;
    lease.destination_parent.sync_all()?;
    for provenance in &lease.creation_provenance {
        verify_worker_creation_provenance(provenance)?;
    }
    verify_worker_directory_security(&lease.node, expected_uid)?;
    let identity = worker_directory_identity(&lease.node)?;
    let relative =
        open_worker_directory_at(&lease.destination_parent, lease.destination_name.to_bytes())
            .map_err(|_| {
                permission_denied(
                    "worker directory descriptor-relative path changed before release",
                )
            })?;
    if worker_directory_identity(&relative)? != identity {
        return Err(permission_denied(
            "worker directory descriptor-relative path changed before release",
        ));
    }
    verify_worker_path_identity(&lease.path, identity)?;
    Ok(identity)
}

#[allow(dead_code)] // Consumed by the T0.14 per-node Action receipt binder.
pub(super) fn retire_worker_directory_node_authority(
    lease: &WorkerDirectoryNodeLease,
) -> io::Result<()> {
    for provenance in lease.creation_provenance.iter().rev() {
        retire_worker_creation_provenance(provenance)?;
    }
    Ok(())
}

pub(super) fn retire_succeeded_worker_directory_evidence(
    layout: &super::WorkerDirectoryLayout,
    node: super::WorkerDirectoryNode,
) -> io::Result<()> {
    let root_components = absolute_worker_components(layout.root())?;
    let first_creatable = match &layout.creation_policy {
        super::WorkerRootCreationPolicy::ExistingParent { .. } => root_components
            .len()
            .checked_sub(1)
            .ok_or_else(|| invalid_data("worker root has no leaf component"))?,
        super::WorkerRootCreationPolicy::CreateMissingFrom(anchor) => {
            let anchor_components = absolute_worker_components(anchor)?;
            if !root_components.starts_with(&anchor_components)
                || root_components.len() == anchor_components.len()
            {
                return Err(permission_denied(
                    "worker standard root escapes its native profile anchor",
                ));
            }
            anchor_components.len()
        }
    };
    let mut anchor = open_worker_filesystem_root()?;
    let initial_uid = layout.principal.unix_uid()?;
    verify_worker_creation_ancestor(&anchor, initial_uid)?;
    for component in &root_components[..first_creatable] {
        anchor = open_worker_directory_at(&anchor, component)?;
        verify_worker_creation_ancestor(&anchor, initial_uid)?;
    }
    if unsafe { libc::flock(anchor.as_raw_fd(), libc::LOCK_EX) } == -1 {
        return Err(io::Error::last_os_error());
    }
    let expected_uid = revalidate_worker_root_principal(layout)?.unix_uid()?;
    let (staging_parent, destination_parent, name, path, canonical) = worker_node_location(
        layout,
        node,
        &anchor,
        &root_components,
        first_creatable,
        expected_uid,
    )?;
    let staging_name = worker_staging_name(&destination_parent, name)?;
    if worker_parent_entry_exists(&staging_parent, &staging_name)? {
        return Err(permission_denied(
            "succeeded worker evidence has an unresolved staging candidate",
        ));
    }
    let directory = open_worker_directory_at(&destination_parent, name)?;
    verify_existing_worker_directory(&directory, expected_uid, canonical)?;
    let identity = worker_directory_identity(&directory)?;
    verify_worker_path_identity(&path, identity)?;
    let retirement = open_worker_creation_provenance_for_retirement(
        &staging_parent,
        &destination_parent,
        name,
        identity,
        expected_uid,
    )?;
    retire_worker_creation_provenance_state(&retirement)
}

fn retire_worker_creation_provenance(provenance: &WorkerCreationProvenance) -> io::Result<()> {
    verify_worker_creation_provenance(provenance)?;
    let retired_name = worker_creation_retired_provenance_name_from_marker(&provenance.name)?;
    if worker_parent_entry_exists(&provenance.parent, &retired_name)? {
        return Err(permission_denied(
            "active and retired worker provenance markers both exist",
        ));
    }
    if unsafe {
        libc::renameatx_np(
            provenance.parent.as_raw_fd(),
            provenance.name.as_ptr(),
            provenance.parent.as_raw_fd(),
            retired_name.as_ptr(),
            libc::RENAME_EXCL,
        )
    } == -1
    {
        let error = io::Error::last_os_error();
        return Err(if error.kind() == io::ErrorKind::AlreadyExists {
            permission_denied("retired worker provenance marker already exists")
        } else {
            error
        });
    }
    #[cfg(test)]
    fail_worker_provenance_retirement_at(
        super::WorkerProvenanceRetirementFault::AfterMarkerRename,
    )?;
    // The exact retired directory is the durable terminal marker. A future
    // uninstall path may remove it; successful creation retirement must not.
    verify_retired_worker_creation_provenance(provenance)?;
    sync_worker_creation_provenance_parent(&provenance.parent)?;
    verify_retired_worker_creation_provenance(provenance)
}

enum WorkerCreationProvenanceRetirement {
    Active(WorkerCreationProvenance),
    Retired(WorkerCreationProvenance),
}

fn open_worker_creation_provenance_for_retirement(
    staging_parent: &std::fs::File,
    destination_parent: &std::fs::File,
    destination_name: &[u8],
    created_identity: super::WorkerDirectoryIdentity,
    expected_uid: u32,
) -> io::Result<WorkerCreationProvenanceRetirement> {
    let active_name = worker_creation_provenance_name(destination_parent, destination_name)?;
    let retired_name =
        worker_creation_retired_provenance_name(destination_parent, destination_name)?;
    let active_exists = worker_parent_entry_exists(staging_parent, &active_name)?;
    let retired_exists = worker_parent_entry_exists(staging_parent, &retired_name)?;
    if active_exists && retired_exists {
        return Err(permission_denied(
            "active and retired worker provenance markers both exist",
        ));
    }
    let (provenance, retired) = if active_exists {
        (
            open_worker_creation_provenance_at_name(
                staging_parent,
                destination_parent,
                destination_name,
                created_identity,
                expected_uid,
                active_name,
            )?
            .ok_or_else(|| permission_denied("active worker provenance marker disappeared"))?,
            false,
        )
    } else if retired_exists {
        (
            open_worker_creation_provenance_at_name(
                staging_parent,
                destination_parent,
                destination_name,
                created_identity,
                expected_uid,
                retired_name,
            )?
            .ok_or_else(|| permission_denied("retired worker provenance marker disappeared"))?,
            true,
        )
    } else {
        return Err(permission_denied(
            "succeeded worker evidence lacks an exact retired provenance marker",
        ));
    };
    Ok(if retired {
        WorkerCreationProvenanceRetirement::Retired(provenance)
    } else {
        WorkerCreationProvenanceRetirement::Active(provenance)
    })
}

fn retire_worker_creation_provenance_state(
    retirement: &WorkerCreationProvenanceRetirement,
) -> io::Result<()> {
    match retirement {
        WorkerCreationProvenanceRetirement::Active(provenance) => {
            retire_worker_creation_provenance(provenance)
        }
        WorkerCreationProvenanceRetirement::Retired(provenance) => {
            verify_retired_worker_creation_provenance(provenance)?;
            sync_worker_creation_provenance_parent(&provenance.parent)?;
            verify_retired_worker_creation_provenance(provenance)
        }
    }
}

fn sync_worker_creation_provenance_parent(parent: &std::fs::File) -> io::Result<()> {
    #[cfg(test)]
    fail_worker_provenance_retirement_at(super::WorkerProvenanceRetirementFault::BeforeParentSync)?;
    parent.sync_all()
}
struct OpenedWorkerDirectory {
    directory: std::fs::File,
    disposition: super::WorkerDirectoryNodeDisposition,
    provenance: Option<WorkerCreationProvenance>,
}

struct WorkerDirectoryOpenError {
    primary: io::Error,
    published: Option<OpenedWorkerDirectory>,
}

impl WorkerDirectoryOpenError {
    fn published(primary: io::Error, published: OpenedWorkerDirectory) -> Self {
        Self {
            primary,
            published: Some(published),
        }
    }

    fn into_parts(self) -> (io::Error, Option<OpenedWorkerDirectory>) {
        (self.primary, self.published)
    }

    fn kind(&self) -> io::ErrorKind {
        self.primary.kind()
    }
}

impl std::fmt::Display for WorkerDirectoryOpenError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.primary.fmt(formatter)
    }
}

impl From<io::Error> for WorkerDirectoryOpenError {
    fn from(primary: io::Error) -> Self {
        Self {
            primary,
            published: None,
        }
    }
}

impl From<WorkerDirectoryOpenError> for io::Error {
    fn from(error: WorkerDirectoryOpenError) -> Self {
        error.primary
    }
}

struct WorkerCreationProvenance {
    parent: std::fs::File,
    name: CString,
    directory: std::fs::File,
    directory_identity: super::WorkerDirectoryIdentity,
    file: std::fs::File,
    file_identity: PrivateFileIdentity,
    expected_record: Vec<u8>,
}

pub(super) struct WorkerDirectoryLease {
    _creation_lock: std::fs::File,
    layout: super::WorkerDirectoryLayout,
    nodes: [std::fs::File; 6],
    creation_provenance: Vec<WorkerCreationProvenance>,
}

pub(super) fn reverify_worker_directory_lease(
    lease: &WorkerDirectoryLease,
    observations: &[super::WorkerDirectoryNodeObservation; 6],
) -> io::Result<()> {
    let expected_uid = revalidate_worker_root_principal(&lease.layout)?.unix_uid()?;
    for provenance in &lease.creation_provenance {
        verify_worker_creation_provenance(provenance)?;
    }
    for (directory, observation) in lease.nodes.iter().zip(observations) {
        verify_worker_directory_security(directory, expected_uid)?;
        if worker_directory_identity(directory)? != observation.identity() {
            return Err(permission_denied(
                "retained worker directory identity changed before release",
            ));
        }
        let reopened = open_existing_worker_path(observation.path())?;
        if worker_directory_identity(&reopened)? != observation.identity() {
            return Err(permission_denied(
                "worker directory path changed before retained evidence release",
            ));
        }
    }
    Ok(())
}

pub(super) fn retire_worker_directory_authority(lease: &WorkerDirectoryLease) -> io::Result<()> {
    // Child evidence is retired before the root record, so a partial cleanup
    // leaves the root transaction visibly incomplete rather than silently
    // converting an unbound creation into an ordinary existing tree.
    for provenance in lease.creation_provenance.iter().rev() {
        retire_worker_creation_provenance(provenance)?;
    }
    Ok(())
}

fn worker_creation_provenance_name(
    destination_parent: &std::fs::File,
    destination_name: &[u8],
) -> io::Result<CString> {
    worker_creation_provenance_name_with_prefix(
        destination_parent,
        destination_name,
        ".styrn-worker-provenance-",
    )
}

fn worker_creation_retired_provenance_name(
    destination_parent: &std::fs::File,
    destination_name: &[u8],
) -> io::Result<CString> {
    worker_creation_provenance_name_with_prefix(
        destination_parent,
        destination_name,
        ".styrn-worker-retired-",
    )
}

fn worker_creation_active_provenance_name_from_retired(
    retired_name: &std::ffi::CStr,
) -> io::Result<CString> {
    const RETIRED_PREFIX: &[u8] = b".styrn-worker-retired-";
    let suffix = retired_name
        .to_bytes()
        .strip_prefix(RETIRED_PREFIX)
        .ok_or_else(|| invalid_data("retired worker provenance name has an invalid prefix"))?;
    let mut name = b".styrn-worker-provenance-".to_vec();
    name.extend_from_slice(suffix);
    CString::new(name).map_err(|_| invalid_data("worker provenance name contains a NUL byte"))
}

fn worker_creation_retired_provenance_name_from_marker(
    marker_name: &std::ffi::CStr,
) -> io::Result<CString> {
    const ACTIVE_PREFIX: &[u8] = b".styrn-worker-provenance-";
    const RETIRED_PREFIX: &[u8] = b".styrn-worker-retired-";
    if marker_name.to_bytes().starts_with(RETIRED_PREFIX) {
        return Ok(marker_name.to_owned());
    }
    let suffix = marker_name
        .to_bytes()
        .strip_prefix(ACTIVE_PREFIX)
        .ok_or_else(|| invalid_data("active worker provenance name has an invalid prefix"))?;
    let mut name = RETIRED_PREFIX.to_vec();
    name.extend_from_slice(suffix);
    CString::new(name).map_err(|_| invalid_data("worker provenance name contains a NUL byte"))
}

fn worker_creation_provenance_name_with_prefix(
    destination_parent: &std::fs::File,
    destination_name: &[u8],
    prefix: &str,
) -> io::Result<CString> {
    use std::fmt::Write;

    let identity = worker_directory_identity(destination_parent)?;
    let mut digest = Sha256::new();
    digest.update(b"styrn-worker-provenance-v1");
    digest.update(identity.volume.to_le_bytes());
    digest.update(identity.file_id);
    digest.update(destination_name);
    let digest = digest.finalize();
    let mut name = String::from(prefix);
    for byte in &digest[..16] {
        write!(&mut name, "{byte:02x}").expect("writing a provenance digest cannot fail");
    }
    CString::new(name).map_err(|_| invalid_data("worker provenance name contains a NUL byte"))
}

fn worker_creation_provenance_record(
    staging_parent: &std::fs::File,
    destination_parent: &std::fs::File,
    destination_name: &[u8],
    created_identity: super::WorkerDirectoryIdentity,
    provenance_directory_identity: super::WorkerDirectoryIdentity,
    provenance_file_identity: PrivateFileIdentity,
    expected_uid: u32,
) -> io::Result<Vec<u8>> {
    let staging_parent = worker_directory_identity(staging_parent)?;
    let destination_parent = worker_directory_identity(destination_parent)?;
    let name_length = u32::try_from(destination_name.len())
        .map_err(|_| invalid_data("worker directory component is too long"))?;
    let mut record = Vec::with_capacity(144 + destination_name.len());
    record.extend_from_slice(b"STYRN-WORKER-PROVENANCE-V2\0");
    for identity in [
        staging_parent,
        destination_parent,
        created_identity,
        provenance_directory_identity,
    ] {
        record.extend_from_slice(&identity.volume.to_le_bytes());
        record.extend_from_slice(&identity.file_id);
    }
    record.extend_from_slice(&provenance_file_identity.first.to_le_bytes());
    record.extend_from_slice(&provenance_file_identity.second.to_le_bytes());
    record.extend_from_slice(&expected_uid.to_le_bytes());
    record.extend_from_slice(&name_length.to_le_bytes());
    record.extend_from_slice(destination_name);
    Ok(record)
}

fn worker_provenance_file_identity(file: &std::fs::File) -> io::Result<PrivateFileIdentity> {
    let mut status = unsafe { std::mem::zeroed::<libc::stat>() };
    if unsafe { libc::fstat(file.as_raw_fd(), &mut status) } == -1 {
        return Err(io::Error::last_os_error());
    }
    if status.st_mode & libc::S_IFMT != libc::S_IFREG
        || status.st_mode & 0o777 != 0o600
        || status.st_uid != unsafe { libc::geteuid() }
        || status.st_nlink != 1
    {
        return Err(permission_denied(
            "worker creation provenance is not a private regular file",
        ));
    }
    verify_no_extended_acl_fd(file.as_raw_fd())?;
    Ok(PrivateFileIdentity::new(
        status.st_dev as u64,
        status.st_ino as u64,
    ))
}

fn worker_provenance_identity_at(
    parent: &std::fs::File,
    name: &std::ffi::CStr,
) -> io::Result<PrivateFileIdentity> {
    let mut status = unsafe { std::mem::zeroed::<libc::stat>() };
    if unsafe {
        libc::fstatat(
            parent.as_raw_fd(),
            name.as_ptr(),
            &mut status,
            libc::AT_SYMLINK_NOFOLLOW,
        )
    } == -1
    {
        return Err(io::Error::last_os_error());
    }
    if status.st_mode & libc::S_IFMT != libc::S_IFREG {
        return Err(permission_denied(
            "worker creation provenance path is not a regular file",
        ));
    }
    Ok(PrivateFileIdentity::new(
        status.st_dev as u64,
        status.st_ino as u64,
    ))
}

fn verify_worker_creation_provenance(provenance: &WorkerCreationProvenance) -> io::Result<()> {
    verify_worker_creation_provenance_at_name(provenance, &provenance.name)
}

fn verify_worker_creation_provenance_at_name(
    provenance: &WorkerCreationProvenance,
    name: &std::ffi::CStr,
) -> io::Result<()> {
    use std::io::{Read, Seek};

    verify_staged_worker_directory_security(
        &provenance.directory,
        unsafe { libc::geteuid() },
        unsafe { libc::geteuid() },
    )?;
    if worker_directory_identity(&provenance.directory)? != provenance.directory_identity
        || worker_directory_identity_at(&provenance.parent, name)? != provenance.directory_identity
        || worker_provenance_file_identity(&provenance.file)? != provenance.file_identity
        || worker_provenance_identity_at(&provenance.directory, c"record")?
            != provenance.file_identity
        || worker_parent_entry_snapshot(&provenance.directory)?
            != vec![(
                b"record".to_vec(),
                super::WorkerDirectoryIdentity::from_unix(
                    provenance.file_identity.first,
                    provenance.file_identity.second,
                ),
            )]
    {
        return Err(permission_denied(
            "worker creation provenance identity changed",
        ));
    }
    let mut reader = provenance.file.try_clone()?;
    reader.rewind()?;
    let mut actual = Vec::new();
    reader.read_to_end(&mut actual)?;
    if actual != provenance.expected_record {
        return Err(permission_denied(
            "worker creation provenance content changed",
        ));
    }
    Ok(())
}

fn verify_retired_worker_creation_provenance(
    provenance: &WorkerCreationProvenance,
) -> io::Result<()> {
    let retired_name = worker_creation_retired_provenance_name_from_marker(&provenance.name)?;
    verify_worker_creation_provenance_at_name(provenance, &retired_name)?;
    let active_name = worker_creation_active_provenance_name_from_retired(&retired_name)?;
    if worker_parent_entry_exists(&provenance.parent, &active_name)? {
        return Err(permission_denied(
            "active and retired worker provenance markers both exist",
        ));
    }
    Ok(())
}

fn create_worker_creation_provenance(
    staging_parent: &std::fs::File,
    destination_parent: &std::fs::File,
    destination_name: &[u8],
    created_identity: super::WorkerDirectoryIdentity,
    expected_uid: u32,
) -> io::Result<WorkerCreationProvenance> {
    use std::io::Write;

    let name = worker_creation_provenance_name(destination_parent, destination_name)?;
    let retired_name =
        worker_creation_retired_provenance_name(destination_parent, destination_name)?;
    let entries_before = worker_parent_entry_snapshot(staging_parent)?;
    if entries_before
        .iter()
        .any(|(entry, _)| entry == retired_name.to_bytes())
    {
        return Err(permission_denied(
            "retired worker provenance conflicts with a new creation",
        ));
    }
    if unsafe { libc::mkdirat(staging_parent.as_raw_fd(), name.as_ptr(), 0o700) } == -1 {
        let error = io::Error::last_os_error();
        return Err(if error.kind() == io::ErrorKind::AlreadyExists {
            permission_denied("worker creation provenance already exists ambiguously")
        } else {
            error
        });
    }
    let directory = open_worker_directory_at(staging_parent, name.to_bytes())?;
    let directory_identity = worker_directory_identity(&directory)?;
    let mut expected_entries = entries_before;
    expected_entries.push((name.to_bytes().to_vec(), directory_identity));
    expected_entries.sort_by(|left, right| left.0.cmp(&right.0));
    if worker_parent_entry_snapshot(staging_parent)? != expected_entries {
        return Err(permission_denied(
            "worker creation provenance directory changed before its first retained handle",
        ));
    }
    harden_new_worker_directory(&directory, unsafe { libc::geteuid() })?;
    let descriptor = unsafe {
        libc::openat(
            directory.as_raw_fd(),
            c"record".as_ptr(),
            libc::O_RDWR | libc::O_CREAT | libc::O_EXCL | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            0o600,
        )
    };
    if descriptor == -1 {
        return Err(io::Error::last_os_error());
    }
    let mut file = unsafe { std::fs::File::from_raw_fd(descriptor) };
    clear_extended_acl_fd(file.as_raw_fd())?;
    if unsafe { libc::fchmod(file.as_raw_fd(), 0o600) } == -1 {
        return Err(io::Error::last_os_error());
    }
    let file_identity = worker_provenance_file_identity(&file)?;
    let expected_record = worker_creation_provenance_record(
        staging_parent,
        destination_parent,
        destination_name,
        created_identity,
        directory_identity,
        file_identity,
        expected_uid,
    )
    .map_err(|error| {
        io::Error::new(
            error.kind(),
            format!("encoding worker creation provenance failed: {error}"),
        )
    })?;
    file.write_all(&expected_record)?;
    file.sync_all()?;
    directory.sync_all()?;
    staging_parent.sync_all()?;
    let provenance = WorkerCreationProvenance {
        parent: staging_parent.try_clone()?,
        name,
        directory,
        directory_identity,
        file,
        file_identity,
        expected_record,
    };
    verify_worker_creation_provenance(&provenance)?;
    Ok(provenance)
}

fn open_worker_creation_provenance(
    staging_parent: &std::fs::File,
    destination_parent: &std::fs::File,
    destination_name: &[u8],
    created_identity: super::WorkerDirectoryIdentity,
    expected_uid: u32,
) -> io::Result<Option<WorkerCreationProvenance>> {
    let name = worker_creation_provenance_name(destination_parent, destination_name)?;
    open_worker_creation_provenance_at_name(
        staging_parent,
        destination_parent,
        destination_name,
        created_identity,
        expected_uid,
        name,
    )
}

fn open_retired_worker_creation_provenance(
    staging_parent: &std::fs::File,
    destination_parent: &std::fs::File,
    destination_name: &[u8],
    created_identity: super::WorkerDirectoryIdentity,
    expected_uid: u32,
) -> io::Result<Option<WorkerCreationProvenance>> {
    let name = worker_creation_retired_provenance_name(destination_parent, destination_name)?;
    let provenance = open_worker_creation_provenance_at_name(
        staging_parent,
        destination_parent,
        destination_name,
        created_identity,
        expected_uid,
        name,
    )?;
    if let Some(provenance) = &provenance {
        verify_retired_worker_creation_provenance(provenance)?;
    }
    Ok(provenance)
}

fn open_worker_creation_provenance_at_name(
    staging_parent: &std::fs::File,
    destination_parent: &std::fs::File,
    destination_name: &[u8],
    created_identity: super::WorkerDirectoryIdentity,
    expected_uid: u32,
    name: CString,
) -> io::Result<Option<WorkerCreationProvenance>> {
    let directory = match open_worker_directory_at(staging_parent, name.to_bytes()) {
        Ok(directory) => directory,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error),
    };
    verify_staged_worker_directory_security(&directory, unsafe { libc::geteuid() }, unsafe {
        libc::geteuid()
    })?;
    let directory_identity = worker_directory_identity(&directory)?;
    let descriptor = unsafe {
        libc::openat(
            directory.as_raw_fd(),
            c"record".as_ptr(),
            libc::O_RDONLY | libc::O_NONBLOCK | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        )
    };
    if descriptor == -1 {
        let error = worker_directory_open_error(io::Error::last_os_error());
        return Err(if error.kind() == io::ErrorKind::NotFound {
            permission_denied("worker creation provenance record is missing")
        } else {
            error
        });
    }
    let file = unsafe { std::fs::File::from_raw_fd(descriptor) };
    let file_identity = worker_provenance_file_identity(&file)?;
    let expected_record = worker_creation_provenance_record(
        staging_parent,
        destination_parent,
        destination_name,
        created_identity,
        directory_identity,
        file_identity,
        expected_uid,
    )?;
    let provenance = WorkerCreationProvenance {
        parent: staging_parent.try_clone()?,
        name,
        directory,
        directory_identity,
        file,
        file_identity,
        expected_record,
    };
    verify_worker_creation_provenance(&provenance)?;
    Ok(Some(provenance))
}

fn absolute_worker_components(path: &Path) -> io::Result<Vec<&[u8]>> {
    let mut components = path.components();
    if !matches!(components.next(), Some(std::path::Component::RootDir)) {
        return Err(invalid_data("worker directory path is not absolute"));
    }
    components
        .map(|component| match component {
            std::path::Component::Normal(name) => Ok(name.as_bytes()),
            _ => Err(invalid_data("worker directory path is not normalized")),
        })
        .collect()
}

fn worker_first_creatable_component(
    layout: &super::WorkerDirectoryLayout,
    root_components: &[&[u8]],
) -> io::Result<usize> {
    match &layout.creation_policy {
        super::WorkerRootCreationPolicy::ExistingParent { .. } => root_components
            .len()
            .checked_sub(1)
            .ok_or_else(|| invalid_data("worker root has no leaf component")),
        super::WorkerRootCreationPolicy::CreateMissingFrom(anchor) => {
            let anchor_components = absolute_worker_components(anchor)?;
            if !root_components.starts_with(&anchor_components)
                || root_components.len() == anchor_components.len()
            {
                return Err(permission_denied(
                    "worker standard root escapes its native profile anchor",
                ));
            }
            Ok(anchor_components.len())
        }
    }
}

fn worker_creation_anchor_path(layout: &super::WorkerDirectoryLayout) -> io::Result<PathBuf> {
    match &layout.creation_policy {
        super::WorkerRootCreationPolicy::ExistingParent { .. } => layout
            .root()
            .parent()
            .map(Path::to_path_buf)
            .ok_or_else(|| invalid_data("worker root has no fixed parent anchor")),
        super::WorkerRootCreationPolicy::CreateMissingFrom(anchor) => Ok(anchor.clone()),
    }
}

fn open_worker_creation_anchor(
    root_components: &[&[u8]],
    first_creatable: usize,
    expected_uid: u32,
) -> io::Result<std::fs::File> {
    let mut anchor = open_worker_filesystem_root()?;
    verify_worker_creation_ancestor(&anchor, expected_uid)?;
    for component in &root_components[..first_creatable] {
        anchor = open_worker_directory_at(&anchor, component)?;
        verify_worker_creation_ancestor(&anchor, expected_uid)?;
    }
    Ok(anchor)
}

fn open_worker_filesystem_root() -> io::Result<std::fs::File> {
    let descriptor = unsafe {
        libc::open(
            c"/".as_ptr(),
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        )
    };
    if descriptor == -1 {
        return Err(io::Error::last_os_error());
    }
    Ok(unsafe { std::fs::File::from_raw_fd(descriptor) })
}

fn open_existing_worker_path(path: &Path) -> io::Result<std::fs::File> {
    let mut directory = open_worker_filesystem_root()?;
    for component in absolute_worker_components(path)? {
        directory = open_worker_directory_at(&directory, component)?;
    }
    Ok(directory)
}

fn verify_worker_path_identity(
    path: &Path,
    expected: super::WorkerDirectoryIdentity,
) -> io::Result<()> {
    let reopened = open_existing_worker_path(path)?;
    if worker_directory_identity(&reopened)? != expected {
        return Err(permission_denied(
            "worker root pathname changed during layout creation",
        ));
    }
    Ok(())
}

fn open_or_create_worker_directory_at(
    staging_parent: &std::fs::File,
    parent: &std::fs::File,
    name: &[u8],
    may_create: bool,
    expected_uid: u32,
    existing_must_be_canonical: bool,
    unpublished_parent: Option<&CreatorOnlyUnpublishedParent<'_>>,
) -> Result<OpenedWorkerDirectory, WorkerDirectoryOpenError> {
    match open_worker_directory_at(parent, name) {
        Ok(directory) => {
            let created_identity = worker_recovery_candidate_identity(name, &directory)?;
            let active = open_worker_creation_provenance(
                staging_parent,
                parent,
                name,
                created_identity,
                expected_uid,
            )?;
            let retired = open_retired_worker_creation_provenance(
                staging_parent,
                parent,
                name,
                created_identity,
                expected_uid,
            )?;
            if active.is_some() && retired.is_some() {
                return Err(permission_denied(
                    "active and retired worker provenance markers both exist",
                )
                .into());
            }
            if let Some(provenance) = active {
                if let Some(authority) = unpublished_parent {
                    authority.reverify_parent(parent)?;
                    if authority.worker_uid != expected_uid || !existing_must_be_canonical {
                        return Err(permission_denied(
                            "unpublished parent authority does not match the canonical worker child",
                        ).into());
                    }
                    verify_existing_worker_directory(
                        &directory,
                        expected_uid,
                        existing_must_be_canonical,
                    )?;
                    return Ok(OpenedWorkerDirectory {
                        directory,
                        disposition: super::WorkerDirectoryNodeDisposition::Created,
                        provenance: Some(provenance),
                    });
                }
                return Err(permission_denied(
                    "published worker creation provenance is replayable conflict evidence, not receipt ownership",
                ).into());
            }
            drop(retired);
            verify_existing_worker_directory(&directory, expected_uid, existing_must_be_canonical)?;
            return Ok(OpenedWorkerDirectory {
                directory,
                disposition: super::WorkerDirectoryNodeDisposition::Existing,
                provenance: None,
            });
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound && may_create => {
            let active_name = worker_creation_provenance_name(parent, name)?;
            let retired_name = worker_creation_retired_provenance_name(parent, name)?;
            if worker_parent_entry_exists(staging_parent, &active_name)?
                || worker_parent_entry_exists(staging_parent, &retired_name)?
            {
                return Err(permission_denied(
                    "worker creation evidence exists without its exact destination directory",
                )
                .into());
            }
        }
        Err(error) => return Err(error.into()),
    }
    let staged =
        create_unpublished_worker_directory(staging_parent, parent, name, expected_uid, false)
            .map_err(|error| {
                io::Error::new(
                    error.kind(),
                    format!("creating unpublished worker directory failed: {error}"),
                )
            })?;
    publish_staged_worker_directory(
        staging_parent,
        staged,
        parent,
        name,
        expected_uid,
        expected_uid,
        existing_must_be_canonical,
    )
}

fn create_or_open_complete_worker_root(
    root_parent: &std::fs::File,
    root_name: &[u8],
    expected_uid: u32,
) -> io::Result<(
    OpenedWorkerDirectory,
    Option<Vec<Option<OpenedWorkerDirectory>>>,
)> {
    match open_worker_directory_at(root_parent, root_name) {
        Ok(directory) => {
            let created_identity = worker_recovery_candidate_identity(root_name, &directory)?;
            let active = open_worker_creation_provenance(
                root_parent,
                root_parent,
                root_name,
                created_identity,
                expected_uid,
            )?;
            let retired = open_retired_worker_creation_provenance(
                root_parent,
                root_parent,
                root_name,
                created_identity,
                expected_uid,
            )?;
            if active.is_some() && retired.is_some() {
                return Err(permission_denied(
                    "active and retired worker provenance markers both exist",
                ));
            }
            if let Some(provenance) = active {
                drop(provenance);
                return Err(permission_denied(
                    "published worker creation provenance is replayable conflict evidence, not receipt ownership",
                ));
            }
            drop(retired);
            verify_worker_directory_security(&directory, expected_uid)?;
            return Ok((
                OpenedWorkerDirectory {
                    directory,
                    disposition: super::WorkerDirectoryNodeDisposition::Existing,
                    provenance: None,
                },
                None,
            ));
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            let active_name = worker_creation_provenance_name(root_parent, root_name)?;
            let retired_name = worker_creation_retired_provenance_name(root_parent, root_name)?;
            if worker_parent_entry_exists(root_parent, &active_name)?
                || worker_parent_entry_exists(root_parent, &retired_name)?
            {
                return Err(permission_denied(
                    "worker creation evidence exists without its exact destination directory",
                ));
            }
        }
        Err(error) => return Err(error),
    }

    let staged = create_unpublished_worker_directory(
        root_parent,
        root_parent,
        root_name,
        expected_uid,
        true,
    )?;
    maybe_interrupt_worker_mkdir();
    let children_result = {
        let recovery_authority = verify_unpublished_worker_recovery_authority(
            &staged,
            root_parent,
            root_parent,
            root_name,
            expected_uid,
        )?;
        open_or_create_worker_children(
            root_parent,
            &staged.directory,
            expected_uid,
            !staged.created,
            recovery_authority.as_ref(),
        )
    };
    let children = match children_result {
        Ok(children) => children,
        Err(error) => return fail_after_staged_tree_cleanup(error, root_parent, &staged),
    };
    let root = publish_staged_worker_directory(
        root_parent,
        staged,
        root_parent,
        root_name,
        expected_uid,
        expected_uid,
        true,
    )?;
    Ok((root, Some(children)))
}

fn fail_after_staged_tree_cleanup<T>(
    original: io::Error,
    parent: &std::fs::File,
    staged: &StagedWorkerDirectory,
) -> io::Result<T> {
    if !staged.created
        || worker_parent_entry_snapshot(parent)?
            .iter()
            .any(|(name, _)| {
                name.starts_with(b".styrn-worker-provenance-")
                    || name.starts_with(b".styrn-worker-retired-")
            })
    {
        return Err(original);
    }
    match remove_known_staged_worker_tree(parent, staged) {
        Ok(()) => Err(original),
        Err(cleanup) => Err(cleanup),
    }
}

fn open_or_create_worker_children(
    staging_parent: &std::fs::File,
    root: &std::fs::File,
    expected_uid: u32,
    require_provenance_for_existing: bool,
    unpublished_parent: Option<&CreatorOnlyUnpublishedParent<'_>>,
) -> io::Result<Vec<Option<OpenedWorkerDirectory>>> {
    let mut children = Vec::with_capacity(super::WorkerDirectoryLayout::child_names().len());
    for name in super::WorkerDirectoryLayout::child_names() {
        let child = open_or_create_worker_directory_at(
            staging_parent,
            root,
            name.as_bytes(),
            true,
            expected_uid,
            true,
            unpublished_parent,
        )?;
        if require_provenance_for_existing
            && child.disposition == super::WorkerDirectoryNodeDisposition::Existing
        {
            return Err(permission_denied(
                "interrupted worker staging child lacks exact creation provenance",
            ));
        }
        children.push(Some(child));
    }
    Ok(children)
}

fn remove_known_staged_worker_tree(
    parent: &std::fs::File,
    staged: &StagedWorkerDirectory,
) -> io::Result<()> {
    for name in super::WorkerDirectoryLayout::child_names() {
        let canonical =
            CString::new(name).expect("canonical worker child names contain no NUL bytes");
        remove_known_empty_staging_child(&staged.directory, &canonical)?;
        let internal = worker_staging_name(&staged.directory, name.as_bytes())?;
        remove_known_empty_staging_child(&staged.directory, &internal)?;
    }
    remove_exact_empty_staged_worker_directory(parent, staged)
}

fn remove_known_empty_staging_child(parent: &std::fs::File, name: &CString) -> io::Result<()> {
    match open_worker_directory_at(parent, name.to_bytes()) {
        Ok(child) => {
            let expected = worker_directory_identity(&child)?;
            if worker_directory_identity_at(parent, name)? != expected {
                return Err(permission_denied(
                    "worker staging child changed before private cleanup",
                ));
            }
            if unsafe { libc::unlinkat(parent.as_raw_fd(), name.as_ptr(), libc::AT_REMOVEDIR) }
                == -1
            {
                return Err(io::Error::last_os_error());
            }
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(error) => return Err(error),
    }
    Ok(())
}

struct StagedWorkerDirectory {
    name: CString,
    directory: std::fs::File,
    identity: super::WorkerDirectoryIdentity,
    created: bool,
}

fn create_unpublished_worker_directory(
    staging_parent: &std::fs::File,
    destination_parent: &std::fs::File,
    destination_name: &[u8],
    expected_uid: u32,
    allow_canonical_children: bool,
) -> io::Result<StagedWorkerDirectory> {
    let name = worker_staging_name(destination_parent, destination_name)?;
    let entries_before = worker_parent_entry_snapshot(staging_parent)?;
    let created =
        if unsafe { libc::mkdirat(staging_parent.as_raw_fd(), name.as_ptr(), 0o700) } == -1 {
            let error = io::Error::last_os_error();
            if error.kind() != io::ErrorKind::AlreadyExists {
                return Err(worker_directory_open_error(error));
            }
            false
        } else {
            true
        };
    if created {
        #[cfg(test)]
        POST_WORKER_MKDIR_HOOK.with(|slot| {
            if let Some(hook) = slot.take() {
                hook(staging_parent.as_raw_fd(), &name);
            }
        });
    }
    let directory = open_worker_directory_at(staging_parent, name.to_bytes())?;
    let identity = worker_directory_identity(&directory)?;
    if created {
        let mut expected_entries = entries_before;
        expected_entries.push((name.to_bytes().to_vec(), identity));
        expected_entries.sort_by(|left, right| left.0.cmp(&right.0));
        if worker_parent_entry_snapshot(staging_parent)? != expected_entries {
            return Err(permission_denied(
                "new worker staging directory ancestry changed before its first retained handle",
            ));
        }
    }
    let creator_uid = unsafe { libc::geteuid() };
    if created {
        harden_new_worker_directory(&directory, creator_uid)?;
    } else {
        // User scope deliberately does not claim containment against hostile same-UID code.
        // The fixed name still lets an interrupted run retain and validate exact inode state.
        verify_staged_worker_directory_security(&directory, creator_uid, expected_uid)?;
        verify_staged_worker_directory_entries(&directory, allow_canonical_children)?;
    }
    Ok(StagedWorkerDirectory {
        name,
        directory,
        identity,
        created,
    })
}

fn worker_parent_entry_snapshot(
    parent: &std::fs::File,
) -> io::Result<Vec<(Vec<u8>, super::WorkerDirectoryIdentity)>> {
    let duplicate = unsafe { libc::fcntl(parent.as_raw_fd(), libc::F_DUPFD_CLOEXEC, 0) };
    if duplicate == -1 {
        return Err(io::Error::last_os_error());
    }
    let stream = unsafe { libc::fdopendir(duplicate) };
    if stream.is_null() {
        unsafe { libc::close(duplicate) };
        return Err(io::Error::last_os_error());
    }
    let stream = OwnedDirectoryStream(stream);
    unsafe { libc::rewinddir(stream.0) };
    let mut entries = Vec::new();
    loop {
        unsafe { *libc::__error() = 0 };
        let entry = unsafe { libc::readdir(stream.0) };
        if entry.is_null() {
            let error = unsafe { *libc::__error() };
            if error != 0 {
                return Err(io::Error::from_raw_os_error(error));
            }
            break;
        }
        let name = unsafe { std::ffi::CStr::from_ptr((*entry).d_name.as_ptr()) };
        if matches!(name.to_bytes(), b"." | b"..") {
            continue;
        }
        let mut status = unsafe { std::mem::zeroed::<libc::stat>() };
        if unsafe {
            libc::fstatat(
                parent.as_raw_fd(),
                name.as_ptr(),
                &mut status,
                libc::AT_SYMLINK_NOFOLLOW,
            )
        } == -1
        {
            return Err(io::Error::last_os_error());
        }
        entries.push((
            name.to_bytes().to_vec(),
            super::WorkerDirectoryIdentity::from_unix(status.st_dev as u64, status.st_ino as u64),
        ));
    }
    entries.sort_by(|left, right| left.0.cmp(&right.0));
    Ok(entries)
}

fn maybe_interrupt_worker_mkdir() {
    #[cfg(test)]
    WORKER_MKDIR_INTERRUPT_AFTER.with(|slot| {
        if let Some(remaining) = slot.get() {
            if remaining == 0 {
                slot.set(None);
                panic!("injected worker staging interruption");
            }
            slot.set(Some(remaining - 1));
        }
    });
}

fn maybe_interrupt_worker_publication(complete_root: bool, phase: WorkerPublicationInterruption) {
    #[cfg(test)]
    if complete_root {
        WORKER_PUBLICATION_INTERRUPT.with(|slot| {
            if slot.get() == Some(phase) {
                slot.set(None);
                panic!("injected worker publication interruption");
            }
        });
    }
    #[cfg(not(test))]
    let _ = (complete_root, phase);
}

fn worker_staging_name(
    destination_parent: &std::fs::File,
    destination_name: &[u8],
) -> io::Result<CString> {
    use std::fmt::Write;

    let identity = worker_directory_identity(destination_parent)?;
    let mut digest = Sha256::new();
    digest.update(identity.volume.to_le_bytes());
    digest.update(identity.file_id);
    digest.update(destination_name);
    let digest = digest.finalize();
    let mut name = String::from(".styrn-worker-stage-");
    for byte in &digest[..16] {
        write!(&mut name, "{byte:02x}").expect("writing a staging digest cannot fail");
    }
    CString::new(name).map_err(|_| invalid_data("worker staging name contains a NUL byte"))
}

fn verify_staged_worker_directory_security(
    directory: &std::fs::File,
    creator_uid: u32,
    expected_uid: u32,
) -> io::Result<()> {
    let status = worker_directory_status(directory)?;
    if !matches!(status.st_uid, uid if uid == creator_uid || uid == expected_uid)
        || status.st_mode & 0o777 != 0o700
    {
        return Err(permission_denied(
            "reserved worker staging directory has ambiguous ownership or mode",
        ));
    }
    verify_no_extended_acl_fd(directory.as_raw_fd())
}

fn verify_staged_or_published_worker_directory(
    directory: &std::fs::File,
    expected_uid: u32,
) -> io::Result<()> {
    verify_staged_worker_directory_security(directory, unsafe { libc::geteuid() }, expected_uid)
}

struct CreatorOnlyUnpublishedParent<'authority> {
    parent: &'authority std::fs::File,
    identity: super::WorkerDirectoryIdentity,
    staging_parent: &'authority std::fs::File,
    staging_parent_identity: super::WorkerDirectoryIdentity,
    staging_name: CString,
    canonical_parent: &'authority std::fs::File,
    canonical_parent_identity: super::WorkerDirectoryIdentity,
    canonical_name: CString,
    creator_uid: u32,
    worker_uid: u32,
}

impl CreatorOnlyUnpublishedParent<'_> {
    fn reverify_parent(&self, destination_parent: &std::fs::File) -> io::Result<()> {
        if self.creator_uid == self.worker_uid
            || unsafe { libc::geteuid() } != self.creator_uid
            || worker_directory_identity(self.parent)? != self.identity
            || worker_directory_identity(destination_parent)? != self.identity
        {
            return Err(permission_denied(
                "unpublished worker parent authority no longer names the retained directory",
            ));
        }
        if worker_directory_identity(self.staging_parent)? != self.staging_parent_identity
            || worker_directory_identity(self.canonical_parent)? != self.canonical_parent_identity
            || worker_directory_identity_at(self.staging_parent, &self.staging_name).map_err(
                |_| {
                    permission_denied(
                        "unpublished worker parent no longer occupies its retained staging name",
                    )
                },
            )? != self.identity
        {
            return Err(permission_denied(
                "unpublished worker parent no longer occupies its retained staging name",
            ));
        }
        match worker_directory_identity_at(self.canonical_parent, &self.canonical_name) {
            Ok(identity) if identity == self.identity => {
                return Err(permission_denied(
                    "unpublished worker parent was published at its canonical destination",
                ));
            }
            Ok(_) => {}
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(_) => {
                return Err(permission_denied(
                    "canonical worker destination cannot be reverified as absent or different",
                ));
            }
        }
        let status = worker_directory_status(self.parent)?;
        if status.st_uid != self.creator_uid || status.st_mode & 0o777 != 0o700 {
            return Err(permission_denied(
                "unpublished worker parent is no longer creator-only",
            ));
        }
        verify_no_extended_acl_fd(self.parent.as_raw_fd())
    }
}

fn verify_unpublished_worker_recovery_authority<'authority>(
    staged: &'authority StagedWorkerDirectory,
    staging_parent: &'authority std::fs::File,
    canonical_parent: &'authority std::fs::File,
    canonical_name: &[u8],
    expected_uid: u32,
) -> io::Result<Option<CreatorOnlyUnpublishedParent<'authority>>> {
    if staged.created {
        return Ok(None);
    }
    // A reopened inode number is replayable. Recovery is automatic only while
    // this complete candidate is still inaccessible to a distinct worker.
    let creator_uid = unsafe { libc::geteuid() };
    let status = worker_directory_status(&staged.directory)?;
    if creator_uid == expected_uid
        || status.st_uid != creator_uid
        || status.st_mode & 0o777 != 0o700
    {
        return Err(permission_denied(
            "interrupted worker staging recovery lacks distinct creator-only authority",
        ));
    }
    verify_no_extended_acl_fd(staged.directory.as_raw_fd())?;
    if worker_directory_identity(&staged.directory)? != staged.identity {
        return Err(permission_denied(
            "interrupted worker staging parent identity changed",
        ));
    }
    let authority = CreatorOnlyUnpublishedParent {
        parent: &staged.directory,
        identity: staged.identity,
        staging_parent,
        staging_parent_identity: worker_directory_identity(staging_parent)?,
        staging_name: staged.name.clone(),
        canonical_parent,
        canonical_parent_identity: worker_directory_identity(canonical_parent)?,
        canonical_name: CString::new(canonical_name)
            .map_err(|_| invalid_data("worker directory component contains a NUL byte"))?,
        creator_uid,
        worker_uid: expected_uid,
    };
    authority.reverify_parent(&staged.directory)?;
    Ok(Some(authority))
}

fn verify_staged_worker_directory_entries(
    directory: &std::fs::File,
    allow_canonical_children: bool,
) -> io::Result<()> {
    let canonical_names = super::WorkerDirectoryLayout::child_names();
    let internal_names = canonical_names
        .iter()
        .map(|child| worker_staging_name(directory, child.as_bytes()))
        .collect::<io::Result<Vec<_>>>()?;
    let mut canonical_seen = [false; 5];
    let mut internal_seen = [false; 5];
    let duplicate = unsafe { libc::fcntl(directory.as_raw_fd(), libc::F_DUPFD_CLOEXEC, 0) };
    if duplicate == -1 {
        return Err(io::Error::last_os_error());
    }
    let stream = unsafe { libc::fdopendir(duplicate) };
    if stream.is_null() {
        unsafe { libc::close(duplicate) };
        return Err(io::Error::last_os_error());
    }
    let stream = OwnedDirectoryStream(stream);
    loop {
        unsafe { *libc::__error() = 0 };
        let entry = unsafe { libc::readdir(stream.0) };
        if entry.is_null() {
            let error = unsafe { *libc::__error() };
            if error != 0 {
                return Err(io::Error::from_raw_os_error(error));
            }
            break;
        }
        let name = unsafe { std::ffi::CStr::from_ptr((*entry).d_name.as_ptr()) }.to_bytes();
        if matches!(name, b"." | b"..") {
            continue;
        }
        let canonical = canonical_names
            .iter()
            .position(|allowed| allowed.as_bytes() == name);
        let internal = internal_names
            .iter()
            .position(|allowed| allowed.as_bytes() == name);
        let Some((index, staged)) = canonical
            .map(|index| (index, false))
            .or_else(|| internal.map(|index| (index, true)))
        else {
            return Err(permission_denied(
                "reserved worker staging directory contains an unrelated entry",
            ));
        };
        if !allow_canonical_children || canonical_seen[index] || internal_seen[index] {
            return Err(permission_denied(
                "reserved worker staging directory has an ambiguous child state",
            ));
        }
        if staged {
            internal_seen[index] = true;
        } else {
            canonical_seen[index] = true;
        }
    }
    Ok(())
}

struct OwnedDirectoryStream(*mut libc::DIR);

impl Drop for OwnedDirectoryStream {
    fn drop(&mut self) {
        unsafe { libc::closedir(self.0) };
    }
}

fn publish_staged_worker_directory(
    staging_parent: &std::fs::File,
    staged: StagedWorkerDirectory,
    destination_parent: &std::fs::File,
    destination_name: &[u8],
    created_expected_uid: u32,
    existing_expected_uid: u32,
    existing_must_be_canonical: bool,
) -> Result<OpenedWorkerDirectory, WorkerDirectoryOpenError> {
    let complete_root = existing_must_be_canonical
        && worker_directory_identity(staging_parent)?
            == worker_directory_identity(destination_parent)?;
    let destination_name = CString::new(destination_name)
        .map_err(|_| invalid_data("worker directory component contains a NUL byte"))?;
    verify_staged_worker_directory_security(
        &staged.directory,
        unsafe { libc::geteuid() },
        created_expected_uid,
    )?;
    drop(verify_unpublished_worker_recovery_authority(
        &staged,
        staging_parent,
        destination_parent,
        destination_name.to_bytes(),
        created_expected_uid,
    )?);
    let active_provenance = open_worker_creation_provenance(
        staging_parent,
        destination_parent,
        destination_name.to_bytes(),
        staged.identity,
        created_expected_uid,
    )?;
    if open_retired_worker_creation_provenance(
        staging_parent,
        destination_parent,
        destination_name.to_bytes(),
        staged.identity,
        created_expected_uid,
    )?
    .is_some()
    {
        return Err(permission_denied(
            "retired worker provenance conflicts with an unpublished candidate",
        )
        .into());
    }
    let provenance = match active_provenance {
        Some(provenance) => provenance,
        None if staged.created => create_worker_creation_provenance(
            staging_parent,
            destination_parent,
            destination_name.to_bytes(),
            staged.identity,
            created_expected_uid,
        )
        .map_err(|error| {
            io::Error::new(
                error.kind(),
                format!("creating worker provenance failed: {error}"),
            )
        })?,
        None => {
            return Err(permission_denied(
                "interrupted worker staging directory lacks exact creation provenance",
            )
            .into());
        }
    };
    maybe_interrupt_worker_publication(
        complete_root,
        WorkerPublicationInterruption::AfterProvenance,
    );
    if complete_root {
        maybe_interrupt_worker_mkdir();
    }
    if unsafe {
        libc::renameatx_np(
            staging_parent.as_raw_fd(),
            staged.name.as_ptr(),
            destination_parent.as_raw_fd(),
            destination_name.as_ptr(),
            libc::RENAME_EXCL,
        )
    } == 0
    {
        let opened = OpenedWorkerDirectory {
            directory: staged.directory,
            disposition: super::WorkerDirectoryNodeDisposition::Created,
            provenance: Some(provenance),
        };
        let finish = (|| -> io::Result<()> {
            #[cfg(test)]
            fail_worker_node_post_publish_at(super::WorkerNodePostPublishFault::AfterRename)?;
            #[cfg(test)]
            fail_worker_node_post_publish_at(
                super::WorkerNodePostPublishFault::BeforeDestinationReopen,
            )?;
            let reopened =
                open_worker_directory_at(destination_parent, destination_name.to_bytes())?;
            #[cfg(test)]
            fail_worker_node_post_publish_at(
                super::WorkerNodePostPublishFault::BeforeIdentityCheck,
            )?;
            if worker_directory_identity(&reopened)? != staged.identity {
                return Err(permission_denied(
                    "published worker directory identity changed before verification",
                ));
            }
            #[cfg(test)]
            fail_worker_node_post_publish_at(
                super::WorkerNodePostPublishFault::BeforeFirstParentSync,
            )?;
            destination_parent.sync_all().map_err(|error| {
                io::Error::new(
                    error.kind(),
                    format!("syncing worker publication parent failed: {error}"),
                )
            })?;
            if existing_must_be_canonical && !complete_root {
                #[cfg(test)]
                fail_worker_node_post_publish_at(
                    super::WorkerNodePostPublishFault::BeforeHardening,
                )?;
                harden_new_worker_directory(&opened.directory, created_expected_uid)?;
                #[cfg(test)]
                fail_worker_node_post_publish_at(
                    super::WorkerNodePostPublishFault::BeforeNodeSync,
                )?;
                opened.directory.sync_all().map_err(|error| {
                    io::Error::new(
                        error.kind(),
                        format!("syncing published worker directory failed: {error}"),
                    )
                })?;
                #[cfg(test)]
                fail_worker_node_post_publish_at(
                    super::WorkerNodePostPublishFault::BeforeSecondParentSync,
                )?;
                destination_parent.sync_all().map_err(|error| {
                    io::Error::new(
                        error.kind(),
                        format!("syncing worker ownership parent failed: {error}"),
                    )
                })?;
                #[cfg(test)]
                fail_worker_node_post_publish_at(
                    super::WorkerNodePostPublishFault::BeforeSecurityCheck,
                )?;
                verify_worker_directory_security(&opened.directory, created_expected_uid)?;
            } else {
                verify_staged_or_published_worker_directory(
                    &opened.directory,
                    created_expected_uid,
                )?;
            }
            Ok(())
        })();
        return match finish {
            Ok(()) => Ok(opened),
            Err(error) => Err(WorkerDirectoryOpenError::published(error, opened)),
        };
    }
    let error = io::Error::last_os_error();
    if error.kind() != io::ErrorKind::AlreadyExists {
        return Err(error.into());
    }
    let directory = open_worker_directory_at(destination_parent, destination_name.to_bytes())?;
    if worker_directory_identity(&directory)? != staged.identity {
        return Err(permission_denied(
            "worker publication conflict retains exact creation evidence",
        )
        .into());
    }
    verify_staged_or_published_worker_directory(&directory, existing_expected_uid)?;
    if existing_must_be_canonical && !complete_root {
        harden_new_worker_directory(&directory, existing_expected_uid)?;
        verify_existing_worker_directory(
            &directory,
            existing_expected_uid,
            existing_must_be_canonical,
        )?;
    }
    Ok(OpenedWorkerDirectory {
        directory,
        disposition: super::WorkerDirectoryNodeDisposition::Created,
        provenance: Some(provenance),
    })
}

fn worker_directory_identity_at(
    parent: &std::fs::File,
    name: &std::ffi::CStr,
) -> io::Result<super::WorkerDirectoryIdentity> {
    let mut status = unsafe { std::mem::zeroed::<libc::stat>() };
    if unsafe {
        libc::fstatat(
            parent.as_raw_fd(),
            name.as_ptr(),
            &mut status,
            libc::AT_SYMLINK_NOFOLLOW,
        )
    } == -1
    {
        return Err(io::Error::last_os_error());
    }
    if status.st_mode & libc::S_IFMT != libc::S_IFDIR {
        return Err(permission_denied(
            "worker staging path is not a real directory",
        ));
    }
    Ok(super::WorkerDirectoryIdentity::from_unix(
        u64::try_from(status.st_dev)
            .map_err(|_| invalid_data("worker directory device identity is invalid"))?,
        status.st_ino,
    ))
}

fn remove_exact_empty_staged_worker_directory(
    parent: &std::fs::File,
    staged: &StagedWorkerDirectory,
) -> io::Result<()> {
    if worker_directory_identity_at(parent, &staged.name)? != staged.identity {
        return Err(permission_denied(
            "worker staging directory changed before private cleanup",
        ));
    }
    if unsafe { libc::unlinkat(parent.as_raw_fd(), staged.name.as_ptr(), libc::AT_REMOVEDIR) } == -1
    {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

fn verify_existing_worker_directory(
    directory: &std::fs::File,
    expected_uid: u32,
    must_be_canonical: bool,
) -> io::Result<()> {
    if must_be_canonical {
        verify_worker_directory_security(directory, expected_uid)
    } else {
        verify_worker_creation_ancestor(directory, expected_uid)
    }
}

fn harden_new_worker_directory(directory: &std::fs::File, expected_uid: u32) -> io::Result<()> {
    clear_extended_acl_fd(directory.as_raw_fd())?;
    if unsafe { libc::fchown(directory.as_raw_fd(), expected_uid, !0 as libc::gid_t) } == -1 {
        return Err(io::Error::last_os_error());
    }
    if unsafe { libc::fchmod(directory.as_raw_fd(), 0o700) } == -1 {
        return Err(io::Error::last_os_error());
    }
    verify_worker_directory_security(directory, expected_uid)
}

fn clear_extended_acl_fd(descriptor: i32) -> io::Result<()> {
    let acl = unsafe { acl_init(0) };
    if acl.is_null() {
        return Err(io::Error::last_os_error());
    }
    let acl = OwnedAcl(acl);
    if unsafe { acl_set_fd_np(descriptor, acl.0, ACL_TYPE_EXTENDED) } != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

fn verify_worker_directory_security(
    directory: &std::fs::File,
    expected_uid: u32,
) -> io::Result<()> {
    let status = worker_directory_status(directory)?;
    if status.st_uid != expected_uid || status.st_mode & 0o777 != 0o700 {
        return Err(permission_denied(
            "worker directory owner or mode does not match the exact policy",
        ));
    }
    verify_no_extended_acl_fd(directory.as_raw_fd())
}

fn open_worker_directory_at(parent: &std::fs::File, name: &[u8]) -> io::Result<std::fs::File> {
    let name = CString::new(name)
        .map_err(|_| invalid_data("worker directory component contains a NUL byte"))?;
    let descriptor = unsafe {
        libc::openat(
            parent.as_raw_fd(),
            name.as_ptr(),
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        )
    };
    if descriptor == -1 {
        return Err(worker_directory_open_error(io::Error::last_os_error()));
    }
    let directory = unsafe { std::fs::File::from_raw_fd(descriptor) };
    worker_directory_identity(&directory)?;
    Ok(directory)
}

fn worker_directory_identity(
    directory: &std::fs::File,
) -> io::Result<super::WorkerDirectoryIdentity> {
    let status = worker_directory_status(directory)?;
    Ok(super::WorkerDirectoryIdentity::from_unix(
        u64::try_from(status.st_dev)
            .map_err(|_| invalid_data("worker directory device identity is invalid"))?,
        status.st_ino,
    ))
}

fn worker_directory_status(directory: &std::fs::File) -> io::Result<libc::stat> {
    let mut status = unsafe { std::mem::zeroed::<libc::stat>() };
    if unsafe { libc::fstat(directory.as_raw_fd(), &mut status) } == -1 {
        return Err(io::Error::last_os_error());
    }
    if status.st_mode & libc::S_IFMT != libc::S_IFDIR {
        return Err(permission_denied(
            "worker layout path is not a real directory",
        ));
    }
    Ok(status)
}

fn verify_worker_creation_ancestor(directory: &std::fs::File, expected_uid: u32) -> io::Result<()> {
    let status = worker_directory_status(directory)?;
    let creator_uid = unsafe { libc::geteuid() };
    if (expected_uid != creator_uid && status.st_uid == expected_uid)
        || (status.st_uid != 0 && status.st_uid != expected_uid)
        || (status.st_mode & 0o022 != 0
            && !(status.st_uid == 0 && status.st_mode & libc::S_ISVTX != 0))
    {
        return Err(permission_denied(
            "worker root ancestor does not preserve creator authority over unpublished staging",
        ));
    }
    verify_no_extended_allow_acl_fd(directory.as_raw_fd())
        .map_err(|_| permission_denied("worker root ancestor has an untrusted extended ACL"))
}

fn worker_directory_open_error(error: io::Error) -> io::Error {
    match error.raw_os_error() {
        Some(libc::ELOOP | libc::ENOTDIR) => {
            permission_denied("worker layout ancestry contains a link or non-directory component")
        }
        _ => error,
    }
}

#[allow(dead_code)] // Opaque authority retained by SetupExecutionContext.
pub(super) struct UserExecutionToken {
    uid: u32,
    gid: u32,
    supplementary_groups: Vec<libc::gid_t>,
    home: OsString,
    name: String,
    requires_drop: bool,
}

#[cfg(test)]
pub(super) fn test_user_execution_token(principal: &WorkerPrincipal) -> UserExecutionToken {
    let account =
        account_details_for_uid(principal.unix_uid().unwrap(), principal.account_policy()).unwrap();
    UserExecutionToken {
        uid: principal.unix_uid().unwrap(),
        gid: account.gid,
        supplementary_groups: current_supplementary_groups().unwrap(),
        home: account.home,
        name: principal.name().to_owned(),
        requires_drop: false,
    }
}

pub(super) fn capture_setup_execution_context() -> io::Result<SetupExecutionContext> {
    let caller = UnixCallerIds::new(
        unsafe { libc::getuid() },
        unsafe { libc::geteuid() },
        unsafe { libc::getgid() },
        unsafe { libc::getegid() },
    );
    let mut original_name = None;
    let selected = super::select_unix_execution(caller, || {
        let (identity, name) = super::parse_sudo_origin_entries(std::env::vars_os())?;
        original_name = Some(name);
        Ok(identity)
    })?;
    let account = account_details_for_uid(selected.uid, WorkerAccountPolicy::CurrentUser)?;
    if account.gid != selected.gid
        || (selected.privilege == SetupHostPrivilege::Root
            && original_name.as_deref() != Some(account.principal.name()))
    {
        return Err(permission_denied(
            "sudo original uid, gid, and account name do not identify one native user",
        ));
    }
    let supplementary_groups = if selected.privilege == SetupHostPrivilege::Root {
        supplementary_groups(account.principal.name(), account.gid)?
    } else {
        current_supplementary_groups()?
    };
    Ok(SetupExecutionContext::new(
        selected.privilege,
        account.principal.clone(),
        UserExecutionToken {
            uid: selected.uid,
            gid: selected.gid,
            supplementary_groups,
            home: account.home,
            name: account.principal.name().to_owned(),
            requires_drop: selected.privilege == SetupHostPrivilege::Root,
        },
    ))
}

pub(super) fn invoke_setup_authorization(
    executable: &Path,
    request_path: &Path,
    request_digest: &str,
) -> io::Result<std::process::ExitStatus> {
    let current = std::env::current_exe()?;
    let executable = super::verify_setup_authorization_executable(executable)?;
    let invocation =
        super::unix_authorization_invocation(&executable, request_path, request_digest, &current)?;
    std::process::Command::new(invocation.program)
        .args(invocation.arguments)
        .status()
}

pub(super) fn verify_setup_authorization_path_security(path: &Path) -> io::Result<()> {
    verify_no_extended_acl(path)
}

pub(super) fn run_user_phase(
    token: &UserExecutionToken,
    request: &[u8],
) -> io::Result<std::process::ExitStatus> {
    if request.len() > 64 * 1024 {
        return Err(invalid_data("setup user-phase request is too large"));
    }
    validate_user_execution_token(token)?;
    let mut command = std::process::Command::new(std::env::current_exe()?);
    command.args(["setup", "user-phase"]);
    configure_original_user_command(token, &mut command)?;
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "native Unix user-phase protocol execution is unavailable in this build",
    ))
}

#[cfg(test)]
pub(super) fn run_test_program_as_original(
    token: &UserExecutionToken,
    program: &Path,
    arguments: &[&str],
) -> io::Result<std::process::Output> {
    let mut command = std::process::Command::new(program);
    command.args(arguments);
    configure_original_user_command(token, &mut command)?;
    command.output()
}

#[allow(dead_code)] // Explicit system-account selection is exercised by environmental gates.
pub(super) fn resolve_named_worker_principal(
    name: &str,
    account_policy: WorkerAccountPolicy,
) -> io::Result<WorkerPrincipal> {
    let uid = lookup_worker_uid(name)?;
    let principal = principal_for_uid(uid, account_policy)?;
    if principal.name() != name {
        return Err(permission_denied(
            "worker account name does not match its native uid",
        ));
    }
    Ok(principal)
}

pub(super) fn verify_worker_principal(principal: &WorkerPrincipal) -> io::Result<()> {
    if principal.principal_kind() != PrincipalKind::UnixUid {
        return Err(invalid_data("worker principal kind does not match Unix"));
    }
    let current = principal_for_uid(principal.unix_uid()?, principal.account_policy())?;
    if &current != principal {
        return Err(permission_denied("worker uid/name identity drift detected"));
    }
    Ok(())
}

pub(super) fn dedicated_account_name_is_valid(name: &str) -> bool {
    name.len() <= 255
}

pub(super) fn inspect_dedicated_account(
    spec: &super::DedicatedAccountSpec,
    home_observation: super::NativeDedicatedAccountInspection,
) -> super::NativeDedicatedAccountObservation {
    let identity = match local_identity(spec.name(), CS_IDENTITY_CLASS_USER) {
        Ok(Some(identity)) => identity,
        Ok(None) => return super::NativeDedicatedAccountObservation::Absent,
        Err(_) => return super::NativeDedicatedAccountObservation::Unknowable,
    };
    let uid = unsafe { CSIdentityGetPosixID(identity.0) };
    if uid == 0 {
        return super::NativeDedicatedAccountObservation::PresentBroken;
    }
    let posix_name = match cf_string_to_string(unsafe { CSIdentityGetPosixName(identity.0) }) {
        Ok(name) => name,
        Err(_) => return super::NativeDedicatedAccountObservation::Unknowable,
    };
    let local_uid = match lookup_worker_uid(spec.name()) {
        Ok(uid) => uid,
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            return super::NativeDedicatedAccountObservation::PresentBroken;
        }
        Err(_) => return super::NativeDedicatedAccountObservation::Unknowable,
    };
    let account = match account_details_for_uid(uid, WorkerAccountPolicy::Dedicated) {
        Ok(account) => account,
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            return super::NativeDedicatedAccountObservation::PresentBroken;
        }
        Err(_) => return super::NativeDedicatedAccountObservation::Unknowable,
    };
    let groups = match supplementary_groups(account.principal.name(), account.gid) {
        Ok(groups) => groups,
        Err(_) => return super::NativeDedicatedAccountObservation::Unknowable,
    };
    let admin = match local_identity("admin", CS_IDENTITY_CLASS_GROUP) {
        Ok(Some(admin)) => unsafe { CSIdentityIsMemberOfGroup(identity.0, admin.0) != 0 },
        Ok(None) | Err(_) => return super::NativeDedicatedAccountObservation::Unknowable,
    };
    let home = PathBuf::from(account.home);
    let home_state = inspect_dedicated_home(&home, uid);
    classify_dedicated_account_record(
        spec,
        MacDedicatedAccountRecord {
            principal: account.principal,
            is_local_user: unsafe { CSIdentityGetClass(identity.0) } == CS_IDENTITY_CLASS_USER
                && local_uid == uid
                && posix_name == spec.name(),
            is_enabled: unsafe { CSIdentityIsEnabled(identity.0) != 0 },
            is_hidden: unsafe { CSIdentityIsHidden(identity.0) != 0 },
            is_administrator: admin,
            primary_gid: account.gid,
            supplementary_groups: groups,
            home,
            shell: PathBuf::from(account.shell),
            home_state,
        },
        home_observation,
    )
}

const CS_IDENTITY_CLASS_USER: isize = 1;
const CS_IDENTITY_CLASS_GROUP: isize = 2;
const CS_IDENTITY_QUERY_STRING_EQUALS: isize = 1;
const CS_IDENTITY_QUERY_INCLUDE_HIDDEN: usize = 0x0002;
const CF_STRING_ENCODING_UTF8: u32 = 0x0800_0100;

struct OwnedCoreFoundation(*const c_void);

impl Drop for OwnedCoreFoundation {
    fn drop(&mut self) {
        if !self.0.is_null() {
            unsafe { CFRelease(self.0) };
        }
    }
}

fn local_identity(name: &str, class: isize) -> io::Result<Option<OwnedCoreFoundation>> {
    let name = cf_string(name)?;
    let authority = unsafe { CSGetLocalIdentityAuthority() };
    if authority.is_null() {
        return Err(io::Error::other(
            "native local identity authority is unavailable",
        ));
    }
    let query = unsafe {
        CSIdentityQueryCreateForName(
            std::ptr::null(),
            name.0,
            CS_IDENTITY_QUERY_STRING_EQUALS,
            class,
            authority,
        )
    };
    if query.is_null() {
        return Err(io::Error::other(
            "native local identity query is unavailable",
        ));
    }
    let query = OwnedCoreFoundation(query);
    let mut native_error = std::ptr::null();
    if unsafe {
        CSIdentityQueryExecute(query.0, CS_IDENTITY_QUERY_INCLUDE_HIDDEN, &mut native_error)
    } == 0
    {
        if !native_error.is_null() {
            unsafe { CFRelease(native_error) };
        }
        return Err(io::Error::other("native local identity query failed"));
    }
    let results = unsafe { CSIdentityQueryCopyResults(query.0) };
    if results.is_null() {
        return Err(io::Error::other(
            "native local identity query returned no result set",
        ));
    }
    let results = OwnedCoreFoundation(results);
    let mut exact = None;
    let count = unsafe { CFArrayGetCount(results.0) };
    for index in 0..count {
        let identity = unsafe { CFArrayGetValueAtIndex(results.0, index) };
        if identity.is_null()
            || unsafe { CSIdentityGetClass(identity) } != class
            || cf_string_to_string(unsafe { CSIdentityGetPosixName(identity) })?
                != name_from_cf(&name)?
        {
            continue;
        }
        if exact.is_some() {
            return Err(io::Error::other(
                "native local identity query was ambiguous",
            ));
        }
        exact = Some(OwnedCoreFoundation(unsafe { CFRetain(identity) }));
    }
    Ok(exact)
}

fn cf_string(value: &str) -> io::Result<OwnedCoreFoundation> {
    let string = unsafe {
        CFStringCreateWithBytes(
            std::ptr::null(),
            value.as_ptr(),
            value
                .len()
                .try_into()
                .map_err(|_| invalid_data("native local identity name length is out of range"))?,
            CF_STRING_ENCODING_UTF8,
            0,
        )
    };
    if string.is_null() {
        return Err(io::Error::other(
            "native local identity name allocation failed",
        ));
    }
    Ok(OwnedCoreFoundation(string))
}

fn name_from_cf(value: &OwnedCoreFoundation) -> io::Result<String> {
    cf_string_to_string(value.0)
}

fn cf_string_to_string(value: *const c_void) -> io::Result<String> {
    if value.is_null() {
        return Err(invalid_data("native local identity name is unavailable"));
    }
    let length = unsafe { CFStringGetLength(value) };
    let maximum = unsafe { CFStringGetMaximumSizeForEncoding(length, CF_STRING_ENCODING_UTF8) };
    if !(0..=4096).contains(&maximum) {
        return Err(invalid_data("native local identity name length is invalid"));
    }
    let mut bytes = vec![0_u8; maximum as usize + 1];
    if unsafe {
        CFStringGetCString(
            value,
            bytes.as_mut_ptr().cast(),
            bytes.len().try_into().unwrap_or(isize::MAX),
            CF_STRING_ENCODING_UTF8,
        )
    } == 0
    {
        return Err(invalid_data("native local identity name is invalid"));
    }
    let end = bytes
        .iter()
        .position(|byte| *byte == 0)
        .unwrap_or(bytes.len());
    String::from_utf8(bytes[..end].to_vec())
        .map_err(|_| invalid_data("native local identity name is not UTF-8"))
}

fn inspect_dedicated_home(path: &Path, expected_uid: u32) -> DedicatedHomeState {
    let metadata = match fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            return DedicatedHomeState::Missing;
        }
        Err(_) => return DedicatedHomeState::Unknowable,
    };
    if !metadata.file_type().is_dir()
        || metadata.uid() != expected_uid
        || metadata.permissions().mode() & 0o022 != 0
    {
        return DedicatedHomeState::Unsafe;
    }
    if let Some(issue) = dedicated_home_acl_issue(inspect_extended_acl(path)) {
        return issue;
    }
    match fs::read_dir(path) {
        Ok(mut entries) => match entries.next() {
            None => DedicatedHomeState::EmptySafe,
            Some(Ok(_)) => DedicatedHomeState::PopulatedSafe,
            Some(Err(_)) => DedicatedHomeState::Unknowable,
        },
        Err(_) => DedicatedHomeState::Unknowable,
    }
}

fn dedicated_home_acl_issue(observation: io::Result<bool>) -> Option<DedicatedHomeState> {
    match observation {
        Ok(false) => None,
        Ok(true) => Some(DedicatedHomeState::Unsafe),
        Err(_) => Some(DedicatedHomeState::Unknowable),
    }
}

#[link(name = "CoreFoundation", kind = "framework")]
unsafe extern "C" {
    fn CFRetain(value: *const c_void) -> *const c_void;
    fn CFRelease(value: *const c_void);
    fn CFArrayGetCount(array: *const c_void) -> isize;
    fn CFArrayGetValueAtIndex(array: *const c_void, index: isize) -> *const c_void;
    fn CFStringCreateWithBytes(
        allocator: *const c_void,
        bytes: *const u8,
        length: isize,
        encoding: u32,
        is_external_representation: u8,
    ) -> *const c_void;
    fn CFStringGetLength(string: *const c_void) -> isize;
    fn CFStringGetMaximumSizeForEncoding(length: isize, encoding: u32) -> isize;
    fn CFStringGetCString(
        string: *const c_void,
        buffer: *mut i8,
        buffer_size: isize,
        encoding: u32,
    ) -> u8;
}

#[link(name = "CoreServices", kind = "framework")]
unsafe extern "C" {
    fn CSGetLocalIdentityAuthority() -> *const c_void;
    fn CSIdentityQueryCreateForName(
        allocator: *const c_void,
        name: *const c_void,
        comparison_method: isize,
        identity_class: isize,
        authority: *const c_void,
    ) -> *const c_void;
    fn CSIdentityQueryExecute(query: *const c_void, flags: usize, error: *mut *const c_void) -> u8;
    fn CSIdentityQueryCopyResults(query: *const c_void) -> *const c_void;
    fn CSIdentityGetClass(identity: *const c_void) -> isize;
    fn CSIdentityGetPosixID(identity: *const c_void) -> u32;
    fn CSIdentityGetPosixName(identity: *const c_void) -> *const c_void;
    fn CSIdentityIsMemberOfGroup(identity: *const c_void, group: *const c_void) -> u8;
    fn CSIdentityIsHidden(identity: *const c_void) -> u8;
    fn CSIdentityIsEnabled(identity: *const c_void) -> u8;
}

#[derive(Clone, Copy, Eq, PartialEq)]
enum DedicatedHomeState {
    Missing,
    EmptySafe,
    PopulatedSafe,
    Unsafe,
    Unknowable,
}

#[derive(Clone)]
struct MacDedicatedAccountRecord {
    principal: WorkerPrincipal,
    is_local_user: bool,
    is_enabled: bool,
    is_hidden: bool,
    is_administrator: bool,
    primary_gid: u32,
    supplementary_groups: Vec<libc::gid_t>,
    home: PathBuf,
    shell: PathBuf,
    home_state: DedicatedHomeState,
}

fn classify_dedicated_account_record(
    spec: &super::DedicatedAccountSpec,
    record: MacDedicatedAccountRecord,
    home_observation: super::NativeDedicatedAccountInspection,
) -> super::NativeDedicatedAccountObservation {
    if record.home_state == DedicatedHomeState::Unknowable {
        return super::NativeDedicatedAccountObservation::Unknowable;
    }
    let expected_home = Path::new("/Users").join(spec.name());
    let supported_shell = matches!(record.shell.to_str(), Some("/bin/zsh" | "/bin/bash"));
    let privileged_group = record.primary_gid == 0
        || record.primary_gid == 80
        || record
            .supplementary_groups
            .iter()
            .any(|group| matches!(*group, 0 | 80));
    let home_is_safe = match (home_observation, record.home_state) {
        (_, DedicatedHomeState::EmptySafe)
        | (
            super::NativeDedicatedAccountInspection::Established,
            DedicatedHomeState::PopulatedSafe,
        ) => true,
        (_, DedicatedHomeState::Missing | DedicatedHomeState::Unsafe)
        | (super::NativeDedicatedAccountInspection::Initial, DedicatedHomeState::PopulatedSafe) => {
            false
        }
        (_, DedicatedHomeState::Unknowable) => unreachable!(),
    };
    if record.principal.principal_kind() != PrincipalKind::UnixUid
        || record.principal.account_policy() != WorkerAccountPolicy::Dedicated
        || record.principal.name() != spec.name()
        || !record.is_local_user
        || !record.is_enabled
        || record.is_hidden
        || record.is_administrator
        || privileged_group
        || record.home != expected_home
        || !supported_shell
        || !home_is_safe
    {
        return super::NativeDedicatedAccountObservation::PresentBroken;
    }
    super::NativeDedicatedAccountObservation::PresentHealthy(record.principal)
}

fn principal_for_uid(uid: u32, account_policy: WorkerAccountPolicy) -> io::Result<WorkerPrincipal> {
    account_for_uid(uid, account_policy).map(|(principal, _)| principal)
}

fn account_for_uid(
    uid: u32,
    account_policy: WorkerAccountPolicy,
) -> io::Result<(WorkerPrincipal, u32)> {
    let account = account_details_for_uid(uid, account_policy)?;
    Ok((account.principal, account.gid))
}

struct UnixAccountDetails {
    principal: WorkerPrincipal,
    gid: u32,
    home: OsString,
    shell: OsString,
}

fn account_details_for_uid(
    uid: u32,
    account_policy: WorkerAccountPolicy,
) -> io::Result<UnixAccountDetails> {
    if uid == 0 {
        return Err(permission_denied("root cannot be a worker principal"));
    }
    let mut entry = unsafe { std::mem::zeroed::<libc::passwd>() };
    let mut result = std::ptr::null_mut();
    let mut buffer = vec![0_u8; 16 * 1024];
    let status = unsafe {
        libc::getpwuid_r(
            uid,
            &mut entry,
            buffer.as_mut_ptr().cast(),
            buffer.len(),
            &mut result,
        )
    };
    if status != 0 {
        return Err(io::Error::from_raw_os_error(status));
    }
    if result.is_null()
        || entry.pw_name.is_null()
        || entry.pw_dir.is_null()
        || entry.pw_shell.is_null()
    {
        return Err(io::Error::new(
            io::ErrorKind::NotFound,
            "worker uid has no native account mapping",
        ));
    }
    let name = unsafe { std::ffi::CStr::from_ptr(entry.pw_name) }
        .to_str()
        .map_err(|_| invalid_data("worker account name is not UTF-8"))?;
    let home = OsString::from_vec(
        unsafe { std::ffi::CStr::from_ptr(entry.pw_dir) }
            .to_bytes()
            .to_vec(),
    );
    let shell = OsString::from_vec(
        unsafe { std::ffi::CStr::from_ptr(entry.pw_shell) }
            .to_bytes()
            .to_vec(),
    );
    if !Path::new(&home).is_absolute() {
        return Err(invalid_data("worker home directory is not absolute"));
    }
    Ok(UnixAccountDetails {
        principal: WorkerPrincipal::new(
            PrincipalKind::UnixUid,
            uid.to_string(),
            name,
            account_policy,
        )?,
        gid: entry.pw_gid,
        home,
        shell,
    })
}

fn supplementary_groups(name: &str, primary_gid: u32) -> io::Result<Vec<libc::gid_t>> {
    let name = CString::new(name).map_err(|_| invalid_data("worker account name contains NUL"))?;
    let primary_group = i32::try_from(primary_gid)
        .map_err(|_| invalid_data("worker primary group is out of range"))?;
    let mut count = 16;
    let mut native_groups = vec![0_i32; count as usize];
    if unsafe {
        libc::getgrouplist(
            name.as_ptr(),
            primary_group,
            native_groups.as_mut_ptr(),
            &mut count,
        )
    } == -1
    {
        if !(17..=1024).contains(&count) {
            return Err(permission_denied(
                "worker supplementary group set is invalid",
            ));
        }
        native_groups.resize(count as usize, 0);
        if unsafe {
            libc::getgrouplist(
                name.as_ptr(),
                primary_group,
                native_groups.as_mut_ptr(),
                &mut count,
            )
        } == -1
        {
            return Err(io::Error::last_os_error());
        }
    }
    if !(1..=1024).contains(&count) {
        return Err(permission_denied(
            "worker supplementary group set is invalid",
        ));
    }
    native_groups.truncate(count as usize);
    let mut groups = native_groups
        .into_iter()
        .map(|group| {
            libc::gid_t::try_from(group)
                .map_err(|_| invalid_data("worker supplementary group is out of range"))
        })
        .collect::<io::Result<Vec<_>>>()?;
    groups.retain(|group| *group != primary_gid);
    groups.sort_unstable();
    groups.dedup();
    Ok(groups)
}

fn current_supplementary_groups() -> io::Result<Vec<libc::gid_t>> {
    let count = unsafe { libc::getgroups(0, std::ptr::null_mut()) };
    if !(0..=1024).contains(&count) {
        return Err(permission_denied(
            "current supplementary group set is invalid",
        ));
    }
    let mut groups = vec![0; count as usize];
    if count != 0 && unsafe { libc::getgroups(count, groups.as_mut_ptr()) } != count {
        return Err(io::Error::last_os_error());
    }
    groups.sort_unstable();
    groups.dedup();
    Ok(groups)
}

fn validate_user_execution_token(token: &UserExecutionToken) -> io::Result<()> {
    if token.uid == 0
        || token.name.is_empty()
        || !Path::new(&token.home).is_absolute()
        || token.supplementary_groups.len() > 1024
    {
        return Err(permission_denied(
            "original-user execution token is invalid",
        ));
    }
    Ok(())
}

fn configure_original_user_command(
    token: &UserExecutionToken,
    command: &mut std::process::Command,
) -> io::Result<()> {
    validate_user_execution_token(token)?;
    command.env_clear();
    command.env("HOME", &token.home);
    command.env("USER", &token.name);
    command.env("LOGNAME", &token.name);
    command.env("PATH", "/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin");
    command.current_dir(&token.home);
    let uid = token.uid;
    let gid = token.gid;
    let groups = token.supplementary_groups.clone();
    let requires_drop = token.requires_drop;
    let mut observed_groups = vec![0; 1024];
    unsafe {
        command.pre_exec(move || {
            if requires_drop
                && (libc::setgroups(groups.len() as i32, groups.as_ptr()) != 0
                    || libc::setgid(gid) != 0
                    || libc::setuid(uid) != 0)
            {
                return Err(io::Error::last_os_error());
            }
            if libc::getuid() != uid
                || libc::geteuid() != uid
                || libc::getgid() != gid
                || libc::getegid() != gid
            {
                return Err(io::Error::from_raw_os_error(libc::EPERM));
            }
            let group_count = libc::getgroups(1024, observed_groups.as_mut_ptr());
            if group_count < 0 {
                return Err(io::Error::last_os_error());
            }
            let observed = &mut observed_groups[..group_count as usize];
            observed.sort_unstable();
            if observed != groups.as_slice() {
                return Err(io::Error::from_raw_os_error(libc::EPERM));
            }
            if requires_drop && libc::seteuid(0) == 0 {
                return Err(io::Error::from_raw_os_error(libc::EPERM));
            }
            Ok(())
        });
    }
    Ok(())
}

pub(super) fn create_private_manifest_staging_directory(
    path: &Path,
    _owner: ManifestOwner,
    _principal: &WorkerPrincipal,
) -> io::Result<()> {
    let mut builder = fs::DirBuilder::new();
    builder.mode(0o700).create(path)
}

pub(super) fn harden_manifest_directory(
    path: &Path,
    owner: ManifestOwner,
    _worker: &WorkerPrincipal,
) -> io::Result<()> {
    require_real_directory(path)?;
    clear_extended_acl(path)?;
    apply_owner(path, owner)?;
    let mode = if matches!(owner, ManifestOwner::User) {
        0o700
    } else {
        0o755
    };
    fs::set_permissions(path, fs::Permissions::from_mode(mode))?;
    verify_directory(path, owner, _worker)
}

pub(super) fn harden_manifest_file(
    path: &Path,
    owner: ManifestOwner,
    _worker: &WorkerPrincipal,
) -> io::Result<()> {
    require_regular_file(path)?;
    clear_extended_acl(path)?;
    apply_owner(path, owner)?;
    let mode = if matches!(owner, ManifestOwner::User) {
        0o600
    } else {
        0o644
    };
    fs::set_permissions(path, fs::Permissions::from_mode(mode))?;
    verify_file(path, owner, _worker, mode, "manifest")
}

pub(super) fn open_manifest_lock(
    path: &Path,
    owner: ManifestOwner,
    principal: &WorkerPrincipal,
) -> io::Result<fs::File> {
    let created = create_private_file(path, owner, principal);
    let file = match created {
        Ok(file) => file,
        Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {
            verify_private_file_security(path, owner, principal)?;
            fs::OpenOptions::new().read(true).write(true).open(path)?
        }
        Err(error) => return Err(error),
    };
    verify_private_file_security(path, owner, principal)?;
    Ok(file)
}

pub(super) fn verify_private_file_security(
    path: &Path,
    owner: ManifestOwner,
    principal: &WorkerPrincipal,
) -> io::Result<()> {
    verify_file(path, owner, principal, 0o600, "private store file")?;
    verify_no_extended_acl(path)
}

pub(super) fn create_private_file(
    path: &Path,
    _owner: ManifestOwner,
    _principal: &WorkerPrincipal,
) -> io::Result<fs::File> {
    let file = fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)?;
    clear_extended_acl_fd(file.as_raw_fd())?;
    if unsafe { libc::fchmod(file.as_raw_fd(), 0o600) } == -1 {
        return Err(io::Error::last_os_error());
    }
    Ok(file)
}

#[allow(dead_code)] // Reached by the controller identity consumer on native macOS.
pub(super) fn lock_controller_identity_file(file: &fs::File) -> io::Result<()> {
    if unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX) } == -1 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

pub(super) fn private_file_identity(path: &Path) -> io::Result<PrivateFileIdentity> {
    let metadata = fs::symlink_metadata(path)?;
    if !metadata.is_file() {
        return Err(permission_denied(
            "private store target is not a regular file",
        ));
    }
    Ok(PrivateFileIdentity::new(metadata.dev(), metadata.ino()))
}

#[allow(dead_code)] // Consumed through the deferred T0.13 publication adapter.
pub(super) fn private_file_identity_from_handle(
    file: &std::fs::File,
) -> io::Result<PrivateFileIdentity> {
    let metadata = file.metadata()?;
    if !metadata.is_file() {
        return Err(permission_denied(
            "private publication handle is not a regular file",
        ));
    }
    Ok(PrivateFileIdentity::new(metadata.dev(), metadata.ino()))
}

#[allow(dead_code)] // Consumed through the deferred T0.13 publication adapter.
pub(super) fn verify_private_file_handle_security(
    file: &std::fs::File,
    owner: ManifestOwner,
    principal: &WorkerPrincipal,
) -> io::Result<()> {
    let metadata = file.metadata()?;
    if !metadata.is_file() {
        return Err(permission_denied(
            "private publication handle is not a regular file",
        ));
    }
    let expected_uid = match owner {
        ManifestOwner::System => 0,
        ManifestOwner::User => principal.unix_uid()?,
        #[cfg(test)]
        ManifestOwner::CurrentProcess | ManifestOwner::CurrentProcessWorker => metadata.uid(),
    };
    if metadata.uid() != expected_uid || metadata.mode() & 0o777 != 0o600 {
        return Err(permission_denied(
            "private publication handle ownership or mode is insecure",
        ));
    }
    verify_no_extended_acl_fd(file.as_raw_fd())
}

#[allow(dead_code)] // Consumed through the deferred T0.13 publication adapter.
pub(super) fn publish_private_file_no_replace(
    file: &std::fs::File,
    temporary: &Path,
    destination: &Path,
    owner: ManifestOwner,
    principal: &WorkerPrincipal,
    expected_identity: PrivateFileIdentity,
) -> io::Result<()> {
    if private_file_identity_from_handle(file)? != expected_identity {
        return Err(permission_denied(
            "private publication handle identity changed",
        ));
    }
    drop(open_verified_private_file_for_read(
        temporary,
        owner,
        principal,
        expected_identity,
    )?);
    std::fs::hard_link(temporary, destination)?;
    let parent = destination
        .parent()
        .ok_or_else(|| invalid_data("private publication destination has no parent"))?;
    std::fs::File::open(parent)?.sync_all()?;
    drop(open_verified_private_file_for_read(
        destination,
        owner,
        principal,
        expected_identity,
    )?);
    let removal =
        prepare_verified_private_file_removal(temporary, owner, principal, expected_identity)?;
    consume_verified_private_file(removal)?;
    std::fs::File::open(parent)?.sync_all()
}

pub(super) fn open_verified_private_file_for_read(
    path: &Path,
    owner: ManifestOwner,
    principal: &WorkerPrincipal,
    expected_identity: PrivateFileIdentity,
) -> io::Result<fs::File> {
    use std::os::fd::AsRawFd;

    let file = fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK)
        .open(path)?;
    let metadata = file.metadata()?;
    if !metadata.is_file()
        || PrivateFileIdentity::new(metadata.dev(), metadata.ino()) != expected_identity
    {
        return Err(permission_denied(
            "private store target identity or type changed",
        ));
    }
    let expected_uid = match owner {
        ManifestOwner::System => 0,
        ManifestOwner::User => principal.unix_uid()?,
        #[cfg(test)]
        ManifestOwner::CurrentProcess | ManifestOwner::CurrentProcessWorker => metadata.uid(),
    };
    if metadata.uid() != expected_uid || metadata.mode() & 0o777 != 0o600 {
        return Err(permission_denied(
            "private store file ownership or mode is insecure",
        ));
    }
    verify_no_extended_acl_fd(file.as_raw_fd())?;
    Ok(file)
}

pub(super) fn open_verified_private_file_for_append(
    path: &Path,
    owner: ManifestOwner,
    principal: &WorkerPrincipal,
    expected_identity: PrivateFileIdentity,
) -> io::Result<fs::File> {
    let file = fs::OpenOptions::new()
        .read(true)
        .append(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK)
        .open(path)?;
    if private_file_identity_from_handle(&file)? != expected_identity {
        return Err(permission_denied("private append target identity changed"));
    }
    verify_private_file_handle_security(&file, owner, principal)?;
    Ok(file)
}

pub(crate) struct PrivateFileRemoval {
    parent: fs::File,
    leaf: CString,
    expected_identity: PrivateFileIdentity,
}

pub(super) fn prepare_verified_private_file_removal(
    path: &Path,
    owner: ManifestOwner,
    principal: &WorkerPrincipal,
    expected_identity: PrivateFileIdentity,
) -> io::Result<PrivateFileRemoval> {
    let parent_path = path
        .parent()
        .ok_or_else(|| invalid_data("private file has no parent directory"))?;
    let leaf = path
        .file_name()
        .ok_or_else(|| invalid_data("private file has no leaf name"))?;
    let leaf = CString::new(leaf.as_bytes())
        .map_err(|_| invalid_data("private file leaf contains a NUL byte"))?;
    let parent = fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(parent_path)?;
    let parent_metadata = parent.metadata()?;
    let expected_uid = match owner {
        ManifestOwner::System => 0,
        ManifestOwner::User => principal.unix_uid()?,
        #[cfg(test)]
        ManifestOwner::CurrentProcess | ManifestOwner::CurrentProcessWorker => unsafe {
            libc::geteuid()
        },
    };
    if !parent_metadata.is_dir()
        || parent_metadata.uid() != expected_uid
        || !super::private_file_parent_mode_is_valid(owner, parent_metadata.mode())
    {
        return Err(permission_denied(
            "private file parent ownership or mode is insecure",
        ));
    }
    verify_no_extended_acl_fd(parent.as_raw_fd())?;
    verify_private_file_at(parent.as_raw_fd(), &leaf, expected_uid, expected_identity)?;
    Ok(PrivateFileRemoval {
        parent,
        leaf,
        expected_identity,
    })
}

pub(super) fn consume_verified_private_file(removal: PrivateFileRemoval) -> io::Result<()> {
    let parent = removal.parent.as_raw_fd();
    let expected_uid = unsafe {
        let mut stat = std::mem::zeroed::<libc::stat>();
        if libc::fstatat(
            parent,
            removal.leaf.as_ptr(),
            &mut stat,
            libc::AT_SYMLINK_NOFOLLOW,
        ) == -1
        {
            return Err(io::Error::last_os_error());
        }
        stat.st_uid
    };
    verify_private_file_at(
        parent,
        &removal.leaf,
        expected_uid,
        removal.expected_identity,
    )?;
    let tombstone = CString::new(format!(".styrn-consumed-{}", uuid::Uuid::now_v7()))
        .expect("UUID tombstone names contain no NUL bytes");
    if unsafe {
        libc::renameatx_np(
            parent,
            removal.leaf.as_ptr(),
            parent,
            tombstone.as_ptr(),
            libc::RENAME_EXCL,
        )
    } == -1
    {
        return Err(io::Error::last_os_error());
    }
    verify_private_file_at(parent, &tombstone, expected_uid, removal.expected_identity)?;
    if unsafe { libc::unlinkat(parent, tombstone.as_ptr(), 0) } == -1 {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}

fn verify_private_file_at(
    parent: libc::c_int,
    leaf: &CString,
    expected_uid: u32,
    expected_identity: PrivateFileIdentity,
) -> io::Result<()> {
    let mut stat = unsafe { std::mem::zeroed::<libc::stat>() };
    if unsafe { libc::fstatat(parent, leaf.as_ptr(), &mut stat, libc::AT_SYMLINK_NOFOLLOW) } == -1 {
        return Err(io::Error::last_os_error());
    }
    if stat.st_mode & libc::S_IFMT != libc::S_IFREG
        || PrivateFileIdentity::new(stat.st_dev as u64, stat.st_ino as u64) != expected_identity
        || stat.st_uid != expected_uid
        || stat.st_mode & 0o777 != 0o600
    {
        return Err(permission_denied(
            "private file identity, ownership, or mode changed before consumption",
        ));
    }
    Ok(())
}

pub(super) fn verify_manifest_security(
    path: &Path,
    owner: ManifestOwner,
    worker: &WorkerPrincipal,
    trusted_root: &Path,
) -> io::Result<()> {
    let parent = path
        .parent()
        .ok_or_else(|| invalid_data("manifest path has no parent directory"))?;
    require_real_directory(parent)?;
    require_regular_file(path)?;
    verify_no_extended_acl(parent)?;
    verify_no_extended_acl(path)?;
    let file = fs::metadata(path)?;
    let directory = fs::metadata(parent)?;
    let expected_uid = match owner {
        ManifestOwner::System => 0,
        ManifestOwner::User => worker.unix_uid()?,
        #[cfg(test)]
        ManifestOwner::CurrentProcess | ManifestOwner::CurrentProcessWorker => file.uid(),
    };
    validate_store_inspection(
        owner,
        &UnixManifestInspection {
            expected_uid,
            file_uid: file.uid(),
            file_mode: file.mode() & 0o777,
            directory_uid: directory.uid(),
            directory_mode: directory.mode() & 0o777,
        },
    )?;
    verify_manifest_ancestors(parent, owner, worker, trusted_root)
}

#[allow(dead_code)] // Source-including manifest tests do not include receipt reads.
pub(super) fn open_verified_manifest_file_for_read(
    path: &Path,
    owner: ManifestOwner,
    worker: &WorkerPrincipal,
    trusted_root: &Path,
) -> io::Result<fs::File> {
    use std::os::fd::AsRawFd;

    let parent = path
        .parent()
        .ok_or_else(|| invalid_data("manifest path has no parent directory"))?;
    require_real_directory(parent)?;
    verify_no_extended_acl(parent)?;
    verify_manifest_ancestors(parent, owner, worker, trusted_root)?;
    let file = fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK)
        .open(path)?;
    let file_metadata = file.metadata()?;
    if !file_metadata.is_file() {
        return Err(permission_denied("manifest target is not a regular file"));
    }
    verify_no_extended_acl_fd(file.as_raw_fd())?;
    let directory = fs::metadata(parent)?;
    let expected_uid = match owner {
        ManifestOwner::System => 0,
        ManifestOwner::User => worker.unix_uid()?,
        #[cfg(test)]
        ManifestOwner::CurrentProcess | ManifestOwner::CurrentProcessWorker => file_metadata.uid(),
    };
    validate_store_inspection(
        owner,
        &UnixManifestInspection {
            expected_uid,
            file_uid: file_metadata.uid(),
            file_mode: file_metadata.mode() & 0o777,
            directory_uid: directory.uid(),
            directory_mode: directory.mode() & 0o777,
        },
    )?;
    verify_no_extended_acl(parent)?;
    verify_manifest_ancestors(parent, owner, worker, trusted_root)?;
    Ok(file)
}

pub(super) fn verify_manifest_file_target(path: &Path) -> io::Result<()> {
    require_regular_file(path)
}

pub(super) fn verify_manifest_directory_security(
    directory: &Path,
    owner: ManifestOwner,
    worker: &WorkerPrincipal,
) -> io::Result<()> {
    verify_directory(directory, owner, worker)
}

pub(super) fn publish_manifest_directory(staging: &Path, destination: &Path) -> io::Result<()> {
    const RENAME_EXCL: u32 = 0x0000_0004;
    require_real_directory(staging)?;
    let staging = std::ffi::CString::new(staging.as_os_str().as_bytes())
        .map_err(|_| invalid_data("manifest staging path contains a NUL byte"))?;
    let destination = std::ffi::CString::new(destination.as_os_str().as_bytes())
        .map_err(|_| invalid_data("manifest destination path contains a NUL byte"))?;
    if unsafe { renamex_np(staging.as_ptr(), destination.as_ptr(), RENAME_EXCL) } == -1 {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}

pub(super) fn verify_manifest_parent_chain(
    parent: &Path,
    owner: ManifestOwner,
    worker: &WorkerPrincipal,
) -> io::Result<()> {
    if matches!(owner, ManifestOwner::User) {
        return verify_user_trusted_root_chain(parent, worker.unix_uid()?);
    }
    require_real_directory(parent)?;
    let worker_uid = worker_uid(owner, worker)?;
    let child_uid = match owner {
        ManifestOwner::System => 0,
        ManifestOwner::User => unsafe { libc::geteuid() },
        #[cfg(test)]
        ManifestOwner::CurrentProcess | ManifestOwner::CurrentProcessWorker => unsafe {
            libc::geteuid()
        },
    };
    verify_ancestor_chain(parent, child_uid, owner, worker_uid)
}

pub(super) fn verify_manifest_ancestors(
    directory: &Path,
    owner: ManifestOwner,
    worker: &WorkerPrincipal,
    trusted_root: &Path,
) -> io::Result<()> {
    let system_owner = matches!(owner, ManifestOwner::System);
    if (system_owner && directory != trusted_root)
        || (!system_owner && !directory.starts_with(trusted_root))
    {
        return Err(permission_denied(
            "manifest directory is outside its trusted root",
        ));
    }
    if matches!(owner, ManifestOwner::User) {
        return verify_user_manifest_ancestors(directory, trusted_root, worker.unix_uid()?);
    }
    if !system_owner && directory == trusted_root {
        return require_real_directory(directory);
    }
    require_real_directory(directory)?;
    let worker_uid = worker_uid(owner, worker)?;
    let mut child_uid = fs::symlink_metadata(directory)?.uid();
    let mut current = directory.parent();
    while let Some(ancestor) = current {
        require_real_directory(ancestor)?;
        verify_no_extended_acl(ancestor)?;
        let metadata = fs::metadata(ancestor)?;
        let mode = metadata.mode();
        validate_ancestor_access(metadata.uid(), mode, worker_uid, system_owner)?;
        if mode & 0o022 != 0 {
            let safe_sticky_root = matches!(owner, ManifestOwner::System)
                && mode & 0o1000 != 0
                && metadata.uid() == 0
                && child_uid == 0;
            if !safe_sticky_root {
                return Err(permission_denied(
                    "manifest ancestor grants replacement access",
                ));
            }
        }
        child_uid = metadata.uid();
        if !system_owner && ancestor == trusted_root {
            return Ok(());
        }
        current = ancestor.parent();
    }
    if system_owner {
        Ok(())
    } else {
        Err(permission_denied(
            "manifest trusted root is not an ancestor",
        ))
    }
}

fn verify_user_manifest_ancestors(
    directory: &Path,
    trusted_root: &Path,
    current_uid: u32,
) -> io::Result<()> {
    require_real_directory(directory)?;
    if directory != trusted_root {
        let mut current = directory.parent();
        while let Some(ancestor) = current {
            if ancestor == trusted_root {
                break;
            }
            require_real_directory(ancestor)?;
            verify_no_extended_acl(ancestor)?;
            let metadata = fs::metadata(ancestor)?;
            if metadata.uid() != current_uid || metadata.mode() & 0o022 != 0 {
                return Err(permission_denied(
                    "user state directory owner or write permissions are insecure",
                ));
            }
            current = ancestor.parent();
        }
        if current.is_none() {
            return Err(permission_denied(
                "manifest trusted root is not an ancestor",
            ));
        }
    }
    verify_user_trusted_root_chain(trusted_root, current_uid)
}

fn verify_user_trusted_root_chain(path: &Path, current_uid: u32) -> io::Result<()> {
    verify_user_trusted_root(path, current_uid)?;
    let metadata = fs::metadata(path)?;
    let mut child_uid = metadata.uid();
    let mut reached_system_owner = false;
    let mut current = path.parent();
    while let Some(ancestor) = current {
        require_real_directory(ancestor)?;
        verify_trusted_root_has_no_extended_allow_acl(ancestor)?;
        let metadata = fs::metadata(ancestor)?;
        validate_user_ancestor_access(
            metadata.uid(),
            metadata.mode(),
            child_uid,
            current_uid,
            &mut reached_system_owner,
        )?;
        child_uid = metadata.uid();
        current = ancestor.parent();
    }
    Ok(())
}

fn verify_user_trusted_root(path: &Path, current_uid: u32) -> io::Result<()> {
    require_real_directory(path)?;
    verify_trusted_root_has_no_extended_allow_acl(path)?;
    let metadata = fs::metadata(path)?;
    if metadata.uid() != current_uid || metadata.mode() & 0o022 != 0 {
        return Err(permission_denied(
            "user state root owner or write permissions are insecure",
        ));
    }
    Ok(())
}

fn validate_user_ancestor_access(
    uid: u32,
    mode: u32,
    child_uid: u32,
    current_uid: u32,
    reached_system_owner: &mut bool,
) -> io::Result<()> {
    if uid == 0 {
        *reached_system_owner = true;
    } else if uid != current_uid || *reached_system_owner {
        return Err(permission_denied(
            "user state ancestor has an unrelated or invalid owner transition",
        ));
    }
    if mode & 0o022 != 0 {
        let trusted_owner = uid == 0 || uid == current_uid;
        let sticky_protects_user_child =
            mode & 0o1000 != 0 && child_uid == current_uid && trusted_owner;
        if !sticky_protects_user_child {
            return Err(permission_denied(
                "user state ancestor grants unrelated replacement access",
            ));
        }
    }
    Ok(())
}

fn verify_trusted_root_has_no_extended_allow_acl(path: &Path) -> io::Result<()> {
    let acl = unsafe { acl_get_file(c_path(path)?.as_ptr(), ACL_TYPE_EXTENDED) };
    verify_no_extended_allow_acl_value(acl)
}

fn verify_no_extended_allow_acl_fd(fd: i32) -> io::Result<()> {
    verify_no_extended_allow_acl_value(unsafe { acl_get_fd_np(fd, ACL_TYPE_EXTENDED) })
}

fn verify_no_extended_allow_acl_value(acl: Acl) -> io::Result<()> {
    if acl.is_null() {
        let error = io::Error::last_os_error();
        return if error.kind() == io::ErrorKind::NotFound {
            Ok(())
        } else {
            Err(error)
        };
    }
    let acl = OwnedAcl(acl);
    let mut entry_id = ACL_FIRST_ENTRY;
    loop {
        let mut entry = std::ptr::null_mut();
        let status = unsafe { acl_get_entry(acl.0, entry_id, &mut entry) };
        if (status == 0 || status == 1) && !entry.is_null() {
            let mut tag = 0;
            if unsafe { acl_get_tag_type(entry, &mut tag) } != 0 {
                return Err(io::Error::last_os_error());
            }
            if tag == ACL_EXTENDED_ALLOW {
                return Err(permission_denied(
                    "user state root contains an extended allow ACL",
                ));
            }
            if tag != ACL_EXTENDED_DENY {
                return Err(permission_denied(
                    "user state root contains an unrecognized extended ACL",
                ));
            }
            entry_id = ACL_NEXT_ENTRY;
            continue;
        }
        if (status == 0 || status == -1) && entry.is_null() {
            let error = io::Error::last_os_error();
            if status == 0 || error.raw_os_error() == Some(libc::EINVAL) {
                return Ok(());
            }
            return Err(error);
        }
        return Err(io::Error::last_os_error());
    }
}

fn verify_ancestor_chain(
    start: &Path,
    mut child_uid: u32,
    owner: ManifestOwner,
    worker_uid: Option<u32>,
) -> io::Result<()> {
    let system_owner = matches!(owner, ManifestOwner::System);
    let mut current = Some(start);
    while let Some(ancestor) = current {
        require_real_directory(ancestor)?;
        verify_no_extended_acl(ancestor)?;
        let metadata = fs::metadata(ancestor)?;
        let mode = metadata.mode();
        validate_ancestor_access(metadata.uid(), mode, worker_uid, system_owner)?;
        if mode & 0o022 != 0 {
            let safe_sticky_root =
                system_owner && mode & 0o1000 != 0 && metadata.uid() == 0 && child_uid == 0;
            if !safe_sticky_root {
                return Err(permission_denied(
                    "manifest ancestor grants replacement access",
                ));
            }
        }
        child_uid = metadata.uid();
        current = ancestor.parent();
    }
    Ok(())
}

fn worker_uid(owner: ManifestOwner, worker: &WorkerPrincipal) -> io::Result<Option<u32>> {
    match owner {
        ManifestOwner::System => Ok(Some(worker.unix_uid()?)),
        ManifestOwner::User => Ok(None),
        #[cfg(test)]
        ManifestOwner::CurrentProcess => Ok(None),
        #[cfg(test)]
        ManifestOwner::CurrentProcessWorker => Ok(Some(unsafe { libc::geteuid() })),
    }
}

fn validate_ancestor_access(
    uid: u32,
    mode: u32,
    worker_uid: Option<u32>,
    require_worker_traversal: bool,
) -> io::Result<()> {
    if require_worker_traversal && mode & 0o001 == 0 {
        return Err(permission_denied(
            "manifest ancestor is not traversable by the configured worker",
        ));
    }
    if worker_uid == Some(uid) {
        return Err(permission_denied(
            "configured worker owns a manifest ancestor",
        ));
    }
    Ok(())
}

#[allow(dead_code)] // Called by the environmental selected-account gate.
fn lookup_worker_uid(worker: &str) -> io::Result<u32> {
    let worker = std::ffi::CString::new(worker)
        .map_err(|_| invalid_data("worker account contains a NUL byte"))?;
    let mut entry = unsafe { std::mem::zeroed::<libc::passwd>() };
    let mut result = std::ptr::null_mut();
    let mut buffer = vec![0_u8; 16 * 1024];
    let status = unsafe {
        libc::getpwnam_r(
            worker.as_ptr(),
            &mut entry,
            buffer.as_mut_ptr().cast(),
            buffer.len(),
            &mut result,
        )
    };
    if status != 0 {
        return Err(io::Error::from_raw_os_error(status));
    }
    if result.is_null() {
        return Err(io::Error::new(
            io::ErrorKind::NotFound,
            "configured worker account is unavailable",
        ));
    }
    Ok(entry.pw_uid)
}

#[derive(Clone, Copy)]
struct UnixManifestInspection {
    expected_uid: u32,
    file_uid: u32,
    file_mode: u32,
    directory_uid: u32,
    directory_mode: u32,
}

fn validate_manifest_inspection(inspection: &UnixManifestInspection) -> io::Result<()> {
    if inspection.file_uid != inspection.expected_uid
        || inspection.directory_uid != inspection.expected_uid
    {
        return Err(permission_denied(
            "manifest file and directory owner mismatch",
        ));
    }
    if inspection.file_mode != 0o644 {
        return Err(permission_denied("manifest mode must be 0644"));
    }
    if inspection.directory_mode != 0o755 {
        return Err(permission_denied("manifest directory mode must be 0755"));
    }
    Ok(())
}

fn validate_store_inspection(
    owner: ManifestOwner,
    inspection: &UnixManifestInspection,
) -> io::Result<()> {
    if !matches!(owner, ManifestOwner::User) {
        return validate_manifest_inspection(inspection);
    }
    if inspection.file_uid != inspection.expected_uid
        || inspection.directory_uid != inspection.expected_uid
    {
        return Err(permission_denied(
            "user state file and directory owner mismatch",
        ));
    }
    if inspection.file_mode != 0o600 || inspection.directory_mode != 0o700 {
        return Err(permission_denied(
            "user state requires file mode 0600 and directory mode 0700",
        ));
    }
    Ok(())
}

fn apply_owner(path: &Path, owner: ManifestOwner) -> io::Result<()> {
    match owner {
        ManifestOwner::System => std::os::unix::fs::chown(path, Some(0), Some(0)),
        ManifestOwner::User => Ok(()),
        #[cfg(test)]
        ManifestOwner::CurrentProcess | ManifestOwner::CurrentProcessWorker => Ok(()),
    }
}

fn verify_directory(
    path: &Path,
    owner: ManifestOwner,
    principal: &WorkerPrincipal,
) -> io::Result<()> {
    require_real_directory(path)?;
    verify_no_extended_acl(path)?;
    let metadata = fs::metadata(path)?;
    verify_owner(&metadata, owner, principal, "manifest directory")?;
    let expected_mode = if matches!(owner, ManifestOwner::User) {
        0o700
    } else {
        0o755
    };
    if metadata.mode() & 0o777 != expected_mode {
        return Err(permission_denied(&format!(
            "manifest directory mode must be {expected_mode:04o}"
        )));
    }
    Ok(())
}

fn verify_file(
    path: &Path,
    owner: ManifestOwner,
    principal: &WorkerPrincipal,
    mode: u32,
    label: &str,
) -> io::Result<()> {
    require_regular_file(path)?;
    verify_no_extended_acl(path)?;
    let metadata = fs::metadata(path)?;
    verify_owner(&metadata, owner, principal, label)?;
    if metadata.mode() & 0o777 != mode {
        return Err(permission_denied(&format!(
            "{label} mode must be {mode:04o}, found {:04o}",
            metadata.mode() & 0o777
        )));
    }
    Ok(())
}

fn clear_extended_acl(path: &Path) -> io::Result<()> {
    let acl = unsafe { acl_init(0) };
    if acl.is_null() {
        return Err(io::Error::last_os_error());
    }
    let acl = OwnedAcl(acl);
    let path = c_path(path)?;
    if unsafe { acl_set_file(path.as_ptr(), ACL_TYPE_EXTENDED, acl.0) } != 0 {
        return Err(io::Error::last_os_error());
    }
    verify_no_extended_acl_c_path(&path)
}

fn verify_no_extended_acl(path: &Path) -> io::Result<()> {
    verify_no_extended_acl_c_path(&c_path(path)?)
}

fn inspect_extended_acl(path: &Path) -> io::Result<bool> {
    inspect_extended_acl_c_path(&c_path(path)?)
}

#[cfg(test)]
pub(super) fn seed_incompatible_worker_directory_acl_for_action_test(
    path: &Path,
    _principal: &WorkerPrincipal,
) -> io::Result<()> {
    let mut acl = unsafe { acl_init(1) };
    if acl.is_null() {
        return Err(io::Error::last_os_error());
    }
    let mut entry = std::ptr::null_mut();
    if unsafe { acl_create_entry(&mut acl, &mut entry) } != 0 {
        unsafe {
            acl_free(acl);
        }
        return Err(io::Error::last_os_error());
    }
    let owned = OwnedAcl(acl);
    if unsafe { acl_set_tag_type(entry, ACL_EXTENDED_ALLOW) } != 0 {
        return Err(io::Error::last_os_error());
    }
    let mut uuid = [0_u8; 16];
    if unsafe { mbr_uid_to_uuid(libc::geteuid(), uuid.as_mut_ptr()) } != 0
        || unsafe { acl_set_qualifier(entry, uuid.as_ptr().cast()) } != 0
    {
        return Err(io::Error::last_os_error());
    }
    let mut permissions = std::ptr::null_mut();
    if unsafe { acl_get_permset(entry, &mut permissions) } != 0
        || unsafe { acl_add_perm(permissions, ACL_WRITE_DATA) } != 0
    {
        return Err(io::Error::last_os_error());
    }
    let path = c_path(path)?;
    if unsafe { acl_set_file(path.as_ptr(), ACL_TYPE_EXTENDED, owned.0) } != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

#[cfg(test)]
pub(super) fn worker_directory_acl_is_incompatible_for_action_test(
    path: &Path,
    _principal: &WorkerPrincipal,
) -> io::Result<bool> {
    Ok(verify_no_extended_acl(path).is_err())
}

#[allow(dead_code)] // Source-including manifest tests do not include receipt reads.
fn verify_no_extended_acl_fd(fd: i32) -> io::Result<()> {
    verify_no_extended_acl_value(unsafe { acl_get_fd_np(fd, ACL_TYPE_EXTENDED) })
}

fn verify_no_extended_acl_c_path(path: &std::ffi::CString) -> io::Result<()> {
    verify_no_extended_acl_value(unsafe { acl_get_file(path.as_ptr(), ACL_TYPE_EXTENDED) })
}

fn verify_no_extended_acl_value(acl: Acl) -> io::Result<()> {
    match inspect_extended_acl_value(acl) {
        Ok(false) => Ok(()),
        Ok(true) => Err(permission_denied(
            "manifest security target has an extended ACL",
        )),
        Err(error) => Err(error),
    }
}

fn inspect_extended_acl_c_path(path: &std::ffi::CString) -> io::Result<bool> {
    inspect_extended_acl_value(unsafe { acl_get_file(path.as_ptr(), ACL_TYPE_EXTENDED) })
}

fn inspect_extended_acl_value(acl: Acl) -> io::Result<bool> {
    if acl.is_null() {
        let error = io::Error::last_os_error();
        return if error.kind() == io::ErrorKind::NotFound {
            Ok(false)
        } else {
            Err(error)
        };
    }
    let acl = OwnedAcl(acl);
    let mut entry = std::ptr::null_mut();
    (unsafe { acl_get_entry(acl.0, ACL_FIRST_ENTRY, &mut entry) } == 0)
        .then_some(true)
        .ok_or_else(io::Error::last_os_error)
}

fn c_path(path: &Path) -> io::Result<std::ffi::CString> {
    std::ffi::CString::new(path.as_os_str().as_bytes())
        .map_err(|_| invalid_data("manifest path contains a NUL byte"))
}

struct OwnedAcl(Acl);

impl Drop for OwnedAcl {
    fn drop(&mut self) {
        unsafe {
            acl_free(self.0);
        }
    }
}

fn verify_owner(
    metadata: &fs::Metadata,
    owner: ManifestOwner,
    principal: &WorkerPrincipal,
    label: &str,
) -> io::Result<()> {
    let expected = match owner {
        ManifestOwner::System => 0,
        ManifestOwner::User => principal.unix_uid()?,
        #[cfg(test)]
        ManifestOwner::CurrentProcess | ManifestOwner::CurrentProcessWorker => metadata.uid(),
    };
    if metadata.uid() != expected {
        return Err(permission_denied(&format!(
            "{label} owner must be uid {expected}, found {}",
            metadata.uid()
        )));
    }
    Ok(())
}

fn require_regular_file(path: &Path) -> io::Result<()> {
    let metadata = fs::symlink_metadata(path)?;
    if !metadata.file_type().is_file() {
        return Err(invalid_data(
            "manifest security target is not a regular file",
        ));
    }
    Ok(())
}

fn require_real_directory(path: &Path) -> io::Result<()> {
    let metadata = fs::symlink_metadata(path)?;
    if !metadata.file_type().is_dir() {
        return Err(invalid_data(
            "manifest security target is not a real directory",
        ));
    }
    Ok(())
}

fn permission_denied(message: &str) -> io::Error {
    io::Error::new(io::ErrorKind::PermissionDenied, message.to_owned())
}

fn invalid_data(message: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message.to_owned())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dedicated_account_spec_applies_macos_name_rules() {
        for valid in ["build-agent", "ci_worker", "worker7"] {
            assert!(super::super::DedicatedAccountSpec::new(valid).is_ok());
        }
        let oversized = "a".repeat(256);
        let error = match super::super::DedicatedAccountSpec::new(&oversized) {
            Ok(_) => panic!("macOS-invalid dedicated account name was accepted"),
            Err(error) => error,
        };
        assert_eq!(
            error.to_string(),
            super::super::DEDICATED_ACCOUNT_NAME_ERROR
        );
    }

    fn test_principal() -> WorkerPrincipal {
        resolve_current_worker_principal().unwrap()
    }

    fn healthy_dedicated_account_record() -> MacDedicatedAccountRecord {
        MacDedicatedAccountRecord {
            principal: WorkerPrincipal::new(
                PrincipalKind::UnixUid,
                "501",
                "build-agent",
                WorkerAccountPolicy::Dedicated,
            )
            .unwrap(),
            is_local_user: true,
            is_enabled: true,
            is_hidden: false,
            is_administrator: false,
            primary_gid: 20,
            supplementary_groups: vec![],
            home: PathBuf::from("/Users/build-agent"),
            shell: PathBuf::from("/bin/zsh"),
            home_state: DedicatedHomeState::EmptySafe,
        }
    }

    fn assert_dedicated_account_broken(record: MacDedicatedAccountRecord) {
        let spec = super::super::DedicatedAccountSpec::new("build-agent").unwrap();
        assert!(matches!(
            classify_dedicated_account_record(
                &spec,
                record,
                super::super::NativeDedicatedAccountInspection::Initial,
            ),
            super::super::NativeDedicatedAccountObservation::PresentBroken,
        ));
    }

    #[test]
    fn dedicated_account_observation_rejects_each_unsafe_macos_posture() {
        let spec = super::super::DedicatedAccountSpec::new("build-agent").unwrap();
        assert!(matches!(
            classify_dedicated_account_record(
                &spec,
                healthy_dedicated_account_record(),
                super::super::NativeDedicatedAccountInspection::Initial,
            ),
            super::super::NativeDedicatedAccountObservation::PresentHealthy(_),
        ));

        let mut cases = Vec::new();
        let mut wrong_kind = healthy_dedicated_account_record();
        wrong_kind.principal = WorkerPrincipal::new(
            PrincipalKind::WindowsSid,
            "S-1-5-21-100-200-300-501",
            "build-agent",
            WorkerAccountPolicy::Dedicated,
        )
        .unwrap();
        cases.push(wrong_kind);
        let mut nonlocal = healthy_dedicated_account_record();
        nonlocal.is_local_user = false;
        cases.push(nonlocal);
        let mut disabled = healthy_dedicated_account_record();
        disabled.is_enabled = false;
        cases.push(disabled);
        let mut hidden = healthy_dedicated_account_record();
        hidden.is_hidden = true;
        cases.push(hidden);
        let mut administrator = healthy_dedicated_account_record();
        administrator.is_administrator = true;
        cases.push(administrator);
        let mut privileged_primary = healthy_dedicated_account_record();
        privileged_primary.primary_gid = 80;
        cases.push(privileged_primary);
        let mut privileged_supplementary = healthy_dedicated_account_record();
        privileged_supplementary.supplementary_groups = vec![80];
        cases.push(privileged_supplementary);
        let mut wrong_home = healthy_dedicated_account_record();
        wrong_home.home = PathBuf::from("/Users/unrelated");
        cases.push(wrong_home);
        let mut wrong_shell = healthy_dedicated_account_record();
        wrong_shell.shell = PathBuf::from("/usr/bin/false");
        cases.push(wrong_shell);
        let mut unsafe_home = healthy_dedicated_account_record();
        unsafe_home.home_state = DedicatedHomeState::Unsafe;
        cases.push(unsafe_home);
        let mut populated_home = healthy_dedicated_account_record();
        populated_home.home_state = DedicatedHomeState::PopulatedSafe;
        cases.push(populated_home);

        for record in cases {
            assert_dedicated_account_broken(record);
        }

        let mut unavailable_home = healthy_dedicated_account_record();
        unavailable_home.home_state = DedicatedHomeState::Unknowable;
        assert!(matches!(
            classify_dedicated_account_record(
                &spec,
                unavailable_home,
                super::super::NativeDedicatedAccountInspection::Initial,
            ),
            super::super::NativeDedicatedAccountObservation::Unknowable,
        ));
    }

    #[test]
    fn dedicated_account_binding_allows_safe_contents_only_after_initial_adoption() {
        let spec = super::super::DedicatedAccountSpec::new("build-agent").unwrap();
        let mut populated = healthy_dedicated_account_record();
        populated.home_state = DedicatedHomeState::PopulatedSafe;

        assert!(matches!(
            classify_dedicated_account_record(
                &spec,
                populated.clone(),
                super::super::NativeDedicatedAccountInspection::Initial,
            ),
            super::super::NativeDedicatedAccountObservation::PresentBroken,
        ));
        assert!(matches!(
            classify_dedicated_account_record(
                &spec,
                populated,
                super::super::NativeDedicatedAccountInspection::Established,
            ),
            super::super::NativeDedicatedAccountObservation::PresentHealthy(_),
        ));
    }

    #[test]
    fn dedicated_account_acl_distinguishes_present_from_query_failure() {
        assert!(dedicated_home_acl_issue(Ok(false)).is_none());
        assert!(matches!(
            dedicated_home_acl_issue(Ok(true)),
            Some(DedicatedHomeState::Unsafe)
        ));
        assert!(matches!(
            dedicated_home_acl_issue(Err(
                io::Error::other("injected extended ACL query failure",)
            )),
            Some(DedicatedHomeState::Unknowable)
        ));
    }

    #[test]
    #[ignore = "environmental: requires native macOS and STYRN_TEST_DISTINCT_UNIX_WORKER naming a visible enabled non-administrator local account with an empty safe /Users directory"]
    fn native_dedicated_account_observation_adopts_a_distinct_local_account() {
        let name = std::env::var("STYRN_TEST_DISTINCT_UNIX_WORKER")
            .expect("STYRN_TEST_DISTINCT_UNIX_WORKER must name a disposable local account");
        assert_ne!(name, "styrn");
        let observation = super::super::inspect_dedicated_account(
            super::super::DedicatedAccountSpec::new(&name).unwrap(),
        );
        let super::super::DedicatedAccountObservation::PresentHealthy(handle) = observation else {
            panic!("the configured macOS account did not satisfy dedicated adoption posture");
        };
        let authority = super::super::DedicatedAccountFactoryAuthority::for_test();
        handle
            .reverify_and_bind(&authority, |verified| {
                assert_eq!(verified.principal().name(), name);
                assert_eq!(
                    verified.principal().account_policy(),
                    WorkerAccountPolicy::Dedicated
                );
            })
            .unwrap();
    }

    #[test]
    fn retained_worker_root_identity_detects_path_replacement() {
        let parent = fs::canonicalize(std::env::temp_dir())
            .unwrap()
            .join(format!(
                "styrn-worker-root-swap-{}-{}",
                std::process::id(),
                uuid::Uuid::now_v7()
            ));
        let root = parent.join("root");
        fs::create_dir_all(&root).unwrap();
        let retained = open_existing_worker_path(&root).unwrap();
        let identity = worker_directory_identity(&retained).unwrap();
        let displaced = parent.join("displaced");
        fs::rename(&root, &displaced).unwrap();
        fs::create_dir(&root).unwrap();

        let error = verify_worker_path_identity(&root, identity).unwrap_err();

        assert_eq!(error.kind(), io::ErrorKind::PermissionDenied);
        fs::remove_dir_all(parent).unwrap();
    }

    #[test]
    fn post_mkdir_substitution_is_never_reported_as_a_created_worker_node() {
        fn substitute(parent: i32, name: &std::ffi::CStr) {
            let displaced = c".styrn-test-displaced";
            assert_eq!(
                unsafe { libc::renameat(parent, name.as_ptr(), parent, displaced.as_ptr()) },
                0,
                "{}",
                io::Error::last_os_error()
            );
            assert_eq!(
                unsafe { libc::mkdirat(parent, name.as_ptr(), 0o700) },
                0,
                "{}",
                io::Error::last_os_error()
            );
        }

        let principal = test_principal();
        for scope in [
            crate::platform::InstallationScope::User,
            crate::platform::InstallationScope::System,
        ] {
            let parent = fs::canonicalize(std::env::temp_dir())
                .unwrap()
                .join(format!(
                    "styrn-worker-post-mkdir-swap-{scope:?}-{}-{}",
                    std::process::id(),
                    uuid::Uuid::now_v7()
                ));
            fs::create_dir(&parent).unwrap();
            let root = parent.join("root");
            let layout =
                crate::platform::resolve_worker_directory_layout(scope, &principal, Some(&root))
                    .unwrap();
            set_post_worker_mkdir_hook(substitute);

            let error = create_worker_directory_layout(&layout).unwrap_err();

            assert_eq!(error.kind(), io::ErrorKind::PermissionDenied);
            assert!(!root.exists());
            fs::remove_dir_all(parent).unwrap();
        }
    }

    #[test]
    fn creator_only_unpublished_parent_requires_distinct_worker_and_live_identity() {
        let outer = fs::canonicalize(std::env::temp_dir())
            .unwrap()
            .join(format!(
                "styrn-worker-creator-only-capability-{}-{}",
                std::process::id(),
                uuid::Uuid::now_v7()
            ));
        fs::create_dir(&outer).unwrap();
        let staging_path = outer.join("private-root");
        let canonical_path = outer.join("root");
        fs::create_dir(&staging_path).unwrap();
        fs::set_permissions(&staging_path, fs::Permissions::from_mode(0o700)).unwrap();
        let staging_parent = open_existing_worker_path(&outer).unwrap();
        let directory = open_existing_worker_path(&staging_path).unwrap();
        let staged = StagedWorkerDirectory {
            name: CString::new("private-root").unwrap(),
            identity: worker_directory_identity(&directory).unwrap(),
            directory,
            created: false,
        };
        let creator_uid = unsafe { libc::geteuid() };
        let distinct_worker_uid = creator_uid.checked_add(1).unwrap();

        {
            let capability = verify_unpublished_worker_recovery_authority(
                &staged,
                &staging_parent,
                &staging_parent,
                b"root",
                distinct_worker_uid,
            )
            .unwrap()
            .expect("a retained creator-only parent should mint authority for a distinct worker");
            capability.reverify_parent(&staged.directory).unwrap();
            assert!(verify_unpublished_worker_recovery_authority(
                &staged,
                &staging_parent,
                &staging_parent,
                b"root",
                creator_uid,
            )
            .is_err());
            fs::set_permissions(&staging_path, fs::Permissions::from_mode(0o750)).unwrap();
            assert!(capability.reverify_parent(&staged.directory).is_err());
            fs::set_permissions(&staging_path, fs::Permissions::from_mode(0o700)).unwrap();
            capability.reverify_parent(&staged.directory).unwrap();

            fs::create_dir(&canonical_path).unwrap();
            capability.reverify_parent(&staged.directory).unwrap();
            fs::remove_dir(&canonical_path).unwrap();

            fs::rename(&staging_path, &canonical_path).unwrap();
            fs::create_dir(&staging_path).unwrap();
            fs::set_permissions(&staging_path, fs::Permissions::from_mode(0o700)).unwrap();
            assert!(capability.reverify_parent(&staged.directory).is_err());
        }
        drop(staged);
        drop(staging_parent);
        fs::remove_dir(staging_path).unwrap();
        fs::remove_dir(canonical_path).unwrap();
        fs::remove_dir(outer).unwrap();
    }

    #[test]
    #[ignore = "environmental: requires root on native macOS and STYRN_TEST_DISTINCT_UNIX_WORKER naming a disposable distinct local account"]
    fn creator_only_unpublished_parent_recovers_distinct_worker_children() {
        let worker_name = std::env::var("STYRN_TEST_DISTINCT_UNIX_WORKER")
            .expect("STYRN_TEST_DISTINCT_UNIX_WORKER must name a disposable local account");
        let principal =
            resolve_named_worker_principal(&worker_name, WorkerAccountPolicy::Dedicated).unwrap();
        assert_ne!(principal.unix_uid().unwrap(), unsafe { libc::geteuid() });
        let parent = fs::canonicalize(std::env::temp_dir())
            .unwrap()
            .join(format!(
                "styrn-worker-distinct-recovery-{}-{}",
                std::process::id(),
                uuid::Uuid::now_v7()
            ));
        fs::create_dir(&parent).unwrap();
        fs::set_permissions(&parent, fs::Permissions::from_mode(0o700)).unwrap();
        let root = parent.join("root");
        let layout = crate::platform::resolve_worker_directory_layout(
            crate::platform::InstallationScope::System,
            &principal,
            Some(&root),
        )
        .unwrap();

        set_worker_mkdir_interrupt_after(Some(1));
        let interrupted = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            create_worker_directory_layout(&layout)
        }));
        set_worker_mkdir_interrupt_after(None);
        assert!(interrupted.is_err());
        assert!(!root.exists());

        let creation = create_worker_directory_layout(&layout).unwrap();
        let dispositions = creation
            .bind_after_reverify(|binding| {
                Ok::<_, ()>(
                    binding
                        .observations()
                        .iter()
                        .map(|node| node.disposition())
                        .collect::<Vec<_>>(),
                )
            })
            .unwrap();
        assert_eq!(dispositions.len(), 6);
        assert!(dispositions.iter().all(|disposition| {
            *disposition == crate::platform::WorkerDirectoryNodeDisposition::Created
        }));

        fs::remove_dir_all(parent).unwrap();
    }

    #[test]
    fn same_uid_interrupted_worker_staging_is_retained_as_a_conflict() {
        let principal = test_principal();
        let parent = fs::canonicalize(std::env::temp_dir())
            .unwrap()
            .join(format!(
                "styrn-worker-staging-resume-{}-{}",
                std::process::id(),
                uuid::Uuid::now_v7()
            ));
        fs::create_dir(&parent).unwrap();
        fs::set_permissions(&parent, fs::Permissions::from_mode(0o700)).unwrap();
        let root = parent.join("root");
        let layout = crate::platform::resolve_worker_directory_layout(
            crate::platform::InstallationScope::System,
            &principal,
            Some(&root),
        )
        .unwrap();

        set_worker_mkdir_interrupt_after(Some(1));
        let interrupted = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            create_worker_directory_layout(&layout)
        }));
        set_worker_mkdir_interrupt_after(None);
        assert!(
            interrupted.is_err(),
            "unexpected interruption result: {interrupted:?}"
        );
        assert!(!root.exists());
        let parent_directory = open_existing_worker_path(&parent).unwrap();
        let retained_before = worker_parent_entry_snapshot(&parent_directory).unwrap();

        let error = create_worker_directory_layout(&layout).unwrap_err();

        assert_eq!(error.kind(), io::ErrorKind::PermissionDenied);
        assert!(!root.exists());
        assert_eq!(
            worker_parent_entry_snapshot(&parent_directory).unwrap(),
            retained_before
        );
        fs::remove_dir_all(parent).unwrap();
    }

    #[test]
    fn same_uid_interruption_after_provenance_retains_conflict_evidence() {
        let principal = test_principal();
        let parent = fs::canonicalize(std::env::temp_dir())
            .unwrap()
            .join(format!(
                "styrn-worker-provenance-recovery-{}-{}",
                std::process::id(),
                uuid::Uuid::now_v7()
            ));
        fs::create_dir(&parent).unwrap();
        fs::set_permissions(&parent, fs::Permissions::from_mode(0o700)).unwrap();
        let root = parent.join("root");
        let layout = crate::platform::resolve_worker_directory_layout(
            crate::platform::InstallationScope::System,
            &principal,
            Some(&root),
        )
        .unwrap();

        set_worker_publication_interrupt(Some(WorkerPublicationInterruption::AfterProvenance));
        let interrupted = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            create_worker_directory_layout(&layout)
        }));
        set_worker_publication_interrupt(None);
        assert!(
            interrupted.is_err(),
            "unexpected interruption result: {interrupted:?}"
        );
        assert!(!root.exists());
        let parent_directory = open_existing_worker_path(&parent).unwrap();
        let retained_before = worker_parent_entry_snapshot(&parent_directory).unwrap();

        let error = create_worker_directory_layout(&layout).unwrap_err();

        assert_eq!(error.kind(), io::ErrorKind::PermissionDenied);
        assert!(!root.exists());
        assert_eq!(
            worker_parent_entry_snapshot(&parent_directory).unwrap(),
            retained_before
        );
        fs::remove_dir_all(parent).unwrap();
    }

    #[test]
    fn deleted_worker_child_with_replayed_identity_remains_conflict_evidence() {
        let principal = test_principal();
        let parent = fs::canonicalize(std::env::temp_dir())
            .unwrap()
            .join(format!(
                "styrn-worker-provenance-identity-reuse-{}-{}",
                std::process::id(),
                uuid::Uuid::now_v7()
            ));
        fs::create_dir(&parent).unwrap();
        fs::set_permissions(&parent, fs::Permissions::from_mode(0o700)).unwrap();
        let root = parent.join("root");
        let layout = crate::platform::resolve_worker_directory_layout(
            crate::platform::InstallationScope::System,
            &principal,
            Some(&root),
        )
        .unwrap();

        fs::create_dir(&root).unwrap();
        fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();
        for name in super::super::WorkerDirectoryLayout::child_names()
            .into_iter()
            .filter(|name| *name != "repos")
        {
            let child = root.join(name);
            fs::create_dir(&child).unwrap();
            fs::set_permissions(child, fs::Permissions::from_mode(0o700)).unwrap();
        }
        let unbound_creation = create_worker_directory_layout(&layout).unwrap();
        drop(unbound_creation);
        let original = open_existing_worker_path(&root.join("repos")).unwrap();
        let replayed_identity = worker_directory_identity(&original).unwrap();
        drop(original);
        fs::remove_dir(root.join("repos")).unwrap();
        fs::create_dir(root.join("repos")).unwrap();
        fs::set_permissions(root.join("repos"), fs::Permissions::from_mode(0o700)).unwrap();
        let replacement = open_existing_worker_path(&root.join("repos")).unwrap();
        let replacement_identity = worker_directory_identity(&replacement).unwrap();
        let parent_directory = open_existing_worker_path(&parent).unwrap();
        let retained_before = worker_parent_entry_snapshot(&parent_directory).unwrap();
        set_worker_recovery_identity_override(Some((b"repos".to_vec(), replayed_identity)));

        let result = create_worker_directory_layout(&layout);
        set_worker_recovery_identity_override(None);
        let error = result.unwrap_err();

        assert_eq!(error.kind(), io::ErrorKind::PermissionDenied);
        assert_eq!(
            worker_directory_identity(&open_existing_worker_path(&root.join("repos")).unwrap())
                .unwrap(),
            replacement_identity
        );
        assert_eq!(
            worker_parent_entry_snapshot(&parent_directory).unwrap(),
            retained_before
        );
        fs::remove_dir_all(parent).unwrap();
    }

    #[test]
    fn worker_substituted_compliant_child_is_not_relabelled_created_during_recovery() {
        let principal = test_principal();
        let parent = fs::canonicalize(std::env::temp_dir())
            .unwrap()
            .join(format!(
                "styrn-worker-provenance-substitution-{}-{}",
                std::process::id(),
                uuid::Uuid::now_v7()
            ));
        fs::create_dir(&parent).unwrap();
        fs::set_permissions(&parent, fs::Permissions::from_mode(0o700)).unwrap();
        let root = parent.join("root");
        let layout = crate::platform::resolve_worker_directory_layout(
            crate::platform::InstallationScope::System,
            &principal,
            Some(&root),
        )
        .unwrap();

        set_worker_publication_interrupt(Some(WorkerPublicationInterruption::AfterRootOwnership));
        let interrupted = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            create_worker_directory_layout(&layout)
        }));
        set_worker_publication_interrupt(None);
        assert!(interrupted.is_err());
        assert!(root.is_dir());
        let displaced = root.join("repos-created-by-styrn");
        fs::rename(root.join("repos"), &displaced).unwrap();
        fs::create_dir(root.join("repos")).unwrap();
        fs::set_permissions(root.join("repos"), fs::Permissions::from_mode(0o700)).unwrap();

        let error = create_worker_directory_layout(&layout).unwrap_err();

        assert_eq!(error.kind(), io::ErrorKind::PermissionDenied);
        assert!(root.join("repos").is_dir());
        assert!(displaced.is_dir());
        fs::remove_dir_all(parent).unwrap();
    }

    #[test]
    fn ambiguous_interrupted_worker_staging_is_rejected_without_cleanup_or_adoption() {
        let principal = test_principal();
        let parent = fs::canonicalize(std::env::temp_dir())
            .unwrap()
            .join(format!(
                "styrn-worker-staging-ambiguous-{}-{}",
                std::process::id(),
                uuid::Uuid::now_v7()
            ));
        fs::create_dir(&parent).unwrap();
        fs::set_permissions(&parent, fs::Permissions::from_mode(0o700)).unwrap();
        let root = parent.join("root");
        let layout = crate::platform::resolve_worker_directory_layout(
            crate::platform::InstallationScope::System,
            &principal,
            Some(&root),
        )
        .unwrap();

        set_worker_mkdir_interrupt_after(Some(0));
        let interrupted = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            create_worker_directory_layout(&layout)
        }));
        set_worker_mkdir_interrupt_after(None);
        assert!(interrupted.is_err());
        let staged = fs::read_dir(&parent)
            .unwrap()
            .next()
            .unwrap()
            .unwrap()
            .path();
        let unrelated = staged.join("operator-entry");
        fs::create_dir(&unrelated).unwrap();

        let error = create_worker_directory_layout(&layout).unwrap_err();

        assert_eq!(error.kind(), io::ErrorKind::PermissionDenied);
        assert!(!root.exists());
        assert!(unrelated.is_dir());
        fs::remove_dir_all(parent).unwrap();
    }

    #[test]
    fn existing_acl_bearing_canonical_worker_root_is_rejected_without_rewrite() {
        let principal = test_principal();
        let parent = fs::canonicalize(std::env::temp_dir())
            .unwrap()
            .join(format!(
                "styrn-worker-existing-acl-{}-{}",
                std::process::id(),
                uuid::Uuid::now_v7()
            ));
        let root = parent.join("root");
        fs::create_dir_all(&root).unwrap();
        fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();
        seed_current_user_acl(&root, ACL_EXTENDED_ALLOW);
        let layout = crate::platform::resolve_worker_directory_layout(
            crate::platform::InstallationScope::System,
            &principal,
            Some(&root),
        )
        .unwrap();

        let error = create_worker_directory_layout(&layout).unwrap_err();

        assert_eq!(error.kind(), io::ErrorKind::PermissionDenied);
        assert!(verify_no_extended_acl(&root).is_err());
        assert_eq!(fs::read_dir(&root).unwrap().count(), 0);
        clear_extended_acl(&root).unwrap();
        fs::remove_dir_all(parent).unwrap();
    }

    #[test]
    fn user_profile_anchor_with_mutating_allow_acl_is_rejected_before_creation() {
        let principal = test_principal();
        let parent = fs::canonicalize(std::env::temp_dir())
            .unwrap()
            .join(format!(
                "styrn-worker-profile-acl-{}-{}",
                std::process::id(),
                uuid::Uuid::now_v7()
            ));
        let profile = parent.join("profile");
        fs::create_dir_all(&profile).unwrap();
        fs::set_permissions(&profile, fs::Permissions::from_mode(0o700)).unwrap();
        seed_current_user_acl(&profile, ACL_EXTENDED_ALLOW);
        let root = profile.join("Library/Application Support/Styrn");
        let layout = crate::platform::WorkerDirectoryLayout::new(
            crate::platform::InstallationScope::User,
            root,
            crate::platform::WorkerRootCreationPolicy::CreateMissingFrom(profile.clone()),
            principal,
        );

        let error = create_worker_directory_layout(&layout).unwrap_err();

        assert_eq!(error.kind(), io::ErrorKind::PermissionDenied);
        assert!(!profile.join("Library").exists());
        assert!(verify_no_extended_acl(&profile).is_err());
        clear_extended_acl(&profile).unwrap();
        fs::remove_dir_all(parent).unwrap();
    }

    #[test]
    fn new_worker_nodes_clear_inherited_extended_acl_before_descending() {
        let principal = test_principal();
        let parent = fs::canonicalize(std::env::temp_dir())
            .unwrap()
            .join(format!(
                "styrn-worker-inherited-acl-{}-{}",
                std::process::id(),
                uuid::Uuid::now_v7()
            ));
        let profile = parent.join("profile");
        fs::create_dir_all(&profile).unwrap();
        fs::set_permissions(&profile, fs::Permissions::from_mode(0o700)).unwrap();
        seed_current_user_acl_with_flags_and_permissions(
            &profile,
            ACL_EXTENDED_DENY,
            &[ACL_ENTRY_FILE_INHERIT, ACL_ENTRY_DIRECTORY_INHERIT],
            &[ACL_WRITE_DATA],
        );
        let inheritance_probe = profile.join("inheritance-probe");
        fs::create_dir(&inheritance_probe).unwrap();
        assert!(verify_no_extended_acl(&inheritance_probe).is_err());
        clear_extended_acl(&inheritance_probe).unwrap();
        fs::remove_dir(&inheritance_probe).unwrap();
        let root = profile.join("Library/Application Support/Styrn");
        let layout = crate::platform::WorkerDirectoryLayout::new(
            crate::platform::InstallationScope::User,
            root.clone(),
            crate::platform::WorkerRootCreationPolicy::CreateMissingFrom(profile.clone()),
            principal,
        );

        create_worker_directory_layout(&layout).unwrap();

        for path in [
            profile.join("Library"),
            profile.join("Library/Application Support"),
            root.clone(),
            root.join("repos"),
            root.join("jobs"),
            root.join("cache"),
            root.join("artifacts"),
            root.join("logs"),
        ] {
            verify_no_extended_acl(&path).unwrap();
            assert_eq!(
                fs::metadata(path).unwrap().permissions().mode() & 0o777,
                0o700
            );
        }
        assert!(verify_no_extended_acl(&profile).is_err());
        clear_extended_acl(&profile).unwrap();
        fs::remove_dir_all(parent).unwrap();
    }

    #[test]
    fn deterministic_policy_rejects_wrong_owner_and_worker_write_paths() {
        let valid = UnixManifestInspection {
            expected_uid: 0,
            file_uid: 0,
            file_mode: 0o644,
            directory_uid: 0,
            directory_mode: 0o755,
        };
        assert!(validate_manifest_inspection(&UnixManifestInspection {
            file_uid: 1,
            ..valid
        })
        .is_err());
        assert!(validate_manifest_inspection(&UnixManifestInspection {
            file_mode: 0o664,
            ..valid
        })
        .is_err());
        assert!(validate_manifest_inspection(&UnixManifestInspection {
            directory_mode: 0o775,
            ..valid
        })
        .is_err());
        for directory_mode in [0o700, 0o750] {
            assert!(validate_manifest_inspection(&UnixManifestInspection {
                directory_mode,
                ..valid
            })
            .is_err());
        }
        assert!(validate_manifest_inspection(&valid).is_ok());
    }

    #[test]
    fn worker_owned_read_only_ancestor_is_still_rejected() {
        assert!(validate_ancestor_access(41, 0o555, Some(41), true).is_err());
    }

    #[test]
    fn user_ancestor_policy_accepts_sticky_protection_and_rejects_takeover_authority() {
        let mut reached_system_owner = false;
        assert!(
            validate_user_ancestor_access(0, 0o1777, 41, 41, &mut reached_system_owner,).is_ok()
        );
        assert!(reached_system_owner);

        let mut user_owned_chain = false;
        assert!(validate_user_ancestor_access(41, 0o0777, 41, 41, &mut user_owned_chain,).is_err());
        let mut unrelated_owner_chain = false;
        assert!(
            validate_user_ancestor_access(42, 0o0755, 41, 41, &mut unrelated_owner_chain,).is_err()
        );
        let mut invalid_reverse_transition = true;
        assert!(
            validate_user_ancestor_access(41, 0o0755, 0, 41, &mut invalid_reverse_transition,)
                .is_err()
        );
    }

    #[test]
    fn extended_mutation_acl_survives_chmod_and_must_be_rejected() {
        let directory = std::env::temp_dir().join(format!(
            "styrn-macos-acl-red-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        fs::create_dir(&directory).unwrap();
        let path = directory.join("machine.toml");
        fs::write(&path, "schema_version = 1\n").unwrap();
        seed_current_user_mutation_acl(&path);
        fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();

        assert!(verify_manifest_security(
            &path,
            ManifestOwner::CurrentProcess,
            &test_principal(),
            &directory,
        )
        .is_err());

        harden_manifest_file(&path, ManifestOwner::CurrentProcess, &test_principal()).unwrap();
        verify_manifest_security(
            &path,
            ManifestOwner::CurrentProcess,
            &test_principal(),
            &directory,
        )
        .unwrap();

        seed_current_user_mutation_acl(&directory);
        assert!(verify_manifest_security(
            &path,
            ManifestOwner::CurrentProcess,
            &test_principal(),
            &directory,
        )
        .is_err());
        harden_manifest_directory(&directory, ManifestOwner::CurrentProcess, &test_principal())
            .unwrap();
        verify_manifest_security(
            &path,
            ManifestOwner::CurrentProcess,
            &test_principal(),
            &directory,
        )
        .unwrap();

        let _ = fs::remove_file(path);
        let _ = fs::remove_dir(directory);
    }

    #[test]
    fn user_trusted_root_accepts_protective_deny_acl_but_rejects_every_allow_acl() {
        let directory = std::env::temp_dir().join(format!(
            "styrn-macos-user-root-acl-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        fs::create_dir(&directory).unwrap();
        fs::set_permissions(&directory, fs::Permissions::from_mode(0o700)).unwrap();

        seed_current_user_acl(&directory, ACL_EXTENDED_DENY);
        verify_user_trusted_root(&directory, unsafe { libc::geteuid() }).unwrap();

        seed_current_user_acl(&directory, ACL_EXTENDED_ALLOW);
        assert!(verify_user_trusted_root(&directory, unsafe { libc::geteuid() }).is_err());

        clear_extended_acl(&directory).unwrap();
        fs::remove_dir(directory).unwrap();
    }

    #[test]
    fn user_trusted_root_rejects_allow_acl_after_a_protective_deny_entry() {
        let directory = std::env::temp_dir().join(format!(
            "styrn-macos-user-root-multi-acl-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        fs::create_dir(&directory).unwrap();
        fs::set_permissions(&directory, fs::Permissions::from_mode(0o700)).unwrap();
        seed_current_user_acls(&directory, &[ACL_EXTENDED_DENY, ACL_EXTENDED_ALLOW]);

        assert!(verify_user_trusted_root(&directory, unsafe { libc::geteuid() }).is_err());

        clear_extended_acl(&directory).unwrap();
        fs::remove_dir(directory).unwrap();
    }

    #[test]
    fn native_application_support_is_an_accepted_user_receipt_trusted_root() {
        let root = Path::new(
            &std::env::var("HOME").expect("HOME is required for the macOS user-state contract"),
        )
        .join("Library/Application Support");

        verify_manifest_ancestors(&root, ManifestOwner::User, &test_principal(), &root).unwrap();
    }

    fn seed_current_user_mutation_acl(path: &Path) {
        seed_current_user_acl(path, ACL_EXTENDED_ALLOW);
    }

    fn seed_current_user_acl(path: &Path, tag: i32) {
        seed_current_user_acls(path, &[tag]);
    }

    fn seed_current_user_acl_with_flags_and_permissions(
        path: &Path,
        tag: i32,
        flags: &[i32],
        permissions: &[i32],
    ) {
        seed_current_user_acls_with_flags(path, &[tag], flags, permissions);
    }

    fn seed_current_user_acls(path: &Path, tags: &[i32]) {
        seed_current_user_acls_with_flags(
            path,
            tags,
            &[],
            &[ACL_WRITE_DATA, ACL_DELETE, ACL_DELETE_CHILD],
        );
    }

    fn seed_current_user_acls_with_flags(
        path: &Path,
        tags: &[i32],
        flags: &[i32],
        acl_permissions: &[i32],
    ) {
        let mut acl = unsafe { acl_init(tags.len().try_into().unwrap()) };
        assert!(!acl.is_null());
        let mut uuid = [0_u8; 16];
        assert_eq!(
            unsafe { mbr_uid_to_uuid(libc::geteuid(), uuid.as_mut_ptr()) },
            0
        );
        for tag in tags {
            let mut entry = std::ptr::null_mut();
            assert_eq!(unsafe { acl_create_entry(&mut acl, &mut entry) }, 0);
            assert_eq!(unsafe { acl_set_tag_type(entry, *tag) }, 0);
            assert_eq!(unsafe { acl_set_qualifier(entry, uuid.as_ptr().cast()) }, 0);
            let mut permissions = std::ptr::null_mut();
            assert_eq!(unsafe { acl_get_permset(entry, &mut permissions) }, 0);
            for permission in acl_permissions {
                assert_eq!(unsafe { acl_add_perm(permissions, *permission) }, 0);
            }
            let mut flagset = std::ptr::null_mut();
            assert_eq!(unsafe { acl_get_flagset_np(entry, &mut flagset) }, 0);
            for flag in flags {
                assert_eq!(unsafe { acl_add_flag_np(flagset, *flag) }, 0);
            }
            assert_eq!(unsafe { acl_set_flagset_np(entry, flagset) }, 0);
        }
        let path = c_path(path).unwrap();
        assert_eq!(
            unsafe { acl_set_file(path.as_ptr(), ACL_TYPE_EXTENDED, acl) },
            0
        );
        unsafe {
            acl_free(acl);
        }
    }
}
