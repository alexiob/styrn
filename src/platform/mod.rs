#[cfg(target_os = "linux")]
mod linux;

#[cfg(target_os = "macos")]
mod macos;

#[cfg(target_os = "windows")]
mod windows;

use std::path::Path;
use std::path::PathBuf;

use serde::{Deserialize, Serialize};

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum InstallationScope {
    User,
    System,
}

impl std::str::FromStr for InstallationScope {
    type Err = &'static str;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "user" => Ok(Self::User),
            "system" => Ok(Self::System),
            _ => Err("scope must be 'user' or 'system'"),
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub(crate) enum PrincipalKind {
    UnixUid,
    WindowsSid,
}

/// A validated, stable native account identity.
///
/// Keep this type free of `Display`: callers must choose deliberately whether
/// a diagnostic needs the account name or native identifier.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub(crate) struct WorkerPrincipal {
    principal_kind: PrincipalKind,
    principal_id: String,
    name: String,
}

impl WorkerPrincipal {
    pub(crate) fn new(
        principal_kind: PrincipalKind,
        principal_id: impl Into<String>,
        name: impl Into<String>,
    ) -> std::io::Result<Self> {
        let principal_id = principal_id.into();
        let name = name.into();
        validate_principal_name(principal_kind, &name)?;
        match principal_kind {
            PrincipalKind::UnixUid => validate_unix_uid(&principal_id)?,
            PrincipalKind::WindowsSid => validate_windows_sid(&principal_id)?,
        }
        Ok(Self {
            principal_kind,
            principal_id,
            name,
        })
    }

    pub(crate) fn principal_kind(&self) -> PrincipalKind {
        self.principal_kind
    }

    #[allow(dead_code)] // Used by platform-specific authorization and integration contracts.
    pub(crate) fn principal_id(&self) -> &str {
        &self.principal_id
    }

    pub(crate) fn name(&self) -> &str {
        &self.name
    }

    #[cfg(unix)]
    pub(crate) fn unix_uid(&self) -> std::io::Result<u32> {
        if self.principal_kind != PrincipalKind::UnixUid {
            return Err(invalid_principal("worker principal is not a Unix uid"));
        }
        self.principal_id
            .parse::<u32>()
            .map_err(|_| invalid_principal("worker uid is invalid"))
    }
}

impl<'de> Deserialize<'de> for WorkerPrincipal {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Wire {
            principal_kind: PrincipalKind,
            principal_id: String,
            name: String,
        }

        let wire = Wire::deserialize(deserializer)?;
        Self::new(wire.principal_kind, wire.principal_id, wire.name)
            .map_err(serde::de::Error::custom)
    }
}

fn validate_unix_uid(value: &str) -> std::io::Result<()> {
    let uid = value
        .parse::<u32>()
        .map_err(|_| invalid_principal("worker uid must be canonical decimal u32 text"))?;
    if uid == 0 || uid.to_string() != value {
        return Err(invalid_principal(
            "worker uid must be canonical non-root decimal text",
        ));
    }
    Ok(())
}

fn validate_windows_sid(value: &str) -> std::io::Result<()> {
    let Some(rest) = value.strip_prefix("S-1-") else {
        return Err(invalid_principal("worker SID must use canonical S-1 text"));
    };
    let components = rest.split('-').collect::<Vec<_>>();
    if !(2..=16).contains(&components.len()) {
        return Err(invalid_principal(
            "worker SID has an invalid component count",
        ));
    }
    let authority = canonical_decimal(components[0], u64::MAX)?;
    if authority > 0x0000_ffff_ffff_ffff {
        return Err(invalid_principal("worker SID authority is out of range"));
    }
    for component in &components[1..] {
        canonical_decimal(component, u32::MAX as u64)?;
    }
    if value == "S-1-5-18" {
        return Err(invalid_principal("SYSTEM cannot be a worker principal"));
    }
    Ok(())
}

fn canonical_decimal(value: &str, maximum: u64) -> std::io::Result<u64> {
    let parsed = value
        .parse::<u64>()
        .map_err(|_| invalid_principal("native principal identifier is not decimal"))?;
    if parsed > maximum || parsed.to_string() != value {
        return Err(invalid_principal(
            "native principal identifier is not canonical",
        ));
    }
    Ok(parsed)
}

fn validate_principal_name(_kind: PrincipalKind, value: &str) -> std::io::Result<()> {
    if value.is_empty()
        || value.len() > 256
        || value.trim() != value
        || value.chars().any(char::is_control)
    {
        return Err(invalid_principal("worker account name is invalid"));
    }
    // The stable native id, not a locally invented login-name grammar, is the
    // authority. NSS and directory services legitimately return names outside
    // traditional `useradd` syntax (for example numeric-leading or `$` names).
    // Exclude only values that are ambiguous at filesystem/serialization
    // boundaries; the platform adapter separately proves the exact id/name map.
    let valid = !value
        .bytes()
        .any(|byte| matches!(byte, b'\\' | b'/' | b':'));
    if !valid {
        return Err(invalid_principal("worker account name is ambiguous"));
    }
    Ok(())
}

fn invalid_principal(message: &'static str) -> std::io::Error {
    std::io::Error::new(std::io::ErrorKind::InvalidInput, message)
}

#[allow(dead_code)] // The setup orchestrator consumes all three host classes.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum SetupHostPrivilege {
    Ordinary,
    Root,
    Administrator,
}

/// Native setup identity captured before any mutation.
///
/// The execution token is intentionally opaque, non-serializable, and not
/// `Debug`: it is authority, not request data.
#[allow(dead_code)] // The T0.12 setup orchestrator consumes this boundary.
pub(crate) struct SetupExecutionContext {
    host_privilege: SetupHostPrivilege,
    original_principal: WorkerPrincipal,
    user_token: UserExecutionToken,
}

#[allow(dead_code)] // The T0.12 setup orchestrator passes this to user-phase execution.
pub(crate) struct UserExecutionToken(platform_impl::UserExecutionToken);

#[allow(dead_code)]
impl UserExecutionToken {
    pub(crate) fn run_user_phase(
        &self,
        request: &[u8],
    ) -> std::io::Result<std::process::ExitStatus> {
        platform_impl::run_user_phase(&self.0, request)
    }
}

#[allow(dead_code)]
impl SetupExecutionContext {
    pub(crate) fn capture() -> std::io::Result<Self> {
        platform_impl::capture_setup_execution_context()
    }

    #[cfg(test)]
    pub(crate) fn new_for_test(
        host_privilege: SetupHostPrivilege,
        original_principal: WorkerPrincipal,
    ) -> Self {
        assert_eq!(
            original_principal,
            resolve_current_worker_principal().unwrap(),
            "test execution tokens may only represent the actual current principal"
        );
        let user_token = platform_impl::test_user_execution_token(&original_principal);
        Self::new(host_privilege, original_principal, user_token)
    }

    #[cfg(test)]
    pub(crate) fn with_original_principal_for_test(
        mut self,
        original_principal: WorkerPrincipal,
    ) -> Self {
        self.original_principal = original_principal;
        self
    }

    fn new(
        host_privilege: SetupHostPrivilege,
        original_principal: WorkerPrincipal,
        user_token: platform_impl::UserExecutionToken,
    ) -> Self {
        Self {
            host_privilege,
            original_principal,
            user_token: UserExecutionToken(user_token),
        }
    }

    pub(crate) fn host_privilege(&self) -> SetupHostPrivilege {
        self.host_privilege
    }

    pub(crate) fn original_principal(&self) -> &WorkerPrincipal {
        &self.original_principal
    }

    pub(crate) fn user_token(&self) -> &UserExecutionToken {
        &self.user_token
    }
}

#[cfg(unix)]
#[derive(Clone, Copy)]
struct UnixCallerIds {
    real_uid: u32,
    effective_uid: u32,
    real_gid: u32,
    effective_gid: u32,
}

#[cfg(unix)]
impl UnixCallerIds {
    fn new(real_uid: u32, effective_uid: u32, real_gid: u32, effective_gid: u32) -> Self {
        Self {
            real_uid,
            effective_uid,
            real_gid,
            effective_gid,
        }
    }
}

#[cfg(unix)]
#[derive(Clone, Copy)]
struct UnixOriginalIdentity {
    uid: u32,
    gid: u32,
}

#[cfg(unix)]
impl UnixOriginalIdentity {
    fn new(uid: u32, gid: u32) -> Self {
        Self { uid, gid }
    }
}

#[cfg(unix)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct UnixExecutionSelection {
    privilege: SetupHostPrivilege,
    uid: u32,
    gid: u32,
}

#[cfg(unix)]
impl UnixExecutionSelection {
    fn new(privilege: SetupHostPrivilege, uid: u32, gid: u32) -> Self {
        Self {
            privilege,
            uid,
            gid,
        }
    }
}

#[cfg(unix)]
fn select_unix_execution<F>(
    caller: UnixCallerIds,
    elevated_origin: F,
) -> std::io::Result<UnixExecutionSelection>
where
    F: FnOnce() -> std::io::Result<UnixOriginalIdentity>,
{
    if caller.real_uid == caller.effective_uid
        && caller.real_uid != 0
        && caller.real_gid == caller.effective_gid
        && caller.real_gid != 0
    {
        return Ok(UnixExecutionSelection::new(
            SetupHostPrivilege::Ordinary,
            caller.real_uid,
            caller.real_gid,
        ));
    }
    if caller.real_uid == 0
        && caller.effective_uid == 0
        && caller.real_gid == 0
        && caller.effective_gid == 0
    {
        let original = elevated_origin()?;
        if original.uid == 0 || original.gid == 0 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                "elevated setup requires an original non-root user and group",
            ));
        }
        return Ok(UnixExecutionSelection::new(
            SetupHostPrivilege::Root,
            original.uid,
            original.gid,
        ));
    }
    Err(std::io::Error::new(
        std::io::ErrorKind::PermissionDenied,
        "ambiguous Unix setup caller identity",
    ))
}

#[cfg(unix)]
fn parse_sudo_origin_entries<I, K, V>(entries: I) -> std::io::Result<(UnixOriginalIdentity, String)>
where
    I: IntoIterator<Item = (K, V)>,
    K: AsRef<std::ffi::OsStr>,
    V: AsRef<std::ffi::OsStr>,
{
    let mut uid = None;
    let mut gid = None;
    let mut user = None;
    for (key, value) in entries {
        let slot = if key.as_ref() == std::ffi::OsStr::new("SUDO_UID") {
            Some(&mut uid)
        } else if key.as_ref() == std::ffi::OsStr::new("SUDO_GID") {
            Some(&mut gid)
        } else if key.as_ref() == std::ffi::OsStr::new("SUDO_USER") {
            Some(&mut user)
        } else {
            None
        };
        if let Some(slot) = slot {
            if slot.replace(value.as_ref().to_owned()).is_some() {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::PermissionDenied,
                    "elevated setup has ambiguous sudo origin fields",
                ));
            }
        }
    }
    let parse_id = |value: Option<std::ffi::OsString>| -> std::io::Result<u32> {
        let value = value
            .and_then(|value| value.into_string().ok())
            .ok_or_else(|| {
                std::io::Error::new(
                    std::io::ErrorKind::PermissionDenied,
                    "elevated setup is missing a valid sudo origin",
                )
            })?;
        let id = value.parse::<u32>().map_err(|_| {
            std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                "elevated setup has malformed sudo origin ids",
            )
        })?;
        if id.to_string() != value {
            return Err(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                "elevated setup has non-canonical sudo origin ids",
            ));
        }
        Ok(id)
    };
    let uid = parse_id(uid)?;
    let gid = parse_id(gid)?;
    let user = user
        .and_then(|value| value.into_string().ok())
        .ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                "elevated setup is missing a valid sudo original user",
            )
        })?;
    validate_principal_name(PrincipalKind::UnixUid, &user)?;
    Ok((UnixOriginalIdentity::new(uid, gid), user))
}

#[allow(dead_code)]
const SE_GROUP_ENABLED: u32 = 0x0000_0004;
#[allow(dead_code)]
const SE_GROUP_USE_FOR_DENY_ONLY: u32 = 0x0000_0010;

#[allow(dead_code)] // Native Windows capture is an explicit follow-on gate.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum WindowsTokenElevationType {
    Default,
    Full,
    Limited,
}

#[allow(dead_code)] // Native Windows capture is an explicit follow-on gate.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum WindowsIntegrityLevel {
    Low,
    Medium,
    High,
    System,
}

#[allow(dead_code)] // Native Windows capture is an explicit follow-on gate.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct WindowsTokenPosture {
    elevation_type: WindowsTokenElevationType,
    integrity_level: WindowsIntegrityLevel,
    administrators_group_attributes: Option<u32>,
}

#[allow(dead_code)]
impl WindowsTokenPosture {
    pub(crate) fn new(
        elevation_type: WindowsTokenElevationType,
        integrity_level: WindowsIntegrityLevel,
        administrators_group_attributes: Option<u32>,
    ) -> Self {
        Self {
            elevation_type,
            integrity_level,
            administrators_group_attributes,
        }
    }
}

#[allow(dead_code)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum WindowsUserTokenChoice {
    Current,
    LinkedLimited,
}

#[allow(dead_code)]
fn select_windows_user_token(
    current: WindowsTokenPosture,
    linked: Option<WindowsTokenPosture>,
) -> std::io::Result<WindowsUserTokenChoice> {
    let admin_enabled = |posture: WindowsTokenPosture| {
        posture
            .administrators_group_attributes
            .is_some_and(|attributes| attributes & SE_GROUP_ENABLED != 0)
    };
    let admin_deny_only = |posture: WindowsTokenPosture| {
        posture
            .administrators_group_attributes
            .is_some_and(|attributes| {
                attributes & SE_GROUP_USE_FOR_DENY_ONLY != 0 && attributes & SE_GROUP_ENABLED == 0
            })
    };
    let safe_limited = |posture: WindowsTokenPosture| {
        posture.elevation_type == WindowsTokenElevationType::Limited
            && posture.integrity_level == WindowsIntegrityLevel::Medium
            && admin_deny_only(posture)
    };
    let safe_full = |posture: WindowsTokenPosture| {
        posture.elevation_type == WindowsTokenElevationType::Full
            && posture.integrity_level == WindowsIntegrityLevel::High
            && admin_enabled(posture)
    };

    match current.elevation_type {
        WindowsTokenElevationType::Default
            if current.integrity_level == WindowsIntegrityLevel::Medium
                && current.administrators_group_attributes.is_none() =>
        {
            Ok(WindowsUserTokenChoice::Current)
        }
        WindowsTokenElevationType::Limited
            if safe_limited(current) && linked.is_some_and(safe_full) =>
        {
            Ok(WindowsUserTokenChoice::Current)
        }
        WindowsTokenElevationType::Full
            if safe_full(current) && linked.is_some_and(safe_limited) =>
        {
            Ok(WindowsUserTokenChoice::LinkedLimited)
        }
        _ => Err(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            "Windows has no safe non-elevated medium user token",
        )),
    }
}

fn validated_privileged_phase_arguments(
    executable: &Path,
    request_path: &Path,
    request_digest: &str,
    current_executable: &Path,
) -> std::io::Result<Vec<std::ffi::OsString>> {
    if !executable.is_absolute() || !request_path.is_absolute() || !current_executable.is_absolute()
    {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "setup authorization paths must be absolute",
        ));
    }
    let executable = std::fs::canonicalize(executable)?;
    let current_executable = std::fs::canonicalize(current_executable)?;
    if executable != current_executable {
        return Err(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            "setup authorization executable is not the current binary",
        ));
    }
    if request_path.components().any(|component| {
        matches!(
            component,
            std::path::Component::CurDir | std::path::Component::ParentDir
        )
    }) {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "setup authorization request path is not normalized",
        ));
    }
    if request_path.file_name() != Some(std::ffi::OsStr::new("authorization-request.json"))
        || !authorization_request_path_is_safe_for_argv(request_path)
    {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "setup authorization request path is outside the closed request shape",
        ));
    }
    if request_digest.len() != 64
        || !request_digest
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
    {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "setup authorization request digest is invalid",
        ));
    }
    Ok(vec![
        "setup".into(),
        "privileged-phase".into(),
        "--request".into(),
        request_path.as_os_str().to_owned(),
        "--digest".into(),
        request_digest.into(),
    ])
}

fn authorization_request_path_is_safe_for_argv(path: &Path) -> bool {
    let Some(value) = path.to_str() else {
        return false;
    };
    if value.chars().any(char::is_control)
        || value
            .bytes()
            .any(|byte| matches!(byte, b'=' | b'?' | b'#' | b'\'' | b'"'))
    {
        return false;
    }
    let lowered = value.to_ascii_lowercase();
    ![
        "api_key",
        "apikey",
        "auth_key",
        "authkey",
        "password",
        "passwd",
        "private_key",
        "credential",
        "bearer",
        "secret",
        "token",
    ]
    .iter()
    .any(|marker| lowered.contains(marker))
}

#[cfg(unix)]
struct UnixAuthorizationInvocation {
    program: PathBuf,
    arguments: Vec<std::ffi::OsString>,
}

#[cfg(unix)]
fn unix_authorization_invocation(
    executable: &Path,
    request_path: &Path,
    request_digest: &str,
    current_executable: &Path,
) -> std::io::Result<UnixAuthorizationInvocation> {
    let child_arguments = validated_privileged_phase_arguments(
        executable,
        request_path,
        request_digest,
        current_executable,
    )?;
    let executable = std::fs::canonicalize(executable)?;
    let mut arguments = Vec::with_capacity(child_arguments.len() + 2);
    arguments.push("--".into());
    arguments.push(executable.as_os_str().to_owned());
    arguments.extend(child_arguments);
    Ok(UnixAuthorizationInvocation {
        program: PathBuf::from("/usr/bin/sudo"),
        arguments,
    })
}

#[cfg(unix)]
pub(crate) fn verify_setup_authorization_executable(executable: &Path) -> std::io::Result<PathBuf> {
    use std::os::unix::fs::{MetadataExt, PermissionsExt};

    let executable = std::fs::canonicalize(executable)?;
    let metadata = std::fs::symlink_metadata(&executable)?;
    if !metadata.is_file()
        || metadata.uid() != 0
        || metadata.permissions().mode() & 0o111 == 0
        || metadata.permissions().mode() & 0o022 != 0
    {
        return Err(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            "setup authorization requires an immutable system-installed Styrn executable",
        ));
    }
    platform_impl::verify_setup_authorization_path_security(&executable)?;
    let mut current = executable.parent();
    while let Some(ancestor) = current {
        let metadata = std::fs::symlink_metadata(ancestor)?;
        if !metadata.is_dir() || metadata.uid() != 0 || metadata.permissions().mode() & 0o022 != 0 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                "setup authorization executable ancestry is user-writable",
            ));
        }
        platform_impl::verify_setup_authorization_path_security(ancestor)?;
        current = ancestor.parent();
    }
    Ok(executable)
}

#[cfg(windows)]
#[allow(dead_code)] // Native Windows authorization is an explicit unavailable gate.
pub(crate) fn verify_setup_authorization_executable(executable: &Path) -> std::io::Result<PathBuf> {
    platform_impl::verify_setup_authorization_executable(executable)
}

#[allow(dead_code)] // Wired by the T0.12 setup orchestrator.
pub(crate) fn invoke_setup_authorization(
    executable: &Path,
    request_path: &Path,
    request_digest: &str,
) -> std::io::Result<()> {
    platform_impl::invoke_setup_authorization(executable, request_path, request_digest)
}

#[cfg(unix)]
fn validate_unix_caller_ids(real_uid: u32, effective_uid: u32) -> std::io::Result<u32> {
    if real_uid == 0 || effective_uid == 0 || real_uid != effective_uid {
        return Err(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            "privileged or mismatched caller identity requires an authenticated elevation handoff",
        ));
    }
    Ok(real_uid)
}

#[cfg(test)]
mod principal_tests {
    use super::*;

    #[test]
    fn stable_principal_syntax_is_closed_and_rejects_privileged_ids() {
        assert!(WorkerPrincipal::new(PrincipalKind::UnixUid, "501", "123-build$").is_ok());
        for id in ["", "0", "0501", "4294967296", "-1"] {
            assert!(
                WorkerPrincipal::new(PrincipalKind::UnixUid, id, "worker").is_err(),
                "{id}"
            );
        }
        assert!(WorkerPrincipal::new(
            PrincipalKind::WindowsSid,
            "S-1-5-21-1-2-3-1001",
            "build.agent$",
        )
        .is_ok());
        for id in [
            "S-1-5-18",
            "s-1-5-21-1",
            "S-01-5-21-1",
            "S-1-05-21-1",
            "S-1-5",
            "S-1-281474976710656-1",
        ] {
            assert!(
                WorkerPrincipal::new(PrincipalKind::WindowsSid, id, "worker").is_err(),
                "{id}"
            );
        }
        for name in [
            "",
            " worker",
            "worker ",
            "worker\nname",
            "a/b",
            "a\\b",
            "a:b",
        ] {
            assert!(WorkerPrincipal::new(PrincipalKind::UnixUid, "501", name).is_err());
        }
    }

    #[cfg(unix)]
    #[test]
    fn unix_caller_policy_accepts_only_equal_nonroot_ids() {
        assert_eq!(validate_unix_caller_ids(501, 501).unwrap(), 501);
        for (real, effective) in [(0, 0), (501, 0), (0, 501), (501, 502)] {
            assert!(validate_unix_caller_ids(real, effective).is_err());
        }
    }

    #[cfg(unix)]
    #[test]
    fn unix_authorization_uses_stable_uid_not_account_name() {
        let first = WorkerPrincipal::new(PrincipalKind::UnixUid, "501", "same-name").unwrap();
        let replacement = WorkerPrincipal::new(PrincipalKind::UnixUid, "502", "same-name").unwrap();
        assert_eq!(first.unix_uid().unwrap(), 501);
        assert_eq!(replacement.unix_uid().unwrap(), 502);
    }

    #[test]
    fn native_caller_resolution_ignores_spoofable_identity_environment() {
        const CHILD: &str = "STYRN_NATIVE_CALLER_SPOOF_CHILD";
        if std::env::var_os(CHILD).is_none() {
            let output = std::process::Command::new(std::env::current_exe().unwrap())
                .args([
                    "--exact",
                    "platform::principal_tests::native_caller_resolution_ignores_spoofable_identity_environment",
                    "--nocapture",
                ])
                .env(CHILD, "1")
                .env("USER", "forged-root")
                .env("LOGNAME", "forged-root")
                .env("USERNAME", "forged-root")
                .env("SUDO_UID", "0")
                .output()
                .unwrap();
            assert!(
                output.status.success(),
                "native identity child failed:\nstdout:\n{}\nstderr:\n{}",
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr)
            );
            return;
        }

        let principal = resolve_current_worker_principal().unwrap();
        assert_ne!(principal.name(), "forged-root");
        #[cfg(unix)]
        assert_eq!(
            principal.principal_id(),
            unsafe { libc::getuid() }.to_string()
        );
    }
}

#[cfg(test)]
mod setup_execution_tests {
    use super::*;

    #[cfg(unix)]
    #[test]
    fn unix_context_ignores_sudo_origin_when_ordinary_and_requires_it_when_root() {
        let ordinary = select_unix_execution(UnixCallerIds::new(501, 501, 20, 20), || {
            panic!("ordinary capture must not inspect SUDO_*")
        })
        .unwrap();
        assert_eq!(
            ordinary,
            UnixExecutionSelection::new(SetupHostPrivilege::Ordinary, 501, 20)
        );

        let root = select_unix_execution(UnixCallerIds::new(0, 0, 0, 0), || {
            Ok(UnixOriginalIdentity::new(501, 20))
        })
        .unwrap();
        assert_eq!(
            root,
            UnixExecutionSelection::new(SetupHostPrivilege::Root, 501, 20)
        );

        assert!(select_unix_execution(UnixCallerIds::new(0, 0, 0, 0), || {
            Err(std::io::Error::new(
                std::io::ErrorKind::NotFound,
                "missing origin",
            ))
        })
        .is_err());
        assert!(
            select_unix_execution(UnixCallerIds::new(501, 0, 20, 0), || {
                Ok(UnixOriginalIdentity::new(501, 20))
            })
            .is_err()
        );
    }

    #[cfg(unix)]
    #[test]
    fn sudo_origin_requires_exactly_one_consistent_value_per_field() {
        let valid = parse_sudo_origin_entries([
            ("SUDO_UID", "501"),
            ("SUDO_GID", "20"),
            ("SUDO_USER", "alex"),
            ("UNRELATED", "ignored"),
        ])
        .unwrap();
        assert_eq!(valid.0.uid, 501);
        assert_eq!(valid.0.gid, 20);
        assert_eq!(valid.1, "alex");

        for invalid in [
            vec![("SUDO_UID", "501"), ("SUDO_GID", "20")],
            vec![
                ("SUDO_UID", "501"),
                ("SUDO_UID", "502"),
                ("SUDO_GID", "20"),
                ("SUDO_USER", "alex"),
            ],
            vec![
                ("SUDO_UID", "0501"),
                ("SUDO_GID", "20"),
                ("SUDO_USER", "alex"),
            ],
        ] {
            assert!(parse_sudo_origin_entries(invalid).is_err());
        }
    }

    #[test]
    fn windows_token_policy_uses_only_a_medium_limited_user_token() {
        let limited = WindowsTokenPosture::new(
            WindowsTokenElevationType::Limited,
            WindowsIntegrityLevel::Medium,
            Some(SE_GROUP_USE_FOR_DENY_ONLY),
        );
        let full = WindowsTokenPosture::new(
            WindowsTokenElevationType::Full,
            WindowsIntegrityLevel::High,
            Some(SE_GROUP_ENABLED),
        );
        assert_eq!(
            select_windows_user_token(limited, Some(full)).unwrap(),
            WindowsUserTokenChoice::Current
        );
        assert_eq!(
            select_windows_user_token(full, Some(limited)).unwrap(),
            WindowsUserTokenChoice::LinkedLimited
        );

        let standard = WindowsTokenPosture::new(
            WindowsTokenElevationType::Default,
            WindowsIntegrityLevel::Medium,
            None,
        );
        assert_eq!(
            select_windows_user_token(standard, None).unwrap(),
            WindowsUserTokenChoice::Current
        );

        let uac_off_admin = WindowsTokenPosture::new(
            WindowsTokenElevationType::Default,
            WindowsIntegrityLevel::High,
            Some(SE_GROUP_ENABLED),
        );
        assert!(select_windows_user_token(uac_off_admin, None).is_err());
        assert!(select_windows_user_token(full, None).is_err());
    }

    #[test]
    fn privileged_phase_arguments_are_fixed_and_reject_relative_paths() {
        let current = std::env::current_exe().unwrap();
        let request = std::env::temp_dir().join("authorization-request.json");
        let digest = "a".repeat(64);
        assert_eq!(
            validated_privileged_phase_arguments(&current, &request, &digest, &current).unwrap(),
            vec![
                std::ffi::OsString::from("setup"),
                std::ffi::OsString::from("privileged-phase"),
                std::ffi::OsString::from("--request"),
                request.into_os_string(),
                std::ffi::OsString::from("--digest"),
                std::ffi::OsString::from(&digest),
            ]
        );
        assert!(validated_privileged_phase_arguments(
            Path::new("styrn"),
            Path::new("request.json"),
            &digest,
            &current,
        )
        .is_err());
        assert!(validated_privileged_phase_arguments(
            &current,
            Path::new("request.json"),
            &digest,
            &current,
        )
        .is_err());
        let secret_path = std::env::temp_dir()
            .join("api_key=do-not-echo")
            .join("authorization-request.json");
        let error = validated_privileged_phase_arguments(&current, &secret_path, &digest, &current)
            .unwrap_err();
        assert!(!error.to_string().contains("do-not-echo"));

        #[cfg(unix)]
        {
            let request = std::env::temp_dir().join("authorization-request.json");
            let invocation =
                unix_authorization_invocation(&current, &request, &digest, &current).unwrap();
            assert_eq!(invocation.program, PathBuf::from("/usr/bin/sudo"));
            assert_eq!(
                invocation.arguments,
                vec![
                    std::ffi::OsString::from("--"),
                    current.clone().into_os_string(),
                    std::ffi::OsString::from("setup"),
                    std::ffi::OsString::from("privileged-phase"),
                    std::ffi::OsString::from("--request"),
                    request.into_os_string(),
                    std::ffi::OsString::from("--digest"),
                    std::ffi::OsString::from(digest),
                ]
            );
        }
    }

    #[cfg(unix)]
    #[test]
    fn verified_private_file_removal_rejects_intermediate_directory_substitution() {
        use std::os::unix::fs::{symlink, PermissionsExt};

        let root = std::env::current_dir()
            .unwrap()
            .join("target")
            .join(format!("verified-remove-swap-{}", std::process::id()));
        let route = root.join("route");
        let request_parent = route.join("requests");
        std::fs::create_dir_all(&request_parent).unwrap();
        std::fs::set_permissions(&request_parent, std::fs::Permissions::from_mode(0o700)).unwrap();
        let request = request_parent.join("request.json");
        std::fs::write(&request, b"original").unwrap();
        std::fs::set_permissions(&request, std::fs::Permissions::from_mode(0o600)).unwrap();
        let identity = private_file_identity(&request).unwrap();
        let principal = resolve_current_worker_principal().unwrap();
        let removal = prepare_verified_private_file_removal(
            &request,
            ManifestOwner::CurrentProcess,
            &principal,
            identity,
        )
        .unwrap();

        let original_route = root.join("original-route");
        std::fs::rename(&route, &original_route).unwrap();
        let replacement = root.join("replacement");
        std::fs::create_dir_all(replacement.join("requests")).unwrap();
        let victim = replacement.join("requests/request.json");
        std::fs::write(&victim, b"must survive").unwrap();
        symlink(&replacement, &route).unwrap();

        consume_verified_private_file(removal).unwrap();
        assert_eq!(std::fs::read(&victim).unwrap(), b"must survive");
        assert!(!original_route.join("requests/request.json").exists());

        std::fs::remove_file(&route).unwrap();
        std::fs::remove_dir_all(&root).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn fixed_user_phase_seam_fails_closed_until_native_identity_restoration_exists() {
        let context = SetupExecutionContext::capture().unwrap();
        let error = context.user_token().run_user_phase(b"{}").unwrap_err();
        assert_eq!(error.kind(), std::io::ErrorKind::Unsupported);
    }

    #[cfg(unix)]
    #[test]
    #[ignore = "environmental: run this test under native sudo with SUDO_UID/GID/USER set"]
    fn native_sudo_launch_recovers_the_original_nonroot_principal() {
        let context = SetupExecutionContext::capture().unwrap();
        assert_eq!(context.host_privilege(), SetupHostPrivilege::Root);
        assert_ne!(context.original_principal().unix_uid().unwrap(), 0);
    }
}

#[derive(Clone, Copy, Debug)]
pub(crate) enum ManifestOwner {
    System,
    #[allow(dead_code)] // Source-including manifest fixtures omit the user receipt store.
    User,
    #[cfg(test)]
    CurrentProcess,
    #[cfg(test)]
    CurrentProcessWorker,
}

/// A staging pathname created with the platform's private-at-creation policy.
///
/// The containing parent is verified against worker takeover before this value
/// is minted, so keeping its field private prevents generic code from
/// publishing a separately created or worker-authorized directory.
pub(crate) struct PrivateManifestStagingDirectory {
    path: PathBuf,
}

/// Stable identity captured while enumerating a private transaction file.
/// The subsequent no-follow open must verify the same object before reading.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct PrivateFileIdentity {
    first: u64,
    second: u64,
}

impl PrivateFileIdentity {
    fn new(first: u64, second: u64) -> Self {
        Self { first, second }
    }
}

impl PrivateManifestStagingDirectory {
    pub(crate) fn path(&self) -> &Path {
        &self.path
    }
}

pub(crate) fn create_private_manifest_staging_directory(
    path: &Path,
    owner: ManifestOwner,
    principal: &WorkerPrincipal,
) -> std::io::Result<PrivateManifestStagingDirectory> {
    platform_impl::create_private_manifest_staging_directory(path, owner, principal)?;
    Ok(PrivateManifestStagingDirectory {
        path: path.to_path_buf(),
    })
}

pub(crate) fn harden_manifest_directory(
    path: &Path,
    owner: ManifestOwner,
    worker: &WorkerPrincipal,
) -> std::io::Result<()> {
    platform_impl::harden_manifest_directory(path, owner, worker)
}

pub(crate) fn harden_manifest_file(
    path: &Path,
    owner: ManifestOwner,
    worker: &WorkerPrincipal,
) -> std::io::Result<()> {
    platform_impl::harden_manifest_file(path, owner, worker)
}

pub(crate) fn open_manifest_lock(
    path: &Path,
    owner: ManifestOwner,
    principal: &WorkerPrincipal,
) -> std::io::Result<std::fs::File> {
    platform_impl::open_manifest_lock(path, owner, principal)
}

#[allow(dead_code)] // Source-including manifest tests do not include receipt recovery.
pub(crate) fn verify_private_file_security(
    path: &Path,
    owner: ManifestOwner,
    principal: &WorkerPrincipal,
) -> std::io::Result<()> {
    platform_impl::verify_private_file_security(path, owner, principal)
}

pub(crate) fn create_private_file(
    path: &Path,
    owner: ManifestOwner,
    principal: &WorkerPrincipal,
) -> std::io::Result<std::fs::File> {
    platform_impl::create_private_file(path, owner, principal)
}

#[allow(dead_code)] // Source-including manifest tests omit receipt recovery.
pub(crate) fn private_file_identity(path: &Path) -> std::io::Result<PrivateFileIdentity> {
    platform_impl::private_file_identity(path)
}

#[allow(dead_code)] // Source-including manifest tests omit receipt recovery.
pub(crate) fn open_verified_private_file_for_read(
    path: &Path,
    owner: ManifestOwner,
    principal: &WorkerPrincipal,
    expected_identity: PrivateFileIdentity,
) -> std::io::Result<std::fs::File> {
    platform_impl::open_verified_private_file_for_read(path, owner, principal, expected_identity)
}

#[allow(dead_code)] // Source-including manifest tests omit authorization execution.
pub(crate) struct PrivateFileRemoval(platform_impl::PrivateFileRemoval);

#[allow(dead_code)] // Source-including manifest tests omit authorization execution.
pub(crate) fn prepare_verified_private_file_removal(
    path: &Path,
    owner: ManifestOwner,
    principal: &WorkerPrincipal,
    expected_identity: PrivateFileIdentity,
) -> std::io::Result<PrivateFileRemoval> {
    platform_impl::prepare_verified_private_file_removal(path, owner, principal, expected_identity)
        .map(PrivateFileRemoval)
}

#[allow(dead_code)] // Source-including manifest tests omit authorization execution.
pub(crate) fn consume_verified_private_file(removal: PrivateFileRemoval) -> std::io::Result<()> {
    platform_impl::consume_verified_private_file(removal.0)
}

pub(crate) fn verify_manifest_security(
    path: &Path,
    owner: ManifestOwner,
    worker: &WorkerPrincipal,
    trusted_root: &Path,
) -> std::io::Result<()> {
    platform_impl::verify_manifest_security(path, owner, worker, trusted_root)
}

#[allow(dead_code)] // Source-including manifest tests do not include receipt reads.
pub(crate) fn open_verified_manifest_file_for_read(
    path: &Path,
    owner: ManifestOwner,
    worker: &WorkerPrincipal,
    trusted_root: &Path,
) -> std::io::Result<std::fs::File> {
    platform_impl::open_verified_manifest_file_for_read(path, owner, worker, trusted_root)
}

pub(crate) fn verify_manifest_ancestors(
    directory: &Path,
    owner: ManifestOwner,
    worker: &WorkerPrincipal,
    trusted_root: &Path,
) -> std::io::Result<()> {
    platform_impl::verify_manifest_ancestors(directory, owner, worker, trusted_root)
}

pub(crate) fn verify_manifest_parent_chain(
    parent: &Path,
    owner: ManifestOwner,
    worker: &WorkerPrincipal,
) -> std::io::Result<()> {
    platform_impl::verify_manifest_parent_chain(parent, owner, worker)
}

pub(crate) fn verify_manifest_directory_security(
    directory: &Path,
    owner: ManifestOwner,
    worker: &WorkerPrincipal,
) -> std::io::Result<()> {
    platform_impl::verify_manifest_directory_security(directory, owner, worker)
}

pub(crate) fn publish_manifest_directory(
    staging: &PrivateManifestStagingDirectory,
    destination: &Path,
) -> std::io::Result<()> {
    platform_impl::publish_manifest_directory(staging.path(), destination)
}

pub(crate) fn verify_manifest_file_target(path: &Path) -> std::io::Result<()> {
    platform_impl::verify_manifest_file_target(path)
}

pub(crate) fn resolve_current_worker_principal() -> std::io::Result<WorkerPrincipal> {
    platform_impl::resolve_current_worker_principal()
}

#[allow(dead_code)] // Explicit system-account selection is exercised by environmental gates.
pub(crate) fn resolve_named_worker_principal(name: &str) -> std::io::Result<WorkerPrincipal> {
    platform_impl::resolve_named_worker_principal(name)
}

pub(crate) fn verify_worker_principal(principal: &WorkerPrincipal) -> std::io::Result<()> {
    platform_impl::verify_worker_principal(principal)
}

/// Replaces a completed temporary file with its destination. Ownership and
/// permission hardening belong at this boundary in T0.7.
pub(crate) fn replace_file(temporary: &Path, destination: &Path) -> std::io::Result<()> {
    #[cfg(not(target_os = "windows"))]
    {
        std::fs::rename(temporary, destination)
    }
    #[cfg(target_os = "windows")]
    {
        windows::replace_file(temporary, destination)
    }
}

/// Makes a completed atomic directory-entry replacement durable where the
/// host requires an explicit parent-directory flush. Windows publication uses
/// `MOVEFILE_WRITE_THROUGH` in `replace_file`.
#[allow(dead_code)] // Source-including contract tests do not include receipt publication.
pub(crate) fn sync_parent_directory(directory: &Path) -> std::io::Result<()> {
    #[cfg(not(target_os = "windows"))]
    {
        std::fs::File::open(directory)?.sync_all()
    }
    #[cfg(target_os = "windows")]
    {
        let _ = directory;
        Ok(())
    }
}

#[cfg(target_os = "linux")]
use linux as platform_impl;

#[cfg(target_os = "macos")]
use macos as platform_impl;

#[cfg(target_os = "windows")]
use windows as platform_impl;
