//! Closed setup authorization request and execution boundary.
//!
//! Ordinary actions are journaled before this module creates any authorization
//! request. The parent process can ask one native adapter to launch the exact
//! current executable, but it never dispatches a privileged action itself.

use super::{execution::ApplyReport, Action, ActionCheck, PlanOperation, Privilege};
#[cfg(test)]
use super::{execution::PreparedActionRunner, ActionEffect, ActionError};
#[cfg(test)]
use crate::platform::{SetupExecutionContext, SetupHostPrivilege};
use crate::{
    platform::{ManifestOwner, WorkerPrincipal},
    setup::receipt::{InstallationScope, ReceiptMetadataSource, ReceiptStore},
};
use chrono::{DateTime, Duration, SecondsFormat, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    collections::HashSet,
    fs,
    io::{Read, Write},
    path::{Component, Path, PathBuf},
};
use thiserror::Error;
use uuid::Uuid;

const REQUEST_SCHEMA_VERSION: u8 = 1;
const REQUEST_LIFETIME: Duration = Duration::minutes(5);
const MAX_REQUEST_BYTES: usize = 64 * 1024;

pub(super) trait AuthorizationInvoker {
    fn invoke(
        &mut self,
        executable: &Path,
        request_path: &Path,
        request_digest: &str,
    ) -> Result<(), AuthorizationInvocationError>;
}

/// The only production authorization launcher. It delegates credential UI to
/// the native OS adapter and accepts success only from a zero-exit child.
#[allow(dead_code)] // T0.20 wires this into the setup command orchestration.
pub(super) struct NativeAuthorizationInvoker;

impl AuthorizationInvoker for NativeAuthorizationInvoker {
    fn invoke(
        &mut self,
        executable: &Path,
        request_path: &Path,
        request_digest: &str,
    ) -> Result<(), AuthorizationInvocationError> {
        classify_native_authorization(crate::platform::invoke_setup_authorization(
            executable,
            request_path,
            request_digest,
        ))
    }
}

fn classify_native_authorization(
    result: std::io::Result<std::process::ExitStatus>,
) -> Result<(), AuthorizationInvocationError> {
    let status = result.map_err(|error| {
        if error.kind() == std::io::ErrorKind::PermissionDenied {
            AuthorizationInvocationError::Failed
        } else {
            AuthorizationInvocationError::Launch(error)
        }
    })?;
    if status.success() {
        Ok(())
    } else {
        Err(AuthorizationInvocationError::ChildFailed {
            exit_code: status.code(),
        })
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum PrivilegeConsent {
    NotGranted,
    Granted,
}

#[allow(dead_code)] // T0.20 maps the one prompt or explicit flag to this policy.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum SystemAuthorizationPolicy {
    NotGranted,
    InteractiveConsent,
    ExplicitNoninteractive,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct AuthorizationOptions {
    consent: PrivilegeConsent,
    no_elevate: bool,
}

impl AuthorizationOptions {
    pub(super) fn from_policy(
        policy: SystemAuthorizationPolicy,
        no_elevate: bool,
    ) -> Result<Self, AuthorizationError> {
        let consent = match policy {
            SystemAuthorizationPolicy::NotGranted => PrivilegeConsent::NotGranted,
            SystemAuthorizationPolicy::InteractiveConsent
            | SystemAuthorizationPolicy::ExplicitNoninteractive => PrivilegeConsent::Granted,
        };
        if no_elevate && consent == PrivilegeConsent::Granted {
            return Err(AuthorizationError::RequestInvalid);
        }
        Ok(Self {
            consent,
            no_elevate,
        })
    }

    #[cfg(test)]
    fn noninteractive_yes() -> Self {
        Self::pending()
    }

    #[cfg(test)]
    fn interactive_yes_without_privilege_consent() -> Self {
        Self::pending()
    }

    #[cfg(test)]
    fn interactive_decline() -> Self {
        Self::pending()
    }

    #[cfg(test)]
    fn interactive_no_elevate() -> Self {
        Self::from_policy(SystemAuthorizationPolicy::NotGranted, true).unwrap()
    }

    #[cfg(test)]
    fn noninteractive_default() -> Self {
        Self::pending()
    }

    #[cfg(test)]
    fn interactive_accept() -> Self {
        Self::authorized()
    }

    #[cfg(test)]
    fn noninteractive_authorize_system() -> Self {
        Self::authorized()
    }

    #[cfg(test)]
    fn pending() -> Self {
        Self::from_policy(SystemAuthorizationPolicy::NotGranted, false).unwrap()
    }

    #[cfg(test)]
    fn authorized() -> Self {
        Self::from_policy(SystemAuthorizationPolicy::InteractiveConsent, false).unwrap()
    }

    fn should_invoke(self) -> bool {
        !self.no_elevate && self.consent == PrivilegeConsent::Granted
    }
}

#[derive(Clone, Copy, Debug, Deserialize, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
enum HostPrivilegeClass {
    UnixRoot,
    WindowsAdministrator,
}

#[derive(Clone, Debug)]
pub(super) struct AuthorizationContext {
    host_id: String,
    executable: PathBuf,
    request_path: PathBuf,
    principal: WorkerPrincipal,
    privilege_class: HostPrivilegeClass,
    now: DateTime<Utc>,
}

impl AuthorizationContext {
    #[allow(dead_code)] // T0.20 captures this after probe/plan and before mutation.
    pub(super) fn capture(
        host_id: &str,
        request_path: PathBuf,
        principal: WorkerPrincipal,
    ) -> Result<Self, AuthorizationError> {
        let privilege_class = if cfg!(target_os = "windows") {
            HostPrivilegeClass::WindowsAdministrator
        } else {
            HostPrivilegeClass::UnixRoot
        };
        let context = Self {
            host_id: host_id.to_owned(),
            executable: std::env::current_exe().map_err(|_| AuthorizationError::RequestInvalid)?,
            request_path,
            principal,
            privilege_class,
            now: Utc::now(),
        };
        context.validate()?;
        Ok(context)
    }

    #[cfg(test)]
    fn new_for_test(
        host_id: &str,
        executable: PathBuf,
        request_path: PathBuf,
        principal: WorkerPrincipal,
        now: &str,
    ) -> Result<Self, AuthorizationError> {
        let now = parse_canonical_timestamp(now)?;
        let privilege_class = if cfg!(target_os = "windows") {
            HostPrivilegeClass::WindowsAdministrator
        } else {
            HostPrivilegeClass::UnixRoot
        };
        let context = Self {
            host_id: host_id.to_owned(),
            executable,
            request_path,
            principal,
            privilege_class,
            now,
        };
        context.validate()?;
        Ok(context)
    }

    fn validate(&self) -> Result<(), AuthorizationError> {
        if self.host_id.len() > 255
            || !self
                .host_id
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-' | b'_'))
            || !crate::setup::validate_probe_static_text(&self.host_id)
        {
            return Err(AuthorizationError::RequestInvalid);
        }
        validate_absolute_normalized_path(&self.executable)?;
        validate_absolute_normalized_path(&self.request_path)?;
        if self.request_path.file_name() != Some(std::ffi::OsStr::new("authorization-request.json"))
            || !self
                .request_path
                .parent()
                .and_then(Path::to_str)
                .is_some_and(crate::setup::validate_probe_static_text)
        {
            return Err(AuthorizationError::RequestInvalid);
        }
        let current_executable =
            std::env::current_exe().map_err(|_| AuthorizationError::RequestInvalid)?;
        if self.executable != current_executable {
            return Err(AuthorizationError::RequestInvalid);
        }
        crate::platform::verify_worker_principal(&self.principal)
            .map_err(|_| AuthorizationError::PrincipalInvalid)
    }

    fn executable(&self) -> &Path {
        &self.executable
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum PrivilegedStatus {
    NotNeeded,
    NeedsHuman { count: usize },
    Pending { count: usize },
    AuthorizationLaunched { count: usize },
}

pub(super) struct AuthorizedExecutionReport {
    ordinary: ApplyReport,
    privileged_status: PrivilegedStatus,
}

impl AuthorizedExecutionReport {
    fn ordinary(&self) -> &ApplyReport {
        &self.ordinary
    }

    fn privileged_status(&self) -> PrivilegedStatus {
        self.privileged_status
    }

    fn everything_ready(&self) -> bool {
        self.ordinary.pending_count() == 0
            && matches!(self.privileged_status, PrivilegedStatus::NotNeeded)
    }
}

#[derive(Debug, Error)]
pub(super) enum AuthorizationInvocationError {
    #[error("native authorization was cancelled or failed")]
    Failed,
    #[error("native authorization could not be launched")]
    Launch(#[source] std::io::Error),
    #[error("privileged setup child failed with exit code {exit_code:?}")]
    ChildFailed { exit_code: Option<i32> },
}

#[derive(Debug, Error)]
pub(super) enum AuthorizationError {
    #[error(transparent)]
    Apply(#[from] super::execution::ApplyPlanError),
    #[error("setup authorization request is invalid")]
    RequestInvalid,
    #[error("setup authorization principal is invalid")]
    PrincipalInvalid,
    #[error("setup authorization request could not be written")]
    RequestWrite(#[source] std::io::Error),
    #[error("setup authorization request could not be read safely")]
    RequestRead(#[source] std::io::Error),
    #[error("setup authorization request was already consumed or could not be reserved")]
    RequestConsumed(#[source] crate::setup::receipt::ReceiptStoreError),
    #[error(transparent)]
    Invocation(#[from] AuthorizationInvocationError),
}

impl AuthorizationError {
    #[allow(dead_code)] // T0.20 maps this through the setup command envelope.
    fn error_code(&self) -> &'static str {
        match self {
            Self::Apply(error) => error.error_code(),
            Self::RequestInvalid
            | Self::PrincipalInvalid
            | Self::RequestRead(_)
            | Self::RequestConsumed(_) => "setup.plan_invalid",
            Self::RequestWrite(_) | Self::Invocation(_) => "setup.elevation_required",
        }
    }

    #[allow(dead_code)] // T0.20 maps this through the setup command envelope.
    fn exit_code(&self) -> u8 {
        13
    }
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct AuthorizationRequest {
    schema_version: u8,
    request_id: String,
    issued_at: String,
    expires_at: String,
    installation_scope: RequestScope,
    host_id: String,
    executable: String,
    principal: WorkerPrincipal,
    privilege_class: HostPrivilegeClass,
    displayed_actions: Vec<RequestedAction>,
}

#[derive(Clone, Debug, Deserialize, Hash, PartialEq, Eq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
enum RequestedAction {
    Foundation {
        action_id: String,
        privilege: RequestedPrivilege,
        operation: RequestedOperation,
    },
    #[cfg(test)]
    TestState {
        action_id: String,
        privilege: RequestedPrivilege,
        marker: u8,
    },
}

impl RequestedAction {
    fn action_id(&self) -> &str {
        match self {
            Self::Foundation { action_id, .. } => action_id,
            #[cfg(test)]
            Self::TestState { action_id, .. } => action_id,
        }
    }

    fn privilege(&self) -> RequestedPrivilege {
        match self {
            Self::Foundation { privilege, .. } => *privilege,
            #[cfg(test)]
            Self::TestState { privilege, .. } => *privilege,
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Hash, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
enum RequestedPrivilege {
    Root,
    Admin,
}

#[derive(Clone, Copy, Debug, Deserialize, Hash, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
enum RequestedOperation {
    Create,
    Reconfigure,
    Done,
    NeedsHuman,
    Skipped,
    Remove,
}

#[derive(Clone, Copy, Debug, Deserialize, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
enum RequestScope {
    System,
}

pub(super) fn execute_with_authorization<I: AuthorizationInvoker>(
    plan: &mut Vec<Action>,
    ordinary_store: &ReceiptStore,
    ordinary_metadata: &mut ReceiptMetadataSource,
    context: &AuthorizationContext,
    options: AuthorizationOptions,
    invoker: &mut I,
) -> Result<AuthorizedExecutionReport, AuthorizationError> {
    context.validate()?;
    if !ordinary_store.binds_user_authorization_request(&context.request_path, &context.principal) {
        return Err(AuthorizationError::RequestInvalid);
    }
    validate_plan(plan, context.privilege_class)?;

    let mut ordinary = Vec::new();
    let mut ordinary_indices = Vec::new();
    let mut retained = Vec::new();
    for (index, action) in std::mem::take(plan).into_iter().enumerate() {
        if action.privilege() == Privilege::None {
            ordinary_indices.push(index);
            ordinary.push(action);
        } else {
            retained.push((index, action));
        }
    }

    let ordinary_result =
        super::execution::apply_plan_with_journal(&mut ordinary, ordinary_store, ordinary_metadata);
    retained.extend(ordinary_indices.into_iter().zip(ordinary));
    retained.sort_unstable_by_key(|(index, _)| *index);
    plan.extend(retained.into_iter().map(|(_, action)| action));
    let ordinary = ordinary_result?;

    let mut requested_privileged = Vec::new();
    let mut privileged_needs_human = 0;
    for action in plan
        .iter()
        .filter(|action| action.privilege() != Privilege::None)
    {
        match action
            .check()
            .map_err(super::execution::ApplyPlanError::Action)?
        {
            ActionCheck::Todo => requested_privileged.push(requested_action(action)),
            ActionCheck::Done => {}
            ActionCheck::NeedsHuman(_) => privileged_needs_human += 1,
        }
    }
    let privileged_count = requested_privileged.len();

    let privileged_status = if privileged_count == 0 && privileged_needs_human == 0 {
        PrivilegedStatus::NotNeeded
    } else if privileged_count == 0 {
        PrivilegedStatus::NeedsHuman {
            count: privileged_needs_human,
        }
    } else if !options.should_invoke() {
        PrivilegedStatus::Pending {
            count: privileged_count,
        }
    } else {
        let request_digest = write_authorization_request(&requested_privileged, context)?;
        let invocation =
            invoker.invoke(&context.executable, &context.request_path, &request_digest);
        if invocation.is_err() {
            let _ = fs::remove_file(&context.request_path);
        }
        invocation?;
        // A successful native launcher only proves that the child exited zero.
        // Readiness remains pending until the parent verifies the typed child
        // result and protected system receipt in the activation slice.
        PrivilegedStatus::AuthorizationLaunched {
            count: privileged_count,
        }
    };

    Ok(AuthorizedExecutionReport {
        ordinary,
        privileged_status,
    })
}

fn validate_plan(
    plan: &[Action],
    privilege_class: HostPrivilegeClass,
) -> Result<(), AuthorizationError> {
    let mut names = HashSet::with_capacity(plan.len());
    for action in plan {
        if !names.insert(action.name().as_str()) {
            return Err(AuthorizationError::RequestInvalid);
        }
        let valid_privilege = match (privilege_class, action.privilege()) {
            (_, Privilege::None)
            | (HostPrivilegeClass::UnixRoot, Privilege::Root)
            | (HostPrivilegeClass::WindowsAdministrator, Privilege::Admin) => true,
            (HostPrivilegeClass::UnixRoot, Privilege::Admin)
            | (HostPrivilegeClass::WindowsAdministrator, Privilege::Root) => false,
        };
        if !valid_privilege {
            return Err(AuthorizationError::RequestInvalid);
        }
    }
    Ok(())
}

fn write_authorization_request(
    displayed_actions: &[RequestedAction],
    context: &AuthorizationContext,
) -> Result<String, AuthorizationError> {
    let executable = context
        .executable
        .to_str()
        .ok_or(AuthorizationError::RequestInvalid)?;
    if !crate::setup::validate_probe_static_text(executable) {
        return Err(AuthorizationError::RequestInvalid);
    }
    if !crate::setup::validate_probe_static_text(context.principal.principal_id())
        || !crate::setup::validate_probe_static_text(context.principal.name())
    {
        return Err(AuthorizationError::RequestInvalid);
    }
    let request = AuthorizationRequest {
        schema_version: REQUEST_SCHEMA_VERSION,
        request_id: Uuid::now_v7().to_string(),
        issued_at: context.now.to_rfc3339_opts(SecondsFormat::Secs, true),
        expires_at: (context.now + REQUEST_LIFETIME).to_rfc3339_opts(SecondsFormat::Secs, true),
        installation_scope: RequestScope::System,
        host_id: context.host_id.clone(),
        executable: executable.to_owned(),
        principal: context.principal.clone(),
        privilege_class: context.privilege_class,
        displayed_actions: displayed_actions.to_vec(),
    };
    let bytes = serde_json::to_vec(&request).map_err(|_| AuthorizationError::RequestInvalid)?;
    if bytes.len() > MAX_REQUEST_BYTES {
        return Err(AuthorizationError::RequestInvalid);
    }
    let parent = context
        .request_path
        .parent()
        .ok_or(AuthorizationError::RequestInvalid)?;
    crate::platform::verify_manifest_parent_chain(parent, ManifestOwner::User, &context.principal)
        .map_err(AuthorizationError::RequestWrite)?;
    let mut file = crate::platform::create_private_file(
        &context.request_path,
        ManifestOwner::User,
        &context.principal,
    )
    .map_err(AuthorizationError::RequestWrite)?;
    let result = (|| {
        file.write_all(&bytes)?;
        file.sync_all()?;
        crate::platform::verify_private_file_security(
            &context.request_path,
            ManifestOwner::User,
            &context.principal,
        )
    })();
    if let Err(error) = result {
        let _ = fs::remove_file(&context.request_path);
        return Err(AuthorizationError::RequestWrite(error));
    }
    Ok(request_digest(&bytes))
}

#[cfg(test)]
fn write_request(
    plan: &[Action],
    context: &AuthorizationContext,
) -> Result<String, AuthorizationError> {
    let displayed_actions = plan
        .iter()
        .filter(|action| action.privilege() != Privilege::None)
        .map(requested_action)
        .collect::<Vec<_>>();
    write_authorization_request(&displayed_actions, context)
}

fn requested_action(action: &Action) -> RequestedAction {
    let privilege = match action.privilege() {
        Privilege::Root => RequestedPrivilege::Root,
        Privilege::Admin => RequestedPrivilege::Admin,
        Privilege::None => unreachable!("ordinary actions cannot enter an authorization request"),
    };
    match action {
        Action::Foundation(action) => RequestedAction::Foundation {
            action_id: action.name.as_str().to_owned(),
            privilege,
            operation: match action.operation {
                PlanOperation::Create => RequestedOperation::Create,
                PlanOperation::Reconfigure => RequestedOperation::Reconfigure,
                PlanOperation::Done => RequestedOperation::Done,
                PlanOperation::NeedsHuman => RequestedOperation::NeedsHuman,
                PlanOperation::Skipped => RequestedOperation::Skipped,
                PlanOperation::Remove => RequestedOperation::Remove,
            },
        },
        #[cfg(test)]
        Action::Test(action) => RequestedAction::TestState {
            action_id: action.name.as_str().to_owned(),
            privilege,
            marker: action.marker,
        },
    }
}

pub(super) fn run_privileged_request(
    context: &AuthorizationContext,
    expected_request_digest: &str,
    recomputed_plan: &mut Vec<Action>,
    system_store: &ReceiptStore,
    metadata: &mut ReceiptMetadataSource,
) -> Result<ApplyReport, AuthorizationError> {
    #[cfg(not(test))]
    crate::platform::verify_setup_authorization_executable(&context.executable)
        .map_err(|_| AuthorizationError::RequestInvalid)?;
    context.validate()?;
    if system_store.installation_scope() != InstallationScope::System {
        return Err(AuthorizationError::RequestInvalid);
    }
    if system_store.worker_principal() != &context.principal {
        return Err(AuthorizationError::PrincipalInvalid);
    }
    validate_plan(recomputed_plan, context.privilege_class)?;
    if recomputed_plan
        .iter()
        .any(|action| action.privilege() == Privilege::None)
    {
        return Err(AuthorizationError::RequestInvalid);
    }
    validate_request_digest(expected_request_digest)?;
    let (request, removal) = read_request(context, expected_request_digest)?;
    validate_request(&request, context)?;
    let displayed = request
        .displayed_actions
        .iter()
        .cloned()
        .collect::<HashSet<_>>();
    if displayed.len() != request.displayed_actions.len() {
        return Err(AuthorizationError::RequestInvalid);
    }

    let mut selected_indices = Vec::new();
    for (index, action) in recomputed_plan.iter().enumerate() {
        match action
            .check()
            .map_err(super::execution::ApplyPlanError::Action)?
        {
            ActionCheck::Todo => selected_indices.push(index),
            ActionCheck::Done | ActionCheck::NeedsHuman(_) => {}
        }
    }
    if selected_indices
        .iter()
        .map(|index| requested_action(&recomputed_plan[*index]))
        .any(|action| !displayed.contains(&action))
    {
        return Err(AuthorizationError::RequestInvalid);
    }

    system_store
        .reserve_authorization(&request.request_id)
        .map_err(AuthorizationError::RequestConsumed)?;
    crate::platform::consume_verified_private_file(removal)
        .map_err(AuthorizationError::RequestRead)?;
    let selected_set = selected_indices.iter().copied().collect::<HashSet<_>>();
    let mut selected = Vec::with_capacity(selected_indices.len());
    let mut retained = Vec::new();
    for (index, action) in std::mem::take(recomputed_plan).into_iter().enumerate() {
        if selected_set.contains(&index) {
            selected.push(action);
        } else {
            retained.push((index, action));
        }
    }
    let result = super::execution::apply_plan_with_journal(&mut selected, system_store, metadata);
    retained.extend(selected_indices.into_iter().zip(selected));
    retained.sort_unstable_by_key(|(index, _)| *index);
    recomputed_plan.extend(retained.into_iter().map(|(_, action)| action));
    Ok(result?)
}

/// Applies a mixed system-scope plan after the native authorization boundary.
///
/// Receipt preparation and publication remain in this process. Only the
/// prepared mutation is dispatched: ordinary actions go through the original
/// user's sealed runner, while host actions stay in the authorized process.
#[cfg(test)]
fn execute_system_plan_with_test_user_runner<U: PreparedActionRunner>(
    plan: &mut [Action],
    system_store: &ReceiptStore,
    metadata: &mut ReceiptMetadataSource,
    context: &SetupExecutionContext,
    user_runner: &mut U,
) -> Result<ApplyReport, AuthorizationError> {
    if system_store.installation_scope() != InstallationScope::System
        || system_store.worker_principal() != context.original_principal()
    {
        return Err(AuthorizationError::PrincipalInvalid);
    }
    crate::platform::verify_worker_principal(context.original_principal())
        .map_err(|_| AuthorizationError::PrincipalInvalid)?;

    let privilege_class = match context.host_privilege() {
        #[cfg(not(target_os = "windows"))]
        SetupHostPrivilege::Root => HostPrivilegeClass::UnixRoot,
        #[cfg(target_os = "windows")]
        SetupHostPrivilege::Administrator => HostPrivilegeClass::WindowsAdministrator,
        SetupHostPrivilege::Ordinary => return Err(AuthorizationError::RequestInvalid),
        #[cfg(not(target_os = "windows"))]
        SetupHostPrivilege::Administrator => return Err(AuthorizationError::RequestInvalid),
        #[cfg(target_os = "windows")]
        SetupHostPrivilege::Root => return Err(AuthorizationError::RequestInvalid),
    };
    validate_plan(plan, privilege_class)?;

    struct SplitRunner<'a, U> {
        user: &'a mut U,
        host_privilege: Privilege,
    }

    impl<U: PreparedActionRunner> PreparedActionRunner for SplitRunner<'_, U> {
        fn execute_prepared(
            &mut self,
            action: &mut Action,
            expected: &ActionEffect,
        ) -> Result<ActionEffect, ActionError> {
            if action.privilege() == Privilege::None {
                self.user.execute_prepared(action, expected)
            } else if action.privilege() == self.host_privilege {
                action.execute_prepared()
            } else {
                Err(ActionError::apply_failed(action.name().clone()))
            }
        }
    }

    let host_privilege = match privilege_class {
        HostPrivilegeClass::UnixRoot => Privilege::Root,
        HostPrivilegeClass::WindowsAdministrator => Privilege::Admin,
    };
    let mut runner = SplitRunner {
        user: user_runner,
        host_privilege,
    };
    Ok(super::execution::apply_plan_with_runner(
        plan,
        system_store,
        metadata,
        &mut runner,
    )?)
}

fn read_request(
    context: &AuthorizationContext,
    expected_request_digest: &str,
) -> Result<(AuthorizationRequest, crate::platform::PrivateFileRemoval), AuthorizationError> {
    let identity = crate::platform::private_file_identity(&context.request_path)
        .map_err(AuthorizationError::RequestRead)?;
    let removal = crate::platform::prepare_verified_private_file_removal(
        &context.request_path,
        ManifestOwner::User,
        &context.principal,
        identity,
    )
    .map_err(AuthorizationError::RequestRead)?;
    let file = crate::platform::open_verified_private_file_for_read(
        &context.request_path,
        ManifestOwner::User,
        &context.principal,
        identity,
    )
    .map_err(AuthorizationError::RequestRead)?;
    let mut bytes = Vec::new();
    file.take((MAX_REQUEST_BYTES + 1) as u64)
        .read_to_end(&mut bytes)
        .map_err(AuthorizationError::RequestRead)?;
    if bytes.len() > MAX_REQUEST_BYTES {
        return Err(AuthorizationError::RequestInvalid);
    }
    if request_digest(&bytes) != expected_request_digest {
        return Err(AuthorizationError::RequestInvalid);
    }
    let request = serde_json::from_slice(&bytes).map_err(|_| AuthorizationError::RequestInvalid)?;
    Ok((request, removal))
}

fn request_digest(bytes: &[u8]) -> String {
    use std::fmt::Write as _;

    let digest = Sha256::digest(bytes);
    let mut encoded = String::with_capacity(64);
    for byte in digest {
        write!(&mut encoded, "{byte:02x}").expect("writing hexadecimal to a String cannot fail");
    }
    encoded
}

fn validate_request_digest(value: &str) -> Result<(), AuthorizationError> {
    if value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
    {
        Ok(())
    } else {
        Err(AuthorizationError::RequestInvalid)
    }
}

fn validate_request(
    request: &AuthorizationRequest,
    context: &AuthorizationContext,
) -> Result<(), AuthorizationError> {
    if request.schema_version != REQUEST_SCHEMA_VERSION
        || request.installation_scope != RequestScope::System
        || request.host_id != context.host_id
        || request.executable != context.executable.to_string_lossy()
        || request.principal != context.principal
        || request.privilege_class != context.privilege_class
        || request.displayed_actions.is_empty()
    {
        return Err(AuthorizationError::RequestInvalid);
    }
    let request_id =
        Uuid::parse_str(&request.request_id).map_err(|_| AuthorizationError::RequestInvalid)?;
    if request_id.get_version_num() != 7 || request_id.to_string() != request.request_id {
        return Err(AuthorizationError::RequestInvalid);
    }
    let issued_at = parse_canonical_timestamp(&request.issued_at)?;
    let expires_at = parse_canonical_timestamp(&request.expires_at)?;
    if issued_at > context.now
        || expires_at <= context.now
        || expires_at <= issued_at
        || expires_at - issued_at > REQUEST_LIFETIME
    {
        return Err(AuthorizationError::RequestInvalid);
    }
    if !crate::setup::validate_probe_static_text(&request.host_id)
        || !crate::setup::validate_probe_static_text(&request.executable)
        || !crate::setup::validate_probe_static_text(request.principal.principal_id())
        || !crate::setup::validate_probe_static_text(request.principal.name())
    {
        return Err(AuthorizationError::RequestInvalid);
    }
    validate_absolute_normalized_path(Path::new(&request.executable))?;
    let mut action_ids = HashSet::with_capacity(request.displayed_actions.len());
    for action in &request.displayed_actions {
        super::ActionName::parse(action.action_id())
            .map_err(|_| AuthorizationError::RequestInvalid)?;
        if !action_ids.insert(action.action_id()) {
            return Err(AuthorizationError::RequestInvalid);
        }
        if !matches!(
            (context.privilege_class, action.privilege()),
            (HostPrivilegeClass::UnixRoot, RequestedPrivilege::Root)
                | (
                    HostPrivilegeClass::WindowsAdministrator,
                    RequestedPrivilege::Admin
                )
        ) {
            return Err(AuthorizationError::RequestInvalid);
        }
    }
    Ok(())
}

fn parse_canonical_timestamp(value: &str) -> Result<DateTime<Utc>, AuthorizationError> {
    let parsed = DateTime::parse_from_rfc3339(value)
        .map_err(|_| AuthorizationError::RequestInvalid)?
        .with_timezone(&Utc);
    if parsed.to_rfc3339_opts(SecondsFormat::Secs, true) != value {
        return Err(AuthorizationError::RequestInvalid);
    }
    Ok(parsed)
}

fn validate_absolute_normalized_path(path: &Path) -> Result<(), AuthorizationError> {
    if !path.is_absolute()
        || path
            .components()
            .any(|component| matches!(component, Component::CurDir | Component::ParentDir))
    {
        return Err(AuthorizationError::RequestInvalid);
    }
    Ok(())
}

#[cfg(test)]
mod tests;
