use super::{
    Action, ActionCheck, ActionDescription, ActionEffect, ActionError, ActionName,
    ActionParameters, ActionPlan, CreatedDirectoryEffect, DeferredSystemActionParameters,
    HumanInstructions, MutationCompletion, NeedsHuman, PreparedExecutionError,
    VerifiedActionEffect, WorkerDirectoryActionParameters,
};
use crate::platform::{
    InstallationScope, SetupExecutionContext, SetupHostPrivilege, WorkerAccountPolicy,
    WorkerDirectoryBindingError, WorkerDirectoryBound, WorkerDirectoryLayout,
    WorkerDirectoryNodeCreateOutcome, WorkerDirectoryNodeDisposition,
    WorkerDirectoryNodeFailureBindingError, WorkerDirectoryNodeFailureBound,
    WorkerDirectoryNodeInspection, WorkerDirectoryNodeObservation,
};
use sha2::{Digest, Sha256};
use std::path::{Component, Path, PathBuf};

const ROOT_ACTION_ID: &str = "identity.directory.root";
const DESCRIPTION: &str = "Create one current-user worker directory node.";
const DEDICATED_DESCRIPTION: &str = "Create one dedicated system worker directory node.";
const NEEDS_HUMAN: &str = "Inspect and repair this worker directory node, then rerun setup.";

pub(crate) struct WorkerDirectoryAction {
    description: ActionDescription,
    layout: WorkerDirectoryLayout,
    parameters: WorkerDirectoryActionParameters,
    expected_effect: ActionEffect,
    privilege: super::Privilege,
    dedicated_ready: Option<super::dedicated_account::DedicatedAccountReady>,
}

pub(in crate::setup) fn current_user_worker_directory_plan(
    context: &SetupExecutionContext,
) -> Result<ActionPlan, ActionError> {
    let principal = validate_context(context)?;
    let layout =
        crate::platform::resolve_worker_directory_layout(InstallationScope::User, &principal, None)
            .map_err(|_| factory_error())?;
    build_plan(layout, principal, super::Privilege::None, None)
}

#[cfg(test)]
pub(super) fn current_user_worker_directory_plan_for_test(
    context: &SetupExecutionContext,
    root: PathBuf,
    creation_anchor: Option<PathBuf>,
) -> Result<(ActionPlan, WorkerDirectoryLayout), ActionError> {
    let principal = validate_context(context)?;
    let layout = crate::platform::worker_directory_layout_for_test(
        InstallationScope::User,
        principal.clone(),
        root,
        creation_anchor,
    );
    let plan = build_plan(layout.clone(), principal, super::Privilege::None, None)?;
    Ok((plan, layout))
}

#[allow(dead_code)] // T0.20 supplies the selected ready adoption.
pub(in crate::setup) fn dedicated_system_worker_directory_plan(
    ready: &super::dedicated_account::DedicatedAccountReady,
) -> Result<ActionPlan, ActionError> {
    let principal = ready
        .reverify_target(Clone::clone)
        .map_err(|_| factory_error())?;
    let layout = crate::platform::resolve_worker_directory_layout(
        InstallationScope::System,
        &principal,
        None,
    )
    .map_err(|_| factory_error())?;
    build_plan(layout, principal, dedicated_native_privilege(), Some(ready))
}

#[cfg(test)]
pub(in crate::setup) fn dedicated_system_worker_directory_plan_for_test(
    ready: &super::dedicated_account::DedicatedAccountReady,
    root: PathBuf,
    creation_anchor: Option<PathBuf>,
) -> Result<(ActionPlan, WorkerDirectoryLayout), ActionError> {
    let principal = ready
        .reverify_target(Clone::clone)
        .map_err(|_| factory_error())?;
    let layout = crate::platform::worker_directory_layout_for_test(
        InstallationScope::System,
        principal.clone(),
        root,
        creation_anchor,
    );
    let plan = build_plan(
        layout.clone(),
        principal,
        dedicated_native_privilege(),
        Some(ready),
    )?;
    Ok((plan, layout))
}

fn dedicated_native_privilege() -> super::Privilege {
    #[cfg(not(target_os = "windows"))]
    {
        super::Privilege::Root
    }
    #[cfg(target_os = "windows")]
    {
        super::Privilege::Admin
    }
}

fn validate_context(
    context: &SetupExecutionContext,
) -> Result<crate::platform::WorkerPrincipal, ActionError> {
    if context.host_privilege() != SetupHostPrivilege::Ordinary
        || context.original_principal().account_policy() != WorkerAccountPolicy::CurrentUser
    {
        return Err(factory_error());
    }
    let current =
        crate::platform::resolve_current_worker_principal().map_err(|_| factory_error())?;
    if context.original_principal() != &current {
        return Err(factory_error());
    }
    crate::platform::verify_worker_principal(context.original_principal())
        .map_err(|_| factory_error())?;
    Ok(current)
}

fn build_plan(
    layout: WorkerDirectoryLayout,
    principal: crate::platform::WorkerPrincipal,
    privilege: super::Privilege,
    dedicated_ready: Option<&super::dedicated_account::DedicatedAccountReady>,
) -> Result<ActionPlan, ActionError> {
    let root = validated_path(layout.root())?;
    layout
        .materialization_nodes()
        .into_iter()
        .map(|node| {
            let path = layout.path_for_node(node).ok_or_else(factory_error)?;
            let effect_path = validated_path_text(&path)?.to_owned();
            let action_id = ActionName::parse(&node.action_id()).map_err(|_| factory_error())?;
            let parameters = WorkerDirectoryActionParameters {
                action_id,
                installation_scope: layout.installation_scope(),
                principal: principal.clone(),
                root: root.clone(),
                node,
                path,
            };
            Ok(Action::WorkerDirectory(Box::new(WorkerDirectoryAction {
                description: ActionDescription::new(if dedicated_ready.is_some() {
                    DEDICATED_DESCRIPTION
                } else {
                    DESCRIPTION
                })
                .expect("static worker-directory description is valid"),
                layout: layout.clone(),
                expected_effect: directory_effect(effect_path),
                parameters,
                privilege,
                dedicated_ready: dedicated_ready.cloned(),
            })))
        })
        .collect()
}

fn validated_path(path: &Path) -> Result<PathBuf, ActionError> {
    validated_path_text(path)?;
    if !path.is_absolute()
        || path.file_name().is_none()
        || path
            .components()
            .any(|component| matches!(component, Component::CurDir | Component::ParentDir))
        || path.components().collect::<PathBuf>().as_os_str() != path.as_os_str()
    {
        return Err(factory_error());
    }
    Ok(path.to_path_buf())
}

fn validated_path_text(path: &Path) -> Result<&str, ActionError> {
    path.to_str()
        .filter(|value| {
            value.len() <= 4096
                && super::super::validate_probe_static_text(value)
                && recorded_path_text_is_normalized(value)
        })
        .ok_or_else(factory_error)
}

fn recorded_path_text_is_normalized(value: &str) -> bool {
    #[cfg(not(target_os = "windows"))]
    {
        value.starts_with('/')
            && (value == "/"
                || (!value.ends_with('/')
                    && !value.contains("//")
                    && value
                        .split('/')
                        .skip(1)
                        .all(|segment| !segment.is_empty() && !matches!(segment, "." | ".."))))
    }
    #[cfg(target_os = "windows")]
    {
        windows_recorded_path_is_normalized(value)
    }
}

#[cfg(any(test, target_os = "windows"))]
fn windows_recorded_path_is_normalized(value: &str) -> bool {
    let bytes = value.as_bytes();
    if bytes.len() < 3
        || !bytes[0].is_ascii_alphabetic()
        || bytes[1] != b':'
        || bytes[2] != b'\\'
        || value.starts_with(r"\\")
        || value.starts_with(r"\\?\")
        || value.starts_with(r"\\.\")
        || value.contains('/')
        || value.ends_with('\\')
        || value.contains(r"\\")
    {
        return false;
    }
    value.split('\\').skip(1).all(|segment| {
        !segment.is_empty()
            && !matches!(segment, "." | "..")
            && !segment.contains(':')
            && !segment.ends_with(['.', ' '])
            && !segment
                .chars()
                .any(|character| matches!(character, '<' | '>' | '"' | '|' | '?' | '*'))
            && !is_reserved_windows_device_name(segment)
    })
}

#[cfg(any(test, target_os = "windows"))]
fn is_reserved_windows_device_name(segment: &str) -> bool {
    let stem = segment
        .split_once('.')
        .map_or(segment, |(stem, _)| stem)
        .to_ascii_uppercase();
    matches!(stem.as_str(), "CON" | "PRN" | "AUX" | "NUL")
        || stem
            .strip_prefix("COM")
            .or_else(|| stem.strip_prefix("LPT"))
            .is_some_and(|number| {
                matches!(
                    number,
                    "1" | "2" | "3" | "4" | "5" | "6" | "7" | "8" | "9" | "¹" | "²" | "³"
                )
            })
}

#[cfg(test)]
pub(super) fn windows_recorded_path_is_normalized_for_test(value: &str) -> bool {
    windows_recorded_path_is_normalized(value)
}

pub(super) fn directory_effect(path: impl Into<String>) -> ActionEffect {
    ActionEffect {
        directories_created: vec![CreatedDirectoryEffect { path: path.into() }],
        files_created: Vec::new(),
        files_modified: Vec::new(),
        files_appended: Vec::new(),
        services: Vec::new(),
        accounts: Vec::new(),
        registry_keys: Vec::new(),
        firewall_rules: Vec::new(),
        download_provenance: None,
    }
}

fn factory_error() -> ActionError {
    ActionError::check_failed(
        ActionName::parse(ROOT_ACTION_ID).expect("static worker-directory root action ID is valid"),
    )
}

impl WorkerDirectoryAction {
    pub(super) fn deferred_parameters(
        &self,
    ) -> Result<DeferredSystemActionParameters, ActionError> {
        if self.parameters.installation_scope() != InstallationScope::System
            || self.parameters.principal().account_policy() != WorkerAccountPolicy::Dedicated
            || self.privilege == super::Privilege::None
        {
            return Err(factory_error());
        }
        let mut hasher = Sha256::new();
        hasher.update(b"styrn.deferred-system-action.v1\0");
        for field in [
            self.parameters.action_id().as_str(),
            self.parameters.principal().principal_id(),
            self.parameters.principal().name(),
            validated_path_text(self.parameters.root())?,
            validated_path_text(self.parameters.path())?,
        ] {
            hasher.update((field.len() as u64).to_be_bytes());
            hasher.update(field.as_bytes());
        }
        let mut parameter_sha256 = String::with_capacity(64);
        use std::fmt::Write as _;
        for byte in hasher.finalize() {
            write!(&mut parameter_sha256, "{byte:02x}")
                .expect("writing hexadecimal to a String cannot fail");
        }
        Ok(DeferredSystemActionParameters {
            action_id: self.parameters.action_id().clone(),
            target_scope: InstallationScope::System,
            target_principal: self.parameters.principal().clone(),
            parameter_sha256: parameter_sha256.into_boxed_str(),
        })
    }

    pub(super) fn name(&self) -> &ActionName {
        self.parameters.action_id()
    }

    pub(super) fn parameters(&self) -> ActionParameters {
        ActionParameters::WorkerDirectory(self.parameters.clone())
    }

    pub(super) fn description(&self) -> &ActionDescription {
        &self.description
    }

    pub(super) fn expected_effect(&self) -> ActionEffect {
        self.expected_effect.clone()
    }

    pub(super) fn privilege(&self) -> super::Privilege {
        self.privilege
    }

    pub(super) fn check(&self) -> ActionCheck {
        if !self.dedicated_binding_is_current() {
            return map_inspection(WorkerDirectoryNodeInspection::Unknowable(
                crate::platform::WorkerDirectoryInspectionIssue::PrincipalDrift,
            ));
        }
        map_inspection(crate::platform::inspect_worker_directory_node(
            &self.layout,
            self.parameters.node(),
        ))
    }

    pub(super) fn execute_prepared_and_bind<Value, BindingError>(
        &self,
        bind: impl for<'authority> FnOnce(
            VerifiedActionEffect<'authority>,
        ) -> Result<Value, BindingError>,
    ) -> Result<(MutationCompletion, Value), PreparedExecutionError<BindingError>> {
        if !self.dedicated_binding_is_current() {
            return Err(PreparedExecutionError::Action(ActionError::apply_failed(
                self.name().clone(),
            )));
        }
        let authority = super::native_mutation_authority();
        match crate::platform::create_worker_directory_node(
            &self.layout,
            self.parameters.node(),
            &authority,
        ) {
            Ok(WorkerDirectoryNodeCreateOutcome::Existing) => {
                Err(PreparedExecutionError::ReceiptConflict)
            }
            Ok(WorkerDirectoryNodeCreateOutcome::Created(creation)) => {
                match creation.bind_after_reverify(|binding| {
                    bind_verified_effect(self, binding.observation(), bind)
                }) {
                    Ok(WorkerDirectoryBound::Bound(value)) => {
                        Ok((MutationCompletion::Applied, value))
                    }
                    Ok(WorkerDirectoryBound::BoundWithRetirementFailure { value, .. }) => Ok((
                        MutationCompletion::AppliedThenFailedRetainingSucceededIntent(
                            ActionError::apply_failed(self.name().clone()),
                        ),
                        value,
                    )),
                    Err(WorkerDirectoryBindingError::Reverification(_))
                    | Err(WorkerDirectoryBindingError::AuthorityRetirement(_)) => {
                        Err(PreparedExecutionError::Action(ActionError::apply_failed(
                            self.name().clone(),
                        )))
                    }
                    Err(WorkerDirectoryBindingError::Binding(error)) => {
                        map_binding_error(self, error)
                    }
                }
            }
            Err(error) => {
                match error.bind_retained_creation_evidence_after_reverify(|binding| {
                    bind_verified_effect(self, binding.observation(), bind)
                }) {
                    Ok(bound) => map_failure_bound(self, bound),
                    Err(WorkerDirectoryNodeFailureBindingError::NoRetainedEvidence(_))
                    | Err(WorkerDirectoryNodeFailureBindingError::Reverification { .. }) => {
                        Err(PreparedExecutionError::Action(ActionError::apply_failed(
                            self.name().clone(),
                        )))
                    }
                    Err(WorkerDirectoryNodeFailureBindingError::Binding { error, .. }) => {
                        map_binding_error(self, error)
                    }
                }
            }
        }
    }

    fn dedicated_binding_is_current(&self) -> bool {
        self.dedicated_ready.as_ref().is_none_or(|ready| {
            ready
                .reverify_target(|principal| principal == self.parameters.principal())
                .unwrap_or(false)
        })
    }
}

fn map_failure_bound<Value, BindingError>(
    action: &WorkerDirectoryAction,
    bound: WorkerDirectoryNodeFailureBound<Value>,
) -> Result<(MutationCompletion, Value), PreparedExecutionError<BindingError>> {
    match bound {
        WorkerDirectoryNodeFailureBound::Bound { value, .. } => Ok((
            MutationCompletion::AppliedThenFailed(ActionError::apply_failed(action.name().clone())),
            value,
        )),
        WorkerDirectoryNodeFailureBound::BoundWithRetirementFailure { value, .. } => Ok((
            MutationCompletion::AppliedThenFailedRetainingSucceededIntent(
                ActionError::apply_failed(action.name().clone()),
            ),
            value,
        )),
    }
}

#[cfg(test)]
pub(super) fn map_failure_bound_for_test<Value, BindingError>(
    action: &WorkerDirectoryAction,
    bound: WorkerDirectoryNodeFailureBound<Value>,
) -> Result<(MutationCompletion, Value), PreparedExecutionError<BindingError>> {
    map_failure_bound(action, bound)
}

enum EffectBindingError<BindingError> {
    ReceiptConflict,
    PrincipalDrift,
    Binding(BindingError),
}

fn bind_verified_effect<Value, BindingError>(
    action: &WorkerDirectoryAction,
    observation: &WorkerDirectoryNodeObservation,
    bind: impl for<'authority> FnOnce(VerifiedActionEffect<'authority>) -> Result<Value, BindingError>,
) -> Result<Value, EffectBindingError<BindingError>> {
    if !action.dedicated_binding_is_current() {
        return Err(EffectBindingError::PrincipalDrift);
    }
    if observation.disposition() != WorkerDirectoryNodeDisposition::Created
        || observation.path() != action.parameters.path()
    {
        return Err(EffectBindingError::ReceiptConflict);
    }
    let path = observation
        .path()
        .to_str()
        .ok_or(EffectBindingError::ReceiptConflict)?;
    let effect = directory_effect(path);
    if effect != action.expected_effect {
        return Err(EffectBindingError::ReceiptConflict);
    }
    bind(VerifiedActionEffect {
        effect: &effect,
        _authority: std::marker::PhantomData,
    })
    .map_err(EffectBindingError::Binding)
}

fn map_binding_error<Value, BindingError>(
    action: &WorkerDirectoryAction,
    error: EffectBindingError<BindingError>,
) -> Result<(MutationCompletion, Value), PreparedExecutionError<BindingError>> {
    match error {
        EffectBindingError::ReceiptConflict => Err(PreparedExecutionError::ReceiptConflict),
        EffectBindingError::PrincipalDrift => Err(PreparedExecutionError::Action(
            ActionError::apply_failed(action.name().clone()),
        )),
        EffectBindingError::Binding(error) => Err(PreparedExecutionError::Binding(error)),
    }
}

fn map_inspection(inspection: WorkerDirectoryNodeInspection) -> ActionCheck {
    match inspection {
        WorkerDirectoryNodeInspection::Absent => ActionCheck::Todo,
        WorkerDirectoryNodeInspection::Healthy => ActionCheck::Done,
        WorkerDirectoryNodeInspection::Conflict(_)
        | WorkerDirectoryNodeInspection::Unknowable(_) => ActionCheck::NeedsHuman(NeedsHuman::new(
            HumanInstructions::new(NEEDS_HUMAN)
                .expect("static worker-directory instructions are valid"),
            None,
        )),
    }
}

#[cfg(test)]
pub(super) fn check_inspection_for_test(
    _action: &WorkerDirectoryAction,
    inspection: WorkerDirectoryNodeInspection,
) -> ActionCheck {
    map_inspection(inspection)
}
