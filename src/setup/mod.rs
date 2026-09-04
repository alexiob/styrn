#![allow(unexpected_cfgs)] // Exact rustc compile-boundary fixtures use private cfg names.

#[allow(dead_code)]
#[cfg(not(any(
    action_core_fixture,
    action_compile_fixture,
    plan_pending_authority_forge_fixture,
    plan_pending_publication_forge_fixture,
    plan_completed_execution_construct_fixture,
    plan_completed_execution_mutate_fixture,
    plan_completed_execution_clone_fixture,
    plan_completed_execution_serialize_fixture,
    plan_pending_projection_fixture,
)))]
mod config;
#[allow(dead_code)]
#[cfg(not(any(
    action_core_fixture,
    action_compile_fixture,
    plan_pending_authority_forge_fixture,
    plan_pending_publication_forge_fixture,
    plan_completed_execution_construct_fixture,
    plan_completed_execution_mutate_fixture,
    plan_completed_execution_clone_fixture,
    plan_completed_execution_serialize_fixture,
    plan_pending_projection_fixture,
)))]
mod interactive;
#[allow(dead_code)] // Task 4 wires this concrete orchestrator to the CLI boundary.
#[cfg(not(any(
    action_core_fixture,
    action_compile_fixture,
    plan_pending_authority_forge_fixture,
    plan_pending_publication_forge_fixture,
    plan_completed_execution_construct_fixture,
    plan_completed_execution_mutate_fixture,
    plan_completed_execution_clone_fixture,
    plan_completed_execution_serialize_fixture,
    plan_pending_projection_fixture,
)))]
mod orchestrator;

#[allow(unused_imports)]
#[cfg(not(any(
    action_core_fixture,
    action_compile_fixture,
    plan_pending_authority_forge_fixture,
    plan_pending_publication_forge_fixture,
    plan_completed_execution_construct_fixture,
    plan_completed_execution_mutate_fixture,
    plan_completed_execution_clone_fixture,
    plan_completed_execution_serialize_fixture,
    plan_pending_projection_fixture,
)))]
pub(crate) use config::{
    load_effective_rootless_setup, persist_interactive_replay, validate_rootless_setup_request,
    EffectiveRootlessSetup, SetupInputError,
};
#[allow(unused_imports)]
#[cfg(not(any(
    action_core_fixture,
    action_compile_fixture,
    plan_pending_authority_forge_fixture,
    plan_pending_publication_forge_fixture,
    plan_completed_execution_construct_fixture,
    plan_completed_execution_mutate_fixture,
    plan_completed_execution_clone_fixture,
    plan_completed_execution_serialize_fixture,
    plan_pending_projection_fixture,
)))]
pub(crate) use interactive::collect_interactive_answers;
#[allow(unused_imports)]
#[cfg(not(any(
    action_core_fixture,
    action_compile_fixture,
    plan_pending_authority_forge_fixture,
    plan_pending_publication_forge_fixture,
    plan_completed_execution_construct_fixture,
    plan_completed_execution_mutate_fixture,
    plan_completed_execution_clone_fixture,
    plan_completed_execution_serialize_fixture,
    plan_pending_projection_fixture,
)))]
pub(crate) use orchestrator::{
    apply_rootless_setup, prepare_rootless_setup, EnrollmentCard, RootlessPendingResult,
    RootlessSetupError, RootlessSetupOutcome, RootlessSetupPlan, RootlessSetupPlanItem,
};
#[cfg(test)]
pub(in crate::setup) use orchestrator::{
    prepare_rootless_setup_for_test, prepare_rootless_setup_for_test_with_ssh_directory,
    prepare_rootless_setup_for_test_with_ssh_directory_and_host_key,
};

#[allow(dead_code)]
pub(crate) mod action;
#[allow(dead_code)]
#[cfg(not(any(action_core_fixture, action_compile_fixture)))]
pub(crate) mod pending;
#[allow(dead_code)]
pub(crate) mod plan;
#[allow(dead_code)]
pub(crate) mod probe;
#[allow(dead_code)]
mod probe_values;
#[allow(dead_code)]
mod probe_wire;
#[allow(dead_code)]
#[cfg(not(any(action_core_fixture, action_compile_fixture)))]
pub(crate) mod promotion;
#[allow(dead_code)]
#[cfg(not(action_core_fixture))]
pub(crate) mod receipt;

#[allow(unused_imports)]
pub(crate) use probe_wire::{DoctorFinding, DoctorFindingState, ObservedState, ProbeObservation};

#[cfg(not(any(
    action_core_fixture,
    action_compile_fixture,
    plan_pending_authority_forge_fixture,
    plan_pending_publication_forge_fixture,
    plan_completed_execution_construct_fixture,
    plan_completed_execution_mutate_fixture,
    plan_completed_execution_clone_fixture,
    plan_completed_execution_serialize_fixture,
    plan_pending_projection_fixture,
)))]
pub(crate) fn worker_doctor_findings(
    manifest: &crate::manifest::MachineManifest,
    authorized_public_key: &str,
) -> Result<Vec<DoctorFinding>, probe::ProbeCatalogError> {
    Ok(
        probe::production_worker_doctor_catalog(manifest, authorized_public_key)?
            .observe()
            .doctor_findings(),
    )
}

fn observe_worker_probes(probes: &[Box<dyn probe::WorkerProbe>]) -> ObservedState {
    probe_wire::observe(probes)
}

fn validate_probe_static_text(value: &str) -> bool {
    probe_wire::validate_static_text(value)
}
