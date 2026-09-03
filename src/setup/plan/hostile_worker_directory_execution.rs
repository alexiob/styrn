#[cfg(plan_worker_native_authority_construct_fixture)]
fn construct_native_mutation_authority() {
    let _authority = crate::setup::action::NativeMutationAuthority(());
}

#[cfg(plan_worker_native_mutation_call_fixture)]
fn call_native_worker_directory_mutation(
    layout: &crate::platform::WorkerDirectoryLayout,
    node: crate::platform::WorkerDirectoryNode,
) {
    let _ = crate::platform::create_worker_directory_node(
        layout,
        node,
        &crate::setup::action::native_mutation_authority(),
    );
}

#[cfg(plan_worker_prepare_fixture)]
fn prepare_worker_directory_action(action: &crate::setup::action::Action) {
    let _ = action.prepare();
}

#[cfg(plan_worker_execute_prepared_fixture)]
fn execute_prepared_worker_directory_action(action: &mut crate::setup::action::Action) {
    let _ = action.execute_prepared_and_bind(|_verified| Ok::<(), ()>(()));
}

#[cfg(plan_worker_parameters_construct_fixture)]
fn construct_worker_directory_parameters(
    action_id: crate::setup::action::ActionName,
    installation_scope: crate::platform::InstallationScope,
    principal: crate::platform::WorkerPrincipal,
    root: std::path::PathBuf,
    node: crate::platform::WorkerDirectoryNode,
    path: std::path::PathBuf,
) {
    let _parameters = crate::setup::action::WorkerDirectoryActionParameters {
        action_id,
        installation_scope,
        principal,
        root,
        node,
        path,
    };
}

#[cfg(plan_worker_verified_effect_construct_fixture)]
fn construct_verified_action_effect(effect: &crate::setup::action::ActionEffect) {
    let _verified = crate::setup::action::VerifiedActionEffect {
        effect,
        _authority: std::marker::PhantomData,
    };
}
