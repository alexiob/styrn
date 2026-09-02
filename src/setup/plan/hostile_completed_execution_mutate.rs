#[cfg(plan_completed_execution_mutate_fixture)]
pub(super) fn mutate(token: &mut crate::setup::action::CompletedExecutionToken) {
    token.pending.clear();
}

#[cfg(plan_completed_execution_clone_fixture)]
pub(super) fn clone(token: crate::setup::action::CompletedExecutionToken) {
    let _ = token.clone();
}

#[cfg(plan_completed_execution_serialize_fixture)]
pub(super) fn serialize(token: &crate::setup::action::CompletedExecutionToken) {
    let _ = serde_json::to_string(token);
}
