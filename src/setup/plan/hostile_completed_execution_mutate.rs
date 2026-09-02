pub(super) fn mutate(token: &mut crate::setup::action::CompletedExecutionToken) {
    token.pending.clear();
}
