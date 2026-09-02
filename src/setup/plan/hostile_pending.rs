pub(super) fn forge_pending(
    id: crate::setup::action::ActionName,
    needs_human: crate::setup::action::NeedsHuman,
) {
    let _ = crate::setup::action::PendingAction::new(id, needs_human);
}
