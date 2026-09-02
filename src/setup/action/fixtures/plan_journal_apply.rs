#![allow(dead_code)]

#[path = "../../../platform/mod.rs"]
mod platform;
#[path = "../../mod.rs"]
mod setup;

fn attempt_journal_apply(
    plan: &mut [setup::action::Action],
    store: &setup::receipt::ReceiptStore,
    metadata: &mut setup::receipt::ReceiptMetadataSource,
) {
    let _ = setup::action::apply_plan_with_journal(plan, store, metadata);
}

fn main() {}
