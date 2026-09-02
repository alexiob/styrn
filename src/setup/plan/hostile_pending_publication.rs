#[cfg(plan_pending_publication_forge_fixture)]
pub(super) fn publish_raw_slice(
    manifest_store: &crate::manifest::MachineManifestStore,
    receipt_store: &crate::setup::receipt::ReceiptStore,
    draft: &mut crate::manifest::MachineManifestDraft,
    metadata: &mut crate::setup::receipt::ReceiptMetadataSource,
) {
    let _ = crate::setup::pending::publish_manifest(
        manifest_store,
        receipt_store,
        draft,
        &[],
        metadata,
    );
}

#[cfg(plan_pending_authority_forge_fixture)]
pub(super) fn forge_publication_authority() {
    let _ = crate::setup::pending::PendingPublicationAuthority(());
}
