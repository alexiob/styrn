pub(super) fn project(draft: &mut crate::manifest::MachineManifestDraft) {
    let _ = crate::setup::pending::project_manifest(draft, &[]);
}
