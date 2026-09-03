//! Crash-safe promotion from current-user fallback authority to protected System authority.

use crate::platform::{InstallationScope, WorkerAccountPolicy, WorkerPrincipal};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    fmt::Write as _,
    io::{Read, Write},
    path::{Component, Path, PathBuf},
};

const SCOPE_PROMOTION_ACTION_ID: &str = "identity.scope-promotion";

#[cfg(test)]
std::thread_local! {
    static INTERRUPT_AFTER_CHECKPOINT: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
    static INTERRUPT_AFTER_USER_RETIREMENT: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
}

#[cfg(test)]
fn set_interrupt_after_checkpoint_for_test(value: bool) {
    INTERRUPT_AFTER_CHECKPOINT.with(|slot| slot.set(value));
}

#[cfg(test)]
fn set_interrupt_after_user_retirement_for_test(value: bool) {
    INTERRUPT_AFTER_USER_RETIREMENT.with(|slot| slot.set(value));
}

/// Typed, non-owning receipt-v1 checkpoint for an authority promotion.
///
/// Construction stays inside this module; receipt code can only project an
/// already-validated value and cannot turn an arbitrary action into promotion
/// evidence.
pub(crate) struct ScopePromotionCheckpoint {
    machine_id: uuid::Uuid,
    user_manifest_path: Box<str>,
    user_manifest_sha256: Box<str>,
    system_manifest_path: Box<str>,
    system_manifest_sha256: Box<str>,
    system_manifest_identity_sha256: Box<str>,
    system_receipt_path: Box<str>,
    system_receipt_sha256: Box<str>,
    system_receipt_identity_sha256: Box<str>,
    authorization_request_id: uuid::Uuid,
    authorization_request_sha256: Box<str>,
    authorization_record_path: Box<str>,
    authorization_record_sha256: Box<str>,
    authorization_record_identity_sha256: Box<str>,
    promotion_intent_path: Box<str>,
    promotion_intent_sha256: Box<str>,
    promotion_intent_identity_sha256: Box<str>,
    completion_record_path: Box<str>,
    completion_record_sha256: Box<str>,
    completion_record_identity_sha256: Box<str>,
    original_operator: WorkerPrincipal,
    target_principal: WorkerPrincipal,
    selector_sha256: Box<str>,
    promotion_intent_id: uuid::Uuid,
}

impl ScopePromotionCheckpoint {
    #[allow(clippy::too_many_arguments)] // Receipt v1 binds this complete immutable tuple.
    fn new(
        machine_id: uuid::Uuid,
        original_operator: &WorkerPrincipal,
        target_principal: &WorkerPrincipal,
        selector_sha256: &str,
        user_manifest_path: &str,
        user_manifest_sha256: &str,
        system_manifest_path: &str,
        system_manifest_sha256: &str,
        system_manifest_identity_sha256: &str,
        system_receipt_path: &str,
        system_receipt_sha256: &str,
        system_receipt_identity_sha256: &str,
        authorization_request_id: uuid::Uuid,
        authorization_request_sha256: &str,
        authorization_record_path: &str,
        authorization_record_sha256: &str,
        authorization_record_identity_sha256: &str,
        promotion_intent_path: &str,
        promotion_intent_sha256: &str,
        promotion_intent_identity_sha256: &str,
        completion_record_path: &str,
        completion_record_sha256: &str,
        completion_record_identity_sha256: &str,
        promotion_intent_id: uuid::Uuid,
    ) -> Result<Self, ScopePromotionError> {
        if !is_uuid_v7(machine_id)
            || !is_uuid_v7(promotion_intent_id)
            || !is_uuid_v7(authorization_request_id)
            || original_operator.account_policy() != WorkerAccountPolicy::CurrentUser
            || target_principal.account_policy() != WorkerAccountPolicy::Dedicated
            || original_operator == target_principal
            || !valid_sha256(selector_sha256)
            || !valid_sha256(user_manifest_sha256)
            || !valid_sha256(system_manifest_sha256)
            || !valid_sha256(system_manifest_identity_sha256)
            || !valid_sha256(system_receipt_sha256)
            || !valid_sha256(system_receipt_identity_sha256)
            || !valid_sha256(authorization_request_sha256)
            || !valid_sha256(authorization_record_sha256)
            || !valid_sha256(authorization_record_identity_sha256)
            || !valid_sha256(promotion_intent_sha256)
            || !valid_sha256(promotion_intent_identity_sha256)
            || !valid_sha256(completion_record_sha256)
            || !valid_sha256(completion_record_identity_sha256)
            || sha256_hex(target_principal.name().as_bytes()) != selector_sha256
            || !normalized_absolute_path(user_manifest_path)
            || !normalized_absolute_path(system_manifest_path)
            || !normalized_absolute_path(system_receipt_path)
            || !normalized_absolute_path(authorization_record_path)
            || !normalized_absolute_path(promotion_intent_path)
            || !normalized_absolute_path(completion_record_path)
            || user_manifest_path == system_manifest_path
        {
            return Err(ScopePromotionError::Conflict);
        }
        crate::platform::verify_worker_principal(original_operator)
            .map_err(|_| ScopePromotionError::Conflict)?;
        Ok(Self {
            machine_id,
            user_manifest_path: user_manifest_path.into(),
            user_manifest_sha256: user_manifest_sha256.into(),
            system_manifest_path: system_manifest_path.into(),
            system_manifest_sha256: system_manifest_sha256.into(),
            system_manifest_identity_sha256: system_manifest_identity_sha256.into(),
            system_receipt_path: system_receipt_path.into(),
            system_receipt_sha256: system_receipt_sha256.into(),
            system_receipt_identity_sha256: system_receipt_identity_sha256.into(),
            authorization_request_id,
            authorization_request_sha256: authorization_request_sha256.into(),
            authorization_record_path: authorization_record_path.into(),
            authorization_record_sha256: authorization_record_sha256.into(),
            authorization_record_identity_sha256: authorization_record_identity_sha256.into(),
            promotion_intent_path: promotion_intent_path.into(),
            promotion_intent_sha256: promotion_intent_sha256.into(),
            promotion_intent_identity_sha256: promotion_intent_identity_sha256.into(),
            completion_record_path: completion_record_path.into(),
            completion_record_sha256: completion_record_sha256.into(),
            completion_record_identity_sha256: completion_record_identity_sha256.into(),
            original_operator: original_operator.clone(),
            target_principal: target_principal.clone(),
            selector_sha256: selector_sha256.into(),
            promotion_intent_id,
        })
    }

    #[allow(clippy::too_many_arguments)] // Durable recovery must rebind the complete receipt tuple.
    pub(in crate::setup) fn from_durable_receipt(
        machine_id: uuid::Uuid,
        original_operator: &WorkerPrincipal,
        target_principal: &WorkerPrincipal,
        selector_sha256: &str,
        user_manifest_path: &str,
        user_manifest_sha256: &str,
        system_manifest_path: &str,
        system_manifest_sha256: &str,
        system_manifest_identity_sha256: &str,
        system_receipt_path: &str,
        system_receipt_sha256: &str,
        system_receipt_identity_sha256: &str,
        authorization_request_id: uuid::Uuid,
        authorization_request_sha256: &str,
        authorization_record_path: &str,
        authorization_record_sha256: &str,
        authorization_record_identity_sha256: &str,
        promotion_intent_path: &str,
        promotion_intent_sha256: &str,
        promotion_intent_identity_sha256: &str,
        completion_record_path: &str,
        completion_record_sha256: &str,
        completion_record_identity_sha256: &str,
        promotion_intent_id: uuid::Uuid,
        _authority: &ScopePromotionAuthority,
    ) -> Result<Self, ScopePromotionError> {
        Self::new(
            machine_id,
            original_operator,
            target_principal,
            selector_sha256,
            user_manifest_path,
            user_manifest_sha256,
            system_manifest_path,
            system_manifest_sha256,
            system_manifest_identity_sha256,
            system_receipt_path,
            system_receipt_sha256,
            system_receipt_identity_sha256,
            authorization_request_id,
            authorization_request_sha256,
            authorization_record_path,
            authorization_record_sha256,
            authorization_record_identity_sha256,
            promotion_intent_path,
            promotion_intent_sha256,
            promotion_intent_identity_sha256,
            completion_record_path,
            completion_record_sha256,
            completion_record_identity_sha256,
            promotion_intent_id,
        )
    }

    #[cfg(test)]
    #[allow(clippy::too_many_arguments)] // Mirrors the production tuple for focused contract tests.
    fn new_for_test(
        machine_id: uuid::Uuid,
        original_operator: &WorkerPrincipal,
        target_principal: &WorkerPrincipal,
        selector_sha256: &str,
        user_manifest_path: &str,
        user_manifest_sha256: &str,
        system_manifest_path: &str,
        system_manifest_sha256: &str,
        promotion_intent_id: uuid::Uuid,
    ) -> Result<Self, ScopePromotionError> {
        let system_parent = Path::new(system_manifest_path)
            .parent()
            .ok_or(ScopePromotionError::Conflict)?;
        let system_receipt_path = path_text(&system_parent.join("receipt.json"))?;
        let authorization_record_path = path_text(
            &system_parent.join(format!(".setup-request-{promotion_intent_id}.consumed")),
        )?;
        let promotion_intent_path = path_text(&Path::new(user_manifest_path).with_file_name(
            format!(".receipt.json.scope-promotion.{promotion_intent_id}.json"),
        ))?;
        let completion_record_path = path_text(&system_parent.join(format!(
            ".receipt.json.scope-promotion.{promotion_intent_id}.completed"
        )))?;
        Self::new(
            machine_id,
            original_operator,
            target_principal,
            selector_sha256,
            user_manifest_path,
            user_manifest_sha256,
            system_manifest_path,
            system_manifest_sha256,
            system_manifest_sha256,
            &system_receipt_path,
            system_manifest_sha256,
            system_manifest_sha256,
            promotion_intent_id,
            system_manifest_sha256,
            &authorization_record_path,
            system_manifest_sha256,
            system_manifest_sha256,
            &promotion_intent_path,
            system_manifest_sha256,
            system_manifest_sha256,
            &completion_record_path,
            system_manifest_sha256,
            system_manifest_sha256,
            promotion_intent_id,
        )
    }

    pub(in crate::setup) const fn action_id(&self) -> &'static str {
        SCOPE_PROMOTION_ACTION_ID
    }

    pub(in crate::setup) fn machine_id(&self) -> uuid::Uuid {
        self.machine_id
    }

    pub(in crate::setup) fn source_scope(&self) -> InstallationScope {
        InstallationScope::User
    }

    pub(in crate::setup) fn target_scope(&self) -> InstallationScope {
        InstallationScope::System
    }

    pub(in crate::setup) fn user_manifest_path(&self) -> &str {
        &self.user_manifest_path
    }

    pub(in crate::setup) fn user_manifest_sha256(&self) -> &str {
        &self.user_manifest_sha256
    }

    pub(in crate::setup) fn system_manifest_path(&self) -> &str {
        &self.system_manifest_path
    }

    pub(in crate::setup) fn system_manifest_sha256(&self) -> &str {
        &self.system_manifest_sha256
    }

    pub(in crate::setup) fn system_manifest_identity_sha256(&self) -> &str {
        &self.system_manifest_identity_sha256
    }

    pub(in crate::setup) fn system_receipt_path(&self) -> &str {
        &self.system_receipt_path
    }

    pub(in crate::setup) fn system_receipt_sha256(&self) -> &str {
        &self.system_receipt_sha256
    }

    pub(in crate::setup) fn system_receipt_identity_sha256(&self) -> &str {
        &self.system_receipt_identity_sha256
    }

    pub(in crate::setup) fn authorization_request_id(&self) -> uuid::Uuid {
        self.authorization_request_id
    }

    pub(in crate::setup) fn authorization_request_sha256(&self) -> &str {
        &self.authorization_request_sha256
    }

    pub(in crate::setup) fn authorization_record_path(&self) -> &str {
        &self.authorization_record_path
    }

    pub(in crate::setup) fn authorization_record_sha256(&self) -> &str {
        &self.authorization_record_sha256
    }

    pub(in crate::setup) fn authorization_record_identity_sha256(&self) -> &str {
        &self.authorization_record_identity_sha256
    }

    pub(in crate::setup) fn promotion_intent_path(&self) -> &str {
        &self.promotion_intent_path
    }

    pub(in crate::setup) fn promotion_intent_sha256(&self) -> &str {
        &self.promotion_intent_sha256
    }

    pub(in crate::setup) fn promotion_intent_identity_sha256(&self) -> &str {
        &self.promotion_intent_identity_sha256
    }

    pub(in crate::setup) fn completion_record_path(&self) -> &str {
        &self.completion_record_path
    }

    pub(in crate::setup) fn completion_record_sha256(&self) -> &str {
        &self.completion_record_sha256
    }

    pub(in crate::setup) fn completion_record_identity_sha256(&self) -> &str {
        &self.completion_record_identity_sha256
    }

    pub(in crate::setup) fn original_operator(&self) -> &WorkerPrincipal {
        &self.original_operator
    }

    pub(in crate::setup) fn target_principal(&self) -> &WorkerPrincipal {
        &self.target_principal
    }

    pub(in crate::setup) fn selector_sha256(&self) -> &str {
        &self.selector_sha256
    }

    pub(in crate::setup) fn promotion_intent_id(&self) -> uuid::Uuid {
        self.promotion_intent_id
    }
}

#[cfg(not(test))]
pub(crate) struct ScopePromotionAuthority(());

#[cfg(test)]
pub(crate) type ScopePromotionAuthority = crate::manifest::TestScopePromotionAuthority;

pub(in crate::setup) fn scope_promotion_authority() -> ScopePromotionAuthority {
    #[cfg(test)]
    {
        crate::manifest::TestScopePromotionAuthority::new()
    }
    #[cfg(not(test))]
    {
        ScopePromotionAuthority(())
    }
}

pub(in crate::setup) struct ScopePromotionPreparation {
    system_candidate: crate::manifest::DedicatedWorkerManifestCandidate,
    original_operator: WorkerPrincipal,
    target_principal: WorkerPrincipal,
    selector_sha256: Box<str>,
    system_receipt_path: PathBuf,
    system_manifest_path: PathBuf,
    authorization_request_id: uuid::Uuid,
    intent_id: uuid::Uuid,
}

impl ScopePromotionPreparation {
    pub(in crate::setup) fn new(
        ready: &crate::setup::action::DedicatedAccountReady,
        system_candidate: crate::manifest::DedicatedWorkerManifestCandidate,
        system_receipt: &crate::setup::receipt::ReceiptStore,
        system_manifest: &crate::manifest::MachineManifestStore,
    ) -> Result<Self, ScopePromotionError> {
        let target_principal = ready
            .reverify_target(Clone::clone)
            .map_err(|_| ScopePromotionError::Conflict)?;
        if system_receipt.installation_scope() != InstallationScope::System
            || system_manifest.installation_scope() != InstallationScope::System
            || system_receipt.worker_principal() != &target_principal
            || system_manifest.worker_principal() != &target_principal
        {
            return Err(ScopePromotionError::Conflict);
        }
        Ok(Self {
            system_candidate,
            original_operator: ready.original_operator().clone(),
            target_principal,
            selector_sha256: sha256_hex(ready.selector().as_bytes()).into(),
            system_receipt_path: system_receipt.path().to_path_buf(),
            system_manifest_path: system_manifest.path().to_path_buf(),
            authorization_request_id: uuid::Uuid::now_v7(),
            intent_id: uuid::Uuid::now_v7(),
        })
    }
}

const PROMOTION_INTENT_VERSION: u32 = 1;
const MAX_PROMOTION_INTENT_BYTES: usize = 64 * 1024;

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ScopePromotionIntentDocument {
    version: u32,
    intent_id: uuid::Uuid,
    original_operator: WorkerPrincipal,
    user_receipt_path: String,
    user_receipt_identity_sha256: String,
    user_manifest_path: String,
    user_manifest_identity_sha256: String,
    user_manifest_sha256: String,
    pending_publication_epoch: usize,
    machine_id: uuid::Uuid,
    target_principal: WorkerPrincipal,
    selector_sha256: String,
    system_receipt_path: String,
    system_manifest_path: String,
    system_manifest_sha256: String,
    candidate_manifest: String,
    authorization_request_id: uuid::Uuid,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    authorization_request_sha256: Option<String>,
    expected_completion: PromotionCompletion,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(in crate::setup) enum PromotionCompletion {
    ProtectedSystemPublication,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(in crate::setup) struct ScopePromotionRequestBinding {
    version: u32,
    authorization_request_id: uuid::Uuid,
    promotion_intent_id: uuid::Uuid,
    promotion_intent_path: String,
    promotion_intent_identity_sha256: String,
    promotion_intent_sha256: String,
    machine_id: uuid::Uuid,
    original_operator: WorkerPrincipal,
    target_principal: WorkerPrincipal,
    selector_sha256: String,
    system_receipt_path: String,
    system_manifest_path: String,
    system_manifest_sha256: String,
    expected_completion: PromotionCompletion,
}

impl ScopePromotionRequestBinding {
    fn from_intent(intent: &ScopePromotionIntent) -> Result<Self, ScopePromotionError> {
        let document = &intent.document;
        if document.authorization_request_sha256.is_some() {
            return Err(ScopePromotionError::Conflict);
        }
        let value = Self {
            version: PROMOTION_INTENT_VERSION,
            authorization_request_id: document.authorization_request_id,
            promotion_intent_id: document.intent_id,
            promotion_intent_path: path_text(&intent.path)?,
            promotion_intent_identity_sha256: intent.identity.binding_sha256(),
            promotion_intent_sha256: sha256_hex(&document.to_json()?),
            machine_id: document.machine_id,
            original_operator: document.original_operator.clone(),
            target_principal: document.target_principal.clone(),
            selector_sha256: document.selector_sha256.clone(),
            system_receipt_path: document.system_receipt_path.clone(),
            system_manifest_path: document.system_manifest_path.clone(),
            system_manifest_sha256: document.system_manifest_sha256.clone(),
            expected_completion: document.expected_completion,
        };
        value.validate()?;
        Ok(value)
    }

    pub(in crate::setup) fn validate(&self) -> Result<(), ScopePromotionError> {
        if self.version != PROMOTION_INTENT_VERSION
            || !is_uuid_v7(self.authorization_request_id)
            || !is_uuid_v7(self.promotion_intent_id)
            || !is_uuid_v7(self.machine_id)
            || self.original_operator.account_policy() != WorkerAccountPolicy::CurrentUser
            || self.target_principal.account_policy() != WorkerAccountPolicy::Dedicated
            || self.original_operator == self.target_principal
            || !normalized_absolute_path(&self.promotion_intent_path)
            || !normalized_absolute_path(&self.system_receipt_path)
            || !normalized_absolute_path(&self.system_manifest_path)
            || !valid_sha256(&self.promotion_intent_identity_sha256)
            || !valid_sha256(&self.promotion_intent_sha256)
            || !valid_sha256(&self.selector_sha256)
            || !valid_sha256(&self.system_manifest_sha256)
            || sha256_hex(self.target_principal.name().as_bytes()) != self.selector_sha256
        {
            return Err(ScopePromotionError::Conflict);
        }
        Ok(())
    }

    pub(in crate::setup) fn authorization_request_id(&self) -> uuid::Uuid {
        self.authorization_request_id
    }

    pub(in crate::setup) fn promotion_intent_id(&self) -> uuid::Uuid {
        self.promotion_intent_id
    }

    pub(in crate::setup) fn original_operator(&self) -> &WorkerPrincipal {
        &self.original_operator
    }

    pub(in crate::setup) fn target_principal(&self) -> &WorkerPrincipal {
        &self.target_principal
    }

    pub(in crate::setup) fn system_receipt_path(&self) -> &str {
        &self.system_receipt_path
    }

    pub(in crate::setup) fn system_manifest_path(&self) -> &str {
        &self.system_manifest_path
    }

    pub(in crate::setup) fn reverify_intent(
        &self,
        user_receipt_store: &crate::setup::receipt::ReceiptStore,
    ) -> Result<(), ScopePromotionError> {
        self.validate()?;
        let expected_path =
            scope_promotion_intent_path(user_receipt_store.path(), self.promotion_intent_id)?;
        if path_text(&expected_path)? != self.promotion_intent_path {
            return Err(ScopePromotionError::Conflict);
        }
        let intent =
            read_scope_promotion_intent(&expected_path, user_receipt_store.worker_principal())?
                .ok_or(ScopePromotionError::Conflict)?;
        validate_live_user_binding(user_receipt_store, None, &intent.document)?;
        let observed = Self::from_intent(&intent)?;
        if &observed != self {
            return Err(ScopePromotionError::Conflict);
        }
        Ok(())
    }
}

const MAX_PROMOTION_PROOF_BYTES: usize = 128 * 1024;

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ScopePromotionCompletionDocument {
    version: u32,
    authorization_request_id: uuid::Uuid,
    authorization_request_sha256: String,
    authorization_record_path: String,
    authorization_record_sha256: String,
    authorization_record_identity_sha256: String,
    request_binding: ScopePromotionRequestBinding,
    system_receipt_path: String,
    system_receipt_sha256: String,
    system_receipt_identity_sha256: String,
    system_manifest_path: String,
    system_manifest_sha256: String,
    system_manifest_identity_sha256: String,
    machine_id: uuid::Uuid,
    expected_completion: PromotionCompletion,
}

struct ScopePromotionCompletionProof {
    document: ScopePromotionCompletionDocument,
    path: PathBuf,
    sha256: String,
    identity_sha256: String,
}

impl ScopePromotionCompletionDocument {
    fn validate(&self) -> Result<(), ScopePromotionError> {
        self.request_binding.validate()?;
        if self.version != PROMOTION_INTENT_VERSION
            || self.authorization_request_id != self.request_binding.authorization_request_id
            || self.machine_id != self.request_binding.machine_id
            || self.expected_completion != PromotionCompletion::ProtectedSystemPublication
            || self.expected_completion != self.request_binding.expected_completion
            || self.system_receipt_path != self.request_binding.system_receipt_path
            || self.system_manifest_path != self.request_binding.system_manifest_path
            || self.system_manifest_sha256 != self.request_binding.system_manifest_sha256
            || !normalized_absolute_path(&self.authorization_record_path)
            || !valid_sha256(&self.authorization_request_sha256)
            || !valid_sha256(&self.authorization_record_sha256)
            || !valid_sha256(&self.authorization_record_identity_sha256)
            || !valid_sha256(&self.system_receipt_sha256)
            || !valid_sha256(&self.system_receipt_identity_sha256)
            || !valid_sha256(&self.system_manifest_identity_sha256)
        {
            return Err(ScopePromotionError::Conflict);
        }
        Ok(())
    }

    fn to_json(&self) -> Result<Vec<u8>, ScopePromotionError> {
        self.validate()?;
        let mut bytes =
            serde_json::to_vec_pretty(self).map_err(|_| ScopePromotionError::Conflict)?;
        bytes.push(b'\n');
        if bytes.len() > MAX_PROMOTION_PROOF_BYTES {
            return Err(ScopePromotionError::Conflict);
        }
        Ok(bytes)
    }

    fn from_json(bytes: &[u8]) -> Result<Self, ScopePromotionError> {
        if bytes.len() > MAX_PROMOTION_PROOF_BYTES {
            return Err(ScopePromotionError::Conflict);
        }
        let value =
            serde_json::from_slice::<Self>(bytes).map_err(|_| ScopePromotionError::Conflict)?;
        value.validate()?;
        if value.to_json()? != bytes {
            return Err(ScopePromotionError::Conflict);
        }
        Ok(value)
    }
}

fn scope_promotion_completion_path(
    system_receipt_path: &Path,
    intent_id: uuid::Uuid,
) -> Result<PathBuf, ScopePromotionError> {
    Ok(system_receipt_path
        .parent()
        .ok_or(ScopePromotionError::Conflict)?
        .join(format!(
            ".receipt.json.scope-promotion.{intent_id}.completed"
        )))
}

pub(in crate::setup) fn write_scope_promotion_completion(
    system_receipt_store: &crate::setup::receipt::ReceiptStore,
    authorization: &crate::setup::receipt::ProtectedScopePromotionAuthorization,
    receipt: &crate::setup::receipt::PromotionReceiptSnapshot,
    manifest: &crate::manifest::PromotionManifestSnapshot,
    _authority: &ScopePromotionAuthority,
) -> Result<(), ScopePromotionError> {
    let binding = authorization.binding();
    if system_receipt_store.installation_scope() != InstallationScope::System
        || system_receipt_store.worker_principal() != binding.target_principal()
        || path_text(system_receipt_store.path())? != binding.system_receipt_path
        || path_text(receipt.path())? != binding.system_receipt_path
        || path_text(manifest.path())? != binding.system_manifest_path
        || manifest.sha256() != binding.system_manifest_sha256
        || manifest.machine_id() != binding.machine_id
    {
        return Err(ScopePromotionError::Conflict);
    }
    let document = ScopePromotionCompletionDocument {
        version: PROMOTION_INTENT_VERSION,
        authorization_request_id: authorization.request_id(),
        authorization_request_sha256: authorization.request_sha256().to_owned(),
        authorization_record_path: path_text(authorization.path())?,
        authorization_record_sha256: authorization.sha256().to_owned(),
        authorization_record_identity_sha256: authorization.identity_sha256().to_owned(),
        request_binding: binding.clone(),
        system_receipt_path: path_text(receipt.path())?,
        system_receipt_sha256: receipt.sha256().to_owned(),
        system_receipt_identity_sha256: receipt.identity_sha256().to_owned(),
        system_manifest_path: path_text(manifest.path())?,
        system_manifest_sha256: manifest.sha256().to_owned(),
        system_manifest_identity_sha256: manifest.identity_sha256(),
        machine_id: manifest.machine_id(),
        expected_completion: PromotionCompletion::ProtectedSystemPublication,
    };
    let bytes = document.to_json()?;
    let path =
        scope_promotion_completion_path(system_receipt_store.path(), binding.promotion_intent_id)?;
    if path.exists() {
        let existing =
            read_scope_promotion_completion(system_receipt_store, binding.promotion_intent_id)?;
        return if existing.document == document {
            Ok(())
        } else {
            Err(ScopePromotionError::Conflict)
        };
    }
    let temporary = path.with_extension("completed.tmp");
    #[cfg(test)]
    let owner = crate::platform::ManifestOwner::CurrentProcess;
    #[cfg(not(test))]
    let owner = crate::platform::ManifestOwner::System;
    let mut file = crate::platform::create_private_publication_file(
        &temporary,
        owner,
        system_receipt_store.worker_principal(),
    )
    .map_err(|_| ScopePromotionError::Stage("completion temporary create"))?;
    let result = (|| {
        file.write_all(&bytes)
            .map_err(|_| ScopePromotionError::Stage("completion temporary write"))?;
        let complete = file
            .complete_exact(&bytes)
            .map_err(|_| ScopePromotionError::Stage("completion temporary completion"))?;
        complete
            .publish_no_replace(&path)
            .map_err(|_| ScopePromotionError::Stage("completion publication"))?;
        crate::platform::sync_parent_directory(path.parent().ok_or(ScopePromotionError::Conflict)?)
            .map_err(|_| ScopePromotionError::Stage("completion parent sync"))
    })();
    if result.is_err() {
        let _ = std::fs::remove_file(&temporary);
    }
    result
}

fn read_scope_promotion_completion(
    system_receipt_store: &crate::setup::receipt::ReceiptStore,
    intent_id: uuid::Uuid,
) -> Result<ScopePromotionCompletionProof, ScopePromotionError> {
    let path = scope_promotion_completion_path(system_receipt_store.path(), intent_id)?;
    let identity =
        crate::platform::private_file_identity(&path).map_err(|_| ScopePromotionError::Conflict)?;
    #[cfg(test)]
    let owner = crate::platform::ManifestOwner::CurrentProcess;
    #[cfg(not(test))]
    let owner = crate::platform::ManifestOwner::System;
    let file = crate::platform::open_verified_private_file_for_read(
        &path,
        owner,
        system_receipt_store.worker_principal(),
        identity,
    )
    .map_err(|_| ScopePromotionError::Conflict)?;
    let mut bytes = Vec::new();
    file.take((MAX_PROMOTION_PROOF_BYTES + 1) as u64)
        .read_to_end(&mut bytes)
        .map_err(|_| ScopePromotionError::Conflict)?;
    let document = ScopePromotionCompletionDocument::from_json(&bytes)?;
    Ok(ScopePromotionCompletionProof {
        document,
        path,
        sha256: sha256_hex(&bytes),
        identity_sha256: identity.binding_sha256(),
    })
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ScopePromotionRecoveryState {
    RetryAuthorization,
    CheckpointThenRetireUser,
    RetireIntent,
}

fn classify_recovery_state(
    user_digest: Option<&str>,
    system_digest: Option<&str>,
    checkpoint_exists: bool,
    expected_user_digest: &str,
    expected_system_digest: &str,
) -> Result<ScopePromotionRecoveryState, ScopePromotionError> {
    match (user_digest, system_digest, checkpoint_exists) {
        (Some(user), None, false) if user == expected_user_digest => {
            Ok(ScopePromotionRecoveryState::RetryAuthorization)
        }
        (Some(user), Some(system), _)
            if user == expected_user_digest && system == expected_system_digest =>
        {
            Ok(ScopePromotionRecoveryState::CheckpointThenRetireUser)
        }
        (None, Some(system), true) if system == expected_system_digest => {
            Ok(ScopePromotionRecoveryState::RetireIntent)
        }
        _ => Err(ScopePromotionError::Conflict),
    }
}

struct ScopePromotionIntent {
    document: ScopePromotionIntentDocument,
    path: PathBuf,
    identity: crate::platform::PrivateFileIdentity,
}

impl ScopePromotionIntentDocument {
    fn validate(&self) -> Result<(), ScopePromotionError> {
        if self.version != PROMOTION_INTENT_VERSION
            || !is_uuid_v7(self.intent_id)
            || !is_uuid_v7(self.machine_id)
            || !is_uuid_v7(self.authorization_request_id)
            || self.original_operator.account_policy() != WorkerAccountPolicy::CurrentUser
            || self.target_principal.account_policy() != WorkerAccountPolicy::Dedicated
            || self.original_operator == self.target_principal
            || !normalized_absolute_path(&self.user_receipt_path)
            || !normalized_absolute_path(&self.user_manifest_path)
            || !normalized_absolute_path(&self.system_receipt_path)
            || !normalized_absolute_path(&self.system_manifest_path)
            || self.user_manifest_path == self.system_manifest_path
            || !valid_sha256(&self.user_receipt_identity_sha256)
            || !valid_sha256(&self.user_manifest_identity_sha256)
            || !valid_sha256(&self.user_manifest_sha256)
            || !valid_sha256(&self.selector_sha256)
            || !valid_sha256(&self.system_manifest_sha256)
            || self
                .authorization_request_sha256
                .as_deref()
                .is_some_and(|digest| !valid_sha256(digest))
            || sha256_hex(self.candidate_manifest.as_bytes()) != self.system_manifest_sha256
        {
            return Err(ScopePromotionError::Conflict);
        }
        Ok(())
    }

    fn to_json(&self) -> Result<Vec<u8>, ScopePromotionError> {
        self.validate()?;
        let mut output =
            serde_json::to_vec_pretty(self).map_err(|_| ScopePromotionError::Conflict)?;
        output.push(b'\n');
        if output.len() > MAX_PROMOTION_INTENT_BYTES {
            return Err(ScopePromotionError::Conflict);
        }
        Ok(output)
    }

    fn from_json(input: &[u8]) -> Result<Self, ScopePromotionError> {
        if input.len() > MAX_PROMOTION_INTENT_BYTES {
            return Err(ScopePromotionError::Conflict);
        }
        let document =
            serde_json::from_slice::<Self>(input).map_err(|_| ScopePromotionError::Conflict)?;
        document.validate()?;
        if document.to_json()? != input {
            return Err(ScopePromotionError::Conflict);
        }
        Ok(document)
    }
}

pub(in crate::setup) fn write_scope_promotion_intent(
    receipt_store: &crate::setup::receipt::ReceiptStore,
    user_manifest_store: &crate::manifest::MachineManifestStore,
    system_manifest_store: &crate::manifest::MachineManifestStore,
    preparation: &ScopePromotionPreparation,
    machine_id: uuid::Uuid,
    _authority: &ScopePromotionAuthority,
) -> Result<uuid::Uuid, ScopePromotionError> {
    if receipt_store.installation_scope() != InstallationScope::User
        || user_manifest_store.installation_scope() != InstallationScope::User
        || receipt_store.worker_principal() != &preparation.original_operator
        || user_manifest_store.worker_principal() != &preparation.original_operator
        || system_manifest_store.path() != preparation.system_manifest_path
    {
        return Err(ScopePromotionError::Conflict);
    }
    let receipt = receipt_store
        .read_snapshot()
        .map_err(|_| ScopePromotionError::Stage("user receipt snapshot"))?;
    let receipt_identity = crate::platform::private_file_identity(receipt_store.path())
        .map_err(|_| ScopePromotionError::Stage("user receipt identity"))?;
    let user_snapshot = user_manifest_store
        .promotion_snapshot(_authority)
        .map_err(|_| ScopePromotionError::Stage("user manifest snapshot"))?
        .ok_or(ScopePromotionError::Stage("user manifest absent"))?;
    if user_snapshot.machine_id() != machine_id {
        return Err(ScopePromotionError::Conflict);
    }
    let system_candidate = preparation
        .system_candidate
        .scope_promotion_canonical(machine_id, _authority)
        .map_err(|_| ScopePromotionError::Stage("system manifest candidate"))?;
    let document = ScopePromotionIntentDocument {
        version: PROMOTION_INTENT_VERSION,
        intent_id: preparation.intent_id,
        original_operator: preparation.original_operator.clone(),
        user_receipt_path: path_text(receipt_store.path())?,
        user_receipt_identity_sha256: receipt_identity.binding_sha256(),
        user_manifest_path: path_text(user_snapshot.path())?,
        user_manifest_identity_sha256: user_snapshot.identity_sha256(),
        user_manifest_sha256: user_snapshot.sha256().to_owned(),
        pending_publication_epoch: receipt.pending_publication_count(),
        machine_id,
        target_principal: preparation.target_principal.clone(),
        selector_sha256: preparation.selector_sha256.to_string(),
        system_receipt_path: path_text(&preparation.system_receipt_path)?,
        system_manifest_path: path_text(&preparation.system_manifest_path)?,
        system_manifest_sha256: sha256_hex(system_candidate.as_bytes()),
        candidate_manifest: system_candidate,
        authorization_request_id: preparation.authorization_request_id,
        authorization_request_sha256: None,
        expected_completion: PromotionCompletion::ProtectedSystemPublication,
    };
    let expected_bytes = document
        .to_json()
        .map_err(|_| ScopePromotionError::Stage("promotion intent validation"))?;
    let path = scope_promotion_intent_path(receipt_store.path(), preparation.intent_id)?;
    reject_concurrent_scope_promotion_intents(&path)?;
    if let Some(existing) = read_scope_promotion_intent(&path, receipt_store.worker_principal())? {
        return if existing.document == document {
            Ok(existing.document.intent_id)
        } else {
            Err(ScopePromotionError::Conflict)
        };
    }
    let temporary = path.with_file_name(format!(
        ".receipt.json.scope-promotion.{}.tmp",
        preparation.intent_id
    ));
    let mut file = crate::platform::create_private_publication_file(
        &temporary,
        crate::platform::ManifestOwner::User,
        receipt_store.worker_principal(),
    )
    .map_err(|_| ScopePromotionError::Stage("promotion temporary create"))?;
    file.write_all(&expected_bytes)
        .map_err(|_| ScopePromotionError::Stage("promotion temporary write"))?;
    let complete = file
        .complete_exact(&expected_bytes)
        .map_err(|_| ScopePromotionError::Stage("promotion temporary completion"))?;
    complete
        .publish_no_replace(&path)
        .map_err(|_| ScopePromotionError::Stage("promotion intent publication"))?;
    Ok(document.intent_id)
}

pub(in crate::setup) fn scope_promotion_request_binding(
    receipt_store: &crate::setup::receipt::ReceiptStore,
    intent_id: uuid::Uuid,
) -> Result<ScopePromotionRequestBinding, ScopePromotionError> {
    let path = scope_promotion_intent_path(receipt_store.path(), intent_id)?;
    let intent = read_scope_promotion_intent(&path, receipt_store.worker_principal())?
        .ok_or(ScopePromotionError::Conflict)?;
    validate_live_user_binding(receipt_store, None, &intent.document)?;
    ScopePromotionRequestBinding::from_intent(&intent)
}

/// Recovers the one immutable protected promotion binding after the ephemeral
/// User authorization request has been retired. The intent remains the User
/// authority until finalization and is the only admissible reconstruction
/// source; legacy intent bytes are deliberately classified as conflict by
/// `from_intent` rather than upgraded into protected evidence.
pub(in crate::setup) fn scope_promotion_request_binding_for_resume(
    receipt_store: &crate::setup::receipt::ReceiptStore,
) -> Result<ScopePromotionRequestBinding, ScopePromotionError> {
    if receipt_store.installation_scope() != InstallationScope::User {
        return Err(ScopePromotionError::Conflict);
    }
    let parent = receipt_store
        .path()
        .parent()
        .ok_or(ScopePromotionError::Conflict)?;
    let mut recovered = None;
    for entry in std::fs::read_dir(parent).map_err(|_| ScopePromotionError::Conflict)? {
        let entry = entry.map_err(|_| ScopePromotionError::Conflict)?;
        let name = entry.file_name();
        let Some(name) = name.to_str() else {
            continue;
        };
        if !name.starts_with(".receipt.json.scope-promotion.") || !name.ends_with(".json") {
            continue;
        }
        if recovered.is_some() {
            return Err(ScopePromotionError::Conflict);
        }
        let intent = read_scope_promotion_intent(&entry.path(), receipt_store.worker_principal())?
            .ok_or(ScopePromotionError::Conflict)?;
        validate_live_user_binding(receipt_store, None, &intent.document)?;
        let binding = ScopePromotionRequestBinding::from_intent(&intent)?;
        recovered = Some(binding);
    }
    recovered.ok_or(ScopePromotionError::Conflict)
}

fn reject_concurrent_scope_promotion_intents(expected: &Path) -> Result<(), ScopePromotionError> {
    let parent = expected.parent().ok_or(ScopePromotionError::Conflict)?;
    let expected_name = expected.file_name().ok_or(ScopePromotionError::Conflict)?;
    let entries = std::fs::read_dir(parent).map_err(|_| ScopePromotionError::Conflict)?;
    for entry in entries {
        let entry = entry.map_err(|_| ScopePromotionError::Conflict)?;
        let name = entry.file_name();
        let Some(name_text) = name.to_str() else {
            continue;
        };
        if name != expected_name
            && name_text.starts_with(".receipt.json.scope-promotion.")
            && name_text.ends_with(".json")
        {
            return Err(ScopePromotionError::Conflict);
        }
    }
    Ok(())
}

fn scope_promotion_intent_path(
    receipt_path: &Path,
    intent_id: uuid::Uuid,
) -> Result<PathBuf, ScopePromotionError> {
    let parent = receipt_path.parent().ok_or(ScopePromotionError::Conflict)?;
    Ok(parent.join(format!(".receipt.json.scope-promotion.{intent_id}.json")))
}

fn read_scope_promotion_intent(
    path: &Path,
    operator: &WorkerPrincipal,
) -> Result<Option<ScopePromotionIntent>, ScopePromotionError> {
    let identity = match crate::platform::private_file_identity(path) {
        Ok(identity) => identity,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(_) => return Err(ScopePromotionError::Conflict),
    };
    let file = crate::platform::open_verified_private_file_for_read(
        path,
        crate::platform::ManifestOwner::User,
        operator,
        identity,
    )
    .map_err(|_| ScopePromotionError::Conflict)?;
    let mut input = Vec::new();
    file.take((MAX_PROMOTION_INTENT_BYTES + 1) as u64)
        .read_to_end(&mut input)
        .map_err(|_| ScopePromotionError::Conflict)?;
    let document = ScopePromotionIntentDocument::from_json(&input)?;
    Ok(Some(ScopePromotionIntent {
        document,
        path: path.to_path_buf(),
        identity,
    }))
}

fn path_text(path: &Path) -> Result<String, ScopePromotionError> {
    let value = path.to_str().ok_or(ScopePromotionError::Conflict)?;
    if !normalized_absolute_path(value) {
        return Err(ScopePromotionError::Conflict);
    }
    Ok(value.to_owned())
}

fn sha256_hex(bytes: &[u8]) -> String {
    let mut output = String::with_capacity(64);
    for byte in Sha256::digest(bytes) {
        write!(&mut output, "{byte:02x}").expect("writing hexadecimal cannot fail");
    }
    output
}

#[allow(clippy::needless_return)] // Windows is a deliberate closed refusal branch until T0.18.
pub(in crate::setup) fn publish_scope_promotion_system_manifest(
    user_receipt_store: &crate::setup::receipt::ReceiptStore,
    intent_id: uuid::Uuid,
    system_receipt_store: &crate::setup::receipt::ReceiptStore,
    system_manifest_store: &crate::manifest::MachineManifestStore,
    completed: &crate::setup::action::CompletedExecutionToken,
    metadata: &mut crate::setup::receipt::ReceiptMetadataSource,
) -> Result<uuid::Uuid, ScopePromotionError> {
    #[cfg(target_os = "windows")]
    {
        let _ = (
            user_receipt_store,
            intent_id,
            system_receipt_store,
            system_manifest_store,
            completed,
            metadata,
        );
        return Err(ScopePromotionError::Conflict);
    }
    #[cfg(not(target_os = "windows"))]
    {
        let path = scope_promotion_intent_path(user_receipt_store.path(), intent_id)?;
        let intent = read_scope_promotion_intent(&path, user_receipt_store.worker_principal())?
            .ok_or(ScopePromotionError::Conflict)?;
        let document = &intent.document;
        validate_live_user_binding(user_receipt_store, None, document)?;
        if system_receipt_store.installation_scope() != InstallationScope::System
            || system_manifest_store.installation_scope() != InstallationScope::System
            || system_receipt_store.worker_principal() != &document.target_principal
            || system_manifest_store.worker_principal() != &document.target_principal
            || path_text(system_receipt_store.path())? != document.system_receipt_path
            || path_text(system_manifest_store.path())? != document.system_manifest_path
            || sha256_hex(document.target_principal.name().as_bytes()) != document.selector_sha256
        {
            return Err(ScopePromotionError::Conflict);
        }
        let pending_authority = crate::setup::pending::pending_publication_authority();
        let authority = scope_promotion_authority();
        let request_binding = ScopePromotionRequestBinding::from_intent(&intent)?;
        let authorization = system_receipt_store
            .verify_scope_promotion_authorization(
                document.authorization_request_id,
                &request_binding,
                &authority,
            )
            .map_err(|_| ScopePromotionError::Stage("protected authorization marker"))?;
        system_receipt_store
            .validate_scope_promotion_system_completion(&authority)
            .map_err(|_| ScopePromotionError::Stage("system directory receipt completion"))?;
        let session = system_receipt_store
            .begin_pending_publication(&pending_authority)
            .map_err(|_| ScopePromotionError::Stage("system receipt publication session"))?;
        let machine_id = session.publish_scope_promotion_system_manifest(
            system_manifest_store,
            &document.candidate_manifest,
            document.machine_id,
            completed,
            metadata,
            &pending_authority,
            &authority,
            &authorization,
        )?;
        let system = system_manifest_store
            .promotion_snapshot(&authority)
            .map_err(|_| ScopePromotionError::Conflict)?
            .ok_or(ScopePromotionError::Conflict)?;
        if system.machine_id() != document.machine_id
            || system.sha256() != document.system_manifest_sha256
        {
            return Err(ScopePromotionError::Conflict);
        }
        Ok(machine_id)
    }
}

#[allow(clippy::needless_return)] // Windows is a deliberate closed refusal branch until T0.18.
pub(in crate::setup) fn finalize_scope_promotion(
    user_receipt_store: &crate::setup::receipt::ReceiptStore,
    user_manifest_store: &crate::manifest::MachineManifestStore,
    system_receipt_store: &crate::setup::receipt::ReceiptStore,
    system_manifest_store: &crate::manifest::MachineManifestStore,
    intent_id: uuid::Uuid,
    metadata: &mut crate::setup::receipt::ReceiptMetadataSource,
) -> Result<crate::platform::EstablishedDedicatedAccountEvidence, ScopePromotionError> {
    #[cfg(target_os = "windows")]
    {
        let _ = (
            user_receipt_store,
            user_manifest_store,
            system_receipt_store,
            system_manifest_store,
            intent_id,
            metadata,
        );
        return Err(ScopePromotionError::Conflict);
    }
    #[cfg(not(target_os = "windows"))]
    {
        let authority = scope_promotion_authority();
        let path = scope_promotion_intent_path(user_receipt_store.path(), intent_id)?;
        let Some(intent) =
            read_scope_promotion_intent(&path, user_receipt_store.worker_principal())?
        else {
            return recover_completed_scope_promotion(
                user_receipt_store,
                user_manifest_store,
                system_receipt_store,
                system_manifest_store,
                intent_id,
                &authority,
            );
        };
        let document = &intent.document;
        if user_receipt_store.installation_scope() != InstallationScope::User
            || user_manifest_store.installation_scope() != InstallationScope::User
            || system_receipt_store.installation_scope() != InstallationScope::System
            || system_manifest_store.installation_scope() != InstallationScope::System
            || user_receipt_store.worker_principal() != &document.original_operator
            || user_manifest_store.worker_principal() != &document.original_operator
            || system_receipt_store.worker_principal() != &document.target_principal
            || system_manifest_store.worker_principal() != &document.target_principal
            || path_text(user_receipt_store.path())? != document.user_receipt_path
            || path_text(user_manifest_store.path())? != document.user_manifest_path
            || path_text(system_receipt_store.path())? != document.system_receipt_path
            || path_text(system_manifest_store.path())? != document.system_manifest_path
            || sha256_hex(document.target_principal.name().as_bytes()) != document.selector_sha256
        {
            return Err(ScopePromotionError::Conflict);
        }
        let pending_authority = crate::setup::pending::pending_publication_authority();
        let system_receipt_session = system_receipt_store
            .begin_pending_publication(&pending_authority)
            .map_err(|_| ScopePromotionError::Conflict)?;
        let request_binding = ScopePromotionRequestBinding::from_intent(&intent)?;
        let authorization = system_receipt_store
            .verify_scope_promotion_authorization(
                document.authorization_request_id,
                &request_binding,
                &authority,
            )
            .map_err(|_| ScopePromotionError::Conflict)?;
        let system_receipt = system_receipt_session
            .promotion_receipt_snapshot()
            .map_err(|_| ScopePromotionError::Conflict)?;
        let system = system_manifest_store
            .promotion_snapshot(&authority)
            .map_err(|_| ScopePromotionError::Conflict)?
            .ok_or(ScopePromotionError::Conflict)?;
        if system.machine_id() != document.machine_id
            || system.sha256() != document.system_manifest_sha256
            || system.canonical() != document.candidate_manifest
        {
            return Err(ScopePromotionError::Conflict);
        }
        let completion = read_scope_promotion_completion(system_receipt_store, document.intent_id)?;
        if completion.document.request_binding != request_binding
            || completion.document.authorization_request_sha256 != authorization.request_sha256()
            || completion.document.authorization_record_path != path_text(authorization.path())?
            || completion.document.authorization_record_sha256 != authorization.sha256()
            || completion.document.authorization_record_identity_sha256
                != authorization.identity_sha256()
            || completion.document.system_receipt_path != path_text(system_receipt.path())?
            || completion.document.system_receipt_sha256 != system_receipt.sha256()
            || completion.document.system_receipt_identity_sha256
                != system_receipt.identity_sha256()
            || completion.document.system_manifest_path != path_text(system.path())?
            || completion.document.system_manifest_sha256 != system.sha256()
            || completion.document.system_manifest_identity_sha256 != system.identity_sha256()
        {
            return Err(ScopePromotionError::Conflict);
        }
        drop(system_receipt_session);
        let checkpoint = ScopePromotionCheckpoint::new(
            document.machine_id,
            &document.original_operator,
            &document.target_principal,
            &document.selector_sha256,
            &document.user_manifest_path,
            &document.user_manifest_sha256,
            &document.system_manifest_path,
            &document.system_manifest_sha256,
            &completion.document.system_manifest_identity_sha256,
            &document.system_receipt_path,
            &completion.document.system_receipt_sha256,
            &completion.document.system_receipt_identity_sha256,
            document.authorization_request_id,
            &completion.document.authorization_request_sha256,
            &completion.document.authorization_record_path,
            &completion.document.authorization_record_sha256,
            &completion.document.authorization_record_identity_sha256,
            &request_binding.promotion_intent_path,
            &request_binding.promotion_intent_sha256,
            &request_binding.promotion_intent_identity_sha256,
            &path_text(&completion.path)?,
            &completion.sha256,
            &completion.identity_sha256,
            document.intent_id,
        )
        .map_err(|_| ScopePromotionError::Stage("promotion checkpoint tuple"))?;
        let receipt = user_receipt_store
            .read_snapshot()
            .map_err(|_| ScopePromotionError::Stage("promotion checkpoint receipt read"))?;
        let checkpoint_exists = receipt
            .has_scope_promotion_checkpoint(&checkpoint)
            .map_err(|_| ScopePromotionError::Stage("promotion checkpoint lookup"))?;
        let current_receipt_identity =
            crate::platform::private_file_identity(user_receipt_store.path())
                .map_err(|_| ScopePromotionError::Conflict)?;
        if current_receipt_identity.binding_sha256() != document.user_receipt_identity_sha256
            && !checkpoint_exists
        {
            return Err(ScopePromotionError::Conflict);
        }
        let source = user_manifest_store
            .promotion_snapshot(&authority)
            .map_err(|_| ScopePromotionError::Conflict)?;
        if let Some(source) = &source {
            if source.machine_id() != document.machine_id
                || source.sha256() != document.user_manifest_sha256
                || source.identity_sha256() != document.user_manifest_identity_sha256
            {
                return Err(ScopePromotionError::Conflict);
            }
        } else if !checkpoint_exists {
            return Err(ScopePromotionError::Conflict);
        }
        let recovery = classify_recovery_state(
            source
                .as_ref()
                .map(crate::manifest::PromotionManifestSnapshot::sha256),
            Some(system.sha256()),
            checkpoint_exists,
            &document.user_manifest_sha256,
            &document.system_manifest_sha256,
        )?;
        if recovery == ScopePromotionRecoveryState::RetryAuthorization {
            return Err(ScopePromotionError::Conflict);
        }
        user_receipt_store
            .commit_scope_promotion_checkpoint(&checkpoint, metadata, &authority, || {
                #[cfg(test)]
                if INTERRUPT_AFTER_CHECKPOINT.with(std::cell::Cell::get) {
                    return Err(crate::setup::receipt::ReceiptStoreError::Write(
                        std::io::Error::new(
                            std::io::ErrorKind::Interrupted,
                            "injected interruption after promotion checkpoint",
                        ),
                    ));
                }
                if let Some(source) = &source {
                    user_manifest_store
                        .retire_promotion_source(source, &authority)
                        .map_err(|_| crate::setup::receipt::ReceiptStoreError::IntentConflict)?;
                }
                #[cfg(test)]
                if INTERRUPT_AFTER_USER_RETIREMENT.with(std::cell::Cell::get) {
                    return Err(crate::setup::receipt::ReceiptStoreError::Write(
                        std::io::Error::new(
                            std::io::ErrorKind::Interrupted,
                            "injected interruption after user-manifest retirement",
                        ),
                    ));
                }
                let removal = crate::platform::prepare_verified_private_file_removal(
                    &intent.path,
                    crate::platform::ManifestOwner::User,
                    user_receipt_store.worker_principal(),
                    intent.identity,
                )
                .map_err(crate::setup::receipt::ReceiptStoreError::Security)?;
                crate::platform::consume_verified_private_file(removal)
                    .map_err(crate::setup::receipt::ReceiptStoreError::Write)?;
                crate::platform::sync_parent_directory(
                    intent
                        .path
                        .parent()
                        .ok_or(crate::setup::receipt::ReceiptStoreError::InvalidDestination)?,
                )
                .map_err(crate::setup::receipt::ReceiptStoreError::Write)
            })
            .map_err(|_| ScopePromotionError::Conflict)?;
        established_evidence(&document.target_principal, &authority)
    }
}

#[cfg(not(target_os = "windows"))]
fn recover_completed_scope_promotion(
    user_receipt_store: &crate::setup::receipt::ReceiptStore,
    user_manifest_store: &crate::manifest::MachineManifestStore,
    system_receipt_store: &crate::setup::receipt::ReceiptStore,
    system_manifest_store: &crate::manifest::MachineManifestStore,
    intent_id: uuid::Uuid,
    authority: &ScopePromotionAuthority,
) -> Result<crate::platform::EstablishedDedicatedAccountEvidence, ScopePromotionError> {
    if user_receipt_store.installation_scope() != InstallationScope::User
        || user_manifest_store.installation_scope() != InstallationScope::User
        || system_receipt_store.installation_scope() != InstallationScope::System
        || system_manifest_store.installation_scope() != InstallationScope::System
    {
        return Err(ScopePromotionError::Conflict);
    }
    let receipt = user_receipt_store
        .read_snapshot()
        .map_err(|_| ScopePromotionError::Conflict)?;
    let checkpoint = receipt
        .scope_promotion_checkpoint(intent_id, authority)
        .map_err(|_| ScopePromotionError::Conflict)?
        .ok_or(ScopePromotionError::Conflict)?;
    if checkpoint.original_operator() != user_receipt_store.worker_principal()
        || checkpoint.original_operator() != user_manifest_store.worker_principal()
        || checkpoint.target_principal() != system_receipt_store.worker_principal()
        || checkpoint.target_principal() != system_manifest_store.worker_principal()
        || path_text(user_manifest_store.path())? != checkpoint.user_manifest_path()
        || path_text(system_receipt_store.path())? != checkpoint.system_receipt_path()
        || path_text(system_manifest_store.path())? != checkpoint.system_manifest_path()
        || user_manifest_store
            .promotion_snapshot(authority)
            .map_err(|_| ScopePromotionError::Conflict)?
            .is_some()
    {
        return Err(ScopePromotionError::Conflict);
    }
    let pending_authority = crate::setup::pending::pending_publication_authority();
    let system_receipt_session = system_receipt_store
        .begin_pending_publication(&pending_authority)
        .map_err(|_| ScopePromotionError::Conflict)?;
    let system_receipt = system_receipt_session
        .promotion_receipt_snapshot()
        .map_err(|_| ScopePromotionError::Conflict)?;
    if system_receipt.sha256() != checkpoint.system_receipt_sha256()
        || system_receipt.identity_sha256() != checkpoint.system_receipt_identity_sha256()
    {
        return Err(ScopePromotionError::Conflict);
    }
    let completion = read_scope_promotion_completion(system_receipt_store, intent_id)?;
    let binding = &completion.document.request_binding;
    if path_text(&completion.path)? != checkpoint.completion_record_path()
        || completion.sha256 != checkpoint.completion_record_sha256()
        || completion.identity_sha256 != checkpoint.completion_record_identity_sha256()
        || binding.promotion_intent_id != intent_id
        || binding.promotion_intent_path != checkpoint.promotion_intent_path()
        || binding.promotion_intent_sha256 != checkpoint.promotion_intent_sha256()
        || binding.promotion_intent_identity_sha256 != checkpoint.promotion_intent_identity_sha256()
        || binding.machine_id != checkpoint.machine_id()
        || binding.original_operator != *checkpoint.original_operator()
        || binding.target_principal != *checkpoint.target_principal()
        || binding.selector_sha256 != checkpoint.selector_sha256()
        || binding.system_receipt_path != checkpoint.system_receipt_path()
        || binding.system_manifest_path != checkpoint.system_manifest_path()
        || binding.system_manifest_sha256 != checkpoint.system_manifest_sha256()
        || binding.authorization_request_id != checkpoint.authorization_request_id()
    {
        return Err(ScopePromotionError::Conflict);
    }
    let authorization = system_receipt_store
        .verify_scope_promotion_authorization(
            checkpoint.authorization_request_id(),
            binding,
            authority,
        )
        .map_err(|_| ScopePromotionError::Conflict)?;
    if authorization.request_sha256() != checkpoint.authorization_request_sha256()
        || path_text(authorization.path())? != checkpoint.authorization_record_path()
        || authorization.sha256() != checkpoint.authorization_record_sha256()
        || authorization.identity_sha256() != checkpoint.authorization_record_identity_sha256()
        || completion.document.authorization_request_sha256
            != checkpoint.authorization_request_sha256()
        || completion.document.authorization_record_path != checkpoint.authorization_record_path()
        || completion.document.authorization_record_sha256
            != checkpoint.authorization_record_sha256()
        || completion.document.authorization_record_identity_sha256
            != checkpoint.authorization_record_identity_sha256()
        || completion.document.system_receipt_path != checkpoint.system_receipt_path()
        || completion.document.system_receipt_sha256 != checkpoint.system_receipt_sha256()
        || completion.document.system_receipt_identity_sha256
            != checkpoint.system_receipt_identity_sha256()
    {
        return Err(ScopePromotionError::Conflict);
    }
    let system = system_manifest_store
        .promotion_snapshot(authority)
        .map_err(|_| ScopePromotionError::Conflict)?
        .ok_or(ScopePromotionError::Conflict)?;
    if system.machine_id() != checkpoint.machine_id()
        || system.sha256() != checkpoint.system_manifest_sha256()
        || system.identity_sha256() != checkpoint.system_manifest_identity_sha256()
        || completion.document.system_manifest_path != checkpoint.system_manifest_path()
        || completion.document.system_manifest_sha256 != checkpoint.system_manifest_sha256()
        || completion.document.system_manifest_identity_sha256
            != checkpoint.system_manifest_identity_sha256()
    {
        return Err(ScopePromotionError::Conflict);
    }
    drop(system_receipt_session);
    established_evidence(checkpoint.target_principal(), authority)
}

#[cfg(not(target_os = "windows"))]
fn established_evidence(
    target: &WorkerPrincipal,
    authority: &ScopePromotionAuthority,
) -> Result<crate::platform::EstablishedDedicatedAccountEvidence, ScopePromotionError> {
    #[cfg(test)]
    let evidence = crate::platform::established_dedicated_account_evidence_from_promotion(
        target.name(),
        target.clone(),
    );
    #[cfg(not(test))]
    let evidence = crate::platform::established_dedicated_account_evidence_from_promotion(
        target.name(),
        target.clone(),
        authority,
    );
    let _ = authority;
    evidence.map_err(|_| ScopePromotionError::Conflict)
}

fn validate_live_user_binding(
    receipt_store: &crate::setup::receipt::ReceiptStore,
    user_manifest_store: Option<&crate::manifest::MachineManifestStore>,
    document: &ScopePromotionIntentDocument,
) -> Result<(), ScopePromotionError> {
    if receipt_store.installation_scope() != InstallationScope::User
        || receipt_store.worker_principal() != &document.original_operator
        || path_text(receipt_store.path())? != document.user_receipt_path
    {
        return Err(ScopePromotionError::Conflict);
    }
    let receipt_identity = crate::platform::private_file_identity(receipt_store.path())
        .map_err(|_| ScopePromotionError::Conflict)?;
    if receipt_identity.binding_sha256() != document.user_receipt_identity_sha256 {
        return Err(ScopePromotionError::Conflict);
    }
    let receipt = receipt_store
        .read_snapshot()
        .map_err(|_| ScopePromotionError::Conflict)?;
    if receipt.pending_publication_count() != document.pending_publication_epoch {
        return Err(ScopePromotionError::Conflict);
    }
    if let Some(store) = user_manifest_store {
        let authority = scope_promotion_authority();
        let snapshot = store
            .promotion_snapshot(&authority)
            .map_err(|_| ScopePromotionError::Conflict)?
            .ok_or(ScopePromotionError::Conflict)?;
        if path_text(snapshot.path())? != document.user_manifest_path
            || snapshot.machine_id() != document.machine_id
            || snapshot.sha256() != document.user_manifest_sha256
            || snapshot.identity_sha256() != document.user_manifest_identity_sha256
        {
            return Err(ScopePromotionError::Conflict);
        }
    }
    Ok(())
}

#[derive(Debug, thiserror::Error)]
pub(crate) enum ScopePromotionError {
    #[error("scope promotion evidence conflicts with durable setup state")]
    Conflict,
    #[error("scope promotion evidence conflicts with durable setup state")]
    Stage(&'static str),
}

impl ScopePromotionError {
    pub(crate) const fn error_code(&self) -> &'static str {
        "setup.receipt_conflict"
    }
}

fn is_uuid_v7(value: uuid::Uuid) -> bool {
    value.get_version_num() == 7 && value.get_variant() == uuid::Variant::RFC4122
}

fn valid_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn normalized_absolute_path(value: &str) -> bool {
    let path = Path::new(value);
    path.is_absolute()
        && path
            .components()
            .all(|component| !matches!(component, Component::CurDir | Component::ParentDir))
}

#[cfg(test)]
mod tests {
    fn native_manifest_draft(
        scope: crate::platform::InstallationScope,
    ) -> crate::manifest::MachineManifestDraft {
        let mut draft = crate::manifest::MachineManifest::parse_toml(include_str!(
            "../../examples/machine.controller-worker.toml"
        ))
        .unwrap()
        .without_machine_id();
        draft.installation = Some(crate::manifest::Installation { scope });
        #[cfg(target_os = "linux")]
        {
            draft.platform.os = crate::manifest::OperatingSystem::Linux;
        }
        #[cfg(target_os = "macos")]
        {
            draft.platform.os = crate::manifest::OperatingSystem::Macos;
        }
        #[cfg(target_os = "windows")]
        {
            draft.platform.os = crate::manifest::OperatingSystem::Windows;
        }
        draft
    }

    #[test]
    fn scope_promotion_recovery_accepts_only_the_three_safe_durable_states() {
        use super::ScopePromotionRecoveryState::{
            CheckpointThenRetireUser, RetireIntent, RetryAuthorization,
        };
        let user = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        let system = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
        let third = "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc";
        assert_eq!(
            super::classify_recovery_state(Some(user), None, false, user, system).unwrap(),
            RetryAuthorization
        );
        assert_eq!(
            super::classify_recovery_state(Some(user), Some(system), false, user, system).unwrap(),
            CheckpointThenRetireUser
        );
        assert_eq!(
            super::classify_recovery_state(None, Some(system), true, user, system).unwrap(),
            RetireIntent
        );
        for before in [None, Some(user), Some(third)] {
            for after in [None, Some(system), Some(third)] {
                for checkpoint in [false, true] {
                    let expected_safe = matches!(
                        (before, after, checkpoint),
                        (Some(value), None, false) if value == user
                    ) || matches!(
                        (before, after, checkpoint),
                        (Some(before_value), Some(after_value), _)
                            if before_value == user && after_value == system
                    ) || matches!(
                        (before, after, checkpoint),
                        (None, Some(value), true) if value == system
                    );
                    assert_eq!(
                        super::classify_recovery_state(before, after, checkpoint, user, system,)
                            .is_ok(),
                        expected_safe,
                        "unexpected recovery classification for {before:?}/{after:?}/{checkpoint}",
                    );
                }
            }
        }
    }

    #[test]
    fn scope_promotion_rejects_concurrent_intent_files() {
        let root = std::env::temp_dir().join(format!(
            "styrn-concurrent-scope-promotion-{}",
            uuid::Uuid::now_v7()
        ));
        std::fs::create_dir_all(&root).unwrap();
        let expected = root.join(format!(
            ".receipt.json.scope-promotion.{}.json",
            uuid::Uuid::now_v7()
        ));
        assert!(super::reject_concurrent_scope_promotion_intents(&expected).is_ok());
        let temporary = root.join(".receipt.json.scope-promotion.interrupted.tmp");
        std::fs::write(&temporary, b"incomplete").unwrap();
        assert!(super::reject_concurrent_scope_promotion_intents(&expected).is_ok());
        let other = root.join(format!(
            ".receipt.json.scope-promotion.{}.json",
            uuid::Uuid::now_v7()
        ));
        std::fs::write(&other, b"untrusted").unwrap();
        assert!(super::reject_concurrent_scope_promotion_intents(&expected).is_err());
        assert_eq!(std::fs::read(&other).unwrap(), b"untrusted");
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn scope_promotion_checkpoint_is_typed_non_owning_user_history() {
        let operator = crate::platform::resolve_current_worker_principal().unwrap();
        let target = crate::platform::WorkerPrincipal::new(
            operator.principal_kind(),
            operator.principal_id(),
            "build-agent",
            crate::platform::WorkerAccountPolicy::Dedicated,
        )
        .unwrap();
        let checkpoint = super::ScopePromotionCheckpoint::new_for_test(
            uuid::Uuid::now_v7(),
            &operator,
            &target,
            "7f81291a9c35cb94e74c8794e4c1ea1c0966b92fc67a72490ef0df956320a394",
            "/tmp/styrn-user-machine.toml",
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "/tmp/styrn-system-machine.toml",
            "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
            uuid::Uuid::now_v7(),
        )
        .unwrap();

        assert_eq!(checkpoint.action_id(), "identity.scope-promotion");
        assert_eq!(checkpoint.original_operator(), &operator);
        assert_eq!(checkpoint.target_principal(), &target);
    }

    #[test]
    fn scope_promotion_checkpoint_is_durable_once_and_cannot_claim_effects() {
        let operator = crate::platform::resolve_current_worker_principal().unwrap();
        let target = crate::platform::WorkerPrincipal::new(
            operator.principal_kind(),
            operator.principal_id(),
            "build-agent",
            crate::platform::WorkerAccountPolicy::Dedicated,
        )
        .unwrap();
        let root = std::env::current_dir()
            .unwrap()
            .join("target")
            .join(format!("styrn-scope-promotion-{}", uuid::Uuid::now_v7()));
        let receipt_path = root.join("styrn/receipt.json");
        let store = crate::setup::receipt::ReceiptStore::new_user_for_test(&receipt_path);
        let checkpoint = super::ScopePromotionCheckpoint::new_for_test(
            uuid::Uuid::now_v7(),
            &operator,
            &target,
            "7f81291a9c35cb94e74c8794e4c1ea1c0966b92fc67a72490ef0df956320a394",
            "/tmp/styrn-user-machine.toml",
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "/tmp/styrn-system-machine.toml",
            "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
            uuid::Uuid::now_v7(),
        )
        .unwrap();
        let authority = super::scope_promotion_authority();
        let mut metadata = crate::setup::receipt::ReceiptMetadataSource::for_test([(
            "019cad99-54a0-7000-8000-000000000011",
            "2026-09-03T11:00:00Z",
        )]);

        store
            .append_scope_promotion_checkpoint(&checkpoint, &mut metadata, &authority)
            .unwrap();
        store
            .append_scope_promotion_checkpoint(&checkpoint, &mut metadata, &authority)
            .unwrap();
        let document: serde_json::Value =
            serde_json::from_slice(&std::fs::read(&receipt_path).unwrap()).unwrap();
        let entries = document["entries"].as_array().unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0]["action"]["type"], "scope_promotion");
        assert_eq!(entries[0]["privilege_used"], "none");
        assert_eq!(entries[0]["status"], "applied");
        for field in [
            "directories_created",
            "files_created",
            "files_modified",
            "services",
            "accounts",
            "registry_keys",
            "firewall_rules",
        ] {
            assert_eq!(entries[0][field].as_array().unwrap().len(), 0);
        }
        assert!(entries[0]["download_provenance"].is_null());
        let _ = std::fs::remove_dir_all(root);
    }

    #[cfg(not(target_os = "windows"))]
    #[derive(Clone, Copy, Eq, PartialEq)]
    enum PromotionProofCase {
        Normal,
        InterruptedAfterAuthorizationRecord,
        InterruptedAfterRequestRetirement,
        InterruptedDuringSystemJournaling,
        HostileResumeEvidence,
        AlteredIntentBeforePublication,
        AlteredIntentAfterAuthorization,
        MissingCompletionBeforePublicationRerun,
        MissingAuthorizationBeforeFinalization,
        SubstitutedReceiptBeforeFinalization,
        MissingAuthorizationAfterIntentRetirement,
    }

    #[test]
    #[cfg(not(target_os = "windows"))]
    fn scope_promotion_preserves_one_uuid_and_dedicated_account_established_rerun() {
        run_scope_promotion_protocol(PromotionProofCase::Normal);
    }

    #[test]
    #[cfg(not(target_os = "windows"))]
    fn scope_promotion_authorization_resumes_each_protected_interruption() {
        run_scope_promotion_protocol(PromotionProofCase::InterruptedAfterAuthorizationRecord);
        run_scope_promotion_protocol(PromotionProofCase::InterruptedAfterRequestRetirement);
        run_scope_promotion_protocol(PromotionProofCase::InterruptedDuringSystemJournaling);
    }

    #[test]
    #[cfg(not(target_os = "windows"))]
    fn scope_promotion_resume_rejects_digest_action_binding_identity_and_completed_replay() {
        run_scope_promotion_protocol(PromotionProofCase::HostileResumeEvidence);
    }

    #[test]
    #[cfg(not(target_os = "windows"))]
    fn legacy_scope_promotion_intent_round_trips_without_becoming_protected_evidence() {
        let bytes = include_bytes!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/examples/setup-scope-promotion-intent-legacy.json"
        ));
        let document = serde_json::from_slice::<super::ScopePromotionIntentDocument>(bytes)
            .expect("legacy intent syntax and fields must deserialize");
        document
            .validate()
            .expect("legacy intent fields must satisfy v1 semantics");
        assert_eq!(document.to_json().unwrap(), bytes);
        let document = super::ScopePromotionIntentDocument::from_json(bytes)
            .expect("legacy intent bytes must be canonical");
        assert_eq!(document.to_json().unwrap(), bytes);
        assert_eq!(
            super::sha256_hex(bytes),
            "cfa5c42510066caf2686172509993329ff4d18d139821be75bcdcac0f5fe6cbc"
        );

        let root = std::env::temp_dir().join(format!(
            "styrn-legacy-promotion-intent-{}",
            uuid::Uuid::now_v7()
        ));
        std::fs::create_dir_all(&root).unwrap();
        let path = root.join("intent.json");
        let principal = crate::platform::resolve_current_worker_principal().unwrap();
        let mut file = crate::platform::create_private_file(
            &path,
            crate::platform::ManifestOwner::User,
            &principal,
        )
        .unwrap();
        use std::io::Write as _;
        file.write_all(bytes).unwrap();
        file.sync_all().unwrap();
        let identity = crate::platform::private_file_identity(&path).unwrap();
        let intent = super::ScopePromotionIntent {
            document,
            path: path.clone(),
            identity,
        };
        let before = std::fs::read(&path).unwrap();
        assert!(matches!(
            super::ScopePromotionRequestBinding::from_intent(&intent),
            Err(super::ScopePromotionError::Conflict)
        ));
        assert_eq!(std::fs::read(&path).unwrap(), before);
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    #[cfg(not(target_os = "windows"))]
    fn scope_promotion_publication_reemits_missing_completion_proof() {
        run_scope_promotion_protocol(PromotionProofCase::MissingCompletionBeforePublicationRerun);
    }

    #[test]
    #[cfg(not(target_os = "windows"))]
    fn scope_promotion_rejects_intent_changed_after_real_authorization() {
        run_scope_promotion_protocol(PromotionProofCase::AlteredIntentBeforePublication);
        run_scope_promotion_protocol(PromotionProofCase::AlteredIntentAfterAuthorization);
    }

    #[test]
    #[cfg(not(target_os = "windows"))]
    fn scope_promotion_finalization_requires_protected_authorization_and_receipt_identity() {
        run_scope_promotion_protocol(PromotionProofCase::MissingAuthorizationBeforeFinalization);
        run_scope_promotion_protocol(PromotionProofCase::SubstitutedReceiptBeforeFinalization);
    }

    #[test]
    #[cfg(not(target_os = "windows"))]
    fn scope_promotion_intent_absent_recovery_revalidates_protected_evidence() {
        run_scope_promotion_protocol(PromotionProofCase::MissingAuthorizationAfterIntentRetirement);
    }

    #[cfg(not(target_os = "windows"))]
    fn run_scope_promotion_protocol(case: PromotionProofCase) {
        let root = std::env::temp_dir().join(format!(
            "styrn-scope-promotion-e2e-{}",
            uuid::Uuid::now_v7()
        ));
        std::fs::create_dir_all(&root).unwrap();
        let root = std::fs::canonicalize(root).unwrap();
        let operator = crate::platform::resolve_current_worker_principal().unwrap();
        let selector = operator.name().to_owned();
        let (ready, target) = crate::setup::action::tests::dedicated_ready_for_test(&selector);
        let user_layout = crate::platform::worker_directory_layout_for_test(
            crate::platform::InstallationScope::User,
            operator.clone(),
            root.join("user-worker"),
            Some(root.clone()),
        );
        let system_root = root.join("system-worker");
        let (mut system_plan, system_layout) =
            crate::setup::action::dedicated_system_worker_directory_plan_for_test(
                &ready,
                system_root,
                Some(root.clone()),
            )
            .unwrap();

        let user_receipt_path = root.join("user-state/styrn/receipt.json");
        let user_receipt =
            crate::setup::receipt::ReceiptStore::new_user_for_test(&user_receipt_path);
        let user_manifest_path = root.join("user-config/styrn/machine.toml");
        let user_manifest =
            crate::manifest::MachineManifestStore::new_user_with_worker_layout_for_test(
                &user_manifest_path,
                operator.clone(),
                &user_layout,
            )
            .unwrap();
        let mut user_draft =
            crate::manifest::CurrentUserWorkerManifestCandidate::derive_with_layout_for_test(
                &native_manifest_draft(crate::platform::InstallationScope::User),
                &operator,
                &user_layout,
            )
            .unwrap()
            .into_draft();
        let mut prerequisite = vec![crate::setup::action::dedicated_account_prerequisite(
            crate::platform::DedicatedAccountSpec::new(&selector).unwrap(),
        )
        .unwrap()];
        let mut user_metadata = crate::setup::receipt::ReceiptMetadataSource::for_test([
            (
                "019cad99-54a0-7000-8000-000000000021",
                "2026-09-03T12:00:00Z",
            ),
            (
                "019cad99-54a0-7000-8000-000000000022",
                "2026-09-03T12:00:01Z",
            ),
            (
                "019cad99-54a0-7000-8000-000000000023",
                "2026-09-03T12:00:02Z",
            ),
        ]);
        let user_execution = crate::setup::action::apply_plan_with_journal(
            &mut prerequisite,
            &user_receipt,
            &mut user_metadata,
        )
        .unwrap();

        std::fs::create_dir_all(root.join("system-state")).unwrap();
        let system_receipt_path = root.join("system-state/styrn/receipt.json");
        let system_receipt =
            crate::setup::receipt::ReceiptStore::new_system_for_test_with_worker_layout(
                &system_receipt_path,
                system_layout.clone(),
            );
        let system_candidate = ready
            .manifest_candidate_with_layout_for_test(
                &native_manifest_draft(crate::platform::InstallationScope::System),
                &system_layout,
            )
            .unwrap();
        std::fs::create_dir_all(root.join("system-config")).unwrap();
        let system_manifest_path = root.join("system-config/styrn/machine.toml");
        let system_manifest =
            crate::manifest::MachineManifestStore::new_system_dedicated_with_layout_for_test(
                &system_manifest_path,
                &system_candidate,
                &system_layout,
            )
            .unwrap();
        let preparation = super::ScopePromotionPreparation::new(
            &ready,
            system_candidate,
            &system_receipt,
            &system_manifest,
        )
        .unwrap();
        let machine_id = crate::setup::pending::publish_manifest_and_begin_scope_promotion(
            &user_manifest,
            &system_manifest,
            &user_receipt,
            &mut user_draft,
            user_execution.completion(),
            &mut user_metadata,
            &preparation,
        )
        .unwrap();
        assert!(user_manifest_path.is_file());
        assert!(!system_manifest_path.exists());

        let mut system_metadata = crate::setup::receipt::ReceiptMetadataSource::for_test([
            (
                "019cad99-54a0-7000-8000-000000000031",
                "2026-09-03T12:01:00Z",
            ),
            (
                "019cad99-54a0-7000-8000-000000000032",
                "2026-09-03T12:01:01Z",
            ),
            (
                "019cad99-54a0-7000-8000-000000000033",
                "2026-09-03T12:01:02Z",
            ),
            (
                "019cad99-54a0-7000-8000-000000000034",
                "2026-09-03T12:01:03Z",
            ),
            (
                "019cad99-54a0-7000-8000-000000000035",
                "2026-09-03T12:01:04Z",
            ),
            (
                "019cad99-54a0-7000-8000-000000000036",
                "2026-09-03T12:01:05Z",
            ),
            (
                "019cad99-54a0-7000-8000-000000000037",
                "2026-09-03T12:01:06Z",
            ),
        ]);
        let request_path = root.join("user-state/styrn/authorization-request.json");
        let request = crate::setup::action::prepare_scope_promotion_authorization_request_for_test(
            &system_plan,
            request_path.clone(),
            operator.clone(),
            &user_receipt,
            preparation.intent_id,
        )
        .unwrap();
        let original_request_bytes = std::fs::read(&request_path).unwrap();
        let intent_path =
            super::scope_promotion_intent_path(&user_receipt_path, preparation.intent_id).unwrap();
        if case == PromotionProofCase::AlteredIntentBeforePublication {
            let authorized_intent = std::fs::read(&intent_path).unwrap();
            let mut altered_intent =
                super::ScopePromotionIntentDocument::from_json(&authorized_intent).unwrap();
            let mut altered_candidate =
                crate::manifest::MachineManifest::parse_toml(&altered_intent.candidate_manifest)
                    .unwrap();
            altered_candidate.name.push_str("-unauthorized");
            altered_intent.candidate_manifest = altered_candidate.to_toml().unwrap();
            altered_intent.system_manifest_sha256 =
                super::sha256_hex(altered_intent.candidate_manifest.as_bytes());
            std::fs::write(&intent_path, altered_intent.to_json().unwrap()).unwrap();
            let error = request
                .run_scope_promotion(
                    &mut system_plan,
                    &user_receipt,
                    &system_receipt,
                    &mut system_metadata,
                )
                .unwrap_err();
            assert_eq!(error.error_code(), "setup.plan_invalid");
            assert!(user_manifest_path.is_file());
            assert!(!system_manifest_path.exists());
            assert_eq!(
                std::fs::read(&intent_path).unwrap(),
                altered_intent.to_json().unwrap()
            );
            let _ = std::fs::remove_dir_all(root);
            return;
        }

        if matches!(
            case,
            PromotionProofCase::InterruptedAfterAuthorizationRecord
                | PromotionProofCase::InterruptedAfterRequestRetirement
                | PromotionProofCase::HostileResumeEvidence
        ) {
            let interruption = if case == PromotionProofCase::InterruptedAfterAuthorizationRecord {
                crate::setup::action::ScopePromotionChildInterruption::AfterAuthorizationRecord
            } else {
                crate::setup::action::ScopePromotionChildInterruption::AfterRequestRetirement
            };
            crate::setup::action::set_scope_promotion_child_interruption_for_test(Some(
                interruption,
            ));
            let error = request
                .run_scope_promotion(
                    &mut system_plan,
                    &user_receipt,
                    &system_receipt,
                    &mut system_metadata,
                )
                .unwrap_err();
            assert_eq!(error.error_code(), "setup.plan_invalid");
            assert!(user_manifest_path.is_file());
            assert!(!system_manifest_path.exists());
            assert!(system_receipt_path
                .parent()
                .unwrap()
                .join(format!(
                    ".setup-request-{}.consumed",
                    preparation.authorization_request_id
                ))
                .is_file());
            if case == PromotionProofCase::InterruptedAfterAuthorizationRecord {
                assert!(request_path.is_file());
            } else {
                assert!(!request_path.exists());
            }
        } else if case == PromotionProofCase::InterruptedDuringSystemJournaling {
            let mut interrupted_metadata =
                crate::setup::receipt::ReceiptMetadataSource::for_test([(
                    "019cad99-54a0-7000-8000-000000000029",
                    "2026-09-03T12:00:59Z",
                )]);
            let error = request
                .run_scope_promotion(
                    &mut system_plan,
                    &user_receipt,
                    &system_receipt,
                    &mut interrupted_metadata,
                )
                .unwrap_err();
            assert_eq!(error.exit_code(), 13);
            let interrupted = system_receipt.read_snapshot().unwrap();
            assert_eq!(interrupted.entry_count(), 1);
            assert!(user_manifest_path.is_file());
            assert!(!system_manifest_path.exists());
            assert!(!request_path.exists());
        }

        let authorization_marker = system_receipt_path.parent().unwrap().join(format!(
            ".setup-request-{}.consumed",
            preparation.authorization_request_id
        ));
        if case == PromotionProofCase::HostileResumeEvidence {
            use std::io::Write as _;

            let intent_bytes = std::fs::read(&intent_path).unwrap();
            let marker_bytes = std::fs::read(&authorization_marker).unwrap();

            let mut different_request =
                serde_json::from_slice::<serde_json::Value>(&original_request_bytes).unwrap();
            different_request["issued_at"] = serde_json::json!("2026-09-03T12:00:29Z");
            different_request["expires_at"] = serde_json::json!("2026-09-03T12:05:29Z");
            let different_request_bytes = serde_json::to_vec(&different_request).unwrap();
            let different_request_digest = super::sha256_hex(&different_request_bytes);
            let mut different_request_file = crate::platform::create_private_file(
                &request_path,
                crate::platform::ManifestOwner::User,
                &operator,
            )
            .unwrap();
            different_request_file
                .write_all(&different_request_bytes)
                .unwrap();
            different_request_file.sync_all().unwrap();
            let error = request
                .run_scope_promotion_with_digest_for_test(
                    &different_request_digest,
                    &mut system_plan,
                    &user_receipt,
                    &system_receipt,
                    &mut system_metadata,
                )
                .unwrap_err();
            assert_eq!(error.error_code(), "setup.plan_invalid");
            assert_eq!(
                std::fs::read(&request_path).unwrap(),
                different_request_bytes
            );
            std::fs::remove_file(&request_path).unwrap();

            let error = request
                .run_scope_promotion_with_digest_for_test(
                    &"0".repeat(64),
                    &mut system_plan,
                    &user_receipt,
                    &system_receipt,
                    &mut system_metadata,
                )
                .unwrap_err();
            assert_eq!(error.error_code(), "setup.plan_invalid");

            let removed_action = system_plan.pop().unwrap();
            let error = request
                .run_scope_promotion(
                    &mut system_plan,
                    &user_receipt,
                    &system_receipt,
                    &mut system_metadata,
                )
                .unwrap_err();
            assert_eq!(error.error_code(), "setup.plan_invalid");
            system_plan.push(removed_action);

            let mut altered_intent =
                super::ScopePromotionIntentDocument::from_json(&intent_bytes).unwrap();
            let mut altered_candidate =
                crate::manifest::MachineManifest::parse_toml(&altered_intent.candidate_manifest)
                    .unwrap();
            altered_candidate.name.push_str("-resume-substitution");
            altered_intent.candidate_manifest = altered_candidate.to_toml().unwrap();
            altered_intent.system_manifest_sha256 =
                super::sha256_hex(altered_intent.candidate_manifest.as_bytes());
            std::fs::write(&intent_path, altered_intent.to_json().unwrap()).unwrap();
            let error = request
                .run_scope_promotion(
                    &mut system_plan,
                    &user_receipt,
                    &system_receipt,
                    &mut system_metadata,
                )
                .unwrap_err();
            assert_eq!(error.error_code(), "setup.plan_invalid");
            std::fs::write(&intent_path, &intent_bytes).unwrap();

            let displaced_marker = authorization_marker.with_extension("consumed.original");
            std::fs::rename(&authorization_marker, &displaced_marker).unwrap();
            std::fs::write(&authorization_marker, &marker_bytes).unwrap();
            use std::os::unix::fs::PermissionsExt as _;
            std::fs::set_permissions(
                &authorization_marker,
                std::fs::Permissions::from_mode(0o600),
            )
            .unwrap();
            let error = request
                .run_scope_promotion(
                    &mut system_plan,
                    &user_receipt,
                    &system_receipt,
                    &mut system_metadata,
                )
                .unwrap_err();
            assert_eq!(error.error_code(), "setup.plan_invalid");
            std::fs::remove_file(&authorization_marker).unwrap();
            std::fs::rename(&displaced_marker, &authorization_marker).unwrap();

            assert!(user_manifest_path.is_file());
            assert!(!system_manifest_path.exists());
            assert!(intent_path.is_file());
            assert!(!request_path.exists());
            assert_eq!(std::fs::read(&intent_path).unwrap(), intent_bytes);
            assert_eq!(std::fs::read(&authorization_marker).unwrap(), marker_bytes);
        }

        let system_execution = request
            .run_scope_promotion(
                &mut system_plan,
                &user_receipt,
                &system_receipt,
                &mut system_metadata,
            )
            .unwrap();
        if case == PromotionProofCase::AlteredIntentAfterAuthorization {
            let authorized_intent = std::fs::read(&intent_path).unwrap();
            let mut altered_intent =
                super::ScopePromotionIntentDocument::from_json(&authorized_intent).unwrap();
            let mut altered_candidate =
                crate::manifest::MachineManifest::parse_toml(&altered_intent.candidate_manifest)
                    .unwrap();
            altered_candidate.name.push_str("-after-reservation");
            altered_intent.candidate_manifest = altered_candidate.to_toml().unwrap();
            altered_intent.system_manifest_sha256 =
                super::sha256_hex(altered_intent.candidate_manifest.as_bytes());
            std::fs::write(&intent_path, altered_intent.to_json().unwrap()).unwrap();
            let error = super::publish_scope_promotion_system_manifest(
                &user_receipt,
                preparation.intent_id,
                &system_receipt,
                &system_manifest,
                system_execution.completion(),
                &mut system_metadata,
            )
            .unwrap_err();
            assert_eq!(error.error_code(), "setup.receipt_conflict");
            assert!(user_manifest_path.is_file());
            assert!(!system_manifest_path.exists());
            assert!(system_receipt_path
                .parent()
                .unwrap()
                .join(format!(
                    ".setup-request-{}.consumed",
                    preparation.authorization_request_id
                ))
                .is_file());
            let _ = std::fs::remove_dir_all(root);
            return;
        }
        super::publish_scope_promotion_system_manifest(
            &user_receipt,
            preparation.intent_id,
            &system_receipt,
            &system_manifest,
            system_execution.completion(),
            &mut system_metadata,
        )
        .unwrap();
        assert!(user_manifest_path.is_file());
        assert!(system_manifest_path.is_file());
        assert_eq!(
            user_manifest.read().unwrap().manifest.machine_id,
            machine_id
        );
        assert_eq!(
            system_manifest.read().unwrap().manifest.machine_id,
            machine_id
        );

        if case == PromotionProofCase::HostileResumeEvidence {
            let error = request
                .run_scope_promotion(
                    &mut system_plan,
                    &user_receipt,
                    &system_receipt,
                    &mut system_metadata,
                )
                .unwrap_err();
            assert_eq!(error.error_code(), "setup.plan_invalid");
            assert!(user_manifest_path.is_file());
            assert!(system_manifest_path.is_file());
            assert!(intent_path.is_file());
            assert!(authorization_marker.is_file());
        }

        if case == PromotionProofCase::MissingCompletionBeforePublicationRerun {
            let completion_path =
                super::scope_promotion_completion_path(&system_receipt_path, preparation.intent_id)
                    .unwrap();
            std::fs::remove_file(&completion_path).unwrap();
            super::publish_scope_promotion_system_manifest(
                &user_receipt,
                preparation.intent_id,
                &system_receipt,
                &system_manifest,
                system_execution.completion(),
                &mut system_metadata,
            )
            .unwrap();
            assert!(completion_path.is_file());
        }

        if case == PromotionProofCase::MissingAuthorizationBeforeFinalization {
            let displaced = authorization_marker.with_extension("consumed.displaced");
            std::fs::rename(&authorization_marker, &displaced).unwrap();
            let error = match super::finalize_scope_promotion(
                &user_receipt,
                &user_manifest,
                &system_receipt,
                &system_manifest,
                preparation.intent_id,
                &mut user_metadata,
            ) {
                Err(error) => error,
                Ok(_) => panic!("missing authorization unexpectedly finalized promotion"),
            };
            assert_eq!(error.error_code(), "setup.receipt_conflict");
            assert!(user_manifest_path.is_file());
            assert!(intent_path.is_file());
            assert!(displaced.is_file());
            let receipt: serde_json::Value =
                serde_json::from_slice(&std::fs::read(&user_receipt_path).unwrap()).unwrap();
            assert!(receipt["entries"]
                .as_array()
                .unwrap()
                .iter()
                .all(|entry| { entry["action"]["type"] != "scope_promotion" }));
            let _ = std::fs::remove_dir_all(root);
            return;
        }
        if case == PromotionProofCase::SubstitutedReceiptBeforeFinalization {
            let displaced = system_receipt_path.with_extension("json.displaced");
            let receipt_bytes = std::fs::read(&system_receipt_path).unwrap();
            std::fs::rename(&system_receipt_path, &displaced).unwrap();
            std::fs::write(&system_receipt_path, &receipt_bytes).unwrap();
            use std::os::unix::fs::PermissionsExt as _;
            std::fs::set_permissions(&system_receipt_path, std::fs::Permissions::from_mode(0o600))
                .unwrap();
            let error = match super::finalize_scope_promotion(
                &user_receipt,
                &user_manifest,
                &system_receipt,
                &system_manifest,
                preparation.intent_id,
                &mut user_metadata,
            ) {
                Err(error) => error,
                Ok(_) => panic!("substituted receipt unexpectedly finalized promotion"),
            };
            assert_eq!(error.error_code(), "setup.receipt_conflict");
            assert!(user_manifest_path.is_file());
            assert!(intent_path.is_file());
            assert_eq!(std::fs::read(&system_receipt_path).unwrap(), receipt_bytes);
            assert!(displaced.is_file());
            let _ = std::fs::remove_dir_all(root);
            return;
        }

        let exact_user_manifest = std::fs::read(&user_manifest_path).unwrap();
        let exact_system_manifest = std::fs::read(&system_manifest_path).unwrap();
        let mut third_system = crate::manifest::MachineManifest::parse_toml(
            std::str::from_utf8(&exact_system_manifest).unwrap(),
        )
        .unwrap();
        third_system.name.push_str("-unexpected");
        std::fs::write(&system_manifest_path, third_system.to_toml().unwrap()).unwrap();
        assert!(super::finalize_scope_promotion(
            &user_receipt,
            &user_manifest,
            &system_receipt,
            &system_manifest,
            preparation.intent_id,
            &mut user_metadata,
        )
        .is_err());
        assert!(user_manifest_path.is_file());
        assert!(system_manifest_path.is_file());
        assert!(
            super::scope_promotion_intent_path(&user_receipt_path, preparation.intent_id)
                .unwrap()
                .is_file()
        );
        std::fs::write(&system_manifest_path, &exact_system_manifest).unwrap();

        let mut third_user = crate::manifest::MachineManifest::parse_toml(
            std::str::from_utf8(&exact_user_manifest).unwrap(),
        )
        .unwrap();
        third_user.machine_id = uuid::Uuid::now_v7();
        std::fs::write(&user_manifest_path, third_user.to_toml().unwrap()).unwrap();
        assert!(super::finalize_scope_promotion(
            &user_receipt,
            &user_manifest,
            &system_receipt,
            &system_manifest,
            preparation.intent_id,
            &mut user_metadata,
        )
        .is_err());
        assert!(user_manifest_path.is_file());
        assert!(system_manifest_path.is_file());
        assert!(
            super::scope_promotion_intent_path(&user_receipt_path, preparation.intent_id)
                .unwrap()
                .is_file()
        );
        std::fs::write(&user_manifest_path, &exact_user_manifest).unwrap();

        use std::os::unix::fs::PermissionsExt as _;
        let displaced_user_manifest = user_manifest_path.with_extension("promotion-source");
        std::fs::rename(&user_manifest_path, &displaced_user_manifest).unwrap();
        std::fs::write(&user_manifest_path, &exact_user_manifest).unwrap();
        std::fs::set_permissions(&user_manifest_path, std::fs::Permissions::from_mode(0o600))
            .unwrap();
        assert!(super::finalize_scope_promotion(
            &user_receipt,
            &user_manifest,
            &system_receipt,
            &system_manifest,
            preparation.intent_id,
            &mut user_metadata,
        )
        .is_err());
        assert!(user_manifest_path.is_file());
        assert!(system_manifest_path.is_file());
        assert!(
            super::scope_promotion_intent_path(&user_receipt_path, preparation.intent_id)
                .unwrap()
                .is_file()
        );
        std::fs::remove_file(&user_manifest_path).unwrap();
        std::fs::rename(&displaced_user_manifest, &user_manifest_path).unwrap();

        super::set_interrupt_after_checkpoint_for_test(true);
        assert!(super::finalize_scope_promotion(
            &user_receipt,
            &user_manifest,
            &system_receipt,
            &system_manifest,
            preparation.intent_id,
            &mut user_metadata,
        )
        .is_err());
        super::set_interrupt_after_checkpoint_for_test(false);
        assert!(user_manifest_path.is_file());
        assert!(system_manifest_path.is_file());
        assert!(
            super::scope_promotion_intent_path(&user_receipt_path, preparation.intent_id)
                .unwrap()
                .is_file()
        );
        super::set_interrupt_after_user_retirement_for_test(true);
        assert!(super::finalize_scope_promotion(
            &user_receipt,
            &user_manifest,
            &system_receipt,
            &system_manifest,
            preparation.intent_id,
            &mut user_metadata,
        )
        .is_err());
        super::set_interrupt_after_user_retirement_for_test(false);
        assert!(!user_manifest_path.exists());
        assert!(system_manifest_path.is_file());
        assert!(
            super::scope_promotion_intent_path(&user_receipt_path, preparation.intent_id)
                .unwrap()
                .is_file()
        );
        let evidence = super::finalize_scope_promotion(
            &user_receipt,
            &user_manifest,
            &system_receipt,
            &system_manifest,
            preparation.intent_id,
            &mut user_metadata,
        )
        .unwrap();
        let observed = crate::platform::inspect_established_dedicated_account_for_test(
            crate::platform::DedicatedAccountSpec::new(&selector).unwrap(),
            &evidence,
            crate::platform::NativeDedicatedAccountObservation::PresentHealthy(target.clone()),
        );
        assert!(matches!(
            observed,
            crate::platform::DedicatedAccountObservation::PresentHealthy(_)
        ));
        let receipt: serde_json::Value =
            serde_json::from_slice(&std::fs::read(&user_receipt_path).unwrap()).unwrap();
        assert_eq!(
            receipt["entries"]
                .as_array()
                .unwrap()
                .iter()
                .filter(|entry| entry["action"]["type"] == "scope_promotion")
                .count(),
            1
        );
        assert!(
            !super::scope_promotion_intent_path(&user_receipt_path, preparation.intent_id)
                .unwrap()
                .exists()
        );
        if case == PromotionProofCase::MissingAuthorizationAfterIntentRetirement {
            let displaced = authorization_marker.with_extension("consumed.displaced");
            std::fs::rename(&authorization_marker, &displaced).unwrap();
            let error = match super::finalize_scope_promotion(
                &user_receipt,
                &user_manifest,
                &system_receipt,
                &system_manifest,
                preparation.intent_id,
                &mut user_metadata,
            ) {
                Err(error) => error,
                Ok(_) => panic!("missing protected evidence unexpectedly recovered promotion"),
            };
            assert_eq!(error.error_code(), "setup.receipt_conflict");
            assert!(!user_manifest_path.exists());
            assert!(system_manifest_path.is_file());
            assert!(!intent_path.exists());
            assert!(displaced.is_file());
            let receipt: serde_json::Value =
                serde_json::from_slice(&std::fs::read(&user_receipt_path).unwrap()).unwrap();
            assert_eq!(
                receipt["entries"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .filter(|entry| entry["action"]["type"] == "scope_promotion")
                    .count(),
                1
            );
            let _ = std::fs::remove_dir_all(root);
            return;
        }
        let recovered = super::finalize_scope_promotion(
            &user_receipt,
            &user_manifest,
            &system_receipt,
            &system_manifest,
            preparation.intent_id,
            &mut user_metadata,
        )
        .unwrap();
        let recovered_observation = crate::platform::inspect_established_dedicated_account_for_test(
            crate::platform::DedicatedAccountSpec::new(&selector).unwrap(),
            &recovered,
            crate::platform::NativeDedicatedAccountObservation::PresentHealthy(target),
        );
        assert!(matches!(
            recovered_observation,
            crate::platform::DedicatedAccountObservation::PresentHealthy(_)
        ));
        let _ = std::fs::remove_dir_all(root);
    }
}
