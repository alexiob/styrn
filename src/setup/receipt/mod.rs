//! Schema-versioned setup receipt journal.

use chrono::{DateTime, FixedOffset, SecondsFormat};
use serde::{Deserialize, Serialize};
#[cfg(test)]
use std::collections::VecDeque;
use std::{
    collections::HashSet,
    fs,
    io::{Read, Write},
    path::{Component, Path, PathBuf},
};
use thiserror::Error;
use uuid::Uuid;

const SCHEMA_VERSION: u32 = 1;

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub(in crate::setup) struct ReceiptDocument {
    schema_version: u32,
    installation_scope: InstallationScope,
    entries: Vec<ReceiptEntry>,
}

impl ReceiptDocument {
    fn empty(installation_scope: InstallationScope) -> Self {
        Self {
            schema_version: SCHEMA_VERSION,
            installation_scope,
            entries: Vec::new(),
        }
    }

    fn from_json(input: &[u8]) -> Result<Self, ReceiptError> {
        let wire = serde_json::from_slice::<ReceiptDocumentWire>(input).map_err(|error| {
            ReceiptError::Parse {
                line: error.line(),
                column: error.column(),
            }
        })?;
        let document = Self {
            schema_version: wire.schema_version,
            installation_scope: wire
                .installation_scope
                .ok_or(ReceiptError::MissingInstallationScope)?,
            entries: wire.entries,
        };
        document.validate()?;
        Ok(document)
    }

    pub(crate) fn to_json(&self) -> Result<Vec<u8>, ReceiptError> {
        self.validate()?;
        let mut bytes = serde_json::to_vec_pretty(self).map_err(|_| ReceiptError::Serialize)?;
        bytes.push(b'\n');
        Ok(bytes)
    }

    fn schema_version(&self) -> u32 {
        self.schema_version
    }

    pub(in crate::setup) fn installation_scope(&self) -> InstallationScope {
        self.installation_scope
    }

    fn entries(&self) -> &[ReceiptEntry] {
        &self.entries
    }

    pub(in crate::setup) fn entry_count(&self) -> usize {
        self.entries.len()
    }

    pub(in crate::setup) fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    fn validate(&self) -> Result<(), ReceiptError> {
        if self.schema_version != SCHEMA_VERSION {
            return Err(ReceiptError::UnknownSchemaVersion);
        }
        let mut ids = HashSet::with_capacity(self.entries.len());
        for entry in &self.entries {
            entry.validate()?;
            if self.installation_scope == InstallationScope::User
                && entry.privilege_used != ReceiptPrivilege::None
            {
                return Err(ReceiptError::PrivilegeOutsideScope);
            }
            if !ids.insert(entry.entry_id.as_str()) {
                return Err(ReceiptError::DuplicateEntryId);
            }
        }
        Ok(())
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ReceiptDocumentWire {
    schema_version: u32,
    installation_scope: Option<InstallationScope>,
    entries: Vec<ReceiptEntry>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum InstallationScope {
    User,
    System,
}

#[derive(Clone, Debug)]
pub(crate) struct ReceiptStore {
    scope: InstallationScope,
    path: PathBuf,
    trusted_root: PathBuf,
    owner: crate::platform::ManifestOwner,
    worker: Option<WorkerPrincipal>,
    #[cfg(test)]
    interruption: Option<PublicationInterruption>,
    #[cfg(test)]
    interrupt_after_prepare: bool,
    #[cfg(test)]
    intent_read_interruption: Option<IntentReadInterruption>,
}

pub(crate) struct ReceiptApplySession<'a> {
    store: &'a ReceiptStore,
    _lock: fs::File,
}

#[derive(Clone)]
pub(crate) struct ReceiptIntent {
    entry: ReceiptEntry,
    path: PathBuf,
    phase: ReceiptIntentPhase,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(in crate::setup) enum ReceiptIntentPhase {
    Prepared,
    Succeeded,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ReceiptIntentDocument {
    schema_version: u32,
    installation_scope: InstallationScope,
    phase: ReceiptIntentPhase,
    entry: ReceiptEntry,
}

impl ReceiptIntentDocument {
    fn validate(&self) -> Result<(), ReceiptError> {
        if self.schema_version != SCHEMA_VERSION {
            return Err(ReceiptError::UnknownSchemaVersion);
        }
        if self.installation_scope == InstallationScope::User
            && self.entry.privilege_used != ReceiptPrivilege::None
        {
            return Err(ReceiptError::PrivilegeOutsideScope);
        }
        self.entry.validate()
    }

    fn to_json(&self) -> Result<Vec<u8>, ReceiptError> {
        self.validate()?;
        let mut bytes = serde_json::to_vec_pretty(self).map_err(|_| ReceiptError::Serialize)?;
        bytes.push(b'\n');
        Ok(bytes)
    }

    fn from_json(input: &[u8]) -> Result<Self, ReceiptError> {
        let document =
            serde_json::from_slice::<Self>(input).map_err(|error| ReceiptError::Parse {
                line: error.line(),
                column: error.column(),
            })?;
        document.validate()?;
        Ok(document)
    }
}

#[cfg(test)]
#[derive(Clone, Copy, Debug)]
enum PublicationInterruption {
    BeforeReplace,
    AfterReplace,
}

#[cfg(test)]
#[derive(Clone, Debug)]
enum IntentReadInterruption {
    #[cfg(unix)]
    Symlink(PathBuf),
    #[cfg(unix)]
    Fifo,
    #[cfg(windows)]
    Reparse(PathBuf),
    Inode,
}

#[derive(Clone, Debug)]
struct WorkerPrincipal(String);

impl WorkerPrincipal {
    fn parse(value: &str) -> Result<Self, ReceiptStoreError> {
        if value.is_empty()
            || value.len() > 256
            || value.trim() != value
            || value.chars().any(char::is_control)
        {
            return Err(ReceiptStoreError::InvalidWorkerPrincipal);
        }
        Ok(Self(value.to_owned()))
    }

    fn as_str(&self) -> &str {
        &self.0
    }
}

impl ReceiptStore {
    fn new_system(path: impl Into<PathBuf>, worker: &str) -> Result<Self, ReceiptStoreError> {
        let path = path.into();
        let trusted_root = path.parent().map(Path::to_path_buf).unwrap_or_default();
        Ok(Self {
            scope: InstallationScope::System,
            path,
            trusted_root,
            owner: crate::platform::ManifestOwner::System,
            worker: Some(WorkerPrincipal::parse(worker)?),
            #[cfg(test)]
            interruption: None,
            #[cfg(test)]
            interrupt_after_prepare: false,
            #[cfg(test)]
            intent_read_interruption: None,
        })
    }

    #[cfg(test)]
    pub(in crate::setup) fn new_for_test(path: impl Into<PathBuf>) -> Self {
        let path = path.into();
        let trusted_root = path.parent().map(Path::to_path_buf).unwrap_or_default();
        Self {
            scope: InstallationScope::System,
            path,
            trusted_root,
            owner: crate::platform::ManifestOwner::CurrentProcess,
            worker: Some(WorkerPrincipal("fixture-worker".to_owned())),
            interruption: None,
            interrupt_after_prepare: false,
            intent_read_interruption: None,
        }
    }

    #[cfg(test)]
    pub(in crate::setup) fn new_user_for_test(path: impl Into<PathBuf>) -> Self {
        let path = path.into();
        let trusted_root = path
            .parent()
            .and_then(Path::parent)
            .map(Path::to_path_buf)
            .unwrap_or_default();
        Self {
            scope: InstallationScope::User,
            path,
            trusted_root,
            owner: crate::platform::ManifestOwner::User,
            worker: None,
            interruption: None,
            interrupt_after_prepare: false,
            intent_read_interruption: None,
        }
    }

    #[cfg(test)]
    fn new_for_test_with_interruption(
        path: impl Into<PathBuf>,
        interruption: PublicationInterruption,
    ) -> Self {
        let mut store = Self::new_for_test(path);
        store.interruption = Some(interruption);
        store
    }

    #[cfg(test)]
    pub(in crate::setup) fn new_for_test_failing_before_replace(path: impl Into<PathBuf>) -> Self {
        Self::new_for_test_with_interruption(path, PublicationInterruption::BeforeReplace)
    }

    #[cfg(test)]
    pub(in crate::setup) fn new_user_for_test_failing_before_replace(
        path: impl Into<PathBuf>,
    ) -> Self {
        let mut store = Self::new_user_for_test(path);
        store.interruption = Some(PublicationInterruption::BeforeReplace);
        store
    }

    #[cfg(test)]
    pub(in crate::setup) fn new_for_test_failing_after_prepare(path: impl Into<PathBuf>) -> Self {
        let mut store = Self::new_for_test(path);
        store.interrupt_after_prepare = true;
        store
    }

    #[cfg(all(test, unix))]
    pub(in crate::setup) fn new_for_test_swapping_intent_with_symlink(
        path: impl Into<PathBuf>,
        target: PathBuf,
    ) -> Self {
        let mut store = Self::new_for_test(path);
        store.intent_read_interruption = Some(IntentReadInterruption::Symlink(target));
        store
    }

    #[cfg(all(test, unix))]
    pub(in crate::setup) fn new_for_test_swapping_intent_with_fifo(
        path: impl Into<PathBuf>,
    ) -> Self {
        let mut store = Self::new_for_test(path);
        store.intent_read_interruption = Some(IntentReadInterruption::Fifo);
        store
    }

    #[cfg(test)]
    pub(in crate::setup) fn new_for_test_swapping_intent_inode(path: impl Into<PathBuf>) -> Self {
        let mut store = Self::new_for_test(path);
        store.intent_read_interruption = Some(IntentReadInterruption::Inode);
        store
    }

    #[cfg(all(test, windows))]
    pub(in crate::setup) fn new_for_test_swapping_intent_with_reparse(
        path: impl Into<PathBuf>,
        target: PathBuf,
    ) -> Self {
        let mut store = Self::new_for_test(path);
        store.intent_read_interruption = Some(IntentReadInterruption::Reparse(target));
        store
    }

    /// Returns a lock-free, complete old-or-new snapshot for status and doctor.
    /// Receipt-driven mutation must use [`ReceiptStore::begin_apply`] instead.
    pub(in crate::setup) fn read_snapshot(&self) -> Result<ReceiptDocument, ReceiptStoreError> {
        let destination = self.validate_destination_policy()?;
        match fs::symlink_metadata(destination) {
            Ok(_) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                // With no destination directory there is no lock namespace
                // to join and therefore no existing receipt to observe.
                return Ok(ReceiptDocument::empty(self.scope));
            }
            Err(error) => return Err(ReceiptStoreError::Read(error)),
        }
        self.verify_directory(destination)?;
        let mut receipt = match crate::platform::open_verified_manifest_file_for_read(
            &self.path,
            self.owner,
            self.worker_name(),
            &self.trusted_root,
        ) {
            Ok(file) => file,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                return Ok(ReceiptDocument::empty(self.scope));
            }
            Err(error) => return Err(ReceiptStoreError::Security(error)),
        };
        let lock_path = self.lock_path();
        match fs::symlink_metadata(&lock_path) {
            Ok(_) => crate::platform::verify_manifest_file_target(&lock_path)
                .map_err(ReceiptStoreError::Security)?,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                return Err(ReceiptStoreError::IntentConflict);
            }
            Err(error) => return Err(ReceiptStoreError::Read(error)),
        }
        let mut input = Vec::new();
        receipt
            .read_to_end(&mut input)
            .map_err(ReceiptStoreError::Read)?;
        self.parse_for_scope(&input)
    }

    pub(in crate::setup) fn begin_apply<'a>(
        &'a self,
        _authority: &crate::setup::action::JournalAuthority,
    ) -> Result<ReceiptApplySession<'a>, ReceiptStoreError> {
        let destination = self.validate_destination_policy()?.to_path_buf();
        self.prepare_destination(&destination)?;
        self.preflight_writer_state()?;
        let lock = crate::platform::open_manifest_lock(&self.lock_path(), self.owner)
            .map_err(ReceiptStoreError::Write)?;
        lock.lock().map_err(ReceiptStoreError::Write)?;
        self.read_locked()?;
        Ok(ReceiptApplySession {
            store: self,
            _lock: lock,
        })
    }

    pub(in crate::setup) fn validate_action_privilege(
        &self,
        privilege: crate::setup::action::Privilege,
    ) -> Result<(), ReceiptStoreError> {
        if self.scope == InstallationScope::User
            && privilege != crate::setup::action::Privilege::None
        {
            Err(ReceiptError::PrivilegeOutsideScope.into())
        } else {
            Ok(())
        }
    }

    #[cfg(test)]
    fn append_entry(&self, entry: ReceiptEntry) -> Result<(), ReceiptStoreError> {
        entry.validate()?;
        if entry.status != ReceiptStatus::Applied {
            return Err(ReceiptStoreError::NonAppliedAppend);
        }
        let destination = self.validate_destination_policy()?.to_path_buf();
        self.prepare_destination(&destination)?;
        self.preflight_writer_state()?;
        let lock = crate::platform::open_manifest_lock(&self.lock_path(), self.owner)
            .map_err(ReceiptStoreError::Write)?;
        lock.lock().map_err(ReceiptStoreError::Write)?;

        let existing = self.read_locked()?;
        let mut candidate = existing.clone();
        candidate.entries.push(entry);
        validate_append_candidate(&existing, &candidate)?;
        self.write_document(&candidate)
    }

    fn read_locked(&self) -> Result<ReceiptDocument, ReceiptStoreError> {
        let mut file = match crate::platform::open_verified_manifest_file_for_read(
            &self.path,
            self.owner,
            self.worker_name(),
            &self.trusted_root,
        ) {
            Ok(file) => file,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                return Ok(ReceiptDocument::empty(self.scope));
            }
            Err(error) => return Err(ReceiptStoreError::Security(error)),
        };
        let mut input = Vec::new();
        file.read_to_end(&mut input)
            .map_err(ReceiptStoreError::Read)?;
        self.parse_for_scope(&input)
    }

    fn preflight_existing_receipt(&self) -> Result<bool, ReceiptStoreError> {
        match fs::symlink_metadata(&self.path) {
            Ok(_) => {
                crate::platform::verify_manifest_file_target(&self.path)
                    .map_err(ReceiptStoreError::Security)?;
                self.verify_security()?;
                Ok(true)
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
            Err(error) => Err(ReceiptStoreError::Read(error)),
        }
    }

    fn preflight_writer_state(&self) -> Result<(), ReceiptStoreError> {
        let receipt_exists = self.preflight_existing_receipt()?;
        if receipt_exists {
            match fs::symlink_metadata(self.lock_path()) {
                Ok(_) => {}
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                    return Err(ReceiptStoreError::IntentConflict);
                }
                Err(error) => return Err(ReceiptStoreError::Read(error)),
            }
        }
        Ok(())
    }

    fn write_document(&self, document: &ReceiptDocument) -> Result<(), ReceiptStoreError> {
        let serialized = document.to_json()?;
        let destination = self
            .path
            .parent()
            .ok_or(ReceiptStoreError::InvalidDestination)?;
        let temporary = destination.join(format!(".receipt.json.{}.tmp", Uuid::now_v7()));
        let result = (|| {
            let mut file = crate::platform::create_private_file(&temporary, self.owner)
                .map_err(ReceiptStoreError::Write)?;
            file.write_all(&serialized)
                .map_err(ReceiptStoreError::Write)?;
            file.flush().map_err(ReceiptStoreError::Write)?;
            file.sync_all().map_err(ReceiptStoreError::Write)?;
            crate::platform::harden_manifest_file(&temporary, self.owner, self.worker_name())
                .map_err(ReceiptStoreError::Write)?;
            self.inject_publication_interruption(PublicationInterruptionPoint::BeforeReplace)?;
            crate::platform::replace_file(&temporary, &self.path)
                .map_err(ReceiptStoreError::Write)?;
            self.inject_publication_interruption(PublicationInterruptionPoint::AfterReplace)?;
            self.verify_security().map_err(|error| match error {
                ReceiptStoreError::Security(error) => ReceiptStoreError::PostReplaceSecurity(error),
                other => other,
            })?;
            crate::platform::sync_parent_directory(destination).map_err(ReceiptStoreError::Write)
        })();
        if result.is_err() {
            let _ = fs::remove_file(&temporary);
        }
        result
    }

    fn inject_publication_interruption(
        &self,
        _point: PublicationInterruptionPoint,
    ) -> Result<(), ReceiptStoreError> {
        #[cfg(test)]
        {
            let interrupted = matches!(
                (self.interruption, _point),
                (
                    Some(PublicationInterruption::BeforeReplace),
                    PublicationInterruptionPoint::BeforeReplace
                ) | (
                    Some(PublicationInterruption::AfterReplace),
                    PublicationInterruptionPoint::AfterReplace
                )
            );
            if interrupted {
                return Err(ReceiptStoreError::Write(std::io::Error::new(
                    std::io::ErrorKind::Interrupted,
                    "injected receipt publication interruption",
                )));
            }
        }
        Ok(())
    }

    fn prepare_destination(&self, destination: &Path) -> Result<(), ReceiptStoreError> {
        if self.scope == InstallationScope::User {
            self.prepare_user_trusted_root()?;
        }
        match fs::symlink_metadata(destination) {
            Ok(_) => self.verify_directory(destination),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                self.create_and_publish_directory(destination)
            }
            Err(error) => Err(ReceiptStoreError::Write(error)),
        }
    }

    fn prepare_user_trusted_root(&self) -> Result<(), ReceiptStoreError> {
        let mut missing = Vec::new();
        let mut current = self.trusted_root.as_path();
        loop {
            match fs::symlink_metadata(current) {
                Ok(_) => {
                    crate::platform::verify_manifest_ancestors(
                        current,
                        self.owner,
                        self.worker_name(),
                        current,
                    )
                    .map_err(ReceiptStoreError::Security)?;
                    break;
                }
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                    missing.push(current.to_path_buf());
                    current = current
                        .parent()
                        .ok_or(ReceiptStoreError::InvalidDestination)?;
                }
                Err(error) => return Err(ReceiptStoreError::Read(error)),
            }
        }

        for directory in missing.into_iter().rev() {
            let parent = directory
                .parent()
                .ok_or(ReceiptStoreError::InvalidDestination)?;
            match crate::platform::create_private_manifest_staging_directory(&directory, self.owner)
            {
                Ok(_) => {
                    crate::platform::harden_manifest_directory(
                        &directory,
                        self.owner,
                        self.worker_name(),
                    )
                    .map_err(ReceiptStoreError::Write)?;
                    crate::platform::sync_parent_directory(parent)
                        .map_err(ReceiptStoreError::Write)?;
                }
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
                    crate::platform::verify_manifest_ancestors(
                        &directory,
                        self.owner,
                        self.worker_name(),
                        &directory,
                    )
                    .map_err(ReceiptStoreError::Security)?;
                }
                Err(error) => return Err(ReceiptStoreError::Write(error)),
            }
        }
        Ok(())
    }

    fn create_and_publish_directory(&self, destination: &Path) -> Result<(), ReceiptStoreError> {
        let parent = destination
            .parent()
            .ok_or(ReceiptStoreError::InvalidDestination)?;
        match self.owner {
            crate::platform::ManifestOwner::System => {
                crate::platform::verify_manifest_parent_chain(
                    parent,
                    self.owner,
                    self.worker_name(),
                )
                .map_err(ReceiptStoreError::Security)?;
            }
            crate::platform::ManifestOwner::User => {
                crate::platform::verify_manifest_ancestors(
                    parent,
                    self.owner,
                    self.worker_name(),
                    &self.trusted_root,
                )
                .map_err(ReceiptStoreError::Security)?;
            }
            #[cfg(test)]
            crate::platform::ManifestOwner::CurrentProcess => {
                crate::platform::verify_manifest_ancestors(
                    parent,
                    self.owner,
                    self.worker_name(),
                    parent,
                )
                .map_err(ReceiptStoreError::Security)?;
            }
            #[cfg(test)]
            crate::platform::ManifestOwner::CurrentProcessWorker => {
                crate::platform::verify_manifest_parent_chain(
                    parent,
                    self.owner,
                    self.worker_name(),
                )
                .map_err(ReceiptStoreError::Security)?;
            }
        }
        let staging_path = parent.join(format!(".styrn.{}.tmp", Uuid::now_v7()));
        let staging =
            crate::platform::create_private_manifest_staging_directory(&staging_path, self.owner)
                .map_err(ReceiptStoreError::Write)?;
        let result = (|| {
            crate::platform::harden_manifest_directory(
                staging.path(),
                self.owner,
                self.worker_name(),
            )
            .map_err(ReceiptStoreError::Write)?;
            match crate::platform::publish_manifest_directory(&staging, destination) {
                Ok(()) => {}
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
                    self.verify_directory(destination)?;
                    fs::remove_dir(staging.path()).map_err(ReceiptStoreError::Write)?;
                }
                Err(error) => return Err(ReceiptStoreError::Write(error)),
            }
            crate::platform::sync_parent_directory(parent).map_err(ReceiptStoreError::Write)
        })();
        if result.is_err() {
            let _ = fs::remove_dir(staging.path());
        }
        result
    }

    fn verify_directory(&self, destination: &Path) -> Result<(), ReceiptStoreError> {
        crate::platform::verify_manifest_ancestors(
            destination,
            self.owner,
            self.worker_name(),
            &self.trusted_root,
        )
        .map_err(ReceiptStoreError::Security)?;
        crate::platform::verify_manifest_directory_security(
            destination,
            self.owner,
            self.worker_name(),
        )
        .map_err(ReceiptStoreError::Security)
    }

    fn verify_security(&self) -> Result<(), ReceiptStoreError> {
        crate::platform::verify_manifest_security(
            &self.path,
            self.owner,
            self.worker_name(),
            &self.trusted_root,
        )
        .map_err(ReceiptStoreError::Security)
    }

    fn lock_path(&self) -> PathBuf {
        self.path
            .parent()
            .unwrap_or_else(|| Path::new(""))
            .join(".receipt.json.lock")
    }

    fn validate_destination_policy(&self) -> Result<&Path, ReceiptStoreError> {
        let destination = self
            .path
            .parent()
            .ok_or(ReceiptStoreError::InvalidDestination)?;
        if !self.path.is_absolute()
            || self.path.file_name().and_then(|name| name.to_str()) != Some("receipt.json")
            || self
                .path
                .components()
                .any(|component| matches!(component, Component::CurDir | Component::ParentDir))
            || self.path.components().collect::<PathBuf>().as_os_str() != self.path.as_os_str()
            || match self.scope {
                InstallationScope::System => destination != self.trusted_root,
                InstallationScope::User => {
                    destination.parent() != Some(self.trusted_root.as_path())
                }
            }
            || destination
                .components()
                .filter(|component| matches!(component, Component::Normal(_)))
                .count()
                < 2
        {
            return Err(ReceiptStoreError::InvalidDestination);
        }
        Ok(destination)
    }

    fn worker_name(&self) -> &str {
        self.worker
            .as_ref()
            .map(WorkerPrincipal::as_str)
            .unwrap_or("")
    }

    fn parse_for_scope(&self, input: &[u8]) -> Result<ReceiptDocument, ReceiptStoreError> {
        let document = ReceiptDocument::from_json(input)?;
        if document.installation_scope != self.scope {
            return Err(ReceiptStoreError::ScopeMismatch);
        }
        Ok(document)
    }
}

impl ReceiptApplySession<'_> {
    pub(in crate::setup) fn interruption_after_prepare(
        &self,
        _authority: &crate::setup::action::JournalAuthority,
    ) -> Result<(), ReceiptStoreError> {
        #[cfg(test)]
        if self.store.interrupt_after_prepare {
            return Err(ReceiptStoreError::Write(std::io::Error::new(
                std::io::ErrorKind::Interrupted,
                "injected interruption after durable receipt intent",
            )));
        }
        Ok(())
    }

    pub(in crate::setup) fn pending_intents(
        &self,
        _authority: &crate::setup::action::JournalAuthority,
    ) -> Result<Vec<ReceiptIntent>, ReceiptStoreError> {
        let directory = self
            .store
            .path
            .parent()
            .ok_or(ReceiptStoreError::InvalidDestination)?;
        let mut paths = Vec::new();
        for entry in fs::read_dir(directory).map_err(ReceiptStoreError::Read)? {
            let entry = entry.map_err(ReceiptStoreError::Read)?;
            let name = entry.file_name();
            let name = name.to_string_lossy();
            if name.starts_with(".receipt.json.transaction.") {
                let path = entry.path();
                let identity = crate::platform::private_file_identity(&path)
                    .map_err(ReceiptStoreError::Security)?;
                paths.push((path, identity));
            }
        }
        paths.sort_by(|left, right| left.0.cmp(&right.0));
        if paths.len() > 1 {
            return Err(ReceiptStoreError::IntentConflict);
        }
        #[cfg(test)]
        if let Some((path, _)) = paths.first() {
            self.inject_intent_read_interruption(path)?;
        }
        paths
            .into_iter()
            .map(|(path, identity)| self.read_intent(&path, identity))
            .collect()
    }

    pub(in crate::setup) fn prepare_intent(
        &self,
        action: &crate::setup::action::ActionName,
        privilege: crate::setup::action::Privilege,
        effect: &crate::setup::action::ActionEffect,
        metadata: &mut ReceiptMetadataSource,
        _authority: &crate::setup::action::JournalAuthority,
    ) -> Result<ReceiptIntent, ReceiptStoreError> {
        if self.store.scope == InstallationScope::User
            && privilege != crate::setup::action::Privilege::None
        {
            return Err(ReceiptError::PrivilegeOutsideScope.into());
        }
        let entry = ReceiptEntry::applied(action, privilege, effect, metadata.next()?)?;
        let path = self.transaction_path(&entry.entry_id);
        let document = ReceiptIntentDocument {
            schema_version: SCHEMA_VERSION,
            installation_scope: self.store.scope,
            phase: ReceiptIntentPhase::Prepared,
            entry: entry.clone(),
        };
        let serialized = document.to_json()?;
        let result = (|| {
            let mut file = crate::platform::create_private_file(&path, self.store.owner)
                .map_err(ReceiptStoreError::Write)?;
            file.write_all(&serialized)
                .map_err(ReceiptStoreError::Write)?;
            file.flush().map_err(ReceiptStoreError::Write)?;
            file.sync_all().map_err(ReceiptStoreError::Write)?;
            crate::platform::sync_parent_directory(
                self.store
                    .path
                    .parent()
                    .ok_or(ReceiptStoreError::InvalidDestination)?,
            )
            .map_err(ReceiptStoreError::Write)
        })();
        if result.is_err() {
            let _ = fs::remove_file(&path);
        }
        result?;
        Ok(ReceiptIntent {
            entry,
            path,
            phase: ReceiptIntentPhase::Prepared,
        })
    }

    pub(in crate::setup) fn mark_intent_succeeded(
        &self,
        intent: &mut ReceiptIntent,
        _authority: &crate::setup::action::JournalAuthority,
    ) -> Result<(), ReceiptStoreError> {
        if intent.phase != ReceiptIntentPhase::Prepared {
            return Err(ReceiptStoreError::IntentConflict);
        }
        let document = ReceiptIntentDocument {
            schema_version: SCHEMA_VERSION,
            installation_scope: self.store.scope,
            phase: ReceiptIntentPhase::Succeeded,
            entry: intent.entry.clone(),
        };
        self.replace_intent(&intent.path, &document.to_json()?)?;
        intent.phase = ReceiptIntentPhase::Succeeded;
        Ok(())
    }

    pub(in crate::setup) fn finalize_intent(
        &self,
        intent: &ReceiptIntent,
        _authority: &crate::setup::action::JournalAuthority,
    ) -> Result<(), ReceiptStoreError> {
        if intent.phase != ReceiptIntentPhase::Succeeded {
            return Err(ReceiptStoreError::IntentConflict);
        }
        let existing = self.store.read_locked()?;
        if let Some(entry) = existing
            .entries
            .iter()
            .find(|entry| entry.entry_id == intent.entry.entry_id)
        {
            if entry != &intent.entry {
                return Err(ReceiptStoreError::IntentConflict);
            }
        } else {
            let mut candidate = existing.clone();
            candidate.entries.push(intent.entry.clone());
            validate_append_candidate(&existing, &candidate)?;
            self.store.write_document(&candidate)?;
        }
        fs::remove_file(&intent.path).map_err(ReceiptStoreError::Write)?;
        crate::platform::sync_parent_directory(
            self.store
                .path
                .parent()
                .ok_or(ReceiptStoreError::InvalidDestination)?,
        )
        .map_err(ReceiptStoreError::Write)
    }

    pub(in crate::setup) fn intent_matches(
        &self,
        intent: &ReceiptIntent,
        action: &crate::setup::action::ActionName,
        privilege: crate::setup::action::Privilege,
        effect: &crate::setup::action::ActionEffect,
        _authority: &crate::setup::action::JournalAuthority,
    ) -> Result<bool, ReceiptStoreError> {
        let comparison = ReceiptEntry::applied(
            action,
            privilege,
            effect,
            ReceiptMetadata {
                entry_id: intent.entry.entry_id.clone(),
                timestamp: intent.entry.timestamp.clone(),
            },
        )?;
        Ok(comparison == intent.entry)
    }

    pub(in crate::setup) fn intent_action_id<'a>(
        &self,
        intent: &'a ReceiptIntent,
        _authority: &crate::setup::action::JournalAuthority,
    ) -> &'a str {
        intent.entry.action.action_id()
    }

    pub(in crate::setup) fn intent_phase(
        &self,
        intent: &ReceiptIntent,
        _authority: &crate::setup::action::JournalAuthority,
    ) -> ReceiptIntentPhase {
        intent.phase
    }

    fn transaction_path(&self, entry_id: &ReceiptEntryId) -> PathBuf {
        self.store
            .path
            .parent()
            .unwrap_or_else(|| Path::new(""))
            .join(format!(
                ".receipt.json.transaction.{}.json",
                entry_id.as_str()
            ))
    }

    fn read_intent(
        &self,
        path: &Path,
        expected_identity: crate::platform::PrivateFileIdentity,
    ) -> Result<ReceiptIntent, ReceiptStoreError> {
        let mut file = crate::platform::open_verified_private_file_for_read(
            path,
            self.store.owner,
            expected_identity,
        )
        .map_err(ReceiptStoreError::Security)?;
        let mut input = Vec::new();
        file.read_to_end(&mut input)
            .map_err(ReceiptStoreError::Read)?;
        let document = ReceiptIntentDocument::from_json(&input)?;
        if document.installation_scope != self.store.scope {
            return Err(ReceiptStoreError::ScopeMismatch);
        }
        let entry = document.entry;
        if self.transaction_path(&entry.entry_id) != path {
            return Err(ReceiptStoreError::IntentConflict);
        }
        Ok(ReceiptIntent {
            entry,
            path: path.to_path_buf(),
            phase: document.phase,
        })
    }

    #[cfg(test)]
    fn inject_intent_read_interruption(&self, path: &Path) -> Result<(), ReceiptStoreError> {
        let Some(interruption) = &self.store.intent_read_interruption else {
            return Ok(());
        };
        let saved = path.with_extension("enumerated-original");
        fs::rename(path, &saved).map_err(ReceiptStoreError::Write)?;
        match interruption {
            #[cfg(unix)]
            IntentReadInterruption::Symlink(target) => {
                std::os::unix::fs::symlink(target, path).map_err(ReceiptStoreError::Write)?;
            }
            #[cfg(unix)]
            IntentReadInterruption::Fifo => {
                use std::os::unix::ffi::OsStrExt;
                let path = std::ffi::CString::new(path.as_os_str().as_bytes()).map_err(|_| {
                    ReceiptStoreError::Write(std::io::Error::new(
                        std::io::ErrorKind::InvalidInput,
                        "intent path contains a NUL byte",
                    ))
                })?;
                if unsafe { libc::mkfifo(path.as_ptr(), 0o600) } != 0 {
                    return Err(ReceiptStoreError::Write(std::io::Error::last_os_error()));
                }
            }
            #[cfg(windows)]
            IntentReadInterruption::Reparse(target) => {
                std::os::windows::fs::symlink_file(target, path)
                    .map_err(ReceiptStoreError::Write)?;
            }
            IntentReadInterruption::Inode => {
                let bytes = fs::read(&saved).map_err(ReceiptStoreError::Read)?;
                let mut replacement = crate::platform::create_private_file(path, self.store.owner)
                    .map_err(ReceiptStoreError::Write)?;
                replacement
                    .write_all(&bytes)
                    .map_err(ReceiptStoreError::Write)?;
                replacement.sync_all().map_err(ReceiptStoreError::Write)?;
            }
        }
        Ok(())
    }

    fn replace_intent(&self, path: &Path, serialized: &[u8]) -> Result<(), ReceiptStoreError> {
        let directory = path.parent().ok_or(ReceiptStoreError::InvalidDestination)?;
        let temporary = directory.join(format!(".receipt.json.intent.{}.tmp", Uuid::now_v7()));
        let result = (|| {
            let mut file = crate::platform::create_private_file(&temporary, self.store.owner)
                .map_err(ReceiptStoreError::Write)?;
            file.write_all(serialized)
                .map_err(ReceiptStoreError::Write)?;
            file.flush().map_err(ReceiptStoreError::Write)?;
            file.sync_all().map_err(ReceiptStoreError::Write)?;
            crate::platform::replace_file(&temporary, path).map_err(ReceiptStoreError::Write)?;
            crate::platform::verify_private_file_security(path, self.store.owner)
                .map_err(ReceiptStoreError::PostReplaceSecurity)?;
            crate::platform::sync_parent_directory(directory).map_err(ReceiptStoreError::Write)
        })();
        if result.is_err() {
            let _ = fs::remove_file(&temporary);
        }
        result
    }
}

#[derive(Clone, Copy)]
enum PublicationInterruptionPoint {
    BeforeReplace,
    AfterReplace,
}

pub(crate) struct ReceiptMetadataSource {
    source: MetadataSource,
}

enum MetadataSource {
    System,
    #[cfg(test)]
    Injected(VecDeque<(String, String)>),
}

impl ReceiptMetadataSource {
    #[allow(dead_code)] // The setup invocation surface begins consuming this in T0.20.
    pub(crate) fn system() -> Self {
        Self {
            source: MetadataSource::System,
        }
    }

    #[cfg(test)]
    pub(in crate::setup) fn for_test<const N: usize>(values: [(&str, &str); N]) -> Self {
        Self {
            source: MetadataSource::Injected(
                values
                    .into_iter()
                    .map(|(id, timestamp)| (id.to_owned(), timestamp.to_owned()))
                    .collect(),
            ),
        }
    }

    fn next(&mut self) -> Result<ReceiptMetadata, ReceiptError> {
        let (entry_id, timestamp) = match &mut self.source {
            MetadataSource::System => (
                Uuid::now_v7().to_string(),
                chrono::Utc::now().to_rfc3339_opts(SecondsFormat::AutoSi, true),
            ),
            #[cfg(test)]
            MetadataSource::Injected(values) => values
                .pop_front()
                .ok_or(ReceiptError::MetadataUnavailable)?,
        };
        let metadata = ReceiptMetadata {
            entry_id: ReceiptEntryId(entry_id),
            timestamp: ReceiptTimestamp(timestamp),
        };
        metadata.entry_id.validate()?;
        metadata.timestamp.validate()?;
        Ok(metadata)
    }
}

struct ReceiptMetadata {
    entry_id: ReceiptEntryId,
    timestamp: ReceiptTimestamp,
}

fn validate_append_candidate(
    existing: &ReceiptDocument,
    candidate: &ReceiptDocument,
) -> Result<(), ReceiptStoreError> {
    candidate.validate()?;
    if candidate.entries.len() != existing.entries.len() + 1
        || candidate.installation_scope != existing.installation_scope
        || !candidate.entries.starts_with(&existing.entries)
        || candidate.entries.last().map(|entry| entry.status) != Some(ReceiptStatus::Applied)
    {
        return Err(ReceiptStoreError::PrefixConflict);
    }
    Ok(())
}

fn canonical_receipt_path(scope: InstallationScope) -> Result<PathBuf, ReceiptStoreError> {
    match scope {
        InstallationScope::System => {
            #[cfg(target_os = "linux")]
            let path = PathBuf::from("/var/lib/styrn/receipt.json");
            #[cfg(target_os = "macos")]
            let path = PathBuf::from("/Library/Application Support/Styrn/receipt.json");
            #[cfg(target_os = "windows")]
            let path = PathBuf::from(r"C:\ProgramData\Styrn\receipt.json");
            Ok(path)
        }
        InstallationScope::User => {
            #[cfg(target_os = "linux")]
            let root = std::env::var_os("XDG_STATE_HOME")
                .map(PathBuf::from)
                .or_else(|| {
                    std::env::var_os("HOME").map(|home| PathBuf::from(home).join(".local/state"))
                });
            #[cfg(target_os = "macos")]
            let root = std::env::var_os("HOME")
                .map(|home| PathBuf::from(home).join("Library/Application Support"));
            #[cfg(target_os = "windows")]
            let root = std::env::var_os("LOCALAPPDATA").map(PathBuf::from);
            let root = root.ok_or(ReceiptStoreError::UserStateDirectoryUnavailable)?;
            if !root.is_absolute() {
                return Err(ReceiptStoreError::UserStateDirectoryUnavailable);
            }
            #[cfg(target_os = "linux")]
            let application = "styrn";
            #[cfg(any(target_os = "macos", target_os = "windows"))]
            let application = "Styrn";
            Ok(root.join(application).join("receipt.json"))
        }
    }
}

pub(crate) fn configured_receipt_store() -> Result<ReceiptStore, ReceiptStoreError> {
    let path = canonical_receipt_path(InstallationScope::User)?;
    let trusted_root = path
        .parent()
        .and_then(Path::parent)
        .map(Path::to_path_buf)
        .ok_or(ReceiptStoreError::InvalidDestination)?;
    Ok(ReceiptStore {
        scope: InstallationScope::User,
        path,
        trusted_root,
        owner: crate::platform::ManifestOwner::User,
        worker: None,
        #[cfg(test)]
        interruption: None,
        #[cfg(test)]
        interrupt_after_prepare: false,
        #[cfg(test)]
        intent_read_interruption: None,
    })
}

pub(crate) fn configured_system_receipt_store(
    worker: &str,
) -> Result<ReceiptStore, ReceiptStoreError> {
    ReceiptStore::new_system(canonical_receipt_path(InstallationScope::System)?, worker)
}

#[derive(Debug, Error)]
pub(crate) enum ReceiptStoreError {
    #[error(transparent)]
    Document(#[from] ReceiptError),
    #[error("could not read setup receipt")]
    Read(#[source] std::io::Error),
    #[error("could not write setup receipt")]
    Write(#[source] std::io::Error),
    #[error("setup receipt security verification failed")]
    Security(#[source] std::io::Error),
    #[error("setup receipt was replaced but security verification failed")]
    PostReplaceSecurity(#[source] std::io::Error),
    #[error("setup receipt destination is not the normalized receipt.json policy path")]
    InvalidDestination,
    #[error("setup receipt append would alter its existing entry prefix")]
    PrefixConflict,
    #[error("T0.11 may finalize only applied receipt entries")]
    NonAppliedAppend,
    #[error("setup receipt transaction does not match the prepared action")]
    IntentConflict,
    #[error("setup receipt worker principal is invalid")]
    InvalidWorkerPrincipal,
    #[error("setup receipt scope does not match the selected installation scope")]
    ScopeMismatch,
    #[error("the current user's standard state directory is unavailable")]
    UserStateDirectoryUnavailable,
}

impl ReceiptStoreError {
    pub(crate) fn error_code(&self) -> &'static str {
        "setup.receipt_conflict"
    }

    pub(crate) fn exit_code(&self) -> u8 {
        13
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ReceiptEntry {
    entry_id: ReceiptEntryId,
    action: ReceiptAction,
    timestamp: ReceiptTimestamp,
    privilege_used: ReceiptPrivilege,
    files_created: Vec<CreatedFile>,
    files_modified: Vec<ModifiedFile>,
    services: Vec<ServiceResource>,
    accounts: Vec<AccountResource>,
    registry_keys: Vec<RegistryKeyResource>,
    firewall_rules: Vec<FirewallRuleResource>,
    download_provenance: DownloadProvenanceSlot,
    status: ReceiptStatus,
}

impl ReceiptEntry {
    fn applied(
        action: &crate::setup::action::ActionName,
        privilege: crate::setup::action::Privilege,
        effect: &crate::setup::action::ActionEffect,
        metadata: ReceiptMetadata,
    ) -> Result<Self, ReceiptError> {
        let entry = Self {
            entry_id: metadata.entry_id,
            action: ReceiptAction::Foundation(FoundationActionParameters {
                action_id: ActionIdentifier(action.as_str().to_owned()),
            }),
            timestamp: metadata.timestamp,
            privilege_used: match privilege {
                crate::setup::action::Privilege::None => ReceiptPrivilege::None,
                crate::setup::action::Privilege::Root => ReceiptPrivilege::Root,
                crate::setup::action::Privilege::Admin => ReceiptPrivilege::Admin,
            },
            files_created: effect
                .files_created()
                .iter()
                .map(|file| CreatedFile {
                    path: RecordedPath(file.path().to_owned()),
                    sha256: Sha256Digest(file.sha256().to_owned()),
                })
                .collect(),
            files_modified: effect
                .files_modified()
                .iter()
                .map(|file| ModifiedFile {
                    path: RecordedPath(file.path().to_owned()),
                    before_sha256: Sha256Digest(file.before_sha256().to_owned()),
                    backup_path: RecordedPath(file.backup_path().to_owned()),
                })
                .collect(),
            services: effect
                .services()
                .iter()
                .map(|name| ServiceResource {
                    name: ResourceIdentifier(name.clone()),
                })
                .collect(),
            accounts: effect
                .accounts()
                .iter()
                .map(|name| AccountResource {
                    name: ResourceIdentifier(name.clone()),
                })
                .collect(),
            registry_keys: effect
                .registry_keys()
                .iter()
                .map(|path| RegistryKeyResource {
                    path: ResourceIdentifier(path.clone()),
                })
                .collect(),
            firewall_rules: effect
                .firewall_rules()
                .iter()
                .map(|name| FirewallRuleResource {
                    name: ResourceIdentifier(name.clone()),
                })
                .collect(),
            download_provenance: DownloadProvenanceSlot(effect.download_provenance().map(
                |provenance| DownloadProvenance {
                    url: HttpsUrl(provenance.url().to_owned()),
                    version: VersionIdentifier(provenance.version().to_owned()),
                    sha256: Sha256Digest(provenance.sha256().to_owned()),
                },
            )),
            status: ReceiptStatus::Applied,
        };
        entry.validate()?;
        Ok(entry)
    }

    fn status(&self) -> ReceiptStatus {
        self.status
    }

    fn validate(&self) -> Result<(), ReceiptError> {
        self.entry_id.validate()?;
        self.action.validate()?;
        self.timestamp.validate()?;
        let mut file_paths = HashSet::new();
        for file in &self.files_created {
            file.validate()?;
            if !file_paths.insert(file.path.0.as_str()) {
                return Err(ReceiptError::ConflictingResources);
            }
        }
        for file in &self.files_modified {
            file.validate()?;
            if !file_paths.insert(file.path.0.as_str())
                || !file_paths.insert(file.backup_path.0.as_str())
            {
                return Err(ReceiptError::ConflictingResources);
            }
        }
        let mut services = HashSet::new();
        for service in &self.services {
            service.name.validate()?;
            if !services.insert(service.name.0.as_str()) {
                return Err(ReceiptError::ConflictingResources);
            }
        }
        let mut accounts = HashSet::new();
        for account in &self.accounts {
            account.name.validate()?;
            if !accounts.insert(account.name.0.as_str()) {
                return Err(ReceiptError::ConflictingResources);
            }
        }
        let mut registry_keys = HashSet::new();
        for key in &self.registry_keys {
            key.validate()?;
            if !registry_keys.insert(key.path.0.as_str()) {
                return Err(ReceiptError::ConflictingResources);
            }
        }
        let mut firewall_rules = HashSet::new();
        for rule in &self.firewall_rules {
            rule.name.validate()?;
            if !firewall_rules.insert(rule.name.0.as_str()) {
                return Err(ReceiptError::ConflictingResources);
            }
        }
        if let Some(provenance) = &self.download_provenance.0 {
            provenance.validate()?;
        }
        if self.status == ReceiptStatus::Pending
            && (self.privilege_used != ReceiptPrivilege::None
                || !self.files_created.is_empty()
                || !self.files_modified.is_empty()
                || !self.services.is_empty()
                || !self.accounts.is_empty()
                || !self.registry_keys.is_empty()
                || !self.firewall_rules.is_empty()
                || self.download_provenance.0.is_some())
        {
            return Err(ReceiptError::InvalidPendingEntry);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(
    tag = "type",
    content = "parameters",
    rename_all = "snake_case",
    deny_unknown_fields
)]
enum ReceiptAction {
    Foundation(FoundationActionParameters),
}

impl ReceiptAction {
    fn action_id(&self) -> &str {
        match self {
            Self::Foundation(parameters) => &parameters.action_id.0,
        }
    }

    fn validate(&self) -> Result<(), ReceiptError> {
        match self {
            Self::Foundation(parameters) => parameters.action_id.validate(),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct FoundationActionParameters {
    action_id: ActionIdentifier,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(transparent)]
struct ReceiptEntryId(String);

impl ReceiptEntryId {
    fn as_str(&self) -> &str {
        &self.0
    }

    fn validate(&self) -> Result<(), ReceiptError> {
        let id = Uuid::parse_str(&self.0).map_err(|_| ReceiptError::InvalidEntryId)?;
        if id.get_version_num() != 7 || id.to_string() != self.0 {
            return Err(ReceiptError::InvalidEntryId);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(transparent)]
struct ActionIdentifier(String);

impl ActionIdentifier {
    fn validate(&self) -> Result<(), ReceiptError> {
        let mut segments = self.0.split('.');
        let Some(first) = segments.next() else {
            return Err(ReceiptError::InvalidActionIdentifier);
        };
        if !valid_action_segment(first)
            || segments.clone().next().is_none()
            || !segments.all(valid_action_segment)
            || !safe_text(&self.0)
        {
            return Err(ReceiptError::InvalidActionIdentifier);
        }
        Ok(())
    }
}

fn valid_action_segment(segment: &str) -> bool {
    let mut characters = segment.chars();
    characters
        .next()
        .is_some_and(|first| first.is_ascii_lowercase())
        && !segment.ends_with('-')
        && characters.all(|character| {
            character.is_ascii_lowercase() || character.is_ascii_digit() || character == '-'
        })
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(transparent)]
struct ReceiptTimestamp(String);

impl ReceiptTimestamp {
    fn validate(&self) -> Result<(), ReceiptError> {
        let timestamp = DateTime::<FixedOffset>::parse_from_rfc3339(&self.0)
            .map_err(|_| ReceiptError::InvalidTimestamp)?;
        if timestamp.offset().local_minus_utc() != 0
            || !self.0.ends_with('Z')
            || timestamp.to_rfc3339_opts(SecondsFormat::AutoSi, true) != self.0
        {
            return Err(ReceiptError::InvalidTimestamp);
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum ReceiptPrivilege {
    None,
    Root,
    Admin,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum ReceiptStatus {
    Applied,
    Pending,
    Adopted,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct CreatedFile {
    path: RecordedPath,
    sha256: Sha256Digest,
}

impl CreatedFile {
    fn validate(&self) -> Result<(), ReceiptError> {
        self.path.validate()?;
        self.sha256.validate()
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ModifiedFile {
    path: RecordedPath,
    before_sha256: Sha256Digest,
    backup_path: RecordedPath,
}

impl ModifiedFile {
    fn validate(&self) -> Result<(), ReceiptError> {
        self.path.validate()?;
        self.before_sha256.validate()?;
        self.backup_path.validate()
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(transparent)]
struct RecordedPath(String);

impl RecordedPath {
    fn validate(&self) -> Result<(), ReceiptError> {
        if !safe_text(&self.0) || !is_normalized_absolute_path(&self.0) {
            return Err(ReceiptError::InvalidRecordedPath);
        }
        Ok(())
    }
}

fn is_normalized_absolute_path(value: &str) -> bool {
    #[cfg(not(target_os = "windows"))]
    {
        is_normalized_unix_path(value)
    }
    #[cfg(target_os = "windows")]
    {
        is_normalized_windows_path(value)
    }
}

#[cfg(any(test, not(target_os = "windows")))]
fn is_normalized_unix_path(value: &str) -> bool {
    value.starts_with('/')
        && (value == "/"
            || (!value.ends_with('/')
                && !value.contains("//")
                && value
                    .split('/')
                    .skip(1)
                    .all(|segment| !segment.is_empty() && !matches!(segment, "." | ".."))))
}

#[cfg(any(test, target_os = "windows"))]
fn is_normalized_windows_path(value: &str) -> bool {
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
                matches!(number, "1" | "2" | "3" | "4" | "5" | "6" | "7" | "8" | "9")
            })
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(transparent)]
struct Sha256Digest(String);

impl Sha256Digest {
    fn validate(&self) -> Result<(), ReceiptError> {
        if self.0.len() != 64
            || !self
                .0
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        {
            return Err(ReceiptError::InvalidSha256);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ServiceResource {
    name: ResourceIdentifier,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct AccountResource {
    name: ResourceIdentifier,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct RegistryKeyResource {
    path: ResourceIdentifier,
}

impl RegistryKeyResource {
    fn validate(&self) -> Result<(), ReceiptError> {
        self.path.validate()?;
        if !self.path.0.starts_with("HKLM\\") && !self.path.0.starts_with("HKEY_LOCAL_MACHINE\\") {
            return Err(ReceiptError::InvalidResourceIdentifier);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct FirewallRuleResource {
    name: ResourceIdentifier,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(transparent)]
struct ResourceIdentifier(String);

impl ResourceIdentifier {
    fn validate(&self) -> Result<(), ReceiptError> {
        if self.0.is_empty() || self.0.len() > 512 || !safe_text(&self.0) {
            return Err(ReceiptError::InvalidResourceIdentifier);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(transparent)]
struct DownloadProvenanceSlot(Option<DownloadProvenance>);

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct DownloadProvenance {
    url: HttpsUrl,
    version: VersionIdentifier,
    sha256: Sha256Digest,
}

impl DownloadProvenance {
    fn validate(&self) -> Result<(), ReceiptError> {
        self.url.validate()?;
        self.version.validate()?;
        self.sha256.validate()
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(transparent)]
struct HttpsUrl(String);

impl HttpsUrl {
    fn validate(&self) -> Result<(), ReceiptError> {
        let Some(remainder) = self.0.strip_prefix("https://") else {
            return Err(ReceiptError::InvalidProvenanceUrl);
        };
        let authority_end = remainder.find(['/', '?', '#']).unwrap_or(remainder.len());
        let authority = &remainder[..authority_end];
        if !safe_text(&self.0)
            || !self.0.is_ascii()
            || self.0.contains('\\')
            || self.0.contains('#')
            || authority.is_empty()
            || authority.contains('@')
            || authority.chars().any(char::is_whitespace)
            || !valid_https_authority(authority)
        {
            return Err(ReceiptError::InvalidProvenanceUrl);
        }
        Ok(())
    }
}

fn valid_https_authority(authority: &str) -> bool {
    if let Some(ipv6) = authority.strip_prefix('[') {
        let Some(closing) = ipv6.find(']') else {
            return false;
        };
        let host = &ipv6[..closing];
        let suffix = &ipv6[closing + 1..];
        return host.parse::<std::net::Ipv6Addr>().is_ok() && valid_optional_port(suffix);
    }

    let (host, port) = match authority.rsplit_once(':') {
        Some((_, "")) => return false,
        Some((host, port)) => (host, Some(port)),
        None => (authority, None),
    };
    if host.is_empty()
        || host.starts_with('.')
        || host.ends_with('.')
        || host.split('.').any(|label| {
            label.is_empty()
                || label.starts_with('-')
                || label.ends_with('-')
                || !label
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
        })
    {
        return false;
    }
    port.is_none_or(valid_port)
}

fn valid_optional_port(suffix: &str) -> bool {
    suffix.is_empty() || suffix.strip_prefix(':').is_some_and(valid_port)
}

fn valid_port(port: &str) -> bool {
    !port.is_empty()
        && port.bytes().all(|byte| byte.is_ascii_digit())
        && port.parse::<u16>().is_ok_and(|port| port != 0)
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(transparent)]
struct VersionIdentifier(String);

impl VersionIdentifier {
    fn validate(&self) -> Result<(), ReceiptError> {
        if self.0.len() > 128
            || !safe_text(&self.0)
            || !self
                .0
                .bytes()
                .next()
                .is_some_and(|byte| byte.is_ascii_alphanumeric())
            || !self.0.bytes().all(|byte| {
                byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'+' | b'-')
            })
        {
            return Err(ReceiptError::InvalidVersionIdentifier);
        }
        Ok(())
    }
}

fn safe_text(value: &str) -> bool {
    value.len() <= 4096 && super::validate_probe_static_text(value)
}

#[derive(Clone, Debug, PartialEq, Eq, Error)]
pub(crate) enum ReceiptError {
    #[error("setup receipt JSON is malformed or does not match schema at {line}:{column}")]
    Parse { line: usize, column: usize },
    #[error("setup receipt could not be serialized")]
    Serialize,
    #[error("setup receipt schema version is unsupported")]
    UnknownSchemaVersion,
    #[error("setup receipt installation scope is required")]
    MissingInstallationScope,
    #[error("user-scope setup receipt entries cannot claim privileged mutation")]
    PrivilegeOutsideScope,
    #[error("setup receipt contains a duplicate entry ID")]
    DuplicateEntryId,
    #[error("setup receipt entry ID is not a canonical UUIDv7")]
    InvalidEntryId,
    #[error("setup receipt action identifier is invalid")]
    InvalidActionIdentifier,
    #[error("setup receipt timestamp is not canonical UTC RFC 3339")]
    InvalidTimestamp,
    #[error("setup receipt contains an invalid absolute normalized path")]
    InvalidRecordedPath,
    #[error("setup receipt SHA-256 digest is not normalized lowercase hexadecimal")]
    InvalidSha256,
    #[error("setup receipt resource identifier is invalid")]
    InvalidResourceIdentifier,
    #[error("setup receipt contains duplicate or conflicting resource records")]
    ConflictingResources,
    #[error("pending setup receipt entries cannot claim mutation or privilege use")]
    InvalidPendingEntry,
    #[error("setup receipt download provenance URL must be a valid HTTPS URL")]
    InvalidProvenanceUrl,
    #[error("setup receipt download version is invalid")]
    InvalidVersionIdentifier,
    #[error("setup receipt metadata source was exhausted")]
    MetadataUnavailable,
}

#[cfg(test)]
mod tests;
