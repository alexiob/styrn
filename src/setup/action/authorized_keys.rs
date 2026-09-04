use super::{
    Action, ActionCheck, ActionDescription, ActionEffect, ActionError, ActionName,
    ActionParameters, ActionPlan, CreatedDirectoryEffect, CreatedFileEffect,
    CurrentUserSshActionParameters, HumanInstructions, NeedsHuman, PlanOperation,
};
use crate::platform::{self, ManifestOwner, WorkerPrincipal};
use sha2::{Digest, Sha256};
use std::collections::HashSet;
use std::fs;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};

const DIRECTORY_ID: &str = "ssh.directory";
const KEYS_ID: &str = "ssh.authorized-keys";
const MAX_BYTES: usize = 1024 * 1024;
const REMEDIATION: &str = "Verify the current user's .ssh/authorized_keys ownership and permissions; if the file already exists, add every requested controller public key without removing existing entries, then rerun setup.";

pub(crate) enum CurrentUserSshAction {
    Directory {
        name: ActionName,
        description: ActionDescription,
        principal: WorkerPrincipal,
        path: PathBuf,
        initially_absent: bool,
        conflict: bool,
    },
    Keys {
        name: ActionName,
        description: ActionDescription,
        principal: WorkerPrincipal,
        directory: PathBuf,
        path: PathBuf,
        before: Option<Vec<u8>>,
        after: Vec<u8>,
        conflict: bool,
    },
}

pub(in crate::setup) fn current_user_ssh_action_plan(
    principal: WorkerPrincipal,
    keys: &[String],
) -> Result<ActionPlan, ActionError> {
    let directory = platform::current_user_ssh_directory(&principal).map_err(|_| action_error())?;
    build(principal, directory, keys)
}

#[cfg(test)]
pub(in crate::setup) fn current_user_ssh_action_plan_for_test(
    principal: WorkerPrincipal,
    directory: PathBuf,
    keys: &[String],
) -> Result<ActionPlan, ActionError> {
    build(principal, directory, keys)
}

fn build(
    principal: WorkerPrincipal,
    directory: PathBuf,
    keys: &[String],
) -> Result<ActionPlan, ActionError> {
    if keys.is_empty()
        || directory.file_name() != Some(std::ffi::OsStr::new(".ssh"))
        || keys.iter().any(|key| {
            key.trim() != key
                || key_identity(key).is_none()
                || !crate::setup::validate_probe_static_text(key)
        })
    {
        return Err(action_error());
    }
    let state = inspect_directory(&directory, &principal);
    let path = directory.join("authorized_keys");
    let (before, after, conflict) = match state {
        DirectoryState::Absent => (
            None,
            append_keys(&[], keys).ok_or_else(action_error)?,
            false,
        ),
        DirectoryState::Ready => match read_keys(&path, &principal) {
            Ok(before) => match append_keys(before.as_deref().unwrap_or_default(), keys) {
                Some(after) if before.is_none() => (None, after, false),
                Some(after) if before.as_deref() == Some(after.as_slice()) => {
                    (before, after, false)
                }
                Some(_) => (before, Vec::new(), true),
                None => (before, Vec::new(), true),
            },
            Err(()) => (None, Vec::new(), true),
        },
        DirectoryState::Conflict => (None, Vec::new(), true),
    };
    Ok(vec![
        Action::CurrentUserSsh(Box::new(CurrentUserSshAction::Directory {
            name: name(DIRECTORY_ID),
            description: ActionDescription::new(
                "Create the invoking user's private OpenSSH directory.",
            )
            .expect("static description is valid"),
            principal: principal.clone(),
            path: directory.clone(),
            initially_absent: state == DirectoryState::Absent,
            conflict: state == DirectoryState::Conflict,
        })),
        Action::CurrentUserSsh(Box::new(CurrentUserSshAction::Keys {
            name: name(KEYS_ID),
            description: ActionDescription::new(
                "Authorize supplied controller public keys for the current user.",
            )
            .expect("static description is valid"),
            principal,
            directory,
            path,
            before,
            after,
            conflict,
        })),
    ])
}

#[derive(Clone, Copy, Eq, PartialEq)]
enum DirectoryState {
    Absent,
    Ready,
    Conflict,
}

fn inspect_directory(path: &Path, principal: &WorkerPrincipal) -> DirectoryState {
    match fs::symlink_metadata(path) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => DirectoryState::Absent,
        Ok(_) if platform::verify_current_user_private_directory(path, principal).is_ok() => {
            DirectoryState::Ready
        }
        Ok(_) | Err(_) => DirectoryState::Conflict,
    }
}

fn read_keys(path: &Path, principal: &WorkerPrincipal) -> Result<Option<Vec<u8>>, ()> {
    let identity = match platform::private_file_identity(path) {
        Ok(identity) => identity,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(_) => return Err(()),
    };
    let mut file = platform::open_verified_private_file_for_read(
        path,
        ManifestOwner::User,
        principal,
        identity,
    )
    .map_err(|_| ())?;
    if file.metadata().map_err(|_| ())?.len() > MAX_BYTES as u64 {
        return Err(());
    }
    let mut bytes = Vec::new();
    Read::by_ref(&mut file)
        .take(MAX_BYTES as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| ())?;
    std::str::from_utf8(&bytes).map_err(|_| ())?;
    if bytes.len() > MAX_BYTES {
        return Err(());
    }
    Ok(Some(bytes))
}

fn append_keys(before: &[u8], required: &[String]) -> Option<Vec<u8>> {
    let text = std::str::from_utf8(before).ok()?;
    let mut present = HashSet::new();
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        present.insert(key_identity(line)?);
    }
    let mut after = before.to_vec();
    for key in required {
        let identity = key_identity(key)?;
        if !present.insert(identity) {
            continue;
        }
        if !after.is_empty() && !after.ends_with(b"\n") {
            after.push(b'\n');
        }
        after.extend_from_slice(key.as_bytes());
        after.push(b'\n');
    }
    (after.len() <= MAX_BYTES).then_some(after)
}

fn key_identity(line: &str) -> Option<(String, String)> {
    platform::parse_authorized_key_line(line)?;
    let mut fields = line.split_ascii_whitespace();
    Some((fields.next()?.to_owned(), fields.next()?.to_owned()))
}

impl CurrentUserSshAction {
    pub(super) fn name(&self) -> &ActionName {
        match self {
            Self::Directory { name, .. } | Self::Keys { name, .. } => name,
        }
    }

    pub(super) fn description(&self) -> &ActionDescription {
        match self {
            Self::Directory { description, .. } | Self::Keys { description, .. } => description,
        }
    }

    pub(super) fn parameters(&self) -> ActionParameters {
        match self {
            Self::Directory {
                name,
                principal,
                path,
                ..
            } => ActionParameters::CurrentUserSsh(CurrentUserSshActionParameters::new(
                name.clone(),
                principal.clone(),
                path.clone(),
                path.clone(),
            )),
            Self::Keys {
                name,
                principal,
                directory,
                path,
                ..
            } => ActionParameters::CurrentUserSsh(CurrentUserSshActionParameters::new(
                name.clone(),
                principal.clone(),
                directory.clone(),
                path.clone(),
            )),
        }
    }

    pub(super) fn check(&self) -> ActionCheck {
        match self {
            Self::Directory {
                principal,
                path,
                initially_absent,
                conflict,
                ..
            } => match inspect_directory(path, principal) {
                DirectoryState::Ready if !conflict => ActionCheck::Done,
                DirectoryState::Absent if *initially_absent && !conflict => ActionCheck::Todo,
                DirectoryState::Absent | DirectoryState::Ready | DirectoryState::Conflict => {
                    ActionCheck::NeedsHuman(needs_human())
                }
            },
            Self::Keys {
                principal,
                directory,
                path,
                before,
                after,
                conflict,
                ..
            } => {
                if *conflict || inspect_directory(directory, principal) == DirectoryState::Conflict
                {
                    return ActionCheck::NeedsHuman(needs_human());
                }
                let current = if inspect_directory(directory, principal) == DirectoryState::Absent {
                    None
                } else {
                    match read_keys(path, principal) {
                        Ok(value) => value,
                        Err(()) => return ActionCheck::NeedsHuman(needs_human()),
                    }
                };
                if current.as_deref() == Some(after) {
                    ActionCheck::Done
                } else if &current == before {
                    ActionCheck::Todo
                } else {
                    ActionCheck::NeedsHuman(needs_human())
                }
            }
        }
    }

    pub(super) fn operation(&self) -> PlanOperation {
        match self {
            Self::Directory {
                initially_absent,
                conflict,
                ..
            } => {
                if *conflict {
                    PlanOperation::NeedsHuman
                } else if *initially_absent {
                    PlanOperation::Create
                } else {
                    PlanOperation::Done
                }
            }
            Self::Keys {
                before,
                after,
                conflict,
                ..
            } => {
                if *conflict {
                    PlanOperation::NeedsHuman
                } else if before.as_deref() == Some(after) {
                    PlanOperation::Done
                } else if before.is_none() {
                    PlanOperation::Create
                } else {
                    PlanOperation::NeedsHuman
                }
            }
        }
    }

    pub(super) fn expected_effect(&self) -> Result<ActionEffect, ActionError> {
        match self {
            Self::Directory {
                path,
                initially_absent: true,
                conflict: false,
                ..
            } => Ok(directory_effect(path)),
            Self::Keys {
                path,
                before,
                after,
                conflict: false,
                ..
            } if before.is_none() => Ok(keys_effect(path, after)),
            _ => Err(ActionError::apply_failed(self.name().clone())),
        }
    }

    pub(super) fn execute(&self) -> Result<ActionEffect, ActionError> {
        match self {
            Self::Directory {
                name,
                principal,
                path,
                initially_absent: true,
                conflict: false,
                ..
            } => {
                platform::create_current_user_private_directory_exclusive(path, principal)
                    .map_err(|_| ActionError::apply_failed(name.clone()))?;
                Ok(directory_effect(path))
            }
            Self::Keys {
                name,
                principal,
                directory,
                path,
                before,
                after,
                conflict: false,
                ..
            } if before.is_none() => {
                if inspect_directory(directory, principal) != DirectoryState::Ready
                    || read_keys(path, principal)
                        .map_err(|_| ActionError::apply_failed(name.clone()))?
                        .is_some()
                {
                    return Err(ActionError::apply_failed(name.clone()));
                }
                publish_keys(directory, path, principal, after, name)?;
                Ok(keys_effect(path, after))
            }
            _ => Err(ActionError::apply_failed(self.name().clone())),
        }
    }
}

fn publish_keys(
    directory: &Path,
    path: &Path,
    principal: &WorkerPrincipal,
    after: &[u8],
    action: &ActionName,
) -> Result<(), ActionError> {
    let temporary = directory.join(format!(
        ".authorized_keys.styrn-{}-{}",
        std::process::id(),
        uuid::Uuid::now_v7().simple()
    ));
    let result = (|| {
        let mut publication =
            platform::create_private_publication_file(&temporary, ManifestOwner::User, principal)?;
        publication.write_all(after)?;
        let complete = publication.complete_exact(after)?;
        complete.publish_no_replace(path)?;
        if read_keys(path, principal).ok().flatten().as_deref() != Some(after) {
            return Err(std::io::Error::other("authorized_keys verification failed"));
        }
        Ok(())
    })();
    if result.is_err() {
        let _ = fs::remove_file(&temporary);
    }
    result.map_err(|_| ActionError::apply_failed(action.clone()))
}

fn directory_effect(path: &Path) -> ActionEffect {
    ActionEffect {
        directories_created: vec![CreatedDirectoryEffect {
            path: path.to_string_lossy().into_owned(),
        }],
        files_created: Vec::new(),
        files_modified: Vec::new(),
        services: Vec::new(),
        accounts: Vec::new(),
        registry_keys: Vec::new(),
        firewall_rules: Vec::new(),
        download_provenance: None,
    }
}

fn keys_effect(path: &Path, after: &[u8]) -> ActionEffect {
    ActionEffect {
        directories_created: Vec::new(),
        files_created: vec![CreatedFileEffect {
            path: path.to_string_lossy().into_owned(),
            sha256: sha256(after),
        }],
        files_modified: Vec::new(),
        services: Vec::new(),
        accounts: Vec::new(),
        registry_keys: Vec::new(),
        firewall_rules: Vec::new(),
        download_provenance: None,
    }
}

fn sha256(bytes: &[u8]) -> String {
    let mut output = String::with_capacity(64);
    use std::fmt::Write as _;
    for byte in Sha256::digest(bytes) {
        write!(&mut output, "{byte:02x}").expect("hex formatting cannot fail");
    }
    output
}

fn needs_human() -> NeedsHuman {
    NeedsHuman::new(
        HumanInstructions::new(REMEDIATION).expect("static instructions are valid"),
        None,
    )
}

fn name(value: &str) -> ActionName {
    ActionName::parse(value).expect("static SSH action name is valid")
}

fn action_error() -> ActionError {
    ActionError::check_failed(name(KEYS_ID))
}

#[cfg(test)]
mod tests {
    use super::{append_keys, current_user_ssh_action_plan_for_test};
    use crate::{
        platform::{self, ManifestOwner},
        setup::action::{Action, ActionParameters, ApplyOutcome},
    };
    use std::fs;

    const KEY: &str = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIAABAgMEBQYHCAkKCwwNDg8QERITFBUWFxgZGhscHR4f styrn-controller";

    #[test]
    fn constrained_active_lines_fail_closed_instead_of_becoming_unrestricted_duplicates() {
        let before = format!("from=\"10.0.0.1\" {KEY}\n");
        assert!(append_keys(before.as_bytes(), &[KEY.to_owned()]).is_none());
    }

    #[test]
    fn comments_are_preserved_and_an_existing_key_is_idempotent() {
        let once = append_keys(b"# existing\n\n", &[KEY.to_owned()]).unwrap();
        assert_eq!(append_keys(&once, &[KEY.to_owned()]).unwrap(), once);
    }

    #[test]
    fn concurrent_ssh_directory_creator_is_never_claimed_as_this_actions_effect() {
        let principal = platform::resolve_current_worker_principal().unwrap();
        let root = std::env::current_dir()
            .unwrap()
            .join("target")
            .join(format!("styrn-ssh-directory-race-{}", uuid::Uuid::now_v7()));
        fs::create_dir(&root).unwrap();
        platform::harden_manifest_directory(&root, platform::ManifestOwner::User, &principal)
            .unwrap();
        let directory = root.join(".ssh");
        let mut plan = current_user_ssh_action_plan_for_test(
            principal.clone(),
            directory.clone(),
            &[KEY.to_owned()],
        )
        .unwrap();
        fs::create_dir(&directory).unwrap();
        platform::harden_manifest_directory(&directory, platform::ManifestOwner::User, &principal)
            .unwrap();

        let Action::CurrentUserSsh(action) = plan.remove(0) else {
            panic!("SSH directory action expected")
        };
        assert!(action.execute().is_err());
        assert!(directory.is_dir());
        assert!(!directory.join("authorized_keys").exists());
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn actions_retain_typed_principal_and_exact_paths_for_the_receipt() {
        let principal = platform::resolve_current_worker_principal().unwrap();
        let directory = std::env::current_dir()
            .unwrap()
            .join("target")
            .join("typed-current-user-ssh")
            .join(".ssh");
        let plan = current_user_ssh_action_plan_for_test(
            principal.clone(),
            directory.clone(),
            &[KEY.to_owned()],
        )
        .unwrap();

        for (action, expected_id, expected_path) in [
            (&plan[0], "ssh.directory", directory.clone()),
            (
                &plan[1],
                "ssh.authorized-keys",
                directory.join("authorized_keys"),
            ),
        ] {
            let ActionParameters::CurrentUserSsh(parameters) = action.parameters() else {
                panic!("current-user SSH action used generic receipt parameters")
            };
            assert_eq!(parameters.action_id().as_str(), expected_id);
            assert_eq!(parameters.principal(), &principal);
            assert_eq!(parameters.directory(), directory);
            assert_eq!(parameters.path(), expected_path);
        }
    }

    #[test]
    fn nonconverged_existing_authorized_keys_is_never_replaced_or_backed_up() {
        let principal = platform::resolve_current_worker_principal().unwrap();
        let root = std::env::current_dir()
            .unwrap()
            .join("target")
            .join(format!(
                "styrn-authorized-keys-race-{}",
                uuid::Uuid::now_v7()
            ));
        let directory = root.join(".ssh");
        fs::create_dir_all(&directory).unwrap();
        platform::harden_manifest_directory(&root, ManifestOwner::User, &principal).unwrap();
        platform::harden_manifest_directory(&directory, ManifestOwner::User, &principal).unwrap();
        let path = directory.join("authorized_keys");
        let existing = b"# operator-owned\n";
        fs::write(&path, existing).unwrap();
        platform::harden_manifest_file(&path, ManifestOwner::User, &principal).unwrap();
        let mut plan =
            current_user_ssh_action_plan_for_test(principal, directory.clone(), &[KEY.to_owned()])
                .unwrap();
        let mut action = plan.remove(1);
        assert!(matches!(action, Action::CurrentUserSsh(_)));

        assert!(matches!(
            action.apply().unwrap(),
            ApplyOutcome::NeedsHuman(_)
        ));
        assert_eq!(fs::read(&path).unwrap(), existing);
        assert_eq!(
            fs::read_dir(&directory)
                .unwrap()
                .map(|entry| entry.unwrap().file_name())
                .collect::<Vec<_>>(),
            [std::ffi::OsString::from("authorized_keys")]
        );
        fs::remove_dir_all(root).unwrap();
    }
}
