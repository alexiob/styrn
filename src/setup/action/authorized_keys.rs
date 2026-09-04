use super::{
    Action, ActionCheck, ActionDescription, ActionEffect, ActionError, ActionName,
    ActionParameters, ActionPlan, AppendedFileEffect, CreatedDirectoryEffect, CreatedFileEffect,
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
        initial_identity: Option<platform::PrivateFileIdentity>,
        required: Vec<String>,
        stanza_id: Option<String>,
        stanza: Vec<u8>,
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
    let (initial_identity, initial_bytes, missing, mut conflict) = match state {
        DirectoryState::Absent => (None, 0, deduplicated(keys), false),
        DirectoryState::Ready => match read_keys(&path, &principal) {
            Ok(None) => (None, 0, deduplicated(keys), false),
            Ok(Some(file)) => match analyze_keys(&file.bytes, keys) {
                Some(analysis) => (
                    Some(file.identity),
                    file.bytes.len(),
                    analysis.missing,
                    analysis.conflict,
                ),
                None => (Some(file.identity), file.bytes.len(), Vec::new(), true),
            },
            Err(()) => (None, 0, Vec::new(), true),
        },
        DirectoryState::Conflict => (None, 0, Vec::new(), true),
    };
    let (stanza_id, stanza) = if conflict || missing.is_empty() {
        (None, Vec::new())
    } else {
        let payload = missing
            .iter()
            .flat_map(|key| [key.as_bytes(), b"\n"].concat())
            .collect::<Vec<_>>();
        let (stanza_id, stanza) = if initial_identity.is_some() {
            let stanza_id = sha256(&payload);
            let mut stanza = format!("# styrn:begin {stanza_id}\n").into_bytes();
            stanza.extend_from_slice(&payload);
            stanza.extend_from_slice(format!("# styrn:end {stanza_id}\n").as_bytes());
            (Some(stanza_id), stanza)
        } else {
            (None, payload)
        };
        let added = stanza.len() + usize::from(initial_identity.is_some());
        if initial_bytes
            .checked_add(added)
            .is_none_or(|size| size > MAX_BYTES)
        {
            conflict = true;
        }
        (stanza_id, stanza)
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
            initial_identity,
            required: keys.to_vec(),
            stanza_id,
            stanza,
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

struct KeyFile {
    identity: platform::PrivateFileIdentity,
    bytes: Vec<u8>,
}

fn read_keys(path: &Path, principal: &WorkerPrincipal) -> Result<Option<KeyFile>, ()> {
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
    Ok(Some(KeyFile { identity, bytes }))
}

fn append_keys(before: &[u8], required: &[String]) -> Option<Vec<u8>> {
    let analysis = analyze_keys(before, required)?;
    if analysis.conflict {
        return None;
    }
    let payload = analysis
        .missing
        .iter()
        .flat_map(|key| [key.as_bytes(), b"\n"].concat())
        .collect::<Vec<_>>();
    let stanza_id = sha256(&payload);
    let mut after = before.to_vec();
    if !payload.is_empty() {
        if !after.is_empty() && !after.ends_with(b"\n") {
            after.push(b'\n');
        }
        after.extend_from_slice(format!("# styrn:begin {stanza_id}\n").as_bytes());
        after.extend_from_slice(&payload);
        after.extend_from_slice(format!("# styrn:end {stanza_id}\n").as_bytes());
    }
    (after.len() <= MAX_BYTES).then_some(after)
}

struct KeyAnalysis {
    missing: Vec<String>,
    conflict: bool,
}

fn analyze_keys(before: &[u8], required: &[String]) -> Option<KeyAnalysis> {
    let text = std::str::from_utf8(before).ok()?;
    validate_owned_markers(text)?;
    let required_identities = required
        .iter()
        .map(|key| key_identity(key))
        .collect::<Option<Vec<_>>>()?;
    let mut unrestricted = HashSet::new();
    let mut constrained = HashSet::new();
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if let Some((identity, is_constrained)) = active_key_identity(line) {
            if is_constrained {
                constrained.insert(identity);
            } else {
                unrestricted.insert(identity);
            }
        } else if required_identities
            .iter()
            .any(|identity| contains_key_identity(line, identity))
        {
            return Some(KeyAnalysis {
                missing: Vec::new(),
                conflict: true,
            });
        }
    }
    let conflict = required_identities
        .iter()
        .any(|identity| constrained.contains(identity) && !unrestricted.contains(identity));
    let mut seen = HashSet::new();
    let missing = required
        .iter()
        .zip(required_identities)
        .filter(|(_, identity)| !unrestricted.contains(identity))
        .filter(|(_, identity)| seen.insert(identity.clone()))
        .map(|(key, _)| key.clone())
        .collect();
    Some(KeyAnalysis { missing, conflict })
}

fn contains_key_identity(line: &str, identity: &(String, String)) -> bool {
    let fields = line.split_ascii_whitespace().collect::<Vec<_>>();
    fields
        .windows(2)
        .any(|fields| fields[0] == identity.0 && fields[1] == identity.1)
}

fn validate_owned_markers(text: &str) -> Option<()> {
    let mut open: Option<(&str, Vec<u8>)> = None;
    for raw_line in text.lines() {
        let line = raw_line.trim();
        if let Some(stanza_id) = line.strip_prefix("# styrn:begin ") {
            if open.is_some() || !valid_stanza_id(stanza_id) {
                return None;
            }
            open = Some((stanza_id, Vec::new()));
        } else if let Some(stanza_id) = line.strip_prefix("# styrn:end ") {
            let (expected, payload) = open.take()?;
            if expected != stanza_id || !valid_stanza_id(stanza_id) || sha256(&payload) != stanza_id
            {
                return None;
            }
        } else if let Some((_, payload)) = &mut open {
            if raw_line != line || key_identity(line).is_none() {
                return None;
            }
            payload.extend_from_slice(line.as_bytes());
            payload.push(b'\n');
        }
    }
    open.is_none().then_some(())
}

fn valid_stanza_id(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn deduplicated(keys: &[String]) -> Vec<String> {
    let mut seen = HashSet::new();
    keys.iter()
        .filter(|key| seen.insert(key_identity(key).expect("validated authorized key")))
        .cloned()
        .collect()
}

fn active_key_identity(line: &str) -> Option<((String, String), bool)> {
    if let Some(identity) = key_identity(line) {
        return Some((identity, false));
    }
    let mut quoted = false;
    let mut escaped = false;
    for (offset, character) in line.char_indices() {
        if escaped {
            escaped = false;
        } else if character == '\\' && quoted {
            escaped = true;
        } else if character == '"' {
            quoted = !quoted;
        } else if character.is_ascii_whitespace() && !quoted {
            let key = line[offset..].trim_start();
            return (!key.is_empty())
                .then(|| key_identity(key))
                .flatten()
                .map(|id| (id, true));
        }
    }
    None
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
                None,
                None,
            )),
            Self::Keys {
                name,
                principal,
                directory,
                path,
                stanza_id,
                stanza,
                ..
            } => ActionParameters::CurrentUserSsh(CurrentUserSshActionParameters::new(
                name.clone(),
                principal.clone(),
                directory.clone(),
                path.clone(),
                stanza_id.clone(),
                stanza_id.as_ref().map(|_| sha256(&append_stanza(stanza))),
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
                initial_identity,
                required,
                stanza,
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
                match (initial_identity, current) {
                    (None, None) if !stanza.is_empty() => ActionCheck::Todo,
                    (None, Some(file)) => match analyze_keys(&file.bytes, required) {
                        Some(analysis) if !analysis.conflict && analysis.missing.is_empty() => {
                            ActionCheck::Done
                        }
                        _ => ActionCheck::NeedsHuman(needs_human()),
                    },
                    (Some(expected), Some(file)) if *expected == file.identity => {
                        match analyze_keys(&file.bytes, required) {
                            Some(analysis) if analysis.conflict => {
                                ActionCheck::NeedsHuman(needs_human())
                            }
                            Some(analysis) if analysis.missing.is_empty() => ActionCheck::Done,
                            Some(_) if !stanza.is_empty() => ActionCheck::Todo,
                            _ => ActionCheck::NeedsHuman(needs_human()),
                        }
                    }
                    _ => ActionCheck::NeedsHuman(needs_human()),
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
                initial_identity,
                stanza,
                conflict,
                ..
            } => {
                if *conflict {
                    PlanOperation::NeedsHuman
                } else if stanza.is_empty() {
                    PlanOperation::Done
                } else if initial_identity.is_none() {
                    PlanOperation::Create
                } else {
                    PlanOperation::Reconfigure
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
                initial_identity: None,
                stanza_id: None,
                stanza,
                conflict: false,
                ..
            } if !stanza.is_empty() => Ok(keys_effect(path, stanza)),
            Self::Keys {
                path,
                initial_identity: Some(_),
                stanza_id: Some(stanza_id),
                stanza,
                conflict: false,
                ..
            } if !stanza.is_empty() => Ok(appended_keys_effect(
                path,
                stanza_id,
                &append_stanza(stanza),
            )),
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
                initial_identity: None,
                stanza_id: None,
                stanza,
                conflict: false,
                ..
            } if !stanza.is_empty() => {
                if inspect_directory(directory, principal) != DirectoryState::Ready
                    || read_keys(path, principal)
                        .map_err(|_| ActionError::apply_failed(name.clone()))?
                        .is_some()
                {
                    return Err(ActionError::apply_failed(name.clone()));
                }
                publish_keys(directory, path, principal, stanza, name)?;
                Ok(keys_effect(path, stanza))
            }
            Self::Keys {
                name,
                principal,
                path,
                initial_identity: Some(initial_identity),
                required,
                stanza_id: Some(stanza_id),
                stanza,
                conflict: false,
                ..
            } if !stanza.is_empty() => {
                let appended = append_stanza(stanza);
                let mut file = platform::open_verified_private_file_for_append(
                    path,
                    ManifestOwner::User,
                    principal,
                    *initial_identity,
                )
                .map_err(|_| ActionError::apply_failed(name.clone()))?;
                let latest = file
                    .read_bounded(MAX_BYTES)
                    .map_err(|_| ActionError::apply_failed(name.clone()))?;
                let latest_analysis = analyze_keys(&latest, required)
                    .ok_or_else(|| ActionError::apply_failed(name.clone()))?;
                if latest_analysis.conflict
                    || latest_analysis.missing.is_empty()
                    || latest
                        .len()
                        .checked_add(appended.len())
                        .is_none_or(|size| size > MAX_BYTES)
                {
                    return Err(ActionError::apply_failed(name.clone()));
                }
                file.append_once(&appended)
                    .map_err(|_| ActionError::apply_failed(name.clone()))?;
                let verified = read_keys(path, principal)
                    .map_err(|_| ActionError::apply_failed(name.clone()))?
                    .ok_or_else(|| ActionError::apply_failed(name.clone()))?;
                if verified.identity != *initial_identity
                    || analyze_keys(&verified.bytes, required)
                        .is_none_or(|analysis| analysis.conflict || !analysis.missing.is_empty())
                {
                    return Err(ActionError::apply_failed(name.clone()));
                }
                Ok(appended_keys_effect(path, stanza_id, &appended))
            }
            _ => Err(ActionError::apply_failed(self.name().clone())),
        }
    }
}

fn append_stanza(stanza: &[u8]) -> Vec<u8> {
    let mut appended = Vec::with_capacity(stanza.len() + 1);
    appended.push(b'\n');
    appended.extend_from_slice(stanza);
    appended
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
        if read_keys(path, principal)
            .ok()
            .flatten()
            .is_none_or(|file| file.bytes != after)
        {
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
        files_appended: Vec::new(),
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
        files_appended: Vec::new(),
        services: Vec::new(),
        accounts: Vec::new(),
        registry_keys: Vec::new(),
        firewall_rules: Vec::new(),
        download_provenance: None,
    }
}

fn appended_keys_effect(path: &Path, stanza_id: &str, appended: &[u8]) -> ActionEffect {
    ActionEffect {
        directories_created: Vec::new(),
        files_created: Vec::new(),
        files_modified: Vec::new(),
        files_appended: vec![AppendedFileEffect {
            path: path.to_string_lossy().into_owned(),
            stanza_id: stanza_id.to_owned(),
            appended_sha256: sha256(appended),
        }],
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
    use std::{fs, io::Write as _};

    const KEY: &str = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIAABAgMEBQYHCAkKCwwNDg8QERITFBUWFxgZGhscHR4f styrn-controller";
    const OTHER_KEY: &str = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjI unrelated";
    const ECDSA_KEY: &str = "ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBBv758VSxSS4n8MUARrxVhXcOdN2IPbneesWHi3aqY6F/eR62SRClVCI+qsEXeVqN97axH+BfF4qWlkKmOLc9zo= unrelated-ecdsa";
    const CERTIFICATE_KEY: &str = "ssh-ed25519-cert-v01@openssh.com AAAAIHNzaC1lZDI1NTE5LWNlcnQtdjAxQG9wZW5zc2guY29tAAAAIMAyy2i16Sp1rHKXmzNRO/Z+oYYVwCYhmwhBymMORjs7AAAAIHkSBu1ocHj8E6vBLP70qtLsffWiX49xLkzU1+/mJROJAAAAAAAAAAAAAAABAAAACXVucmVsYXRlZAAAAAgAAAAEYWxleAAAAABqmp/EAAAAAGqarkYAAAAAAAAAggAAABVwZXJtaXQtWDExLWZvcndhcmRpbmcAAAAAAAAAF3Blcm1pdC1hZ2VudC1mb3J3YXJkaW5nAAAAAAAAABZwZXJtaXQtcG9ydC1mb3J3YXJkaW5nAAAAAAAAAApwZXJtaXQtcHR5AAAAAAAAAA5wZXJtaXQtdXNlci1yYwAAAAAAAAAAAAAAMwAAAAtzc2gtZWQyNTUxOQAAACBUGzk1FGId+VEViGiDBHDqM3qrJuICuqqRaZfLHGrV6QAAAFMAAAALc3NoLWVkMjU1MTkAAABALPZrwaof8FCW1lUrE8dSxkFHse6wF8doet+FRL8EUAUNDY5jM7X6511LUjsxQUP6wLraB48SKFbH3E6p4+dtCA== unrelated-cert";

    #[test]
    fn constrained_active_lines_fail_closed_instead_of_becoming_unrestricted_duplicates() {
        let before = format!("from=\"10.0.0.1\" {KEY}\n");
        assert!(append_keys(before.as_bytes(), &[KEY.to_owned()]).is_none());
    }

    #[test]
    fn unrelated_constrained_keys_do_not_block_an_owned_append() {
        let before = format!("from=\"10.0.0.1\" {OTHER_KEY}\n");
        let after = append_keys(before.as_bytes(), &[KEY.to_owned()]).unwrap();
        assert!(after.starts_with(before.as_bytes()));
        assert!(after
            .windows(KEY.len())
            .any(|window| window == KEY.as_bytes()));
    }

    #[test]
    fn unrelated_unknown_and_malformed_lines_are_preserved_opaquely() {
        let before = format!(
            "{ECDSA_KEY}\n{CERTIFICATE_KEY}\noperator-owned syntax Styrn does not understand\n"
        );
        let after = append_keys(before.as_bytes(), &[KEY.to_owned()]).unwrap();
        assert!(after.starts_with(before.as_bytes()));
        assert!(after
            .windows(KEY.len())
            .any(|window| window == KEY.as_bytes()));
    }

    #[test]
    fn partial_owned_marker_fails_closed_before_another_stanza_is_added() {
        let before = format!(
            "# styrn:begin 98ff7af609c65c1d80216da6639b7237639791245203f28402d2237d6a91a1ae\n{KEY}\n"
        );
        assert!(append_keys(before.as_bytes(), &[KEY.to_owned()]).is_none());
    }

    #[test]
    fn owned_marker_with_mismatched_payload_hash_fails_closed() {
        let before = format!(
            "# styrn:begin aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\n{KEY}\n# styrn:end aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\n"
        );
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
    fn existing_authorized_keys_keeps_external_bytes_and_accepts_an_owned_append() {
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
        let existing = format!("# operator-owned\n{OTHER_KEY}\n");
        fs::write(&path, existing.as_bytes()).unwrap();
        platform::harden_manifest_file(&path, ManifestOwner::User, &principal).unwrap();
        let mut plan =
            current_user_ssh_action_plan_for_test(principal, directory.clone(), &[KEY.to_owned()])
                .unwrap();
        let mut action = plan.remove(1);
        assert!(matches!(action, Action::CurrentUserSsh(_)));
        let concurrent = b"# appended by another tool after planning\n";
        fs::OpenOptions::new()
            .append(true)
            .open(&path)
            .unwrap()
            .write_all(concurrent)
            .unwrap();

        let parameters = action.parameters();
        let ActionParameters::CurrentUserSsh(parameters) = parameters else {
            panic!("current-user SSH parameters expected")
        };
        assert_eq!(
            parameters.owned_stanza_id(),
            Some("98ff7af609c65c1d80216da6639b7237639791245203f28402d2237d6a91a1ae")
        );
        let ApplyOutcome::Applied(effect) = action.apply().unwrap() else {
            panic!("existing authorized_keys was not appended")
        };
        assert!(effect.files_created().is_empty());
        assert!(effect.files_modified().is_empty());
        assert_eq!(effect.files_appended().len(), 1);
        assert_eq!(
            effect.files_appended()[0].stanza_id(),
            "98ff7af609c65c1d80216da6639b7237639791245203f28402d2237d6a91a1ae"
        );
        assert_eq!(
            parameters.owned_stanza_sha256(),
            Some(effect.files_appended()[0].appended_sha256())
        );
        let mut expected = [existing.as_bytes(), concurrent.as_slice()].concat();
        expected.extend_from_slice(
            b"\n# styrn:begin 98ff7af609c65c1d80216da6639b7237639791245203f28402d2237d6a91a1ae\n",
        );
        expected.extend_from_slice(KEY.as_bytes());
        expected.extend_from_slice(
            b"\n# styrn:end 98ff7af609c65c1d80216da6639b7237639791245203f28402d2237d6a91a1ae\n",
        );
        assert_eq!(fs::read(&path).unwrap(), expected);
        assert_eq!(
            fs::read_dir(&directory)
                .unwrap()
                .map(|entry| entry.unwrap().file_name())
                .collect::<Vec<_>>(),
            [std::ffi::OsString::from("authorized_keys")]
        );
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn execute_rechecks_latest_bytes_and_does_not_append_after_external_convergence() {
        let principal = platform::resolve_current_worker_principal().unwrap();
        let root = std::env::current_dir()
            .unwrap()
            .join("target")
            .join(format!(
                "styrn-authorized-keys-execute-race-{}",
                uuid::Uuid::now_v7()
            ));
        let directory = root.join(".ssh");
        fs::create_dir_all(&directory).unwrap();
        platform::harden_manifest_directory(&root, ManifestOwner::User, &principal).unwrap();
        platform::harden_manifest_directory(&directory, ManifestOwner::User, &principal).unwrap();
        let path = directory.join("authorized_keys");
        fs::write(&path, format!("{OTHER_KEY}\n")).unwrap();
        platform::harden_manifest_file(&path, ManifestOwner::User, &principal).unwrap();
        let mut plan =
            current_user_ssh_action_plan_for_test(principal, directory, &[KEY.to_owned()]).unwrap();
        let action = plan.remove(1);
        let externally_converged = format!("{OTHER_KEY}\n{KEY}\n");
        fs::OpenOptions::new()
            .append(true)
            .open(&path)
            .unwrap()
            .write_all(format!("{KEY}\n").as_bytes())
            .unwrap();

        let Action::CurrentUserSsh(action) = action else {
            panic!("SSH key action expected")
        };
        assert!(action.execute().is_err());
        assert_eq!(fs::read(&path).unwrap(), externally_converged.as_bytes());
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn execute_rechecks_latest_bytes_and_refuses_a_new_constraint_on_the_requested_key() {
        let principal = platform::resolve_current_worker_principal().unwrap();
        let root = std::env::current_dir()
            .unwrap()
            .join("target")
            .join(format!(
                "styrn-authorized-keys-constraint-race-{}",
                uuid::Uuid::now_v7()
            ));
        let directory = root.join(".ssh");
        fs::create_dir_all(&directory).unwrap();
        platform::harden_manifest_directory(&root, ManifestOwner::User, &principal).unwrap();
        platform::harden_manifest_directory(&directory, ManifestOwner::User, &principal).unwrap();
        let path = directory.join("authorized_keys");
        fs::write(&path, format!("{OTHER_KEY}\n")).unwrap();
        platform::harden_manifest_file(&path, ManifestOwner::User, &principal).unwrap();
        let mut plan =
            current_user_ssh_action_plan_for_test(principal, directory, &[KEY.to_owned()]).unwrap();
        let action = plan.remove(1);
        let constrained = format!("{OTHER_KEY}\nfrom=\"10.0.0.1\" {KEY}\n");
        fs::OpenOptions::new()
            .append(true)
            .open(&path)
            .unwrap()
            .write_all(format!("from=\"10.0.0.1\" {KEY}\n").as_bytes())
            .unwrap();

        let Action::CurrentUserSsh(action) = action else {
            panic!("SSH key action expected")
        };
        assert!(action.execute().is_err());
        assert_eq!(fs::read(&path).unwrap(), constrained.as_bytes());
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn an_existing_owned_stanza_makes_the_action_byte_identical_on_rerun() {
        let principal = platform::resolve_current_worker_principal().unwrap();
        let root = std::env::current_dir()
            .unwrap()
            .join("target")
            .join(format!(
                "styrn-authorized-keys-rerun-{}",
                uuid::Uuid::now_v7()
            ));
        let directory = root.join(".ssh");
        fs::create_dir_all(&directory).unwrap();
        platform::harden_manifest_directory(&root, ManifestOwner::User, &principal).unwrap();
        platform::harden_manifest_directory(&directory, ManifestOwner::User, &principal).unwrap();
        let path = directory.join("authorized_keys");
        let bytes = append_keys(b"# existing\n", &[KEY.to_owned()]).unwrap();
        fs::write(&path, &bytes).unwrap();
        platform::harden_manifest_file(&path, ManifestOwner::User, &principal).unwrap();

        let mut plan =
            current_user_ssh_action_plan_for_test(principal, directory, &[KEY.to_owned()]).unwrap();
        assert!(matches!(
            plan.remove(1).apply().unwrap(),
            ApplyOutcome::Noop
        ));
        assert_eq!(fs::read(&path).unwrap(), bytes);
        fs::remove_dir_all(root).unwrap();
    }
}
