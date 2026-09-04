#![allow(dead_code)] // Task 3 is the first production transport consumer.

use crate::manifest::MachineManifest;
use crate::platform;
use base64::{engine::general_purpose::STANDARD_NO_PAD, Engine as _};
use sha2::{Digest, Sha256};
use std::fmt;
use std::io::{Read as _, Write as _};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicU64, Ordering};

const MAX_CONTROLLER_NAME_BYTES: usize = 64;
const MAX_PUBLIC_KEY_BYTES: usize = 16 * 1024;
static STAGING_SEQUENCE: AtomicU64 = AtomicU64::new(0);

/// A locally-held, per-controller OpenSSH identity.
///
/// Its fields remain private so callers cannot substitute a path or public-key
/// line after this module has validated the pair.
#[derive(Clone, Debug)]
pub(crate) struct ControllerIdentity {
    private_path: PathBuf,
    public_path: PathBuf,
    public_line: String,
    fingerprint: String,
    created: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum IdentityError {
    Invalid,
    Conflict,
    CapabilityUnavailable,
    OperationFailed,
}

impl fmt::Display for IdentityError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Invalid => "controller identity configuration is invalid",
            Self::Conflict => "controller identity files conflict or are insecure",
            Self::CapabilityUnavailable => "OpenSSH ssh-keygen is unavailable",
            Self::OperationFailed => "controller identity operation failed",
        })
    }
}

impl std::error::Error for IdentityError {}

impl ControllerIdentity {
    pub(crate) fn load_or_create(
        manifest: &MachineManifest,
        identity_directory: &Path,
        ssh_keygen: &Path,
    ) -> Result<Self, IdentityError> {
        let name = validated_controller_name(&manifest.name)?;
        let principal = platform::verify_controller_identity_directory(identity_directory)
            .map_err(|_| IdentityError::Conflict)?;
        let basename = format!("styrn_{name}_{}_ed25519", manifest.machine_id.simple());
        let private_path = identity_directory.join(&basename);
        let public_path = private_path.with_extension("pub");
        let lock_path = identity_directory.join(format!(".{basename}.lock"));
        let _lock = platform::lock_controller_identity(&lock_path, &principal)
            .map_err(|_| IdentityError::Conflict)?;

        match std::fs::symlink_metadata(&private_path) {
            Ok(_) => load_existing(&private_path, &public_path, &principal, ssh_keygen),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                if std::fs::symlink_metadata(&public_path).is_ok() {
                    return Err(IdentityError::Conflict);
                }
                create_fresh(
                    name,
                    identity_directory,
                    &private_path,
                    &public_path,
                    &principal,
                    ssh_keygen,
                )
            }
            Err(_) => Err(IdentityError::Conflict),
        }
    }

    pub(crate) fn private_path(&self) -> &Path {
        &self.private_path
    }

    pub(crate) fn public_path(&self) -> &Path {
        &self.public_path
    }

    pub(crate) fn public_line(&self) -> &str {
        &self.public_line
    }

    pub(crate) fn fingerprint(&self) -> &str {
        &self.fingerprint
    }

    pub(crate) const fn created(&self) -> bool {
        self.created
    }
}

fn load_existing(
    private_path: &Path,
    public_path: &Path,
    principal: &platform::WorkerPrincipal,
    ssh_keygen: &Path,
) -> Result<ControllerIdentity, IdentityError> {
    platform::verify_controller_identity_file(private_path, principal)
        .map_err(|_| IdentityError::Conflict)?;
    let derived = derive_public_line(ssh_keygen, private_path)?;

    match std::fs::symlink_metadata(public_path) {
        Ok(_) => {
            platform::verify_controller_identity_file(public_path, principal)
                .map_err(|_| IdentityError::Conflict)?;
            let existing = read_public_line(public_path, principal)?;
            if existing != derived {
                return Err(IdentityError::Conflict);
            }
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            recover_public_file(public_path, &derived, principal)?;
        }
        Err(_) => return Err(IdentityError::Conflict),
    }

    Ok(identity_from_public(
        private_path.to_path_buf(),
        public_path.to_path_buf(),
        derived,
        false,
    ))
}

fn create_fresh(
    name: &str,
    directory: &Path,
    private_path: &Path,
    public_path: &Path,
    principal: &platform::WorkerPrincipal,
    ssh_keygen: &Path,
) -> Result<ControllerIdentity, IdentityError> {
    let staging_private = next_staging_path(directory, "private");
    run_keygen(ssh_keygen, name, &staging_private)?;
    platform::harden_new_controller_identity_file(&staging_private, principal)
        .map_err(|_| IdentityError::Conflict)?;
    let public_line = derive_public_line(ssh_keygen, &staging_private)?;
    let _ = std::fs::remove_file(staging_private.with_extension("pub"));

    let staged =
        platform::adopt_controller_identity_private_publication(&staging_private, principal)
            .map_err(|_| IdentityError::Conflict)?;
    match staged.publish_no_replace_without_reading(private_path) {
        Ok(_) => {}
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
            return load_existing(private_path, public_path, principal, ssh_keygen);
        }
        Err(_) => return Err(IdentityError::Conflict),
    }

    recover_public_file(public_path, &public_line, principal)?;
    Ok(identity_from_public(
        private_path.to_path_buf(),
        public_path.to_path_buf(),
        public_line,
        true,
    ))
}

fn recover_public_file(
    public_path: &Path,
    public_line: &str,
    principal: &platform::WorkerPrincipal,
) -> Result<(), IdentityError> {
    let parent = public_path.parent().ok_or(IdentityError::Invalid)?;
    let staging = next_staging_path(parent, "public");
    let mut file =
        platform::create_private_file(&staging, platform::ManifestOwner::User, principal)
            .map_err(|_| IdentityError::OperationFailed)?;
    file.write_all(public_line.as_bytes())
        .and_then(|()| file.write_all(b"\n"))
        .and_then(|()| file.sync_all())
        .map_err(|_| IdentityError::OperationFailed)?;
    drop(file);
    platform::harden_new_controller_identity_file(&staging, principal)
        .map_err(|_| IdentityError::Conflict)?;

    match std::fs::hard_link(&staging, public_path) {
        Ok(()) => {
            platform::sync_parent_directory(parent).map_err(|_| IdentityError::OperationFailed)?;
            platform::verify_controller_identity_file(public_path, principal)
                .map_err(|_| IdentityError::Conflict)?;
            let published = read_public_line(public_path, principal)?;
            if published != public_line {
                return Err(IdentityError::Conflict);
            }
            let _ = std::fs::remove_file(staging);
            Ok(())
        }
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
            let _ = std::fs::remove_file(staging);
            platform::verify_controller_identity_file(public_path, principal)
                .map_err(|_| IdentityError::Conflict)?;
            (read_public_line(public_path, principal)? == public_line)
                .then_some(())
                .ok_or(IdentityError::Conflict)
        }
        Err(_) => Err(IdentityError::OperationFailed),
    }
}

fn run_keygen(ssh_keygen: &Path, name: &str, staging_private: &Path) -> Result<(), IdentityError> {
    let comment = format!("styrn-{name}");
    let output = bounded_tool_output(
        Command::new(ssh_keygen)
            .args(["-q", "-t", "ed25519", "-N", "", "-C", &comment, "-f"])
            .arg(staging_private),
        0,
    )?;
    output
        .status
        .success()
        .then_some(())
        .ok_or(IdentityError::OperationFailed)
}

fn derive_public_line(ssh_keygen: &Path, private_path: &Path) -> Result<String, IdentityError> {
    let output = bounded_tool_output(
        Command::new(ssh_keygen)
            .args(["-q", "-y", "-f"])
            .arg(private_path),
        MAX_PUBLIC_KEY_BYTES,
    )?;
    if !output.status.success() {
        return Err(IdentityError::Conflict);
    }
    parse_public_line(&output.stdout)
}

fn read_public_line(
    path: &Path,
    principal: &platform::WorkerPrincipal,
) -> Result<String, IdentityError> {
    let identity = platform::private_file_identity(path).map_err(|_| IdentityError::Conflict)?;
    let file = platform::open_verified_private_file_for_read(
        path,
        platform::ManifestOwner::User,
        principal,
        identity,
    )
    .map_err(|_| IdentityError::Conflict)?;
    let metadata = file.metadata().map_err(|_| IdentityError::Conflict)?;
    if metadata.len() == 0 || metadata.len() > MAX_PUBLIC_KEY_BYTES as u64 {
        return Err(IdentityError::Conflict);
    }
    let mut bytes = Vec::with_capacity(metadata.len() as usize);
    file.take(MAX_PUBLIC_KEY_BYTES as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| IdentityError::Conflict)?;
    if bytes.len() > MAX_PUBLIC_KEY_BYTES {
        return Err(IdentityError::Conflict);
    }
    parse_public_line(&bytes)
}

struct ToolOutput {
    status: std::process::ExitStatus,
    stdout: Vec<u8>,
}

fn bounded_tool_output(
    command: &mut Command,
    stdout_limit: usize,
) -> Result<ToolOutput, IdentityError> {
    use std::process::Stdio;

    let mut child = command
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|error| {
            if error.kind() == std::io::ErrorKind::NotFound {
                IdentityError::CapabilityUnavailable
            } else {
                IdentityError::OperationFailed
            }
        })?;
    let stdout = child.stdout.take().ok_or(IdentityError::OperationFailed)?;
    let stderr = child.stderr.take().ok_or(IdentityError::OperationFailed)?;
    let stdout_reader = std::thread::spawn(move || drain_bounded(stdout, stdout_limit));
    let stderr_reader = std::thread::spawn(move || drain_bounded(stderr, 64 * 1024));
    let status = child.wait().map_err(|_| IdentityError::OperationFailed)?;
    let stdout = stdout_reader
        .join()
        .map_err(|_| IdentityError::OperationFailed)?;
    let _ = stderr_reader
        .join()
        .map_err(|_| IdentityError::OperationFailed)?;
    Ok(ToolOutput { status, stdout })
}

fn drain_bounded(mut reader: impl std::io::Read, limit: usize) -> Vec<u8> {
    let mut retained = Vec::new();
    let mut buffer = [0_u8; 8192];
    loop {
        match reader.read(&mut buffer) {
            Ok(0) | Err(_) => return retained,
            Ok(read) => {
                let remaining = limit.saturating_sub(retained.len());
                retained.extend_from_slice(&buffer[..read.min(remaining)]);
            }
        }
    }
}

fn parse_public_line(bytes: &[u8]) -> Result<String, IdentityError> {
    if bytes.is_empty() || bytes.len() > MAX_PUBLIC_KEY_BYTES {
        return Err(IdentityError::Conflict);
    }
    let line = std::str::from_utf8(bytes)
        .map_err(|_| IdentityError::Conflict)?
        .trim_end_matches(['\r', '\n']);
    if line.is_empty() || line.contains(['\r', '\n']) {
        return Err(IdentityError::Conflict);
    }
    let mut fields = line.split_ascii_whitespace();
    let algorithm = fields.next().ok_or(IdentityError::Conflict)?;
    let base64 = fields.next().ok_or(IdentityError::Conflict)?;
    let comment = fields.next();
    if algorithm != "ssh-ed25519"
        || fields.next().is_some()
        || comment.is_some_and(|comment| {
            comment.len() > MAX_CONTROLLER_NAME_BYTES + "styrn-".len()
                || !comment
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
        })
    {
        return Err(IdentityError::Conflict);
    }
    let wire = base64::engine::general_purpose::STANDARD
        .decode(base64)
        .map_err(|_| IdentityError::Conflict)?;
    let expected = b"\0\0\0\x0bssh-ed25519\0\0\0\x20";
    if wire.len() != expected.len() + 32 || !wire.starts_with(expected) {
        return Err(IdentityError::Conflict);
    }
    Ok(format!("ssh-ed25519 {base64}"))
}

fn identity_from_public(
    private_path: PathBuf,
    public_path: PathBuf,
    public_line: String,
    created: bool,
) -> ControllerIdentity {
    let base64 = public_line
        .split_once(' ')
        .expect("validated controller public line has two fields")
        .1;
    let wire = base64::engine::general_purpose::STANDARD
        .decode(base64)
        .expect("validated controller public line remains decodable");
    let fingerprint = format!("SHA256:{}", STANDARD_NO_PAD.encode(Sha256::digest(wire)));
    ControllerIdentity {
        private_path,
        public_path,
        public_line,
        fingerprint,
        created,
    }
}

fn validated_controller_name(value: &str) -> Result<&str, IdentityError> {
    (!value.is_empty()
        && value.len() <= MAX_CONTROLLER_NAME_BYTES
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_')))
    .then_some(value)
    .ok_or(IdentityError::Invalid)
}

fn next_staging_path(directory: &Path, kind: &str) -> PathBuf {
    let sequence = STAGING_SEQUENCE.fetch_add(1, Ordering::Relaxed);
    directory.join(format!(
        ".styrn-identity-{kind}-{}-{sequence}",
        std::process::id()
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[cfg(unix)]
    use std::os::unix::fs::PermissionsExt;

    #[test]
    fn controller_identity_fresh_creation_is_idempotent_and_recovers_a_missing_public_file() {
        let root = std::env::current_dir()
            .unwrap()
            .join("target")
            .join(format!(
                "styrn-controller-identity-{}-{}",
                std::process::id(),
                std::thread::current().name().unwrap_or("test")
            ));
        std::fs::create_dir(&root).unwrap();
        #[cfg(unix)]
        std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o700)).unwrap();
        let ssh_keygen = std::path::Path::new("ssh-keygen");
        let manifest = crate::manifest::MachineManifest::parse_toml(include_str!(
            "../../examples/machine.controller-worker.toml"
        ))
        .unwrap();

        let first = ControllerIdentity::load_or_create(&manifest, &root, ssh_keygen)
            .expect("a fresh controller identity must be created");
        assert!(first.created);
        assert!(first.private_path.is_file());
        assert!(first.public_path.is_file());

        let second = ControllerIdentity::load_or_create(&manifest, &root, ssh_keygen)
            .expect("an existing controller identity must be reused");
        assert!(!second.created);
        assert_eq!(first.public_line, second.public_line);
        assert_eq!(first.fingerprint, second.fingerprint);

        std::fs::remove_file(&first.public_path).unwrap();
        let recovered = ControllerIdentity::load_or_create(&manifest, &root, ssh_keygen)
            .expect("a missing public companion must be recovered from the private key");
        assert!(!recovered.created);
        assert_eq!(first.public_line, recovered.public_line);
        assert!(first.public_path.is_file());

        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn controller_identity_rejects_public_only_and_mismatched_pairs() {
        let root = test_identity_directory("pair-conflict");
        let manifest = test_manifest();
        let ssh_keygen = Path::new("ssh-keygen");
        let public = root.join(format!("{}.pub", test_basename()));

        std::fs::write(&public, b"not a public key\n").unwrap();
        assert_eq!(
            ControllerIdentity::load_or_create(&manifest, &root, ssh_keygen).unwrap_err(),
            IdentityError::Conflict
        );
        assert!(!root.join(test_basename()).exists());
        std::fs::remove_file(&public).unwrap();

        let first = ControllerIdentity::load_or_create(&manifest, &root, ssh_keygen).unwrap();
        let other_root = test_identity_directory("pair-other");
        let other = ControllerIdentity::load_or_create(&manifest, &other_root, ssh_keygen).unwrap();
        std::fs::remove_file(&first.public_path).unwrap();
        let principal = crate::platform::verify_controller_identity_directory(&root).unwrap();
        let mut replacement = crate::platform::create_private_file(
            &first.public_path,
            crate::platform::ManifestOwner::User,
            &principal,
        )
        .unwrap();
        replacement.write_all(other.public_line.as_bytes()).unwrap();
        replacement.write_all(b"\n").unwrap();
        replacement.sync_all().unwrap();
        drop(replacement);

        assert_eq!(
            ControllerIdentity::load_or_create(&manifest, &root, ssh_keygen).unwrap_err(),
            IdentityError::Conflict
        );
        std::fs::remove_dir_all(root).unwrap();
        std::fs::remove_dir_all(other_root).unwrap();
    }

    #[test]
    fn controller_identity_machine_suffix_is_stable_under_concurrent_creation() {
        let root = test_identity_directory("concurrent");
        let manifest = test_manifest();
        let barrier = std::sync::Arc::new(std::sync::Barrier::new(2));
        let first_root = root.clone();
        let first_manifest = manifest.clone();
        let first_barrier = barrier.clone();
        let first = std::thread::spawn(move || {
            first_barrier.wait();
            ControllerIdentity::load_or_create(
                &first_manifest,
                &first_root,
                Path::new("ssh-keygen"),
            )
            .unwrap()
        });
        barrier.wait();
        let second =
            ControllerIdentity::load_or_create(&manifest, &root, Path::new("ssh-keygen")).unwrap();
        let first = first.join().unwrap();

        assert!(first.private_path.ends_with(test_basename()));
        assert_eq!(first.public_line, second.public_line);
        assert_ne!(first.created, second.created);
        std::fs::remove_dir_all(root).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn controller_identity_rejects_link_and_insecure_directory_without_creation() {
        use std::os::unix::fs::symlink;

        let manifest = test_manifest();
        let root = test_identity_directory("link");
        let private = root.join(test_basename());
        let target = root.join("other");
        std::fs::write(&target, b"not-a-key").unwrap();
        symlink(&target, &private).unwrap();
        assert_eq!(
            ControllerIdentity::load_or_create(&manifest, &root, Path::new("ssh-keygen"))
                .unwrap_err(),
            IdentityError::Conflict
        );
        std::fs::remove_dir_all(root).unwrap();

        let root = test_identity_directory("insecure");
        std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o777)).unwrap();
        assert_eq!(
            ControllerIdentity::load_or_create(&manifest, &root, Path::new("ssh-keygen"))
                .unwrap_err(),
            IdentityError::Conflict
        );
        assert!(!root.join(test_basename()).exists());
        std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o700)).unwrap();
        std::fs::remove_dir_all(root).unwrap();
    }

    fn test_manifest() -> crate::manifest::MachineManifest {
        crate::manifest::MachineManifest::parse_toml(include_str!(
            "../../examples/machine.controller-worker.toml"
        ))
        .unwrap()
    }

    fn test_basename() -> String {
        let manifest = test_manifest();
        format!(
            "styrn_{}_{}_ed25519",
            manifest.name,
            manifest.machine_id.simple()
        )
    }

    fn test_identity_directory(label: &str) -> PathBuf {
        let root = std::env::current_dir()
            .unwrap()
            .join("target")
            .join(format!(
                "styrn-controller-identity-{label}-{}",
                std::process::id()
            ));
        std::fs::create_dir(&root).unwrap();
        #[cfg(unix)]
        std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o700)).unwrap();
        root
    }
}
