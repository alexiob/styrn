use super::TransportError;
use super::{validate_host, validate_transport_path, RpcProcess, RpcTarget, RpcTransport};
use base64::engine::general_purpose::{STANDARD, STANDARD_NO_PAD};
use base64::Engine;
use sha2::{Digest, Sha256};
use std::collections::HashSet;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::{Command, ExitStatus, Stdio};
use std::time::{Duration, Instant};

const MAX_KEYSCAN_BYTES: usize = 1024 * 1024;
const MAX_TOOL_STDERR_BYTES: usize = 64 * 1024;
const TOOL_TIMEOUT: Duration = Duration::from_secs(12);

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub(crate) struct PinnedHostKey {
    algorithm: String,
    base64: String,
    fingerprint: String,
}

impl PinnedHostKey {
    pub(crate) fn select_scan(
        bytes: &[u8],
        fingerprint: Option<&str>,
    ) -> Result<Self, TransportError> {
        if bytes.is_empty() || bytes.len() > MAX_KEYSCAN_BYTES {
            return Err(TransportError::authentication());
        }
        let text = std::str::from_utf8(bytes).map_err(|_| TransportError::authentication())?;
        let requested = fingerprint
            .map(validate_fingerprint)
            .transpose()?
            .map(str::to_owned);
        let mut keys = Vec::new();
        let mut seen = HashSet::new();
        for line in text.lines() {
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            let fields = line.split_ascii_whitespace().collect::<Vec<_>>();
            if fields.len() != 3 || fields[0].len() > 512 {
                return Err(TransportError::authentication());
            }
            let algorithm = fields[1];
            if !matches!(algorithm, "ssh-ed25519" | "ecdsa-sha2-nistp256" | "ssh-rsa") {
                continue;
            }
            let encoded = fields[2];
            if encoded.len() > 16 * 1024 {
                return Err(TransportError::authentication());
            }
            let wire = STANDARD
                .decode(encoded)
                .map_err(|_| TransportError::authentication())?;
            validate_public_key_wire(algorithm, &wire)?;
            let canonical = STANDARD.encode(&wire);
            if canonical != encoded {
                return Err(TransportError::authentication());
            }
            let fingerprint = format!("SHA256:{}", STANDARD_NO_PAD.encode(Sha256::digest(&wire)));
            let key = Self {
                algorithm: algorithm.to_owned(),
                base64: canonical,
                fingerprint,
            };
            if seen.insert((key.algorithm.clone(), key.base64.clone())) {
                keys.push(key);
            }
        }

        if let Some(requested) = requested {
            let mut matches = keys.into_iter().filter(|key| key.fingerprint == requested);
            let selected = matches.next().ok_or_else(TransportError::authentication)?;
            if matches.next().is_some() {
                return Err(TransportError::authentication());
            }
            return Ok(selected);
        }

        let best_priority = keys
            .iter()
            .map(|key| algorithm_priority(&key.algorithm))
            .min()
            .ok_or_else(TransportError::authentication)?;
        let mut best = keys
            .into_iter()
            .filter(|key| algorithm_priority(&key.algorithm) == best_priority);
        let selected = best.next().ok_or_else(TransportError::authentication)?;
        if best.next().is_some() {
            return Err(TransportError::authentication());
        }
        Ok(selected)
    }

    pub(crate) fn from_parts(
        algorithm: &str,
        base64: &str,
        fingerprint: &str,
    ) -> Result<Self, TransportError> {
        let line = format!("host {algorithm} {base64}\n");
        let selected = Self::select_scan(&line.into_bytes(), Some(fingerprint))?;
        Ok(selected)
    }

    pub(crate) fn algorithm(&self) -> &str {
        &self.algorithm
    }

    pub(crate) fn base64(&self) -> &str {
        &self.base64
    }

    pub(crate) fn fingerprint(&self) -> &str {
        &self.fingerprint
    }

    pub(crate) fn known_hosts_line(&self, host: &str, port: u16) -> Result<String, TransportError> {
        validate_host(host)?;
        if port == 0 {
            return Err(TransportError::authentication());
        }
        let destination = if port == 22 {
            host.to_owned()
        } else {
            format!("[{host}]:{port}")
        };
        Ok(format!(
            "{destination} {} {}\n",
            self.algorithm, self.base64
        ))
    }

    #[cfg(test)]
    pub(super) fn local_for_test() -> Self {
        Self {
            algorithm: "ssh-ed25519".to_owned(),
            base64: String::new(),
            fingerprint: "SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".to_owned(),
        }
    }
}

pub(crate) struct SshTransport {
    ssh: PathBuf,
    keyscan: PathBuf,
    known_hosts: PathBuf,
}

impl SshTransport {
    pub(crate) fn new(ssh: PathBuf, keyscan: PathBuf, known_hosts: PathBuf) -> Self {
        Self {
            ssh,
            keyscan,
            known_hosts,
        }
    }

    pub(crate) fn configured(known_hosts: PathBuf) -> Self {
        let ssh = std::env::var_os("STYRN_SSH")
            .filter(|value| !value.is_empty())
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from("ssh"));
        Self::new(ssh, PathBuf::from("ssh-keyscan"), known_hosts)
    }

    pub(crate) fn scan_host_key(
        &self,
        host: &str,
        port: u16,
        fingerprint: Option<&str>,
    ) -> Result<PinnedHostKey, TransportError> {
        let arguments = ssh_keyscan_arguments(host, port)?;
        let output = run_bounded_tool(&self.keyscan, &arguments, TOOL_TIMEOUT, MAX_KEYSCAN_BYTES)?;
        if !output.status.success() {
            return Err(TransportError::unreachable());
        }
        PinnedHostKey::select_scan(&output.stdout, fingerprint)
    }

    pub(crate) fn scan_host_key_for_setup(
        &self,
        host: &str,
        port: u16,
        fingerprint: Option<&str>,
    ) -> Result<PinnedHostKey, TransportError> {
        let arguments = ssh_keyscan_arguments(host, port)?;
        let output = run_bounded_tool_with_environment(
            &self.keyscan,
            &arguments,
            TOOL_TIMEOUT,
            MAX_KEYSCAN_BYTES,
            ToolEnvironment::Clean,
        )?;
        if !output.status.success() {
            return Err(TransportError::unreachable());
        }
        PinnedHostKey::select_scan(&output.stdout, fingerprint)
    }

    pub(crate) fn verify_host_key(&self, target: &RpcTarget) -> Result<(), TransportError> {
        let arguments = ssh_keyscan_arguments(target.host(), target.port())?;
        let output = run_bounded_tool(&self.keyscan, &arguments, TOOL_TIMEOUT, MAX_KEYSCAN_BYTES)?;
        if !output.status.success() {
            return Err(TransportError::unreachable());
        }
        verify_scanned_host_key(target, &output.stdout)
    }
}

pub(crate) fn verify_scanned_host_key(
    target: &RpcTarget,
    scan: &[u8],
) -> Result<(), TransportError> {
    let observed = PinnedHostKey::select_scan(scan, Some(target.host_key().fingerprint()))?;
    if observed == *target.host_key() {
        Ok(())
    } else {
        Err(TransportError::authentication())
    }
}

impl RpcTransport for SshTransport {
    fn connect(&self, target: &RpcTarget) -> Result<RpcProcess, TransportError> {
        self.verify_host_key(target)?;
        let arguments = ssh_arguments(target, &self.known_hosts)?;
        let mut command = Command::new(&self.ssh);
        command
            .args(arguments)
            .env_remove("STYRN_JSON")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        let mut child = command.spawn().map_err(|error| {
            if error.kind() == std::io::ErrorKind::NotFound {
                TransportError::capability_unavailable()
            } else {
                TransportError::authentication()
            }
        })?;
        let input = child
            .stdin
            .take()
            .ok_or_else(TransportError::authentication)?;
        let output = child
            .stdout
            .take()
            .ok_or_else(TransportError::authentication)?;
        let stderr = child
            .stderr
            .take()
            .ok_or_else(TransportError::authentication)?;
        Ok(RpcProcess::new_ssh(child, input, output, stderr))
    }
}

pub(crate) fn ssh_keyscan_arguments(host: &str, port: u16) -> Result<Vec<String>, TransportError> {
    validate_host(host)?;
    if port == 0 {
        return Err(TransportError::authentication());
    }
    Ok(vec![
        "-T".to_owned(),
        "10".to_owned(),
        "-p".to_owned(),
        port.to_string(),
        "-t".to_owned(),
        "ed25519,ecdsa,rsa".to_owned(),
        "--".to_owned(),
        host.to_owned(),
    ])
}

pub(crate) fn ssh_arguments(
    target: &RpcTarget,
    known_hosts: &Path,
) -> Result<Vec<String>, TransportError> {
    let identity = validate_transport_path(target.identity())?;
    let known_hosts = validate_transport_path(known_hosts)?;
    Ok(vec![
        "-T".to_owned(),
        "-oBatchMode=yes".to_owned(),
        "-oIdentitiesOnly=yes".to_owned(),
        "-oStrictHostKeyChecking=yes".to_owned(),
        format!("-oUserKnownHostsFile={known_hosts}"),
        "-oGlobalKnownHostsFile=none".to_owned(),
        "-oCheckHostIP=no".to_owned(),
        "-oConnectTimeout=10".to_owned(),
        "-oConnectionAttempts=1".to_owned(),
        "-i".to_owned(),
        identity.to_owned(),
        "-p".to_owned(),
        target.port().to_string(),
        "--".to_owned(),
        format!("{}@{}", target.user(), target.host()),
        "styrn rpc serve --stdio".to_owned(),
    ])
}

fn validate_fingerprint(value: &str) -> Result<&str, TransportError> {
    let encoded = value
        .strip_prefix("SHA256:")
        .ok_or_else(TransportError::authentication)?;
    if encoded.len() != 43 || encoded.contains('=') {
        return Err(TransportError::authentication());
    }
    let decoded = STANDARD_NO_PAD
        .decode(encoded)
        .map_err(|_| TransportError::authentication())?;
    if decoded.len() == 32 && STANDARD_NO_PAD.encode(decoded) == encoded {
        Ok(value)
    } else {
        Err(TransportError::authentication())
    }
}

pub(crate) fn validate_host_key_fingerprint(value: &str) -> Result<(), TransportError> {
    validate_fingerprint(value).map(|_| ())
}

fn algorithm_priority(algorithm: &str) -> u8 {
    match algorithm {
        "ssh-ed25519" => 0,
        "ecdsa-sha2-nistp256" => 1,
        "ssh-rsa" => 2,
        _ => u8::MAX,
    }
}

fn validate_public_key_wire(algorithm: &str, mut wire: &[u8]) -> Result<(), TransportError> {
    if take_ssh_string(&mut wire)? != algorithm.as_bytes() {
        return Err(TransportError::authentication());
    }
    match algorithm {
        "ssh-ed25519" => {
            if take_ssh_string(&mut wire)?.len() != 32 || !wire.is_empty() {
                return Err(TransportError::authentication());
            }
        }
        "ecdsa-sha2-nistp256" => {
            if take_ssh_string(&mut wire)? != b"nistp256" {
                return Err(TransportError::authentication());
            }
            let point = take_ssh_string(&mut wire)?;
            if point.len() != 65 || point.first() != Some(&4) || !wire.is_empty() {
                return Err(TransportError::authentication());
            }
        }
        "ssh-rsa" => {
            let exponent = take_ssh_string(&mut wire)?;
            let modulus = take_ssh_string(&mut wire)?;
            if exponent.is_empty() || modulus.len() < 256 || !wire.is_empty() {
                return Err(TransportError::authentication());
            }
        }
        _ => return Err(TransportError::authentication()),
    }
    Ok(())
}

fn take_ssh_string<'a>(wire: &mut &'a [u8]) -> Result<&'a [u8], TransportError> {
    let length = wire
        .get(..4)
        .and_then(|bytes| bytes.try_into().ok())
        .map(u32::from_be_bytes)
        .ok_or_else(TransportError::authentication)? as usize;
    let value = wire
        .get(4..4 + length)
        .ok_or_else(TransportError::authentication)?;
    *wire = &wire[4 + length..];
    Ok(value)
}

struct ToolOutput {
    status: ExitStatus,
    stdout: Vec<u8>,
}

fn run_bounded_tool(
    executable: &Path,
    arguments: &[String],
    timeout: Duration,
    stdout_limit: usize,
) -> Result<ToolOutput, TransportError> {
    run_bounded_tool_with_environment(
        executable,
        arguments,
        timeout,
        stdout_limit,
        ToolEnvironment::Inherited,
    )
}

#[derive(Clone, Copy)]
enum ToolEnvironment {
    Inherited,
    Clean,
}

fn run_bounded_tool_with_environment(
    executable: &Path,
    arguments: &[String],
    timeout: Duration,
    stdout_limit: usize,
    environment: ToolEnvironment,
) -> Result<ToolOutput, TransportError> {
    let mut command = Command::new(executable);
    command.args(arguments);
    match environment {
        ToolEnvironment::Inherited => {
            command.env_remove("STYRN_JSON");
        }
        ToolEnvironment::Clean => {
            command.env_clear();
            #[cfg(windows)]
            if let Some(system_root) = executable
                .parent()
                .and_then(Path::parent)
                .and_then(Path::parent)
            {
                command.env("SystemRoot", system_root);
            }
        }
    }
    let mut child = command
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|error| {
            if error.kind() == std::io::ErrorKind::NotFound {
                TransportError::capability_unavailable()
            } else {
                TransportError::unreachable()
            }
        })?;
    let stdout = child
        .stdout
        .take()
        .ok_or_else(TransportError::unreachable)?;
    let stderr = child
        .stderr
        .take()
        .ok_or_else(TransportError::unreachable)?;
    let stdout_reader = std::thread::spawn(move || read_bounded(stdout, stdout_limit));
    let stderr_reader = std::thread::spawn(move || read_bounded(stderr, MAX_TOOL_STDERR_BYTES));
    let started = Instant::now();
    let status = loop {
        match child.try_wait() {
            Ok(Some(status)) => break status,
            Ok(None) if started.elapsed() < timeout => {
                std::thread::sleep(Duration::from_millis(10));
            }
            Ok(None) | Err(_) => {
                let _ = child.kill();
                let _ = child.wait();
                let _ = stdout_reader.join();
                let _ = stderr_reader.join();
                return Err(TransportError::unreachable());
            }
        }
    };
    let (stdout, overflowed) = stdout_reader
        .join()
        .map_err(|_| TransportError::unreachable())??;
    let _ = stderr_reader
        .join()
        .map_err(|_| TransportError::unreachable())??;
    if overflowed {
        return Err(TransportError::authentication());
    }
    Ok(ToolOutput { status, stdout })
}

#[cfg(all(test, unix))]
mod setup_scanner_tests {
    use super::{PinnedHostKey, SshTransport};
    use std::os::unix::fs::PermissionsExt;

    #[test]
    fn setup_host_key_scan_does_not_inherit_the_callers_environment() {
        assert!(std::env::var_os("HOME").is_some());
        let root = std::env::current_dir()
            .unwrap()
            .join("target")
            .join(format!("styrn-clean-keyscan-{}", uuid::Uuid::now_v7()));
        std::fs::create_dir_all(&root).unwrap();
        let scanner = root.join("ssh-keyscan");
        std::fs::write(
            &scanner,
            b"#!/bin/sh\nif [ \"${HOME+x}\" = x ]; then exit 9; fi\nprintf '%s\\n' 'worker.example ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIAABAgMEBQYHCAkKCwwNDg8QERITFBUWFxgZGhscHR4f'\n",
        )
        .unwrap();
        std::fs::set_permissions(&scanner, std::fs::Permissions::from_mode(0o700)).unwrap();
        let transport = SshTransport::new(root.join("unused"), scanner, root.join("known_hosts"));

        assert!(transport.scan_host_key("worker.example", 22, None).is_err());
        let key = transport
            .scan_host_key_for_setup("worker.example", 22, None)
            .unwrap();
        assert_eq!(
            key,
            PinnedHostKey::from_parts(
                "ssh-ed25519",
                "AAAAC3NzaC1lZDI1NTE5AAAAIAABAgMEBQYHCAkKCwwNDg8QERITFBUWFxgZGhscHR4f",
                "SHA256:ZkAslGjFiUHdGf/WUL8rQvkib4PTvQatUV0OUQSncCA",
            )
            .unwrap()
        );
        std::fs::remove_dir_all(root).unwrap();
    }
}

fn read_bounded(mut reader: impl Read, limit: usize) -> Result<(Vec<u8>, bool), TransportError> {
    let mut bytes = Vec::new();
    reader
        .by_ref()
        .take(limit as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| TransportError::unreachable())?;
    let overflowed = bytes.len() > limit;
    bytes.truncate(limit);
    Ok((bytes, overflowed))
}
