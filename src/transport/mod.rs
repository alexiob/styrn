mod identity;
mod local_child;
mod ssh;

#[allow(unused_imports)]
// The live controller CLI consumer lands in this continuous Task 2-4 wave.
pub(crate) use identity::{ControllerIdentity, IdentityError};
#[allow(unused_imports)]
// The Task 1 integration target consumes this before the public host CLI is wired.
pub(crate) use local_child::LocalChildTransport;
#[allow(unused_imports)] // Source-including tests exercise different transport subsets.
pub(crate) use ssh::{
    ssh_arguments, ssh_keyscan_arguments, verify_scanned_host_key, PinnedHostKey, SshTransport,
};

use crate::output::ErrorCode;
use crate::rpc::frame::{Frame, FrameError, FrameReader, FrameWriter};
use std::fmt;
use std::io::Read;
use std::path::PathBuf;
use std::process::{Child, ChildStdin, ChildStdout, ExitStatus};
use std::thread::JoinHandle;

#[allow(dead_code)]
pub(crate) trait RpcTransport {
    fn connect(&self, target: &RpcTarget) -> Result<RpcProcess, TransportError>;
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct RpcTarget {
    host: String,
    user: String,
    port: u16,
    identity: PathBuf,
    host_key: PinnedHostKey,
}

#[allow(dead_code)] // The live inventory/CLI consumers land in this continuous Task 2-4 wave.
impl RpcTarget {
    pub(crate) fn new(
        host: &str,
        user: &str,
        port: u16,
        identity: PathBuf,
        host_key: PinnedHostKey,
    ) -> Result<Self, TransportError> {
        validate_host(host)?;
        validate_user(user)?;
        validate_transport_path(&identity)?;
        if port == 0 {
            return Err(TransportError::authentication());
        }
        Ok(Self {
            host: host.to_owned(),
            user: user.to_owned(),
            port,
            identity,
            host_key,
        })
    }

    pub(crate) fn host(&self) -> &str {
        &self.host
    }

    pub(crate) fn user(&self) -> &str {
        &self.user
    }

    pub(crate) const fn port(&self) -> u16 {
        self.port
    }

    pub(crate) fn identity(&self) -> &std::path::Path {
        &self.identity
    }

    pub(crate) const fn host_key(&self) -> &PinnedHostKey {
        &self.host_key
    }

    #[cfg(test)]
    #[allow(dead_code)] // The binary unit-test target does not run the separate RPC integration target.
    pub(crate) fn local_for_test() -> Self {
        Self {
            host: "local.test".to_owned(),
            user: "local".to_owned(),
            port: 22,
            identity: PathBuf::from("/local-test-identity"),
            host_key: PinnedHostKey::local_for_test(),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum TransportErrorKind {
    CapabilityUnavailable,
    Unreachable,
    Authentication,
}

#[allow(dead_code)] // The live CLI error mapping lands in this continuous Task 2-4 wave.
impl TransportErrorKind {
    pub(crate) const fn code(self) -> ErrorCode {
        match self {
            Self::CapabilityUnavailable => ErrorCode::CapabilityUnsatisfied,
            Self::Unreachable => ErrorCode::TransportUnreachable,
            Self::Authentication => ErrorCode::TransportAuthFailed,
        }
    }
}

#[derive(Debug)]
pub(crate) struct TransportError {
    kind: TransportErrorKind,
}

impl TransportError {
    pub(crate) const fn capability_unavailable() -> Self {
        Self {
            kind: TransportErrorKind::CapabilityUnavailable,
        }
    }

    pub(crate) const fn unreachable() -> Self {
        Self {
            kind: TransportErrorKind::Unreachable,
        }
    }

    pub(crate) const fn authentication() -> Self {
        Self {
            kind: TransportErrorKind::Authentication,
        }
    }

    #[allow(dead_code)] // Source-including protocol tests omit the transport contract assertions.
    pub(crate) const fn kind(&self) -> TransportErrorKind {
        self.kind
    }

    #[allow(dead_code)] // The live CLI error mapping lands in this continuous Task 2-4 wave.
    pub(crate) const fn code(&self) -> ErrorCode {
        self.kind.code()
    }
}

impl fmt::Display for TransportError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self.kind {
            TransportErrorKind::CapabilityUnavailable => {
                "a required OpenSSH capability is unavailable"
            }
            TransportErrorKind::Unreachable => "the remote host is unreachable",
            TransportErrorKind::Authentication => {
                "the remote host identity or authentication could not be verified"
            }
        })
    }
}

impl std::error::Error for TransportError {}

#[allow(dead_code)] // The Task 1 integration target exercises the controller side of the process boundary.
pub(crate) struct RpcProcess {
    child: Option<Child>,
    input: Option<ChildStdin>,
    output: FrameReader<ChildStdout>,
    stderr: Option<JoinHandle<Vec<u8>>>,
}

#[allow(dead_code)] // The Task 1 integration target exercises the controller side of the process boundary.
impl RpcProcess {
    pub(super) fn new(
        child: Child,
        input: ChildStdin,
        output: ChildStdout,
        stderr: impl Read + Send + 'static,
    ) -> Self {
        Self {
            child: Some(child),
            input: Some(input),
            output: FrameReader::new(output),
            stderr: Some(std::thread::spawn(move || drain_bounded(stderr, 64 * 1024))),
        }
    }

    #[cfg(test)]
    #[allow(dead_code)] // The separate RPC integration target builds a bounded fake peer.
    pub(crate) fn for_test(
        child: Child,
        input: ChildStdin,
        output: ChildStdout,
        stderr: impl Read + Send + 'static,
    ) -> Self {
        Self::new(child, input, output, stderr)
    }

    pub(crate) fn read_frame(&mut self) -> Result<Option<Frame>, FrameError> {
        self.output.read()
    }

    pub(crate) fn write_frame(&mut self, frame: &Frame) -> Result<(), FrameError> {
        let input = self.input.as_mut().ok_or_else(closed_pipe_error)?;
        FrameWriter::new(input).write(frame)
    }

    pub(crate) fn finish(&mut self) -> Result<ExitStatus, TransportError> {
        self.input.take();
        let status = self
            .child
            .take()
            .ok_or_else(TransportError::unreachable)?
            .wait()
            .map_err(|_| TransportError::unreachable())?;
        if let Some(stderr) = self.stderr.take() {
            let _ = stderr.join().map_err(|_| TransportError::unreachable())?;
        }
        Ok(status)
    }

    pub(crate) fn abort(&mut self) {
        self.input.take();
        if let Some(mut child) = self.child.take() {
            let _ = child.kill();
            let _ = child.wait();
        }
        if let Some(stderr) = self.stderr.take() {
            let _ = stderr.join();
        }
    }
}

fn validate_host(host: &str) -> Result<(), TransportError> {
    if host.is_empty() || host.len() > 255 || host.starts_with('-') {
        return Err(TransportError::authentication());
    }
    if let Some(inner) = host
        .strip_prefix('[')
        .and_then(|host| host.strip_suffix(']'))
    {
        if inner.parse::<std::net::Ipv6Addr>().is_ok() {
            return Ok(());
        }
        return Err(TransportError::authentication());
    }
    if host
        .bytes()
        .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-' | b'_'))
    {
        Ok(())
    } else {
        Err(TransportError::authentication())
    }
}

#[allow(dead_code)] // Called by RpcTarget::new once the live inventory consumer lands.
fn validate_user(user: &str) -> Result<(), TransportError> {
    if !user.is_empty()
        && user.len() <= 255
        && !user.starts_with('-')
        && user
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-' | b'_'))
    {
        Ok(())
    } else {
        Err(TransportError::authentication())
    }
}

fn validate_transport_path(path: &std::path::Path) -> Result<&str, TransportError> {
    let value = path.to_str().ok_or_else(TransportError::authentication)?;
    if path.is_absolute() && !value.is_empty() && !value.chars().any(char::is_control) {
        Ok(value)
    } else {
        Err(TransportError::authentication())
    }
}

impl Drop for RpcProcess {
    fn drop(&mut self) {
        self.abort();
    }
}

#[allow(dead_code)] // Reachable through the Task 1 client in the separate integration target.
fn closed_pipe_error() -> FrameError {
    FrameError::io()
}

fn drain_bounded(mut reader: impl Read, limit: usize) -> Vec<u8> {
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
