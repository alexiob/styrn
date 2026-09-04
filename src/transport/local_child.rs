use super::{RpcProcess, RpcTarget, RpcTransport, TransportError};
#[cfg(test)]
use std::path::Path;
use std::path::PathBuf;
use std::process::{Command, Stdio};

pub(crate) struct LocalChildTransport {
    executable: PathBuf,
    config_directory: Option<PathBuf>,
}

impl LocalChildTransport {
    #[cfg(test)]
    #[allow(dead_code)] // The binary unit-test target does not run the separate RPC integration target.
    pub(crate) fn for_test(
        executable: impl AsRef<Path>,
        config_directory: impl AsRef<Path>,
    ) -> Self {
        Self {
            executable: executable.as_ref().to_path_buf(),
            config_directory: Some(config_directory.as_ref().to_path_buf()),
        }
    }

    fn server_command(&self) -> Command {
        let mut command = Command::new(&self.executable);
        command
            .args(["rpc", "serve", "--stdio"])
            .env_remove("STYRN_JSON")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        if let Some(directory) = &self.config_directory {
            command.env("STYRN_CONFIG_DIR", directory);
        }
        command
    }
}

impl RpcTransport for LocalChildTransport {
    fn connect(&self, _target: &RpcTarget) -> Result<RpcProcess, TransportError> {
        let mut command = self.server_command();
        let mut child = command.spawn().map_err(|_| TransportError::unreachable())?;
        let input = child.stdin.take().ok_or_else(TransportError::unreachable)?;
        let output = child
            .stdout
            .take()
            .ok_or_else(TransportError::unreachable)?;
        let stderr = child
            .stderr
            .take()
            .ok_or_else(TransportError::unreachable)?;
        Ok(RpcProcess::new(child, input, output, stderr))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::ffi::OsStr;

    #[test]
    fn local_child_rpc_removes_controller_machine_output_environment() {
        let transport = LocalChildTransport::for_test("styrn", "config");
        let command = transport.server_command();
        assert_eq!(
            command.get_args().collect::<Vec<_>>(),
            ["rpc", "serve", "--stdio"].map(OsStr::new)
        );
        assert!(command
            .get_envs()
            .any(|(name, value)| { name == OsStr::new("STYRN_JSON") && value.is_none() }));
    }
}
