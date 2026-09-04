mod local_child;

#[allow(unused_imports)]
// The Task 1 integration target consumes this before the public host CLI is wired.
pub(crate) use local_child::LocalChildTransport;

use crate::rpc::frame::{Frame, FrameError, FrameReader, FrameWriter};
use std::fmt;
use std::io::Read;
use std::process::{Child, ChildStdin, ChildStdout, ExitStatus};
use std::thread::JoinHandle;

#[allow(dead_code)]
pub(crate) trait RpcTransport {
    fn connect(&self, target: &RpcTarget) -> Result<RpcProcess, TransportError>;
}

#[allow(dead_code)]
#[derive(Clone, Copy, Debug)]
pub(crate) struct RpcTarget;

impl RpcTarget {
    #[cfg(test)]
    #[allow(dead_code)] // The binary unit-test target does not run the separate RPC integration target.
    pub(crate) fn local_for_test() -> Self {
        Self
    }
}

#[derive(Debug)]
pub(crate) struct TransportError;

impl fmt::Display for TransportError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("could not start the RPC transport")
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
            .ok_or(TransportError)?
            .wait()
            .map_err(|_| TransportError)?;
        if let Some(stderr) = self.stderr.take() {
            let _ = stderr.join().map_err(|_| TransportError)?;
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
