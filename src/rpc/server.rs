use super::frame::{Frame, FrameReader, FrameWriter, RpcDiagnostic, ServerHello};
use super::{
    canonical_authorized_public_key, validate_exec_argv, ExecResult, RpcError, WorkerDoctorFinding,
    WorkerDoctorReport, MAX_EXEC_CAPTURE_BYTES, PROTOCOL_MAX, PROTOCOL_MIN, REDACTED_OUTPUT,
};
use crate::output::ErrorCode;
use serde::Deserialize;
use serde_json::{json, Value};
use std::io::{Read, Write};
use std::process::{Command, Stdio};
use std::sync::mpsc;
use std::time::{Duration, Instant};

pub(crate) fn serve(input: impl Read, output: impl Write) -> Result<(), RpcError> {
    let outcome = crate::manifest::configured_manifest_store()
        .and_then(|store| store.read_or_reconcile_missing_machine_id())
        .map_err(|_| {
            RpcError::new(
                ErrorCode::MachineManifestInvalid,
                "the configured machine manifest is invalid",
            )
        })?;
    if outcome.machine_id_minted {
        eprintln!("machine_id was minted and persisted");
    }
    serve_manifest(input, output, outcome.manifest)
}

fn serve_manifest(
    input: impl Read,
    output: impl Write,
    manifest: crate::manifest::MachineManifest,
) -> Result<(), RpcError> {
    let mut reader = FrameReader::new(input);
    let mut writer = FrameWriter::new(output);
    writer
        .write(&Frame::ServerHello(ServerHello {
            protocol_min: PROTOCOL_MIN,
            protocol_max: PROTOCOL_MAX,
            styrn_version: env!("CARGO_PKG_VERSION").to_owned(),
            machine_id: manifest.machine_id,
            name: manifest.name.clone(),
            manifest_schema_version: manifest.schema_version,
        }))
        .map_err(RpcError::frame)?;

    let selection = match reader.read() {
        Ok(Some(Frame::ClientHello(selection))) => selection,
        Ok(Some(Frame::Error { id, errors }))
            if id == "hello"
                && matches!(
                    errors.as_slice(),
                    [error]
                        if error.code == ErrorCode::ProtocolIncompatible.as_str()
                            && error.details.is_none()
                ) =>
        {
            return Ok(())
        }
        Ok(None) => return Ok(()),
        Err(error) if error.kind() == super::frame::FrameErrorKind::Io => {
            return Err(RpcError::frame(error))
        }
        Ok(Some(_)) | Err(_) => {
            return protocol_failure(&mut writer, "hello", ErrorCode::ProtocolMalformed)
        }
    };
    if selection.protocol < PROTOCOL_MIN || selection.protocol > PROTOCOL_MAX {
        return protocol_failure(&mut writer, "hello", ErrorCode::ProtocolIncompatible);
    }

    let mut next_id = 1_u64;
    loop {
        let frame = match reader.read() {
            Ok(Some(frame)) => frame,
            Ok(None) => return Ok(()),
            Err(error) if error.kind() == super::frame::FrameErrorKind::Io => {
                return Err(RpcError::frame(error))
            }
            Err(_) => return protocol_failure(&mut writer, "hello", ErrorCode::ProtocolMalformed),
        };
        let Frame::Request { id, method, params } = frame else {
            return protocol_failure(&mut writer, "hello", ErrorCode::ProtocolMalformed);
        };
        if id != format!("c{next_id}") {
            return protocol_failure(&mut writer, &id, ErrorCode::ProtocolMalformed);
        }
        next_id = next_id
            .checked_add(1)
            .ok_or_else(|| RpcError::malformed("RPC request identifier overflow"))?;

        let response = match handle_request(&manifest, &method, params) {
            Ok(data) => Frame::Response {
                id,
                ok: true,
                data: Some(data),
                errors: Vec::new(),
            },
            Err(HandlerError::Malformed) => {
                return protocol_failure(&mut writer, &id, ErrorCode::ProtocolMalformed)
            }
            Err(HandlerError::Remote) => Frame::Response {
                id,
                ok: false,
                data: None,
                errors: vec![RpcDiagnostic::new(
                    ErrorCode::RemoteExecutionFailed.as_str(),
                    super::REMOTE_EXECUTION_FAILED_MESSAGE,
                )],
            },
        };
        if let Err(error) = writer.write(&response) {
            if error.kind() == super::frame::FrameErrorKind::Oversize {
                writer
                    .write(&Frame::Response {
                        id: match response {
                            Frame::Response { id, .. } => id,
                            _ => unreachable!(),
                        },
                        ok: false,
                        data: None,
                        errors: vec![RpcDiagnostic::new(
                            ErrorCode::RemoteExecutionFailed.as_str(),
                            super::REMOTE_EXECUTION_FAILED_MESSAGE,
                        )],
                    })
                    .map_err(RpcError::frame)?;
            } else {
                return Err(RpcError::frame(error));
            }
        }
    }
}

fn protocol_failure<W: Write>(
    writer: &mut FrameWriter<W>,
    id: &str,
    code: ErrorCode,
) -> Result<(), RpcError> {
    let message = match code {
        ErrorCode::ProtocolIncompatible => "the selected RPC protocol is incompatible",
        _ => "the RPC peer sent a malformed frame",
    };
    let _ = writer.write(&Frame::Error {
        id: id.to_owned(),
        errors: vec![RpcDiagnostic::new(code.as_str(), message)],
    });
    Err(RpcError::new(code, message))
}

fn handle_request(
    manifest: &crate::manifest::MachineManifest,
    method: &str,
    params: Value,
) -> Result<Value, HandlerError> {
    match method {
        "machine.manifest" => {
            parse_empty(params)?;
            manifest
                .to_toml()
                .map(|toml| json!({ "toml": toml }))
                .map_err(|_| HandlerError::Remote)
        }
        "machine.status" => {
            parse_empty(params)?;
            serde_json::to_value(
                crate::resources::capture_machine_status(manifest)
                    .map_err(|_| HandlerError::Remote)?,
            )
            .map_err(|_| HandlerError::Remote)
        }
        "machine.doctor" => {
            let params: DoctorParams =
                serde_json::from_value(params).map_err(|_| HandlerError::Malformed)?;
            let authorized_public_key =
                canonical_authorized_public_key(&params.authorized_public_key)
                    .map_err(|_| HandlerError::Malformed)?;
            let findings = crate::setup::worker_doctor_findings(manifest, &authorized_public_key)
                .map_err(|_| HandlerError::Remote)?
                .into_iter()
                .map(|finding| {
                    serde_json::to_value(finding)
                        .and_then(serde_json::from_value::<WorkerDoctorFinding>)
                })
                .collect::<Result<Vec<_>, _>>()
                .map_err(|_| HandlerError::Remote)?;
            let report = WorkerDoctorReport {
                findings,
                coverage: "phase1_minimum".to_owned(),
                complete: false,
            };
            report
                .validate_for_client()
                .map_err(|_| HandlerError::Remote)?;
            serde_json::to_value(report).map_err(|_| HandlerError::Remote)
        }
        "exec.run" => {
            let params: ExecParams =
                serde_json::from_value(params).map_err(|_| HandlerError::Malformed)?;
            validate_exec_argv(&params.argv).map_err(|_| HandlerError::Malformed)?;
            serde_json::to_value(run_exec(&params.argv)?).map_err(|_| HandlerError::Remote)
        }
        _ => Err(HandlerError::Malformed),
    }
}

fn parse_empty(params: Value) -> Result<(), HandlerError> {
    if params.as_object().is_some_and(serde_json::Map::is_empty) {
        Ok(())
    } else {
        Err(HandlerError::Malformed)
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct DoctorParams {
    authorized_public_key: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ExecParams {
    argv: Vec<String>,
}

#[derive(Clone, Copy)]
enum HandlerError {
    Malformed,
    Remote,
}

fn run_exec(argv: &[String]) -> Result<ExecResult, HandlerError> {
    let started = Instant::now();
    let mut child = Command::new(&argv[0])
        .args(&argv[1..])
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|_| HandlerError::Remote)?;
    let stdout = child.stdout.take().ok_or(HandlerError::Remote)?;
    let stderr = child.stderr.take().ok_or(HandlerError::Remote)?;
    let (overflow_sender, overflow_receiver) = mpsc::channel();
    let stdout_thread = capture_thread(stdout, overflow_sender.clone());
    let stderr_thread = capture_thread(stderr, overflow_sender);

    let status = loop {
        if overflow_receiver.try_recv().is_ok() {
            let _ = child.kill();
            let _ = child.wait();
            let _ = stdout_thread.join();
            let _ = stderr_thread.join();
            return Err(HandlerError::Remote);
        }
        match child.try_wait() {
            Ok(Some(status)) => break status,
            Ok(None) => std::thread::sleep(Duration::from_millis(2)),
            Err(_) => {
                let _ = child.kill();
                let _ = child.wait();
                let _ = stdout_thread.join();
                let _ = stderr_thread.join();
                return Err(HandlerError::Remote);
            }
        }
    };
    let stdout = stdout_thread
        .join()
        .map_err(|_| HandlerError::Remote)?
        .map_err(|_| HandlerError::Remote)?;
    let stderr = stderr_thread
        .join()
        .map_err(|_| HandlerError::Remote)?
        .map_err(|_| HandlerError::Remote)?;
    if stdout.overflow || stderr.overflow {
        return Err(HandlerError::Remote);
    }
    let exit_code = status.code().ok_or(HandlerError::Remote)?;
    let (stdout, stdout_lossy, stdout_redacted) = sanitize_capture(stdout.bytes);
    let (stderr, stderr_lossy, stderr_redacted) = sanitize_capture(stderr.bytes);
    Ok(ExecResult {
        exit_code,
        stdout,
        stderr,
        duration_ms: u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX),
        stdout_lossy,
        stderr_lossy,
        stdout_redacted,
        stderr_redacted,
    })
}

struct Capture {
    bytes: Vec<u8>,
    overflow: bool,
}

#[derive(Debug)]
struct CaptureReadError;

fn capture_thread(
    mut reader: impl Read + Send + 'static,
    overflow_sender: mpsc::Sender<()>,
) -> std::thread::JoinHandle<Result<Capture, CaptureReadError>> {
    std::thread::spawn(move || {
        let mut bytes = Vec::new();
        let mut buffer = [0_u8; 8192];
        let mut overflow = false;
        loop {
            match reader.read(&mut buffer) {
                Ok(0) => break,
                Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
                Err(_) => {
                    let _ = overflow_sender.send(());
                    return Err(CaptureReadError);
                }
                Ok(read) => {
                    let remaining = MAX_EXEC_CAPTURE_BYTES.saturating_sub(bytes.len());
                    bytes.extend_from_slice(&buffer[..read.min(remaining)]);
                    if read > remaining && !overflow {
                        overflow = true;
                        let _ = overflow_sender.send(());
                    }
                }
            }
        }
        Ok(Capture { bytes, overflow })
    })
}

fn sanitize_capture(bytes: Vec<u8>) -> (String, bool, bool) {
    let lossy = std::str::from_utf8(&bytes).is_err();
    let text = String::from_utf8_lossy(&bytes).into_owned();
    if crate::manifest::contains_secret_shaped_text(&text) {
        (REDACTED_OUTPUT.to_owned(), lossy, true)
    } else {
        (text, lossy, false)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io;

    struct FailingReader;

    impl Read for FailingReader {
        fn read(&mut self, _buffer: &mut [u8]) -> io::Result<usize> {
            Err(io::Error::other("injected transport read failure"))
        }
    }

    struct InterruptedOnceReader {
        step: u8,
    }

    impl Read for InterruptedOnceReader {
        fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
            let bytes = match self.step {
                0 => b"before-".as_slice(),
                1 => {
                    self.step += 1;
                    return Err(io::Error::from(io::ErrorKind::Interrupted));
                }
                2 => b"after".as_slice(),
                _ => return Ok(0),
            };
            self.step += 1;
            buffer[..bytes.len()].copy_from_slice(bytes);
            Ok(bytes.len())
        }
    }

    struct PartialThenErrorReader {
        emitted_partial: bool,
    }

    impl Read for PartialThenErrorReader {
        fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
            if self.emitted_partial {
                Err(io::Error::other("injected capture failure"))
            } else {
                self.emitted_partial = true;
                buffer[..7].copy_from_slice(b"partial");
                Ok(7)
            }
        }
    }

    #[test]
    fn rpc_server_frame_io_error_is_transport_session_lost() {
        let manifest = crate::manifest::MachineManifest::parse_toml(include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/examples/machine.controller-worker.toml"
        )))
        .unwrap();
        let mut output = Vec::new();

        let error = serve_manifest(FailingReader, &mut output, manifest).unwrap_err();

        assert_eq!(error.code(), ErrorCode::TransportSessionLost);
        assert_eq!(error.exit_code().as_i32(), 3);
        assert_eq!(output.iter().filter(|byte| **byte == b'\n').count(), 1);
    }

    #[test]
    fn rpc_capture_retries_interrupted_reads_without_truncating_output() {
        let (failure_sender, failure_receiver) = mpsc::channel();
        let capture = capture_thread(InterruptedOnceReader { step: 0 }, failure_sender)
            .join()
            .unwrap()
            .unwrap();

        assert_eq!(capture.bytes, b"before-after");
        assert!(!capture.overflow);
        assert!(failure_receiver.try_recv().is_err());
    }

    #[test]
    fn rpc_capture_propagates_non_interrupted_read_failure() {
        let (failure_sender, failure_receiver) = mpsc::channel();
        let capture = capture_thread(
            PartialThenErrorReader {
                emitted_partial: false,
            },
            failure_sender,
        )
        .join()
        .unwrap();

        assert!(capture.is_err());
        assert!(failure_receiver.try_recv().is_ok());
    }
}
