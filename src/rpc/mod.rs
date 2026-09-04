pub(crate) mod frame;
mod server;

use crate::output::{ErrorCode, StyrnExit};
use crate::transport::RpcProcess;
use frame::{ClientHello, Frame, FrameError, FrameErrorKind, RpcDiagnostic, ServerHello};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::collections::HashSet;
use std::fmt;
use std::ops::RangeInclusive;
use uuid::Uuid;

pub(crate) const PROTOCOL_MIN: u32 = 1;
pub(crate) const PROTOCOL_MAX: u32 = 1;
const MANIFEST_SCHEMA_VERSION: u64 = 1;
const MAX_EXEC_ARGUMENTS: usize = 256;
const MAX_EXEC_ARGUMENT_BYTES: usize = 32 * 1024;
const MAX_EXEC_TOTAL_BYTES: usize = 256 * 1024;
const MAX_EXEC_CAPTURE_BYTES: usize = 1024 * 1024;
const REDACTED_OUTPUT: &str = "[redacted secret-shaped output]";
const REMOTE_EXECUTION_FAILED_MESSAGE: &str = "the worker could not complete the RPC method";

pub(crate) fn serve_stdio() -> Result<(), RpcError> {
    let stdin = std::io::stdin();
    let stdout = std::io::stdout();
    server::serve(stdin.lock(), stdout.lock())
}

pub(crate) fn highest_protocol_intersection(
    ours: RangeInclusive<u32>,
    theirs: RangeInclusive<u32>,
) -> Option<u32> {
    let minimum = (*ours.start()).max(*theirs.start());
    let maximum = (*ours.end()).min(*theirs.end());
    (minimum <= maximum).then_some(maximum)
}

pub(crate) fn negotiate_server_hello(hello: &ServerHello) -> Result<u32, RpcError> {
    if hello.manifest_schema_version != MANIFEST_SCHEMA_VERSION {
        return Err(RpcError::new(
            ErrorCode::ProtocolIncompatible,
            "the worker manifest schema is not supported by this controller",
        ));
    }
    highest_protocol_intersection(
        PROTOCOL_MIN..=PROTOCOL_MAX,
        hello.protocol_min..=hello.protocol_max,
    )
    .ok_or_else(|| {
        RpcError::new(
            ErrorCode::ProtocolIncompatible,
            "the controller and worker protocol ranges do not intersect; run styrn upgrade <host>",
        )
    })
}

pub(crate) fn incompatible_server_hello_diagnostic(hello: &ServerHello) -> RpcDiagnostic {
    RpcDiagnostic::new(
        ErrorCode::ProtocolIncompatible.as_str(),
        &format!(
            "controller protocol range [{PROTOCOL_MIN}, {PROTOCOL_MAX}], worker protocol range [{}, {}], controller manifest schema {MANIFEST_SCHEMA_VERSION}, worker manifest schema {}",
            hello.protocol_min, hello.protocol_max, hello.manifest_schema_version
        ),
    )
}

#[derive(Debug)]
pub(crate) struct RpcError {
    code: ErrorCode,
    message: &'static str,
}

impl RpcError {
    pub(crate) const fn new(code: ErrorCode, message: &'static str) -> Self {
        Self { code, message }
    }

    pub(crate) fn frame(error: FrameError) -> Self {
        let code = if error.kind() == FrameErrorKind::Io {
            ErrorCode::TransportSessionLost
        } else {
            ErrorCode::ProtocolMalformed
        };
        Self::new(
            code,
            "the RPC session could not read or write a valid frame",
        )
    }

    pub(crate) const fn malformed(message: &'static str) -> Self {
        Self::new(ErrorCode::ProtocolMalformed, message)
    }

    pub(crate) const fn code(&self) -> ErrorCode {
        self.code
    }

    pub(crate) const fn exit_code(&self) -> StyrnExit {
        self.code.exit_code()
    }
}

impl fmt::Display for RpcError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.message)
    }
}

impl std::error::Error for RpcError {}

#[derive(Clone, Debug)]
pub(crate) struct ExpectedPeer {
    machine_id: Uuid,
    name: String,
    user: String,
}

impl ExpectedPeer {
    pub(crate) fn new(machine_id: Uuid, name: &str, user: &str) -> Result<Self, RpcError> {
        if machine_id.get_version_num() != 7
            || name.is_empty()
            || name.len() > 255
            || user.is_empty()
            || user.len() > 255
            || name.chars().any(char::is_control)
            || user.chars().any(char::is_control)
        {
            return Err(RpcError::new(
                ErrorCode::UsageInvalidArgument,
                "the expected RPC peer is invalid",
            ));
        }
        Ok(Self {
            machine_id,
            name: name.to_owned(),
            user: user.to_owned(),
        })
    }

    #[allow(dead_code)] // Source-including non-protocol targets omit peer-binding assertions.
    pub(crate) const fn machine_id(&self) -> Uuid {
        self.machine_id
    }
}

pub(crate) struct RpcClient {
    process: RpcProcess,
    hello: ServerHello,
    next_id: u64,
    terminated: bool,
}

impl RpcClient {
    pub(crate) fn connect(mut process: RpcProcess) -> Result<Self, RpcError> {
        let hello = match process.read_frame().map_err(RpcError::frame)? {
            Some(Frame::ServerHello(hello)) => hello,
            Some(_) => {
                return Err(RpcError::malformed(
                    "the RPC server did not speak a valid hello first",
                ))
            }
            None => {
                return Err(RpcError::new(
                    process.pre_hello_error_code(),
                    "the RPC server closed before hello",
                ))
            }
        };
        let protocol = match negotiate_server_hello(&hello) {
            Ok(protocol) => protocol,
            Err(error) => {
                let _ = process.write_frame(&Frame::Error {
                    id: "hello".to_owned(),
                    errors: vec![incompatible_server_hello_diagnostic(&hello)],
                });
                return Err(error);
            }
        };
        process
            .write_frame(&Frame::ClientHello(ClientHello {
                protocol,
                styrn_version: env!("CARGO_PKG_VERSION").to_owned(),
            }))
            .map_err(RpcError::frame)?;
        Ok(Self {
            process,
            hello,
            next_id: 1,
            terminated: false,
        })
    }

    pub(crate) const fn server_hello(&self) -> &ServerHello {
        &self.hello
    }

    pub(crate) fn machine_manifest(
        &mut self,
        expected: &ExpectedPeer,
    ) -> Result<crate::manifest::MachineManifest, RpcError> {
        let data = self.request("machine.manifest", json!({}))?;
        let result = (|| {
            validate_remote_value(&data)?;
            let manifest_toml = data
                .as_object()
                .and_then(|object| object.get("toml"))
                .and_then(Value::as_str)
                .ok_or_else(|| RpcError::malformed("the worker manifest response was malformed"))?;
            let manifest =
                crate::manifest::MachineManifest::parse_toml(manifest_toml).map_err(|_| {
                    RpcError::new(
                        ErrorCode::MachineManifestInvalid,
                        "the worker returned an invalid machine manifest",
                    )
                })?;
            if manifest.to_toml().ok().as_deref() != Some(manifest_toml) {
                return Err(RpcError::malformed(
                    "the worker returned a noncanonical machine manifest",
                ));
            }
            validate_hello_manifest_binding(&self.hello, &manifest, expected)?;
            Ok(manifest)
        })();
        result.map_err(|error| self.terminate(error))
    }

    pub(crate) fn machine_status(&mut self) -> Result<crate::resources::MachineStatus, RpcError> {
        let data = self.request("machine.status", json!({}))?;
        let result = (|| {
            validate_remote_value(&data)?;
            let status: crate::resources::MachineStatus = serde_json::from_value(data)
                .map_err(|_| RpcError::malformed("the worker status response was malformed"))?;
            status
                .validate_for_client(self.hello.machine_id)
                .map_err(|_| RpcError::malformed("the worker status response was invalid"))?;
            Ok(status)
        })();
        result.map_err(|error| self.terminate(error))
    }

    pub(crate) fn machine_doctor(
        &mut self,
        authorized_public_key: &str,
    ) -> Result<WorkerDoctorReport, RpcError> {
        let authorized_public_key = canonical_authorized_public_key(authorized_public_key)?;
        let data = self.request(
            "machine.doctor",
            json!({ "authorized_public_key": authorized_public_key }),
        )?;
        let result = WorkerDoctorReport::from_remote_value(data);
        result.map_err(|error| self.terminate(error))
    }

    pub(crate) fn exec(&mut self, argv: &[String]) -> Result<ExecResult, RpcError> {
        validate_exec_argv(argv)?;
        let data = self.request("exec.run", json!({ "argv": argv }))?;
        let result = serde_json::from_value(data)
            .map_err(|_| RpcError::malformed("the worker exec response was malformed"))
            .and_then(ExecResult::sanitize_for_client);
        result.map_err(|error| self.terminate(error))
    }

    pub(crate) fn finish(mut self) -> Result<(), RpcError> {
        if self.terminated {
            return Err(RpcError::new(
                ErrorCode::TransportSessionLost,
                "the RPC session was already terminated",
            ));
        }
        let status = self.process.finish().map_err(|_| {
            RpcError::new(
                ErrorCode::TransportSessionLost,
                "the RPC process could not be reaped",
            )
        })?;
        if status.success() {
            Ok(())
        } else {
            Err(RpcError::new(
                ErrorCode::TransportSessionLost,
                "the RPC process exited unexpectedly",
            ))
        }
    }

    fn request(&mut self, method: &str, params: Value) -> Result<Value, RpcError> {
        if self.terminated {
            return Err(RpcError::new(
                ErrorCode::TransportSessionLost,
                "the RPC session was already terminated",
            ));
        }
        let id = format!("c{}", self.next_id);
        self.next_id = match self.next_id.checked_add(1) {
            Some(next_id) => next_id,
            None => {
                let error = RpcError::malformed("RPC request identifier overflow");
                return Err(self.terminate(error));
            }
        };
        if let Err(error) = self.process.write_frame(&Frame::Request {
            id: id.clone(),
            method: method.to_owned(),
            params,
        }) {
            let error = RpcError::frame(error);
            return Err(self.terminate(error));
        }
        let frame = match self.process.read_frame() {
            Ok(frame) => frame,
            Err(error) => {
                let error = RpcError::frame(error);
                return Err(self.terminate(error));
            }
        };
        match frame {
            Some(Frame::Response {
                id: response_id,
                ok: true,
                data: Some(data),
                errors,
            }) if response_id == id && errors.is_empty() => Ok(data),
            Some(Frame::Response {
                id: response_id,
                ok: false,
                errors,
                ..
            }) if response_id == id && is_remote_execution_failure(&errors) => Err(RpcError::new(
                ErrorCode::RemoteExecutionFailed,
                REMOTE_EXECUTION_FAILED_MESSAGE,
            )),
            Some(Frame::Error {
                id: error_id,
                errors,
            }) if error_id == id => {
                let code = errors
                    .first()
                    .and_then(|error| ErrorCode::from_str(&error.code))
                    .filter(|code| {
                        matches!(
                            code,
                            ErrorCode::ProtocolIncompatible | ErrorCode::ProtocolMalformed
                        )
                    })
                    .unwrap_or(ErrorCode::ProtocolMalformed);
                let error = RpcError::new(code, "the worker rejected the RPC session");
                Err(self.terminate(error))
            }
            Some(_) => {
                let error = RpcError::malformed(
                    "the RPC response did not match the sole outstanding request",
                );
                Err(self.terminate(error))
            }
            None => {
                let error = RpcError::new(
                    ErrorCode::TransportSessionLost,
                    "the RPC session ended before its response",
                );
                Err(self.terminate(error))
            }
        }
    }

    fn terminate(&mut self, error: RpcError) -> RpcError {
        if !self.terminated {
            self.process.abort();
            self.terminated = true;
        }
        error
    }

    #[cfg(test)]
    #[allow(dead_code)] // Source-including non-protocol targets omit hostile-peer assertions.
    pub(crate) fn request_for_test(&mut self, method: &str) -> Result<Value, RpcError> {
        self.request(method, json!({}))
    }

    #[cfg(test)]
    #[allow(dead_code)] // Source-including non-protocol targets omit hostile-peer assertions.
    pub(crate) const fn terminated_for_test(&self) -> bool {
        self.terminated
    }
}

fn is_remote_execution_failure(errors: &[RpcDiagnostic]) -> bool {
    matches!(
        errors,
        [error]
            if error.code == ErrorCode::RemoteExecutionFailed.as_str()
                && error.message == REMOTE_EXECUTION_FAILED_MESSAGE
                && error.details.is_none()
    )
}

pub(crate) fn validate_hello_manifest_binding(
    hello: &ServerHello,
    manifest: &crate::manifest::MachineManifest,
    expected: &ExpectedPeer,
) -> Result<(), RpcError> {
    let manifest_user = manifest
        .transport
        .as_ref()
        .and_then(|transport| transport.user.as_deref());
    let identity_user = manifest
        .worker_identity
        .as_ref()
        .map(|identity| identity.name.as_str());
    if hello.machine_id != manifest.machine_id
        || hello.name != manifest.name
        || hello.manifest_schema_version != manifest.schema_version
        || hello.machine_id != expected.machine_id
        || hello.name != expected.name
        || manifest_user != Some(expected.user.as_str())
        || identity_user != Some(expected.user.as_str())
    {
        return Err(RpcError::malformed(
            "the RPC hello and worker manifest binding did not match",
        ));
    }
    Ok(())
}

pub(crate) fn canonical_authorized_public_key(value: &str) -> Result<String, RpcError> {
    if value.len() > 16 * 1024 || crate::platform::parse_authorized_key_line(value).is_none() {
        return Err(RpcError::new(
            ErrorCode::UsageInvalidArgument,
            "the controller public key is invalid",
        ));
    }
    let mut fields = value.split_ascii_whitespace();
    let key_type = fields.next().ok_or_else(invalid_public_key)?;
    let encoded = fields.next().ok_or_else(invalid_public_key)?;
    Ok(format!("{key_type} {encoded}"))
}

fn invalid_public_key() -> RpcError {
    RpcError::new(
        ErrorCode::UsageInvalidArgument,
        "the controller public key is invalid",
    )
}

fn validate_remote_value(value: &Value) -> Result<(), RpcError> {
    if remote_value_contains_secret(value) {
        Err(RpcError::malformed(
            "the worker response contained secret-shaped text",
        ))
    } else {
        Ok(())
    }
}

#[cfg(test)]
#[allow(dead_code)] // The separate RPC integration target checks additive unknown fields.
pub(crate) fn validate_remote_value_for_test(value: &Value) -> Result<(), RpcError> {
    validate_remote_value(value)
}

fn remote_value_contains_secret(value: &Value) -> bool {
    match value {
        Value::Object(object) => object.iter().any(|(key, value)| {
            crate::manifest::contains_secret_shaped_text(key)
                || value.as_str().is_some_and(|text| {
                    crate::manifest::contains_secret_shaped_text(&format!("{key}: {text}"))
                })
                || remote_value_contains_secret(value)
        }),
        Value::Array(values) => values.iter().any(remote_value_contains_secret),
        Value::String(value) => crate::manifest::contains_secret_shaped_text(value),
        Value::Null | Value::Bool(_) | Value::Number(_) => false,
    }
}

pub(crate) fn validate_exec_argv(argv: &[String]) -> Result<(), RpcError> {
    if argv.is_empty() || argv.len() > MAX_EXEC_ARGUMENTS || argv[0].is_empty() {
        return Err(invalid_argv());
    }
    let mut total = 0_usize;
    for argument in argv {
        if argument.len() > MAX_EXEC_ARGUMENT_BYTES
            || crate::manifest::contains_secret_shaped_text(argument)
        {
            return Err(invalid_argv());
        }
        total = total.checked_add(argument.len()).ok_or_else(invalid_argv)?;
        if total > MAX_EXEC_TOTAL_BYTES {
            return Err(invalid_argv());
        }
    }
    Ok(())
}

fn invalid_argv() -> RpcError {
    RpcError::new(
        ErrorCode::UsageInvalidArgument,
        "the exec argv vector is invalid or contains secret-shaped input",
    )
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub(crate) struct WorkerDoctorReport {
    pub(crate) findings: Vec<WorkerDoctorFinding>,
    pub(crate) coverage: String,
    pub(crate) complete: bool,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub(crate) struct WorkerDoctorFinding {
    id: String,
    state: WorkerDoctorFindingState,
    severity: WorkerDoctorSeverity,
    message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    remediation: Option<WorkerDoctorRemediation>,
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
enum WorkerDoctorFindingState {
    Pass,
    Fail,
    Unknown,
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
enum WorkerDoctorSeverity {
    Info,
    Warning,
    Error,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
struct WorkerDoctorRemediation {
    summary: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    styrn_args: Option<Vec<String>>,
}

impl WorkerDoctorFinding {
    fn from_pending_action(index: usize, action: &crate::manifest::PendingAction) -> Self {
        let severity = match action.severity {
            crate::manifest::PendingSeverity::Info => WorkerDoctorSeverity::Info,
            crate::manifest::PendingSeverity::Warning => WorkerDoctorSeverity::Warning,
            crate::manifest::PendingSeverity::Error => WorkerDoctorSeverity::Error,
        };
        Self {
            id: format!("pending.action-{}", index + 1),
            state: WorkerDoctorFindingState::Fail,
            severity,
            message: "a worker manifest pending action remains unresolved".to_owned(),
            remediation: Some(WorkerDoctorRemediation {
                summary:
                    "complete the corresponding pending action in the worker manifest, then rerun styrn host doctor"
                        .to_owned(),
                styrn_args: None,
            }),
        }
    }
}

impl WorkerDoctorReport {
    pub(crate) fn from_remote_value(value: Value) -> Result<Self, RpcError> {
        validate_remote_value(&value)?;
        let report: Self = serde_json::from_value(value)
            .map_err(|_| RpcError::malformed("the worker doctor response was malformed"))?;
        report.validate_for_client()?;
        Ok(report)
    }

    pub(crate) fn validate_for_client(&self) -> Result<(), RpcError> {
        if self.coverage != "phase1_minimum"
            || self.complete
            || self.findings.is_empty()
            || self.findings.len() > 64
        {
            return Err(RpcError::malformed(
                "the worker doctor response was invalid",
            ));
        }
        let mut ids = HashSet::with_capacity(self.findings.len());
        for finding in &self.findings {
            if crate::setup::probe::ProbeId::parse(&finding.id).is_err()
                || !ids.insert(finding.id.as_str())
                || finding.message.is_empty()
                || finding.message.len() > 1024
                || finding.message.chars().any(char::is_control)
                || crate::manifest::contains_secret_shaped_text(&finding.message)
                || finding.remediation.as_ref().is_some_and(|remediation| {
                    remediation.summary.is_empty()
                        || remediation.summary.len() > 1024
                        || remediation.summary.chars().any(char::is_control)
                        || crate::manifest::contains_secret_shaped_text(&remediation.summary)
                        || remediation.styrn_args.as_deref().is_some_and(|arguments| {
                            arguments != ["machine".to_owned(), "init".to_owned()]
                        })
                })
            {
                return Err(RpcError::malformed(
                    "the worker doctor response was invalid",
                ));
            }
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub(crate) struct ExecResult {
    pub(crate) exit_code: i32,
    pub(crate) stdout: String,
    pub(crate) stderr: String,
    pub(crate) duration_ms: u64,
    pub(crate) stdout_lossy: bool,
    pub(crate) stderr_lossy: bool,
    pub(crate) stdout_redacted: bool,
    pub(crate) stderr_redacted: bool,
}

impl ExecResult {
    pub(crate) fn sanitize_for_client(mut self) -> Result<Self, RpcError> {
        if self.stdout.len() > MAX_EXEC_CAPTURE_BYTES || self.stderr.len() > MAX_EXEC_CAPTURE_BYTES
        {
            return Err(RpcError::malformed(
                "the worker exec response exceeded its capture limit",
            ));
        }
        sanitize_remote_capture(&mut self.stdout, &mut self.stdout_redacted);
        sanitize_remote_capture(&mut self.stderr, &mut self.stderr_redacted);
        Ok(self)
    }
}

fn sanitize_remote_capture(capture: &mut String, redacted: &mut bool) {
    if *redacted || crate::manifest::contains_secret_shaped_text(capture) {
        capture.clear();
        capture.push_str(REDACTED_OUTPUT);
        *redacted = true;
    }
}
