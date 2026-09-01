use chrono::{DateTime, SecondsFormat, Utc};
use serde::{Serialize, Serializer};
use serde_json::{json, Value};
use std::fmt;
use std::io::Write;

const SCHEMA: &str = "styrn.command.v1";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(i32)]
pub(crate) enum StyrnExit {
    Success = 0,
    InternalError = 1,
    Usage = 2,
    Unreachable = 3,
    Authentication = 4,
    RemoteExecution = 5,
    ResourceAdmission = 6,
    CapabilityUnavailable = 7,
    Protocol = 8,
    PartialFleet = 9,
    Timeout = 10,
    AgentHarness = 11,
    Workflow = 12,
    Setup = 13,
}

impl StyrnExit {
    pub(crate) const ALL: [Self; 14] = [
        Self::Success,
        Self::InternalError,
        Self::Usage,
        Self::Unreachable,
        Self::Authentication,
        Self::RemoteExecution,
        Self::ResourceAdmission,
        Self::CapabilityUnavailable,
        Self::Protocol,
        Self::PartialFleet,
        Self::Timeout,
        Self::AgentHarness,
        Self::Workflow,
        Self::Setup,
    ];

    pub(crate) const fn as_i32(self) -> i32 {
        self as i32
    }
}

pub(crate) fn exit_process(exit: StyrnExit) -> ! {
    std::process::exit(exit.as_i32())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ErrorCode {
    UsageInvalidArgument,
    UsageConfigInvalid,
    TransportUnreachable,
    TransportAuthFailed,
    TransportSessionLost,
    ProtocolIncompatible,
    ProtocolMalformed,
    MachineManifestInvalid,
    ResourceMemoryAdmissionDenied,
    ResourceCpuAdmissionDenied,
    ResourceDiskAdmissionDenied,
    ResourceHeavyExclusivityDenied,
    ResourceJobDiskLimitExceeded,
    ResourceHostDiskFloor,
    CapabilityUnsatisfied,
    JobNotFound,
    JobTimeout,
    JobCancelled,
    JobWorkflowFailed,
    JobSupervisorLost,
    AgentNotFound,
    AgentHarnessError,
    ProjectProfileInvalid,
    ProjectWorkflowNotDeclared,
    ProjectRevisionUnresolved,
    ProjectWorktreeDirty,
    FleetPartial,
    InternalError,
    SetupProbeFailed,
    SetupPlanInvalid,
    SetupConfirmationRequired,
    SetupElevationRequired,
    SetupApplyFailed,
    SetupNeedsHuman,
    SetupUnsupportedOs,
    SetupReceiptConflict,
    SetupAdoptMismatch,
}

impl ErrorCode {
    pub(crate) const ALL: [Self; 37] = [
        Self::UsageInvalidArgument,
        Self::UsageConfigInvalid,
        Self::TransportUnreachable,
        Self::TransportAuthFailed,
        Self::TransportSessionLost,
        Self::ProtocolIncompatible,
        Self::ProtocolMalformed,
        Self::MachineManifestInvalid,
        Self::ResourceMemoryAdmissionDenied,
        Self::ResourceCpuAdmissionDenied,
        Self::ResourceDiskAdmissionDenied,
        Self::ResourceHeavyExclusivityDenied,
        Self::ResourceJobDiskLimitExceeded,
        Self::ResourceHostDiskFloor,
        Self::CapabilityUnsatisfied,
        Self::JobNotFound,
        Self::JobTimeout,
        Self::JobCancelled,
        Self::JobWorkflowFailed,
        Self::JobSupervisorLost,
        Self::AgentNotFound,
        Self::AgentHarnessError,
        Self::ProjectProfileInvalid,
        Self::ProjectWorkflowNotDeclared,
        Self::ProjectRevisionUnresolved,
        Self::ProjectWorktreeDirty,
        Self::FleetPartial,
        Self::InternalError,
        Self::SetupProbeFailed,
        Self::SetupPlanInvalid,
        Self::SetupConfirmationRequired,
        Self::SetupElevationRequired,
        Self::SetupApplyFailed,
        Self::SetupNeedsHuman,
        Self::SetupUnsupportedOs,
        Self::SetupReceiptConflict,
        Self::SetupAdoptMismatch,
    ];

    pub(crate) fn from_str(value: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|code| code.as_str() == value)
    }

    pub(crate) const fn as_str(self) -> &'static str {
        match self {
            Self::UsageInvalidArgument => "usage.invalid_argument",
            Self::UsageConfigInvalid => "usage.config_invalid",
            Self::TransportUnreachable => "transport.unreachable",
            Self::TransportAuthFailed => "transport.auth_failed",
            Self::TransportSessionLost => "transport.session_lost",
            Self::ProtocolIncompatible => "protocol.incompatible",
            Self::ProtocolMalformed => "protocol.malformed",
            Self::MachineManifestInvalid => "machine.manifest_invalid",
            Self::ResourceMemoryAdmissionDenied => "resource.memory_admission_denied",
            Self::ResourceCpuAdmissionDenied => "resource.cpu_admission_denied",
            Self::ResourceDiskAdmissionDenied => "resource.disk_admission_denied",
            Self::ResourceHeavyExclusivityDenied => "resource.heavy_exclusivity_denied",
            Self::ResourceJobDiskLimitExceeded => "resource.job_disk_limit_exceeded",
            Self::ResourceHostDiskFloor => "resource.host_disk_floor",
            Self::CapabilityUnsatisfied => "capability.unsatisfied",
            Self::JobNotFound => "job.not_found",
            Self::JobTimeout => "job.timeout",
            Self::JobCancelled => "job.cancelled",
            Self::JobWorkflowFailed => "job.workflow_failed",
            Self::JobSupervisorLost => "job.supervisor_lost",
            Self::AgentNotFound => "agent.not_found",
            Self::AgentHarnessError => "agent.harness_error",
            Self::ProjectProfileInvalid => "project.profile_invalid",
            Self::ProjectWorkflowNotDeclared => "project.workflow_not_declared",
            Self::ProjectRevisionUnresolved => "project.revision_unresolved",
            Self::ProjectWorktreeDirty => "project.worktree_dirty",
            Self::FleetPartial => "fleet.partial",
            Self::InternalError => "internal.error",
            Self::SetupProbeFailed => "setup.probe_failed",
            Self::SetupPlanInvalid => "setup.plan_invalid",
            Self::SetupConfirmationRequired => "setup.confirmation_required",
            Self::SetupElevationRequired => "setup.elevation_required",
            Self::SetupApplyFailed => "setup.apply_failed",
            Self::SetupNeedsHuman => "setup.needs_human",
            Self::SetupUnsupportedOs => "setup.unsupported_os",
            Self::SetupReceiptConflict => "setup.receipt_conflict",
            Self::SetupAdoptMismatch => "setup.adopt_mismatch",
        }
    }

    pub(crate) const fn exit_code(self) -> StyrnExit {
        match self {
            Self::UsageInvalidArgument
            | Self::UsageConfigInvalid
            | Self::MachineManifestInvalid
            | Self::JobNotFound
            | Self::AgentNotFound
            | Self::ProjectProfileInvalid
            | Self::ProjectWorkflowNotDeclared
            | Self::ProjectRevisionUnresolved
            | Self::ProjectWorktreeDirty => StyrnExit::Usage,
            Self::TransportUnreachable | Self::TransportSessionLost => StyrnExit::Unreachable,
            Self::TransportAuthFailed => StyrnExit::Authentication,
            Self::ProtocolIncompatible | Self::ProtocolMalformed => StyrnExit::Protocol,
            Self::ResourceMemoryAdmissionDenied
            | Self::ResourceCpuAdmissionDenied
            | Self::ResourceDiskAdmissionDenied
            | Self::ResourceHeavyExclusivityDenied => StyrnExit::ResourceAdmission,
            Self::CapabilityUnsatisfied => StyrnExit::CapabilityUnavailable,
            Self::JobTimeout => StyrnExit::Timeout,
            Self::JobCancelled
            | Self::JobWorkflowFailed
            | Self::JobSupervisorLost
            | Self::ResourceJobDiskLimitExceeded
            | Self::ResourceHostDiskFloor => StyrnExit::Workflow,
            Self::AgentHarnessError => StyrnExit::AgentHarness,
            Self::FleetPartial => StyrnExit::PartialFleet,
            Self::InternalError => StyrnExit::InternalError,
            Self::SetupProbeFailed
            | Self::SetupPlanInvalid
            | Self::SetupConfirmationRequired
            | Self::SetupElevationRequired
            | Self::SetupApplyFailed
            | Self::SetupNeedsHuman
            | Self::SetupUnsupportedOs
            | Self::SetupReceiptConflict
            | Self::SetupAdoptMismatch => StyrnExit::Setup,
        }
    }
}

impl Serialize for ErrorCode {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(self.as_str())
    }
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub(crate) struct Diagnostic {
    code: String,
    message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    details: Option<Value>,
}

impl Diagnostic {
    pub(crate) fn new(
        code: impl Into<String>,
        message: impl Into<String>,
        details: Option<Value>,
    ) -> Result<Self, OutputError> {
        let code = code.into();
        let message = message.into();

        if !is_diagnostic_code(&code) {
            return Err(OutputError::InvalidDiagnosticCode);
        }
        if message.is_empty() {
            return Err(OutputError::EmptyDiagnosticMessage);
        }
        if details.as_ref().is_some_and(|details| !details.is_object()) {
            return Err(OutputError::InvalidDiagnosticDetails);
        }

        Ok(Self {
            code,
            message,
            details,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub(crate) struct ErrorDiagnostic {
    code: ErrorCode,
    message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    details: Option<Value>,
}

impl ErrorDiagnostic {
    pub(crate) fn new(
        code: ErrorCode,
        message: impl Into<String>,
        details: Option<Value>,
    ) -> Result<Self, OutputError> {
        let message = message.into();
        validate_diagnostic_parts(&message, details.as_ref())?;

        Ok(Self {
            code,
            message,
            details,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub(crate) struct Envelope {
    schema: &'static str,
    ok: bool,
    command: String,
    timestamp: String,
    data: Value,
    warnings: Vec<Diagnostic>,
    errors: Vec<ErrorDiagnostic>,
}

impl Envelope {
    pub(crate) fn success(
        command: impl Into<String>,
        timestamp: DateTime<Utc>,
        data: Value,
        warnings: Vec<Diagnostic>,
    ) -> Result<Self, OutputError> {
        validate_command(&command.into()).and_then(|command| {
            if !matches!(data, Value::Object(_) | Value::Array(_) | Value::Null) {
                return Err(OutputError::InvalidSuccessData);
            }

            Ok(Self {
                schema: SCHEMA,
                ok: true,
                command,
                timestamp: timestamp.to_rfc3339_opts(SecondsFormat::AutoSi, true),
                data,
                warnings,
                errors: Vec::new(),
            })
        })
    }

    pub(crate) fn failure(
        command: impl Into<String>,
        timestamp: DateTime<Utc>,
        errors: Vec<ErrorDiagnostic>,
        warnings: Vec<Diagnostic>,
    ) -> Result<Self, OutputError> {
        let command = validate_command(&command.into())?;
        if errors.is_empty() {
            return Err(OutputError::MissingFailureError);
        }

        Ok(Self {
            schema: SCHEMA,
            ok: false,
            command,
            timestamp: timestamp.to_rfc3339_opts(SecondsFormat::AutoSi, true),
            data: Value::Null,
            warnings,
            errors,
        })
    }
}

#[derive(Debug, Clone, PartialEq)]
pub(crate) struct CommandFailure {
    envelope: Envelope,
    exit_code: StyrnExit,
}

impl CommandFailure {
    pub(crate) fn new(
        command: impl Into<String>,
        timestamp: DateTime<Utc>,
        code: ErrorCode,
        message: impl Into<String>,
    ) -> Result<Self, OutputError> {
        let envelope = Envelope::failure(
            command,
            timestamp,
            vec![ErrorDiagnostic::new(code, message, None)?],
            Vec::new(),
        )?;

        Ok(Self {
            envelope,
            exit_code: code.exit_code(),
        })
    }

    pub(crate) fn envelope(&self) -> &Envelope {
        &self.envelope
    }

    pub(crate) const fn exit_code(&self) -> StyrnExit {
        self.exit_code
    }
}

#[derive(Debug, Clone, PartialEq)]
pub(crate) struct WorkflowFailure {
    envelope: Envelope,
}

impl WorkflowFailure {
    pub(crate) fn new(
        command: impl Into<String>,
        timestamp: DateTime<Utc>,
        inner_exit_code: i32,
    ) -> Result<Self, OutputError> {
        let command = command.into();
        if !matches!(command.as_str(), "workflow run" | "matrix run") {
            return Err(OutputError::InvalidWorkflowCommand);
        }

        Ok(Self {
            envelope: Envelope {
                schema: SCHEMA,
                ok: false,
                command,
                timestamp: timestamp.to_rfc3339_opts(SecondsFormat::AutoSi, true),
                data: json!({"exit_code": inner_exit_code}),
                warnings: Vec::new(),
                errors: vec![ErrorDiagnostic::new(
                    ErrorCode::JobWorkflowFailed,
                    "workflow command exited with a non-zero status",
                    None,
                )?],
            },
        })
    }

    pub(crate) fn envelope(&self) -> &Envelope {
        &self.envelope
    }

    pub(crate) const fn exit_code(&self) -> StyrnExit {
        StyrnExit::Workflow
    }
}

#[derive(Debug, Clone, PartialEq)]
pub(crate) struct ExecOutcome {
    envelope: Envelope,
    process_exit_code: i32,
}

impl ExecOutcome {
    pub(crate) fn new(
        timestamp: DateTime<Utc>,
        remote_exit_code: i32,
        stdout: impl Into<String>,
        stderr: impl Into<String>,
        duration_ms: u64,
    ) -> Result<Self, OutputError> {
        let envelope = Envelope::success(
            "exec",
            timestamp,
            json!({
                "exit_code": remote_exit_code,
                "stdout": stdout.into(),
                "stderr": stderr.into(),
                "duration_ms": duration_ms,
            }),
            Vec::new(),
        )?;

        Ok(Self {
            envelope,
            process_exit_code: remote_exit_code,
        })
    }

    pub(crate) fn envelope(&self) -> &Envelope {
        &self.envelope
    }

    pub(crate) const fn process_exit_code(&self) -> i32 {
        self.process_exit_code
    }
}

pub(crate) fn catch_unmapped_panic<T>(
    command: impl Into<String>,
    timestamp: DateTime<Utc>,
    operation: impl FnOnce() -> T,
) -> Result<T, CommandFailure> {
    std::panic::catch_unwind(std::panic::AssertUnwindSafe(operation)).map_err(|_| {
        CommandFailure::new(
            command,
            timestamp,
            ErrorCode::InternalError,
            "unexpected internal error",
        )
        .expect("the built-in internal error diagnostic must be valid")
    })
}

pub(crate) fn to_json(envelope: &Envelope) -> Result<String, OutputError> {
    serde_json::to_string(envelope).map_err(OutputError::Serialize)
}

pub(crate) fn write_json(mut writer: impl Write, envelope: &Envelope) -> Result<(), OutputError> {
    let json = to_json(envelope)?;
    writer
        .write_all(json.as_bytes())
        .map_err(OutputError::Write)
}

#[derive(Debug)]
pub(crate) enum OutputError {
    EmptyCommand,
    InvalidSuccessData,
    MissingFailureError,
    InvalidDiagnosticCode,
    EmptyDiagnosticMessage,
    InvalidDiagnosticDetails,
    InvalidWorkflowCommand,
    Serialize(serde_json::Error),
    Write(std::io::Error),
}

impl fmt::Display for OutputError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EmptyCommand => formatter.write_str("command must not be empty"),
            Self::InvalidSuccessData => {
                formatter.write_str("success data must be an object, array, or null")
            }
            Self::MissingFailureError => formatter.write_str("failure requires at least one error"),
            Self::InvalidDiagnosticCode => {
                formatter.write_str("diagnostic code must be dot-namespaced")
            }
            Self::EmptyDiagnosticMessage => {
                formatter.write_str("diagnostic message must not be empty")
            }
            Self::InvalidDiagnosticDetails => {
                formatter.write_str("diagnostic details must be an object")
            }
            Self::InvalidWorkflowCommand => formatter
                .write_str("workflow failures are only valid for workflow run or matrix run"),
            Self::Serialize(error) => {
                write!(formatter, "could not serialize command envelope: {error}")
            }
            Self::Write(error) => write!(formatter, "could not write command envelope: {error}"),
        }
    }
}

impl std::error::Error for OutputError {}

fn validate_command(command: &str) -> Result<String, OutputError> {
    if command.trim().is_empty() {
        Err(OutputError::EmptyCommand)
    } else {
        Ok(command.to_owned())
    }
}

fn is_diagnostic_code(code: &str) -> bool {
    let mut segments = code.split('.');
    let Some(first) = segments.next() else {
        return false;
    };
    segments.next().is_some() && !first.is_empty() && code.split('.').all(valid_code_segment)
}

fn validate_diagnostic_parts(message: &str, details: Option<&Value>) -> Result<(), OutputError> {
    if message.is_empty() {
        return Err(OutputError::EmptyDiagnosticMessage);
    }
    if details.is_some_and(|details| !details.is_object()) {
        return Err(OutputError::InvalidDiagnosticDetails);
    }

    Ok(())
}

fn valid_code_segment(segment: &str) -> bool {
    let mut characters = segment.chars();
    matches!(characters.next(), Some(character) if character.is_ascii_lowercase())
        && characters.all(|character| {
            character.is_ascii_lowercase() || character.is_ascii_digit() || character == '_'
        })
}
