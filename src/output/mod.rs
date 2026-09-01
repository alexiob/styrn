use chrono::{DateTime, SecondsFormat, Utc};
use serde::{Serialize, Serializer};
use serde_json::{json, Value};
use std::fmt;
use std::io::Write;

const SCHEMA: &str = "styrn.command.v1";

macro_rules! define_styrn_exits {
    ($( $variant:ident = $value:literal ),+ $(,)?) => {
        #[derive(Debug, Clone, Copy, PartialEq, Eq)]
        #[repr(i32)]
        pub(crate) enum StyrnExit {
            $( $variant = $value, )+
        }

        impl StyrnExit {
            pub(crate) const ALL: &'static [Self] = &[$(Self::$variant),+];

            pub(crate) const fn as_i32(self) -> i32 {
                self as i32
            }

            pub(crate) fn from_i32(value: i32) -> Option<Self> {
                Self::ALL
                    .iter()
                    .copied()
                    .find(|exit| exit.as_i32() == value)
            }
        }
    };
}

define_styrn_exits! {
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

pub(crate) fn exit_process(exit: StyrnExit) -> ! {
    std::process::exit(exit.as_i32())
}

macro_rules! define_error_codes {
    ($( $variant:ident => ($name:literal, $exit:ident) ),+ $(,)?) => {
        #[derive(Debug, Clone, Copy, PartialEq, Eq)]
        pub(crate) enum ErrorCode {
            $( $variant, )+
        }

        impl ErrorCode {
            pub(crate) const ALL: &'static [Self] = &[$(Self::$variant),+];

            pub(crate) fn from_str(value: &str) -> Option<Self> {
                Self::ALL
                    .iter()
                    .copied()
                    .find(|code| code.as_str() == value)
            }

            pub(crate) const fn as_str(self) -> &'static str {
                match self {
                    $( Self::$variant => $name, )+
                }
            }

            pub(crate) const fn exit_code(self) -> StyrnExit {
                match self {
                    $( Self::$variant => StyrnExit::$exit, )+
                }
            }
        }
    };
}

define_error_codes! {
    UsageInvalidArgument => ("usage.invalid_argument", Usage),
    UsageConfigInvalid => ("usage.config_invalid", Usage),
    TransportUnreachable => ("transport.unreachable", Unreachable),
    TransportAuthFailed => ("transport.auth_failed", Authentication),
    TransportSessionLost => ("transport.session_lost", Unreachable),
    ProtocolIncompatible => ("protocol.incompatible", Protocol),
    ProtocolMalformed => ("protocol.malformed", Protocol),
    MachineManifestInvalid => ("machine.manifest_invalid", Usage),
    ResourceMemoryAdmissionDenied => ("resource.memory_admission_denied", ResourceAdmission),
    ResourceCpuAdmissionDenied => ("resource.cpu_admission_denied", ResourceAdmission),
    ResourceDiskAdmissionDenied => ("resource.disk_admission_denied", ResourceAdmission),
    ResourceHeavyExclusivityDenied => ("resource.heavy_exclusivity_denied", ResourceAdmission),
    ResourceJobDiskLimitExceeded => ("resource.job_disk_limit_exceeded", Workflow),
    ResourceHostDiskFloor => ("resource.host_disk_floor", Workflow),
    CapabilityUnsatisfied => ("capability.unsatisfied", CapabilityUnavailable),
    JobNotFound => ("job.not_found", Usage),
    JobTimeout => ("job.timeout", Timeout),
    JobCancelled => ("job.cancelled", Workflow),
    JobWorkflowFailed => ("job.workflow_failed", Workflow),
    JobSupervisorLost => ("job.supervisor_lost", Workflow),
    AgentNotFound => ("agent.not_found", Usage),
    AgentHarnessError => ("agent.harness_error", AgentHarness),
    ProjectProfileInvalid => ("project.profile_invalid", Usage),
    ProjectWorkflowNotDeclared => ("project.workflow_not_declared", Usage),
    ProjectRevisionUnresolved => ("project.revision_unresolved", Usage),
    ProjectWorktreeDirty => ("project.worktree_dirty", Usage),
    FleetPartial => ("fleet.partial", PartialFleet),
    InternalError => ("internal.error", InternalError),
    SetupProbeFailed => ("setup.probe_failed", Setup),
    SetupPlanInvalid => ("setup.plan_invalid", Setup),
    SetupConfirmationRequired => ("setup.confirmation_required", Setup),
    SetupElevationRequired => ("setup.elevation_required", Setup),
    SetupApplyFailed => ("setup.apply_failed", Setup),
    SetupNeedsHuman => ("setup.needs_human", Setup),
    SetupUnsupportedOs => ("setup.unsupported_os", Setup),
    SetupReceiptConflict => ("setup.receipt_conflict", Setup),
    SetupAdoptMismatch => ("setup.adopt_mismatch", Setup),
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
