use chrono::{DateTime, SecondsFormat, Utc};
use serde::Serialize;
use serde_json::Value;
use std::fmt;
use std::io::Write;

const SCHEMA: &str = "styrn.command.v1";

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
pub(crate) struct Envelope {
    schema: &'static str,
    ok: bool,
    command: String,
    timestamp: String,
    data: Value,
    warnings: Vec<Diagnostic>,
    errors: Vec<Diagnostic>,
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
        errors: Vec<Diagnostic>,
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

fn valid_code_segment(segment: &str) -> bool {
    let mut characters = segment.chars();
    matches!(characters.next(), Some(character) if character.is_ascii_lowercase())
        && characters.all(|character| {
            character.is_ascii_lowercase() || character.is_ascii_digit() || character == '_'
        })
}
