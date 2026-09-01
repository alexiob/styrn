use super::validate_probe_static_text;
use serde::Serialize;
use std::fmt;
use thiserror::Error;

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize)]
#[serde(transparent)]
pub(crate) struct ProbeId(String);

impl ProbeId {
    pub(crate) fn parse(value: &str) -> Result<Self, ProbeIdError> {
        valid_probe_id(value)
            .then(|| Self(value.to_owned()))
            .ok_or(ProbeIdError::Invalid)
    }

    pub(crate) fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for ProbeId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(formatter)
    }
}

fn valid_probe_id(value: &str) -> bool {
    value.split('.').count() >= 2 && value.split('.').all(valid_probe_id_segment)
}

fn valid_probe_id_segment(segment: &str) -> bool {
    let bytes = segment.as_bytes();
    matches!(bytes.first(), Some(b'a'..=b'z'))
        && matches!(bytes.last(), Some(b'a'..=b'z' | b'0'..=b'9'))
        && bytes
            .iter()
            .all(|byte| matches!(byte, b'a'..=b'z' | b'0'..=b'9' | b'-'))
}

#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub(crate) enum ProbeIdError {
    #[error("probe ID must contain lowercase dot-namespaced segments")]
    Invalid,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum FindingSeverity {
    Info,
    Warning,
    Error,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum StyrnCommand {
    MachineInit,
}

impl StyrnCommand {
    pub(crate) fn args(self) -> &'static [&'static str] {
        match self {
            Self::MachineInit => &["machine", "init"],
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct RemediationSpec {
    summary: String,
    command: Option<StyrnCommand>,
}

impl RemediationSpec {
    pub(crate) fn new(
        summary: impl Into<String>,
        command: Option<StyrnCommand>,
    ) -> Result<Self, RemediationSpecError> {
        let summary = summary.into();
        if !validate_probe_static_text(&summary) {
            return Err(RemediationSpecError::UnsafeSummary);
        }
        Ok(Self { summary, command })
    }

    pub(crate) fn summary(&self) -> &str {
        &self.summary
    }

    pub(crate) fn command(&self) -> Option<StyrnCommand> {
        self.command
    }

    fn is_valid(&self) -> bool {
        validate_probe_static_text(&self.summary)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub(crate) enum RemediationSpecError {
    #[error("remediation summary is unsafe")]
    UnsafeSummary,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ProbeDescriptorSpec {
    id: ProbeId,
    label: String,
    failure_severity: FindingSeverity,
    remediation: Option<RemediationSpec>,
}

impl ProbeDescriptorSpec {
    pub(crate) fn new(
        id: ProbeId,
        label: impl Into<String>,
        failure_severity: FindingSeverity,
        remediation: Option<RemediationSpec>,
    ) -> Result<Self, ProbeDescriptorSpecError> {
        let label = label.into();
        if !validate_probe_static_text(&label) {
            return Err(ProbeDescriptorSpecError::UnsafeLabel);
        }
        Ok(Self {
            id,
            label,
            failure_severity,
            remediation,
        })
    }

    pub(crate) fn id(&self) -> &ProbeId {
        &self.id
    }

    pub(crate) fn label(&self) -> &str {
        &self.label
    }

    pub(crate) fn failure_severity(&self) -> FindingSeverity {
        self.failure_severity
    }

    pub(crate) fn remediation(&self) -> Option<&RemediationSpec> {
        self.remediation.as_ref()
    }

    pub(crate) fn is_valid(&self) -> bool {
        valid_probe_id(self.id.as_str())
            && validate_probe_static_text(&self.label)
            && self
                .remediation
                .as_ref()
                .is_none_or(RemediationSpec::is_valid)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub(crate) enum ProbeDescriptorSpecError {
    #[error("probe label is unsafe")]
    UnsafeLabel,
}
