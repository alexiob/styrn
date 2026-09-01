use super::probe::ProbeId;
use super::probe::{
    FindingSeverity, ProbeDescriptorSpec, ProbeStatus, RemediationSpec, StyrnCommand, WorkerProbe,
};
use base64::{
    engine::general_purpose::{URL_SAFE, URL_SAFE_NO_PAD},
    Engine as _,
};
use serde::{ser::SerializeStruct, Serialize, Serializer};

#[derive(Clone, PartialEq, Eq)]
pub(crate) struct Remediation {
    summary: String,
    command: Option<StyrnCommand>,
}

impl Remediation {
    fn from_spec(spec: &RemediationSpec) -> Self {
        Self {
            summary: safe_static_text(spec.summary(), "remediation unavailable"),
            command: spec.command(),
        }
    }
}

impl Serialize for Remediation {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut output =
            serializer.serialize_struct("Remediation", usize::from(self.command.is_some()) + 1)?;
        output.serialize_field(
            "summary",
            &safe_static_text(&self.summary, "remediation unavailable"),
        )?;
        if let Some(command) = self.command {
            output.serialize_field("styrn_args", command.args())?;
        }
        output.end()
    }
}

#[derive(Clone, PartialEq, Eq)]
pub(crate) struct ProbeDescriptor {
    id: ProbeId,
    label: String,
    failure_severity: FindingSeverity,
    remediation: Option<Remediation>,
}

impl ProbeDescriptor {
    fn from_spec(spec: &ProbeDescriptorSpec) -> Self {
        Self {
            id: spec.id().clone(),
            label: safe_static_text(spec.label(), "worker probe"),
            failure_severity: spec.failure_severity(),
            remediation: spec.remediation().map(Remediation::from_spec),
        }
    }

    pub(crate) fn id(&self) -> &ProbeId {
        &self.id
    }
}

impl Serialize for ProbeDescriptor {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut output = serializer.serialize_struct(
            "ProbeDescriptor",
            usize::from(self.remediation.is_some()) + 3,
        )?;
        output.serialize_field("id", &self.id)?;
        output.serialize_field("label", &safe_static_text(&self.label, "worker probe"))?;
        output.serialize_field("failure_severity", &self.failure_severity)?;
        if let Some(remediation) = &self.remediation {
            output.serialize_field("remediation", remediation)?;
        }
        output.end()
    }
}

#[derive(Clone, PartialEq, Eq)]
pub(crate) struct ProbeObservation {
    descriptor: ProbeDescriptor,
    status: ProbeStatus,
}

impl ProbeObservation {
    fn new(descriptor: ProbeDescriptor, status: ProbeStatus) -> Self {
        Self {
            descriptor,
            status: sanitize_status(status),
        }
    }

    pub(crate) fn descriptor(&self) -> &ProbeDescriptor {
        &self.descriptor
    }

    pub(crate) fn status(&self) -> &ProbeStatus {
        &self.status
    }
}

impl Serialize for ProbeObservation {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let status = sanitize_status(self.status.clone());
        let mut output = serializer.serialize_struct("ProbeObservation", 2)?;
        output.serialize_field("descriptor", &self.descriptor)?;
        output.serialize_field("status", &SerializedProbeStatus::from(&status))?;
        output.end()
    }
}

#[derive(Serialize)]
#[serde(tag = "status", rename_all = "snake_case")]
enum SerializedProbeStatus<'a> {
    Absent,
    Present {
        version: Option<&'a str>,
        healthy: bool,
    },
    Broken {
        reason: &'a str,
    },
    Unknowable {
        reason: &'a str,
    },
}

impl<'a> From<&'a ProbeStatus> for SerializedProbeStatus<'a> {
    fn from(status: &'a ProbeStatus) -> Self {
        match status {
            ProbeStatus::Absent => Self::Absent,
            ProbeStatus::Present { version, healthy } => Self::Present {
                version: version.as_deref(),
                healthy: *healthy,
            },
            ProbeStatus::Broken { reason } => Self::Broken { reason },
            ProbeStatus::Unknowable { reason } => Self::Unknowable { reason },
        }
    }
}

#[derive(Clone, PartialEq, Eq)]
pub(crate) struct ObservedState {
    observations: Vec<ProbeObservation>,
}

impl ObservedState {
    pub(crate) fn iter(&self) -> impl ExactSizeIterator<Item = &ProbeObservation> {
        self.observations.iter()
    }

    pub(crate) fn get(&self, id: &ProbeId) -> Option<&ProbeObservation> {
        self.observations
            .iter()
            .find(|observation| observation.descriptor.id == *id)
    }

    pub(crate) fn setup_observations(&self) -> impl ExactSizeIterator<Item = &ProbeObservation> {
        self.iter()
    }

    pub(crate) fn doctor_findings(&self) -> Vec<DoctorFinding> {
        self.iter().map(DoctorFinding::from_observation).collect()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum DoctorFindingState {
    Pass,
    Fail,
    Unknown,
}

#[derive(Clone, PartialEq, Eq)]
pub(crate) struct DoctorFinding {
    id: ProbeId,
    state: DoctorFindingState,
    severity: FindingSeverity,
    message: String,
    remediation: Option<Remediation>,
}

impl DoctorFinding {
    fn from_observation(observation: &ProbeObservation) -> Self {
        let (state, detail) = match observation.status() {
            ProbeStatus::Absent => (DoctorFindingState::Fail, "subject is absent"),
            ProbeStatus::Present { healthy: true, .. } => (DoctorFindingState::Pass, "healthy"),
            ProbeStatus::Present { healthy: false, .. } => {
                (DoctorFindingState::Fail, "present but unhealthy")
            }
            ProbeStatus::Broken { reason } => (DoctorFindingState::Fail, reason.as_str()),
            ProbeStatus::Unknowable { reason } => (DoctorFindingState::Unknown, reason.as_str()),
        };
        let descriptor = observation.descriptor();
        Self {
            id: descriptor.id.clone(),
            state,
            severity: descriptor.failure_severity,
            message: format!(
                "{}: {detail}",
                safe_static_text(&descriptor.label, "worker probe")
            ),
            remediation: descriptor.remediation.clone(),
        }
    }

    pub(crate) fn id(&self) -> &ProbeId {
        &self.id
    }

    pub(crate) fn state(&self) -> DoctorFindingState {
        self.state
    }
}

impl Serialize for DoctorFinding {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut output = serializer
            .serialize_struct("DoctorFinding", usize::from(self.remediation.is_some()) + 4)?;
        output.serialize_field("id", &self.id)?;
        output.serialize_field("state", &self.state)?;
        output.serialize_field("severity", &self.severity)?;
        output.serialize_field(
            "message",
            &safe_runtime_text(&self.message, "worker probe finding"),
        )?;
        if let Some(remediation) = &self.remediation {
            output.serialize_field("remediation", remediation)?;
        }
        output.end()
    }
}

pub(super) fn validate_static_text(value: &str) -> bool {
    is_safe_text(value)
}

pub(super) fn observe(probes: &[Box<dyn WorkerProbe>]) -> ObservedState {
    ObservedState {
        observations: probes
            .iter()
            .map(|probe| {
                let status = match probe.observe() {
                    Ok(status) => status,
                    Err(failure) => ProbeStatus::Unknowable {
                        reason: failure.canonical_reason().to_owned(),
                    },
                };
                ProbeObservation::new(ProbeDescriptor::from_spec(probe.descriptor()), status)
            })
            .collect(),
    }
}

fn sanitize_status(status: ProbeStatus) -> ProbeStatus {
    match status {
        ProbeStatus::Absent => ProbeStatus::Absent,
        ProbeStatus::Present { version, healthy } => ProbeStatus::Present {
            version: version.filter(|version| is_safe_version(version)),
            healthy,
        },
        ProbeStatus::Broken { reason } => ProbeStatus::Broken {
            reason: canonical_reason(&reason),
        },
        ProbeStatus::Unknowable { reason } => ProbeStatus::Unknowable {
            reason: canonical_reason(&reason),
        },
    }
}

fn is_safe_version(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && is_safe_text(value)
        && value
            .bytes()
            .all(|byte| matches!(byte, b'a'..=b'z' | b'A'..=b'Z' | b'0'..=b'9' | b'.' | b'-' | b'_' | b'+'))
}

fn canonical_reason(reason: &str) -> String {
    let normalized = reason.to_ascii_lowercase();
    if normalized.contains("permission") || normalized.contains("eacces") {
        "permission denied".to_owned()
    } else if normalized.contains("unreadable") {
        "state unreadable".to_owned()
    } else if normalized.contains("malformed") || normalized.contains("unsupported") {
        "output was malformed or unsupported".to_owned()
    } else if normalized.contains("prerequisite") {
        "required prerequisite was unavailable".to_owned()
    } else if normalized.contains("inconsistent") || normalized.contains("corrupt") {
        "internally inconsistent state".to_owned()
    } else {
        "probe observation failed".to_owned()
    }
}

fn safe_static_text(value: &str, fallback: &'static str) -> String {
    if is_safe_text(value) {
        value.to_owned()
    } else {
        fallback.to_owned()
    }
}

fn safe_runtime_text(value: &str, fallback: &'static str) -> String {
    safe_static_text(value, fallback)
}

fn is_safe_text(value: &str) -> bool {
    !value.is_empty() && !value.chars().any(char::is_control) && !looks_secret_shaped(value)
}

fn looks_secret_shaped(value: &str) -> bool {
    let normalized = value.to_ascii_lowercase();
    value.chars().any(char::is_control)
        || normalized.contains("-----begin")
        || contains_bearer_credential(&normalized)
        || contains_embedded_compact_jwt(value)
        || contains_sensitive_assignment(value)
        || contains_auth_token_phrase(value)
        || contains_credential_prefix(value)
}

fn contains_bearer_credential(value: &str) -> bool {
    let candidates = credential_candidates(value);
    lexical_tokens(value).iter().any(|token| {
        assignment_pair(token).is_some_and(|(name, continuation)| {
            normalized_marker(name) == "bearer" && looks_credential_continuation(continuation)
        })
    }) || candidates.windows(2).any(|pair| {
        normalized_marker(pair[0]) == "bearer" && looks_credential_continuation(pair[1])
    })
}

fn contains_embedded_compact_jwt(value: &str) -> bool {
    credential_candidates(value).into_iter().any(is_compact_jwt)
}

fn contains_sensitive_assignment(value: &str) -> bool {
    lexical_tokens(value).iter().any(|token| {
        assignment_pair(token).is_some_and(|(name, continuation)| {
            is_sensitive_marker(name) && !continuation.is_empty()
        })
    })
}

fn contains_auth_token_phrase(value: &str) -> bool {
    credential_candidates(value).windows(3).any(|words| {
        normalized_marker(words[0]) == "auth"
            && normalized_marker(words[1]) == "token"
            && looks_credential_continuation(words[2])
    })
}

fn contains_credential_prefix(value: &str) -> bool {
    credential_candidates(value).into_iter().any(|candidate| {
        let candidate = candidate.trim_matches(
            |character: char| !matches!(character, 'A'..='Z' | 'a'..='z' | '0'..='9' | '-' | '_'),
        );
        [
            "sk-",
            "sk_",
            "ghp_",
            "gho_",
            "ghu_",
            "ghs_",
            "github_pat_",
            "tskey-",
            "tskey_",
        ]
        .iter()
        .any(|prefix| candidate.to_ascii_lowercase().starts_with(prefix))
    })
}

fn looks_credential_continuation(value: &str) -> bool {
    let value = value.trim_matches(
        |character: char| !matches!(character, 'A'..='Z' | 'a'..='z' | '0'..='9' | '-' | '_' | '.'),
    );
    !value.is_empty()
        && (is_compact_jwt(value)
            || contains_credential_prefix(value)
            || (value.len() >= 6
                && value.bytes().all(
                    |byte| matches!(byte, b'a'..=b'z' | b'A'..=b'Z' | b'0'..=b'9' | b'-' | b'_'),
                )
                && value
                    .bytes()
                    .any(|byte| byte.is_ascii_digit() || matches!(byte, b'-' | b'_'))))
}

fn lexical_tokens(value: &str) -> Vec<&str> {
    value
        .split(|character: char| {
            character.is_whitespace()
                || matches!(character, ',' | ';' | '(' | ')' | '[' | ']' | '{' | '}')
        })
        .filter(|token| !token.is_empty())
        .collect()
}

fn assignment_pair(token: &str) -> Option<(&str, &str)> {
    let separator = token.find(['=', ':'])?;
    Some((&token[..separator], &token[separator + 1..]))
}

fn normalized_marker(value: &str) -> String {
    value
        .trim_start_matches('-')
        .chars()
        .filter(char::is_ascii_alphanumeric)
        .map(|character| character.to_ascii_lowercase())
        .collect()
}

fn is_sensitive_marker(value: &str) -> bool {
    matches!(
        normalized_marker(value).as_str(),
        "apikey"
            | "auth"
            | "authorization"
            | "password"
            | "privatekey"
            | "secret"
            | "accesskey"
            | "credential"
            | "token"
    )
}

fn credential_candidates(value: &str) -> Vec<&str> {
    value
        .split(|character: char| {
            character.is_whitespace()
                || matches!(
                    character,
                    ':' | '=' | ',' | ';' | '(' | ')' | '[' | ']' | '{' | '}'
                )
        })
        .filter(|candidate| !candidate.is_empty())
        .collect()
}

fn is_compact_jwt(value: &str) -> bool {
    let candidate = value.trim_matches(
        |character: char| !matches!(character, 'A'..='Z' | 'a'..='z' | '0'..='9' | '-' | '_' | '.'),
    );
    is_compact_jwt_segments(candidate)
        || (candidate.trim_end_matches('.').len() < candidate.len()
            && is_compact_jwt_segments(candidate.trim_end_matches('.')))
}

fn is_compact_jwt_segments(candidate: &str) -> bool {
    let mut segments = candidate.split('.');
    let (Some(header), Some(payload), Some(signature), None) = (
        segments.next(),
        segments.next(),
        segments.next(),
        segments.next(),
    ) else {
        return false;
    };
    if header.is_empty() || payload.is_empty() || signature.is_empty() {
        return false;
    }
    URL_SAFE_NO_PAD
        .decode(header)
        .or_else(|_| URL_SAFE.decode(header))
        .ok()
        .and_then(|bytes| serde_json::from_slice::<serde_json::Value>(&bytes).ok())
        .and_then(|header| header.as_object().cloned())
        .is_some_and(|header| header.contains_key("alg"))
}
