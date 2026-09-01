//! Read-only worker-local capability observations shared by setup and doctor.
//!
//! Controller-relational checks deliberately do not have a type in this module:
//! `ProbeCatalog` accepts only sealed `WorkerProbe` implementations, so a
//! controller-side sibling cannot register itself as a worker-local probe.

use base64::{
    engine::general_purpose::{URL_SAFE, URL_SAFE_NO_PAD},
    Engine as _,
};
use serde::{ser::SerializeStruct, Serialize, Serializer};
use std::collections::HashSet;
use std::fmt;
use thiserror::Error;

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize)]
#[serde(transparent)]
pub(crate) struct ProbeId(String);

impl ProbeId {
    pub(crate) fn parse(value: &str) -> Result<Self, ProbeIdError> {
        let valid = value.split('.').count() >= 2 && value.split('.').all(valid_probe_id_segment);
        if !valid {
            return Err(ProbeIdError::Invalid);
        }
        Ok(Self(value.to_owned()))
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

fn valid_probe_id_segment(segment: &str) -> bool {
    let mut chars = segment.bytes();
    matches!(chars.next(), Some(b'a'..=b'z'))
        && chars
            .clone()
            .all(|byte| matches!(byte, b'a'..=b'z' | b'0'..=b'9' | b'-'))
        && matches!(chars.last(), Some(b'a'..=b'z' | b'0'..=b'9'))
}

#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub(crate) enum ProbeIdError {
    #[error("probe ID must contain at least two lowercase dot-namespaced segments")]
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
    fn args(self) -> &'static [&'static str] {
        match self {
            Self::MachineInit => &["machine", "init"],
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Remediation {
    summary: String,
    command: Option<StyrnCommand>,
}

impl Remediation {
    pub(crate) fn new(
        summary: impl Into<String>,
        command: Option<StyrnCommand>,
    ) -> Result<Self, RemediationError> {
        let summary = summary.into();
        if !valid_safe_text(&summary) {
            return Err(RemediationError::UnsafeSummary);
        }

        Ok(Self { summary, command })
    }
}

impl Serialize for Remediation {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut output =
            serializer.serialize_struct("Remediation", usize::from(self.command.is_some()) + 1)?;
        output.serialize_field("summary", &self.summary)?;
        if let Some(command) = self.command {
            output.serialize_field("styrn_args", command.args())?;
        }
        output.end()
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub(crate) enum RemediationError {
    #[error("remediation summary is unsafe")]
    UnsafeSummary,
}

fn valid_safe_text(value: &str) -> bool {
    !value.is_empty() && !value.chars().any(char::is_control) && !looks_secret_shaped(value)
}

fn looks_secret_shaped(value: &str) -> bool {
    let normalized = value.to_ascii_lowercase();
    let compact = normalized
        .bytes()
        .filter(u8::is_ascii_alphanumeric)
        .map(char::from)
        .collect::<String>();

    value.chars().any(char::is_control)
        || normalized.contains("-----begin")
        || has_compact_jwt_header(value)
        || [
            "apikey",
            "authkey",
            "authtoken",
            "token",
            "password",
            "privatekey",
            "secret",
            "accesskey",
            "credential",
        ]
        .iter()
        .any(|needle| compact.contains(needle))
        || [
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
        .any(|prefix| normalized.contains(prefix))
}

fn has_compact_jwt_header(value: &str) -> bool {
    let mut segments = value.split('.');
    let Some(header) = segments.next() else {
        return false;
    };
    let (Some(payload), Some(signature), None) =
        (segments.next(), segments.next(), segments.next())
    else {
        return false;
    };
    if payload.is_empty() || signature.is_empty() {
        return false;
    }

    let decoded = URL_SAFE_NO_PAD
        .decode(header)
        .or_else(|_| URL_SAFE.decode(header));
    decoded
        .ok()
        .and_then(|bytes| serde_json::from_slice::<serde_json::Value>(&bytes).ok())
        .and_then(|header| header.as_object().cloned())
        .is_some_and(|header| header.contains_key("alg"))
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub(crate) struct ProbeDescriptor {
    id: ProbeId,
    label: String,
    failure_severity: FindingSeverity,
    #[serde(skip_serializing_if = "Option::is_none")]
    remediation: Option<Remediation>,
}

impl ProbeDescriptor {
    pub(crate) fn new(
        id: ProbeId,
        label: impl Into<String>,
        failure_severity: FindingSeverity,
        remediation: Option<Remediation>,
    ) -> Result<Self, ProbeDescriptorError> {
        let label = label.into();
        if !valid_safe_text(&label) {
            return Err(ProbeDescriptorError::UnsafeLabel);
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
}

#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub(crate) enum ProbeDescriptorError {
    #[error("probe label is unsafe")]
    UnsafeLabel,
}

mod worker_probe_only {
    pub(crate) trait Sealed {}
}

/// The only extensibility point accepted by the worker-local catalog.
///
/// Implementations are observational: the trait deliberately exposes no
/// mutable state, elevation, command execution, or action/apply capability.
/// It is sealed so a controller-side sibling cannot become a worker probe.
pub(crate) trait WorkerProbe: worker_probe_only::Sealed + Send + Sync {
    fn descriptor(&self) -> &ProbeDescriptor;
    fn observe(&self) -> Result<ProbeStatus, ProbeFailure>;
}

#[derive(Clone, PartialEq, Eq)]
pub(crate) enum ProbeStatus {
    Absent,
    Present {
        version: Option<String>,
        healthy: bool,
    },
    Broken {
        reason: String,
    },
    Unknowable {
        reason: String,
    },
}

#[derive(Clone, PartialEq, Eq)]
pub(crate) struct ProbeFailure {
    kind: ProbeFailureKind,
    detail: ProbeFailureDetail,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum ProbeFailureKind {
    PermissionDenied,
    Unreadable,
    MalformedOutput,
    MissingPrerequisite,
    ObservationFailed,
}

#[derive(Clone, PartialEq, Eq)]
struct ProbeFailureDetail(String);

impl ProbeFailureDetail {
    fn was_supplied(&self) -> bool {
        !self.0.is_empty()
    }
}

impl ProbeFailure {
    pub(crate) fn permission_denied(detail: impl Into<String>) -> Self {
        Self {
            kind: ProbeFailureKind::PermissionDenied,
            detail: ProbeFailureDetail(detail.into()),
        }
    }

    pub(crate) fn unreadable(detail: impl Into<String>) -> Self {
        Self {
            kind: ProbeFailureKind::Unreadable,
            detail: ProbeFailureDetail(detail.into()),
        }
    }

    pub(crate) fn malformed_output(detail: impl Into<String>) -> Self {
        Self {
            kind: ProbeFailureKind::MalformedOutput,
            detail: ProbeFailureDetail(detail.into()),
        }
    }

    pub(crate) fn missing_prerequisite(detail: impl Into<String>) -> Self {
        Self {
            kind: ProbeFailureKind::MissingPrerequisite,
            detail: ProbeFailureDetail(detail.into()),
        }
    }

    pub(crate) fn observation_failed(detail: impl Into<String>) -> Self {
        Self {
            kind: ProbeFailureKind::ObservationFailed,
            detail: ProbeFailureDetail(detail.into()),
        }
    }

    fn reason(&self) -> &'static str {
        let _ = self.detail.was_supplied();
        match self.kind {
            ProbeFailureKind::PermissionDenied => "permission denied",
            ProbeFailureKind::Unreadable => "state unreadable",
            ProbeFailureKind::MalformedOutput => "output was malformed or unsupported",
            ProbeFailureKind::MissingPrerequisite => "required prerequisite was unavailable",
            ProbeFailureKind::ObservationFailed => "probe observation failed",
        }
    }
}

impl ProbeStatus {
    fn sanitized(self) -> Self {
        match self {
            Self::Absent => Self::Absent,
            Self::Present { version, healthy } => Self::Present {
                version: version.and_then(sanitize_version),
                healthy,
            },
            Self::Broken { reason } => Self::Broken {
                reason: sanitize_reason(&reason),
            },
            Self::Unknowable { reason } => Self::Unknowable {
                reason: sanitize_reason(&reason),
            },
        }
    }
}

fn sanitize_version(version: String) -> Option<String> {
    let valid = !version.is_empty()
        && version.len() <= 128
        && !looks_secret_shaped(&version)
        && version
            .bytes()
            .all(|byte| matches!(byte, b'a'..=b'z' | b'A'..=b'Z' | b'0'..=b'9' | b'.' | b'-' | b'_' | b'+'));
    valid.then_some(version)
}

fn sanitize_reason(reason: &str) -> String {
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

#[derive(Clone, PartialEq, Eq)]
pub(crate) struct ProbeObservation {
    descriptor: ProbeDescriptor,
    status: ProbeStatus,
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

impl Serialize for ProbeObservation {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut output = serializer.serialize_struct("ProbeObservation", 2)?;
        output.serialize_field("descriptor", &self.descriptor)?;
        output.serialize_field("status", &SerializedProbeStatus::from(&self.status))?;
        output.end()
    }
}

impl ProbeObservation {
    fn new(descriptor: ProbeDescriptor, status: ProbeStatus) -> Self {
        Self {
            descriptor,
            status: status.sanitized(),
        }
    }

    pub(crate) fn descriptor(&self) -> &ProbeDescriptor {
        &self.descriptor
    }

    pub(crate) fn status(&self) -> &ProbeStatus {
        &self.status
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

    /// A setup view of the same data that doctor projects below; no second list.
    pub(crate) fn setup_observations(&self) -> impl ExactSizeIterator<Item = &ProbeObservation> {
        self.iter()
    }

    pub(crate) fn doctor_findings(&self) -> Vec<DoctorFinding> {
        self.iter().map(DoctorFinding::from_observation).collect()
    }
}

pub(crate) struct ProbeCatalog {
    probes: Vec<Box<dyn WorkerProbe>>,
}

impl ProbeCatalog {
    pub(crate) fn new(probes: Vec<Box<dyn WorkerProbe>>) -> Result<Self, ProbeCatalogError> {
        let mut ids = HashSet::with_capacity(probes.len());
        for probe in &probes {
            let id = probe.descriptor().id().clone();
            if !ids.insert(id.clone()) {
                return Err(ProbeCatalogError::DuplicateId(id));
            }
        }

        Ok(Self { probes })
    }

    pub(crate) fn observe(&self) -> ObservedState {
        ObservedState {
            observations: self
                .probes
                .iter()
                .map(|probe| {
                    let status = match probe.observe() {
                        Ok(status) => status,
                        Err(failure) => ProbeStatus::Unknowable {
                            reason: failure.reason().to_owned(),
                        },
                    };
                    ProbeObservation::new(probe.descriptor().clone(), status)
                })
                .collect(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub(crate) enum ProbeCatalogError {
    #[error("duplicate worker-local probe ID: {0}")]
    DuplicateId(ProbeId),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum DoctorFindingState {
    Pass,
    Fail,
    Unknown,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub(crate) struct DoctorFinding {
    id: ProbeId,
    state: DoctorFindingState,
    severity: FindingSeverity,
    message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    remediation: Option<Remediation>,
}

impl DoctorFinding {
    fn from_observation(observation: &ProbeObservation) -> Self {
        let (state, message) = match observation.status() {
            ProbeStatus::Absent => (DoctorFindingState::Fail, "subject is absent".to_owned()),
            ProbeStatus::Present { healthy: true, .. } => {
                (DoctorFindingState::Pass, "healthy".to_owned())
            }
            ProbeStatus::Present { healthy: false, .. } => {
                (DoctorFindingState::Fail, "present but unhealthy".to_owned())
            }
            ProbeStatus::Broken { reason } => (DoctorFindingState::Fail, reason.clone()),
            ProbeStatus::Unknowable { reason } => (DoctorFindingState::Unknown, reason.clone()),
        };
        let descriptor = observation.descriptor();

        Self {
            id: descriptor.id.clone(),
            state,
            severity: descriptor.failure_severity,
            message: format!("{}: {message}", descriptor.label),
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::path::PathBuf;
    use std::process::Command;
    use std::sync::{
        atomic::{AtomicUsize, Ordering},
        Arc,
    };

    struct FakeProbe {
        descriptor: ProbeDescriptor,
        result: Result<ProbeStatus, ProbeFailure>,
        calls: Arc<AtomicUsize>,
    }

    impl FakeProbe {
        fn new(id: &str, status: ProbeStatus, calls: Arc<AtomicUsize>) -> Self {
            Self {
                descriptor: ProbeDescriptor::new(
                    ProbeId::parse(id).expect("test probe ID must be valid"),
                    "test worker probe",
                    FindingSeverity::Error,
                    None,
                )
                .expect("test descriptor must be valid"),
                result: Ok(status),
                calls,
            }
        }

        fn failure(id: &str, failure: ProbeFailure, calls: Arc<AtomicUsize>) -> Self {
            Self {
                descriptor: ProbeDescriptor::new(
                    ProbeId::parse(id).expect("test probe ID must be valid"),
                    "test worker probe",
                    FindingSeverity::Error,
                    None,
                )
                .expect("test descriptor must be valid"),
                result: Err(failure),
                calls,
            }
        }
    }

    impl worker_probe_only::Sealed for FakeProbe {}

    impl WorkerProbe for FakeProbe {
        fn descriptor(&self) -> &ProbeDescriptor {
            &self.descriptor
        }

        fn observe(&self) -> Result<ProbeStatus, ProbeFailure> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            self.result.clone()
        }
    }

    #[test]
    fn catalog_runs_each_worker_probe_once_in_registration_order_without_losing_status() {
        let calls = Arc::new(AtomicUsize::new(0));
        let catalog = ProbeCatalog::new(vec![
            Box::new(FakeProbe::new(
                "tool.present",
                ProbeStatus::Present {
                    version: Some("1.2.3".to_owned()),
                    healthy: true,
                },
                Arc::clone(&calls),
            )),
            Box::new(FakeProbe::new(
                "tool.absent",
                ProbeStatus::Absent,
                Arc::clone(&calls),
            )),
            Box::new(FakeProbe::new(
                "tool.broken",
                ProbeStatus::Broken {
                    reason: "internally inconsistent state".to_owned(),
                },
                Arc::clone(&calls),
            )),
            Box::new(FakeProbe::new(
                "tool.unknown",
                ProbeStatus::Unknowable {
                    reason: "permission denied while reading state".to_owned(),
                },
                Arc::clone(&calls),
            )),
        ])
        .expect("unique worker-local probes must form a catalog");

        let observed = catalog.observe();

        assert_eq!(calls.load(Ordering::SeqCst), 4);
        assert_eq!(
            observed
                .iter()
                .map(|observation| observation.descriptor().id().as_str())
                .collect::<Vec<_>>(),
            vec!["tool.present", "tool.absent", "tool.broken", "tool.unknown"]
        );
        assert!(matches!(
            observed
                .get(&ProbeId::parse("tool.present").expect("valid ID"))
                .expect("present probe must be observable")
                .status(),
            ProbeStatus::Present {
                version: Some(version),
                healthy: true,
            } if version == "1.2.3"
        ));
        assert!(matches!(
            observed
                .get(&ProbeId::parse("tool.absent").expect("valid ID"))
                .expect("absent probe must be observable")
                .status(),
            ProbeStatus::Absent
        ));
        assert!(matches!(
            observed
                .get(&ProbeId::parse("tool.broken").expect("valid ID"))
                .expect("broken probe must be observable")
                .status(),
            ProbeStatus::Broken { .. }
        ));
        assert!(matches!(
            observed
                .get(&ProbeId::parse("tool.unknown").expect("valid ID"))
                .expect("unknown probe must be observable")
                .status(),
            ProbeStatus::Unknowable { .. }
        ));
    }

    #[test]
    fn one_catalog_sentinel_automatically_surfaces_to_setup_and_worker_doctor() {
        let calls = Arc::new(AtomicUsize::new(0));
        let catalog = ProbeCatalog::new(vec![Box::new(FakeProbe::new(
            "sentinel.shared",
            ProbeStatus::Present {
                version: None,
                healthy: true,
            },
            calls,
        ))])
        .expect("sentinel probe must register");

        let observed = catalog.observe();
        let setup_ids = observed
            .setup_observations()
            .map(|observation| observation.descriptor().id().as_str())
            .collect::<Vec<_>>();
        let doctor_findings = observed.doctor_findings();
        let doctor_ids = doctor_findings
            .iter()
            .map(|finding| finding.id().as_str())
            .collect::<Vec<_>>();

        assert_eq!(setup_ids, vec!["sentinel.shared"]);
        assert_eq!(doctor_ids, vec!["sentinel.shared"]);
    }

    #[test]
    fn duplicate_ids_are_rejected_before_any_probe_runs() {
        let calls = Arc::new(AtomicUsize::new(0));
        let result = ProbeCatalog::new(vec![
            Box::new(FakeProbe::new(
                "tool.git",
                ProbeStatus::Absent,
                Arc::clone(&calls),
            )),
            Box::new(FakeProbe::new(
                "tool.git",
                ProbeStatus::Present {
                    version: None,
                    healthy: true,
                },
                Arc::clone(&calls),
            )),
        ]);

        assert_eq!(calls.load(Ordering::SeqCst), 0);
        assert_eq!(
            result.err(),
            Some(ProbeCatalogError::DuplicateId(
                ProbeId::parse("tool.git").expect("valid ID")
            ))
        );
    }

    #[test]
    fn operational_observation_failures_project_to_unknown_without_becoming_absent_or_false() {
        let cases = [
            (
                "permission",
                ProbeFailure::permission_denied("EACCES token=do-not-leak"),
            ),
            (
                "unreadable",
                ProbeFailure::unreadable("state contains ghp_do-not-leak"),
            ),
            (
                "malformed",
                ProbeFailure::malformed_output("-----BEGIN PRIVATE KEY-----"),
            ),
            (
                "prerequisite",
                ProbeFailure::missing_prerequisite("tskey-do-not-leak"),
            ),
        ];

        for (suffix, failure) in cases {
            let calls = Arc::new(AtomicUsize::new(0));
            let catalog = ProbeCatalog::new(vec![Box::new(FakeProbe::failure(
                &format!("state.{suffix}"),
                failure,
                calls,
            ))])
            .expect("unknown observation probe must register");

            let observed = catalog.observe();
            let finding = observed.doctor_findings().pop().expect("one finding");

            assert!(matches!(
                observed.iter().next().expect("one observation").status(),
                ProbeStatus::Unknowable { .. }
            ));
            assert_eq!(finding.state(), DoctorFindingState::Unknown);
        }
    }

    #[test]
    fn authoritative_lookup_of_its_own_missing_subject_is_absent() {
        let calls = Arc::new(AtomicUsize::new(0));
        let catalog = ProbeCatalog::new(vec![Box::new(FakeProbe::new(
            "tool.git",
            ProbeStatus::Absent,
            calls,
        ))])
        .expect("authoritative lookup probe must register");

        let observed = catalog.observe();
        let finding = observed.doctor_findings().pop().expect("one finding");

        assert!(matches!(
            observed.iter().next().expect("one observation").status(),
            ProbeStatus::Absent
        ));
        assert_eq!(finding.state(), DoctorFindingState::Fail);
    }

    #[test]
    fn serialization_is_tagged_deterministic_and_redacts_unknown_reason() {
        let calls = Arc::new(AtomicUsize::new(0));
        let catalog = ProbeCatalog::new(vec![Box::new(FakeProbe::new(
            "state.protected",
            ProbeStatus::Unknowable {
                reason: "permission denied; token=super-secret-value".to_owned(),
            },
            calls,
        ))])
        .expect("probe must register");

        let observed = catalog.observe();
        let observation = observed.iter().next().expect("one observation");
        let finding = observed.doctor_findings().pop().expect("one finding");
        let observation_json = serde_json::to_string(observation).expect("observation serializes");
        let finding_json = serde_json::to_string(&finding).expect("finding serializes");

        assert_eq!(
            observation_json,
            "{\"descriptor\":{\"id\":\"state.protected\",\"label\":\"test worker probe\",\"failure_severity\":\"error\"},\"status\":{\"status\":\"unknowable\",\"reason\":\"permission denied\"}}"
        );
        assert_eq!(
            finding_json,
            "{\"id\":\"state.protected\",\"state\":\"unknown\",\"severity\":\"error\",\"message\":\"test worker probe: permission denied\"}"
        );
        assert!(!observation_json.contains("super-secret-value"));
        assert!(!finding_json.contains("super-secret-value"));
    }

    #[test]
    fn probe_ids_reject_invalid_segments_without_reserving_controller_strings() {
        for invalid in [
            "",
            "tool",
            "tool. git",
            "tool.git status",
            "tool.git;rm",
            "tool.\u{0000}git",
            "Tool.git",
            "-tool.git",
            "tool-.git",
            "tool.git-",
        ] {
            assert!(
                ProbeId::parse(invalid).is_err(),
                "{invalid:?} must be rejected"
            );
        }
        assert_eq!(
            ProbeId::parse("machine.manifest-worker-readable")
                .expect("worker-local dotted ID must be accepted")
                .as_str(),
            "machine.manifest-worker-readable"
        );
        assert!(ProbeId::parse("controller.tailscale-reachability").is_ok());
    }

    #[test]
    fn remediation_is_a_fixed_styrn_command_and_rejects_secret_shaped_summaries() {
        let remediation = Remediation::new(
            "Initialize this machine before setup.",
            Some(StyrnCommand::MachineInit),
        )
        .expect("fixed styrn command remediation must be accepted");

        assert_eq!(
            serde_json::to_string(&remediation).expect("remediation serializes"),
            "{\"summary\":\"Initialize this machine before setup.\",\"styrn_args\":[\"machine\",\"init\"]}"
        );
        assert!(Remediation::new("use token=not-safe", None).is_err());
    }

    #[test]
    fn catalog_redacts_secret_shaped_dynamic_observation_data_and_rejects_static_data() {
        let secrets = [
            "--api-key=do-not-leak",
            "auth token do-not-leak",
            "secret=do-not-leak",
            "sk_live_do-not-leak",
            "ghp_do-not-leak",
            "github_pat_do-not-leak",
            "tskey-do-not-leak",
            "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.signature",
            "-----BEGIN PRIVATE KEY-----",
        ];

        for (index, secret) in secrets.iter().enumerate() {
            let calls = Arc::new(AtomicUsize::new(0));
            let catalog = ProbeCatalog::new(vec![Box::new(FakeProbe::new(
                &format!("state.secret-{index}"),
                ProbeStatus::Present {
                    version: Some((*secret).to_owned()),
                    healthy: false,
                },
                calls,
            ))])
            .expect("probe must register");

            let observed = catalog.observe();
            let serialized =
                serde_json::to_string(&observed.iter().next().expect("one observation"))
                    .expect("guarded observation serializes");
            let finding_serialized =
                serde_json::to_string(&observed.doctor_findings().pop().expect("one finding"))
                    .expect("guarded finding serializes");

            assert!(!serialized.contains(secret), "version leaked {secret:?}");
            assert!(
                !finding_serialized.contains(secret),
                "finding leaked {secret:?}"
            );
            let descriptor_error = ProbeDescriptor::new(
                ProbeId::parse("tool.git").expect("valid ID"),
                *secret,
                FindingSeverity::Error,
                None,
            )
            .expect_err("secret-shaped static label must be rejected");
            let remediation_error = Remediation::new(*secret, Some(StyrnCommand::MachineInit))
                .expect_err("secret-shaped remediation summary must be rejected");
            assert!(!descriptor_error.to_string().contains(secret));
            assert!(!remediation_error.to_string().contains(secret));
        }
    }

    #[test]
    fn controller_and_raw_serialization_escape_hatches_are_compile_time_rejected() {
        let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        let fixture = manifest_dir.join("src/setup/probe/fixtures/controller_escape_hatch.rs");
        let dependencies = manifest_dir.join("target/debug/deps");
        let output = Command::new("rustc")
            .arg("--edition=2021")
            .arg(&fixture)
            .arg("-L")
            .arg(format!("dependency={}", dependencies.display()))
            .arg("--extern")
            .arg(extern_artifact(&dependencies, "serde"))
            .arg("--extern")
            .arg(extern_artifact(&dependencies, "serde_json"))
            .arg("--extern")
            .arg(extern_artifact(&dependencies, "thiserror"))
            .arg("-o")
            .arg(manifest_dir.join("target/controller-escape-hatch-test"))
            .output()
            .expect("rustc must be available for the compile-fail boundary test");

        assert!(
            !output.status.success(),
            "controller/raw serialization escape hatch unexpectedly compiled"
        );
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(
            stderr.contains("Sealed"),
            "expected sealed worker-probe diagnostic, got:\n{stderr}"
        );
        assert!(
            stderr.contains("Serialize"),
            "expected raw ProbeStatus serialization diagnostic, got:\n{stderr}"
        );
    }

    fn extern_artifact(dependencies: &std::path::Path, crate_name: &str) -> String {
        let prefix = format!("lib{crate_name}-");
        let artifact = fs::read_dir(dependencies)
            .expect("test dependencies directory must exist")
            .filter_map(Result::ok)
            .map(|entry| entry.path())
            .find(|path| {
                path.file_name()
                    .and_then(|name| name.to_str())
                    .is_some_and(|name| name.starts_with(&prefix) && name.ends_with(".rlib"))
            })
            .expect("crate artifact must exist");
        format!("{crate_name}={}", artifact.display())
    }
}
