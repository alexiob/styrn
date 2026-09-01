//! Read-only worker-local capability observations shared by setup and doctor.
//!
//! Controller-relational checks deliberately do not have a type in this module:
//! `ProbeCatalog` accepts only `WorkerProbe` implementations, and the
//! `controller.*` namespace is reserved for the controller doctor layer.

use serde::Serialize;
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
        if value.starts_with("controller.") {
            return Err(ProbeIdError::ControllerNamespace);
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
        && chars.all(|byte| matches!(byte, b'a'..=b'z' | b'0'..=b'9' | b'-'))
}

#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub(crate) enum ProbeIdError {
    #[error("probe ID must contain at least two lowercase dot-namespaced segments")]
    Invalid,
    #[error("controller-relational checks cannot be worker-local probes")]
    ControllerNamespace,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum FindingSeverity {
    Info,
    Warning,
    Error,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub(crate) struct Remediation {
    summary: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    argv: Option<Vec<String>>,
}

impl Remediation {
    pub(crate) fn new(
        summary: impl Into<String>,
        argv: Option<Vec<String>>,
    ) -> Result<Self, RemediationError> {
        let summary = summary.into();
        if !valid_safe_text(&summary) {
            return Err(RemediationError::UnsafeSummary);
        }
        if argv.as_ref().is_some_and(|args| {
            args.is_empty() || args.iter().any(|argument| !valid_safe_text(argument))
        }) {
            return Err(RemediationError::UnsafeArgv);
        }

        Ok(Self { summary, argv })
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub(crate) enum RemediationError {
    #[error("remediation summary is unsafe")]
    UnsafeSummary,
    #[error("remediation argv is unsafe")]
    UnsafeArgv,
}

fn valid_safe_text(value: &str) -> bool {
    !value.is_empty() && !value.chars().any(char::is_control) && !looks_secret_shaped(value)
}

fn looks_secret_shaped(value: &str) -> bool {
    let normalized = value.to_ascii_lowercase();
    [
        "token=",
        "password",
        "private key",
        "api key",
        "auth key",
        "bearer ",
        "-----begin",
        "tskey-",
        "sk-",
    ]
    .iter()
    .any(|needle| normalized.contains(needle))
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

/// The only extensibility point accepted by the worker-local catalog.
///
/// Implementations are observational: the trait deliberately exposes no
/// mutable state, elevation, command execution, or action/apply capability.
pub(crate) trait WorkerProbe: Send + Sync {
    fn descriptor(&self) -> &ProbeDescriptor;
    fn observe(&self) -> ProbeStatus;
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "status", rename_all = "snake_case")]
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

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub(crate) struct ProbeObservation {
    descriptor: ProbeDescriptor,
    status: ProbeStatus,
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

#[derive(Debug, Clone, PartialEq, Eq)]
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
                .map(|probe| ProbeObservation::new(probe.descriptor().clone(), probe.observe()))
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
    use std::sync::{
        atomic::{AtomicUsize, Ordering},
        Arc,
    };

    struct FakeProbe {
        descriptor: ProbeDescriptor,
        status: ProbeStatus,
        calls: Arc<AtomicUsize>,
    }

    impl FakeProbe {
        fn new(id: &str, status: ProbeStatus, calls: Arc<AtomicUsize>) -> Self {
            Self {
                descriptor: ProbeDescriptor::new(
                    ProbeId::parse(id).expect("test probe ID must be valid"),
                    id,
                    FindingSeverity::Error,
                    None,
                )
                .expect("test descriptor must be valid"),
                status,
                calls,
            }
        }
    }

    impl WorkerProbe for FakeProbe {
        fn descriptor(&self) -> &ProbeDescriptor {
            &self.descriptor
        }

        fn observe(&self) -> ProbeStatus {
            self.calls.fetch_add(1, Ordering::SeqCst);
            self.status.clone()
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
    fn observation_failures_project_to_unknown_without_becoming_absent_or_false() {
        let cases = [
            ("permission", "permission denied"),
            ("unreadable", "state unreadable"),
            ("malformed", "unsupported output"),
            ("prerequisite", "missing prerequisite"),
        ];

        for (suffix, reason) in cases {
            let calls = Arc::new(AtomicUsize::new(0));
            let catalog = ProbeCatalog::new(vec![Box::new(FakeProbe::new(
                &format!("state.{suffix}"),
                ProbeStatus::Unknowable {
                    reason: reason.to_owned(),
                },
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
            "{\"descriptor\":{\"id\":\"state.protected\",\"label\":\"state.protected\",\"failure_severity\":\"error\"},\"status\":{\"status\":\"unknowable\",\"reason\":\"permission denied\"}}"
        );
        assert_eq!(
            finding_json,
            "{\"id\":\"state.protected\",\"state\":\"unknown\",\"severity\":\"error\",\"message\":\"state.protected: permission denied\"}"
        );
        assert!(!observation_json.contains("super-secret-value"));
        assert!(!finding_json.contains("super-secret-value"));
    }

    #[test]
    fn probe_ids_reject_invalid_or_controller_relational_namespaces() {
        for invalid in [
            "",
            "tool",
            "tool. git",
            "tool.git status",
            "tool.git;rm",
            "tool.\u{0000}git",
            "Tool.git",
            "controller.tailscale-reachability",
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
    }

    #[test]
    fn remediation_is_typed_argv_data_and_rejects_secret_shaped_values() {
        let remediation = Remediation::new(
            "Initialize this machine before setup.",
            Some(vec![
                "styrn".to_owned(),
                "machine".to_owned(),
                "init".to_owned(),
            ]),
        )
        .expect("safe argv remediation must be accepted");

        assert_eq!(
            serde_json::to_string(&remediation).expect("remediation serializes"),
            "{\"summary\":\"Initialize this machine before setup.\",\"argv\":[\"styrn\",\"machine\",\"init\"]}"
        );
        assert!(Remediation::new("use token=not-safe", None).is_err());
        assert!(Remediation::new("safe", Some(vec!["--password=not-safe".to_owned()])).is_err());
    }
}
