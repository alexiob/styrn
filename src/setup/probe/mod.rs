//! Read-only worker-local probe inputs.
//!
//! Guarded observations and doctor wire DTOs live in sibling `setup::probe_wire`.
//! Implementations can supply only specs and raw statuses; the setup parent
//! mediates conversion into serializable output.

use crate::setup::ObservedState;
use serde::Serialize;
use std::collections::HashSet;
use std::fmt;
use thiserror::Error;

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize)]
#[serde(transparent)]
pub(crate) struct ProbeId(String);

impl ProbeId {
    pub(crate) fn parse(value: &str) -> Result<Self, ProbeIdError> {
        if value.split('.').count() < 2 || !value.split('.').all(valid_probe_id_segment) {
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
        if !super::validate_probe_static_text(&summary) {
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
        if !super::validate_probe_static_text(&label) {
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
}

#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub(crate) enum ProbeDescriptorSpecError {
    #[error("probe label is unsafe")]
    UnsafeLabel,
}

mod worker_probe_only {
    pub(crate) trait Sealed {}
}

pub(crate) trait WorkerProbe: worker_probe_only::Sealed + Send + Sync {
    fn descriptor(&self) -> &ProbeDescriptorSpec;
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
    detail: String,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum ProbeFailureKind {
    PermissionDenied,
    Unreadable,
    MalformedOutput,
    MissingPrerequisite,
    ObservationFailed,
}

impl ProbeFailure {
    pub(crate) fn permission_denied(detail: impl Into<String>) -> Self {
        Self::new(ProbeFailureKind::PermissionDenied, detail)
    }

    pub(crate) fn unreadable(detail: impl Into<String>) -> Self {
        Self::new(ProbeFailureKind::Unreadable, detail)
    }

    pub(crate) fn malformed_output(detail: impl Into<String>) -> Self {
        Self::new(ProbeFailureKind::MalformedOutput, detail)
    }

    pub(crate) fn missing_prerequisite(detail: impl Into<String>) -> Self {
        Self::new(ProbeFailureKind::MissingPrerequisite, detail)
    }

    pub(crate) fn observation_failed(detail: impl Into<String>) -> Self {
        Self::new(ProbeFailureKind::ObservationFailed, detail)
    }

    fn new(kind: ProbeFailureKind, detail: impl Into<String>) -> Self {
        Self {
            kind,
            detail: detail.into(),
        }
    }

    pub(crate) fn canonical_reason(&self) -> &'static str {
        let _ = self.detail.is_empty();
        match self.kind {
            ProbeFailureKind::PermissionDenied => "permission denied",
            ProbeFailureKind::Unreadable => "state unreadable",
            ProbeFailureKind::MalformedOutput => "output was malformed or unsupported",
            ProbeFailureKind::MissingPrerequisite => "required prerequisite was unavailable",
            ProbeFailureKind::ObservationFailed => "probe observation failed",
        }
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
        super::observe_worker_probes(&self.probes)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub(crate) enum ProbeCatalogError {
    #[error("duplicate worker-local probe ID: {0}")]
    DuplicateId(ProbeId),
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::setup::DoctorFindingState;
    use std::sync::{
        atomic::{AtomicUsize, Ordering},
        Arc,
    };
    use std::{
        collections::BTreeMap,
        path::{Path, PathBuf},
        process::Command,
        sync::OnceLock,
    };

    struct FakeProbe {
        descriptor: ProbeDescriptorSpec,
        result: Result<ProbeStatus, ProbeFailure>,
        calls: Arc<AtomicUsize>,
    }

    impl FakeProbe {
        fn new(id: &str, status: ProbeStatus, calls: Arc<AtomicUsize>) -> Self {
            Self {
                descriptor: descriptor(id),
                result: Ok(status),
                calls,
            }
        }

        fn failure(id: &str, failure: ProbeFailure, calls: Arc<AtomicUsize>) -> Self {
            Self {
                descriptor: descriptor(id),
                result: Err(failure),
                calls,
            }
        }
    }

    impl worker_probe_only::Sealed for FakeProbe {}

    impl WorkerProbe for FakeProbe {
        fn descriptor(&self) -> &ProbeDescriptorSpec {
            &self.descriptor
        }

        fn observe(&self) -> Result<ProbeStatus, ProbeFailure> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            self.result.clone()
        }
    }

    mod legitimate_descendant {
        use super::*;

        pub(super) struct ChildProbe {
            descriptor: ProbeDescriptorSpec,
        }

        impl ChildProbe {
            pub(super) fn new() -> Self {
                Self {
                    descriptor: descriptor("tool.descendant"),
                }
            }
        }

        impl worker_probe_only::Sealed for ChildProbe {}

        impl WorkerProbe for ChildProbe {
            fn descriptor(&self) -> &ProbeDescriptorSpec {
                &self.descriptor
            }

            fn observe(&self) -> Result<ProbeStatus, ProbeFailure> {
                Ok(ProbeStatus::Present {
                    version: Some("1.0.0".to_owned()),
                    healthy: true,
                })
            }
        }
    }

    fn descriptor(id: &str) -> ProbeDescriptorSpec {
        ProbeDescriptorSpec::new(
            ProbeId::parse(id).expect("test probe ID must be valid"),
            "test worker probe",
            FindingSeverity::Error,
            None,
        )
        .expect("test descriptor must be valid")
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
                .map(|item| item.descriptor().id().as_str())
                .collect::<Vec<_>>(),
            vec!["tool.present", "tool.absent", "tool.broken", "tool.unknown"]
        );
        assert!(
            matches!(observed.get(&ProbeId::parse("tool.present").unwrap()).unwrap().status(), ProbeStatus::Present { version: Some(version), healthy: true } if version == "1.2.3")
        );
        assert!(matches!(
            observed
                .get(&ProbeId::parse("tool.absent").unwrap())
                .unwrap()
                .status(),
            ProbeStatus::Absent
        ));
        assert!(matches!(
            observed
                .get(&ProbeId::parse("tool.broken").unwrap())
                .unwrap()
                .status(),
            ProbeStatus::Broken { .. }
        ));
        assert!(matches!(
            observed
                .get(&ProbeId::parse("tool.unknown").unwrap())
                .unwrap()
                .status(),
            ProbeStatus::Unknowable { .. }
        ));
    }

    #[test]
    fn descendant_probe_uses_validated_specs_and_catalog_guarded_output() {
        let observed = ProbeCatalog::new(vec![Box::new(legitimate_descendant::ChildProbe::new())])
            .unwrap()
            .observe();
        assert_eq!(observed.iter().count(), 1);
        assert_eq!(
            observed.doctor_findings()[0].state(),
            DoctorFindingState::Pass
        );
    }

    #[test]
    fn one_catalog_sentinel_automatically_surfaces_to_setup_and_worker_doctor() {
        let observed = ProbeCatalog::new(vec![Box::new(FakeProbe::new(
            "sentinel.shared",
            ProbeStatus::Present {
                version: None,
                healthy: true,
            },
            Arc::new(AtomicUsize::new(0)),
        ))])
        .unwrap()
        .observe();
        assert_eq!(
            observed
                .setup_observations()
                .map(|item| item.descriptor().id().as_str())
                .collect::<Vec<_>>(),
            vec!["sentinel.shared"]
        );
        assert_eq!(
            observed
                .doctor_findings()
                .iter()
                .map(|item| item.id().as_str())
                .collect::<Vec<_>>(),
            vec!["sentinel.shared"]
        );
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
                ProbeStatus::Absent,
                Arc::clone(&calls),
            )),
        ]);
        assert_eq!(calls.load(Ordering::SeqCst), 0);
        assert_eq!(
            result.err(),
            Some(ProbeCatalogError::DuplicateId(
                ProbeId::parse("tool.git").unwrap()
            ))
        );
    }

    #[test]
    fn operational_failures_project_to_unknown_without_becoming_absent() {
        for (id, failure) in [
            (
                "state.permission",
                ProbeFailure::permission_denied("EACCES token=do-not-leak"),
            ),
            (
                "state.unreadable",
                ProbeFailure::unreadable("ghp_do-not-leak"),
            ),
            (
                "state.malformed",
                ProbeFailure::malformed_output("-----BEGIN PRIVATE KEY-----"),
            ),
            (
                "state.prerequisite",
                ProbeFailure::missing_prerequisite("tskey-do-not-leak"),
            ),
        ] {
            let observed = ProbeCatalog::new(vec![Box::new(FakeProbe::failure(
                id,
                failure,
                Arc::new(AtomicUsize::new(0)),
            ))])
            .unwrap()
            .observe();
            assert!(matches!(
                observed.iter().next().unwrap().status(),
                ProbeStatus::Unknowable { .. }
            ));
            assert_eq!(
                observed.doctor_findings()[0].state(),
                DoctorFindingState::Unknown
            );
        }
    }

    #[test]
    fn authoritative_own_subject_absence_is_not_an_operational_failure() {
        let observed = ProbeCatalog::new(vec![Box::new(FakeProbe::new(
            "tool.git",
            ProbeStatus::Absent,
            Arc::new(AtomicUsize::new(0)),
        ))])
        .unwrap()
        .observe();
        assert!(matches!(
            observed.iter().next().unwrap().status(),
            ProbeStatus::Absent
        ));
        assert_eq!(
            observed.doctor_findings()[0].state(),
            DoctorFindingState::Fail
        );
    }

    #[test]
    fn guarded_serialization_is_tagged_and_redacts_raw_reason() {
        let observed = ProbeCatalog::new(vec![Box::new(FakeProbe::new(
            "state.protected",
            ProbeStatus::Unknowable {
                reason: "permission denied; token=super-secret-value".to_owned(),
            },
            Arc::new(AtomicUsize::new(0)),
        ))])
        .unwrap()
        .observe();
        let observation = serde_json::to_string(observed.iter().next().unwrap()).unwrap();
        let finding = serde_json::to_string(&observed.doctor_findings()[0]).unwrap();
        assert_eq!(observation, "{\"descriptor\":{\"id\":\"state.protected\",\"label\":\"test worker probe\",\"failure_severity\":\"error\"},\"status\":{\"status\":\"unknowable\",\"reason\":\"permission denied\"}}");
        assert!(!observation.contains("super-secret-value"));
        assert!(!finding.contains("super-secret-value"));
    }

    #[test]
    fn wire_serialization_redacts_every_secret_shaped_runtime_observation() {
        for secret in secret_examples() {
            for status in [
                ProbeStatus::Present {
                    version: Some((*secret).to_owned()),
                    healthy: true,
                },
                ProbeStatus::Broken {
                    reason: (*secret).to_owned(),
                },
                ProbeStatus::Unknowable {
                    reason: (*secret).to_owned(),
                },
            ] {
                let observed = ProbeCatalog::new(vec![Box::new(FakeProbe::new(
                    "state.protected",
                    status,
                    Arc::new(AtomicUsize::new(0)),
                ))])
                .unwrap()
                .observe();
                let observation = serde_json::to_string(observed.iter().next().unwrap()).unwrap();
                let finding = serde_json::to_string(&observed.doctor_findings()[0]).unwrap();
                assert!(
                    !observation.contains(secret),
                    "observation leaked {secret:?}"
                );
                assert!(!finding.contains(secret), "finding leaked {secret:?}");
            }
        }
    }

    #[test]
    fn remediation_serialization_is_a_closed_styrn_command() {
        let remediation = RemediationSpec::new(
            "Initialize the local machine.",
            Some(StyrnCommand::MachineInit),
        )
        .unwrap();
        let descriptor = ProbeDescriptorSpec::new(
            ProbeId::parse("machine.initialized").unwrap(),
            "Machine initialization",
            FindingSeverity::Error,
            Some(remediation),
        )
        .unwrap();
        let observed = ProbeCatalog::new(vec![Box::new(FakeProbe {
            descriptor,
            result: Ok(ProbeStatus::Absent),
            calls: Arc::new(AtomicUsize::new(0)),
        })])
        .unwrap()
        .observe();
        let json = serde_json::to_string(observed.iter().next().unwrap()).unwrap();
        assert!(json.contains("\"styrn_args\":[\"machine\",\"init\"]"));
        for forbidden in ["\"program\"", "sh", "powershell", "-c", "-Command", "curl"] {
            assert!(
                !json.contains(forbidden),
                "remediation exposed {forbidden:?}"
            );
        }
    }

    #[test]
    fn probe_ids_accept_one_character_segments_and_reject_malformed_segments() {
        for invalid in [
            "",
            "tool",
            "tool.",
            "tool.-git",
            "tool.git-",
            "tool. git",
            "Tool.git",
        ] {
            assert!(
                ProbeId::parse(invalid).is_err(),
                "{invalid:?} must be rejected"
            );
        }
        assert_eq!(ProbeId::parse("a.b").unwrap().as_str(), "a.b");
        assert!(ProbeId::parse("controller.tailscale-reachability").is_ok());
    }

    #[test]
    fn secret_classifier_rejects_auth_assignments_and_embedded_credentials_but_allows_plain_text() {
        for secret in secret_examples() {
            let remediation = RemediationSpec::new(*secret, Some(StyrnCommand::MachineInit))
                .expect_err("secret remediation must fail");
            let descriptor = ProbeDescriptorSpec::new(
                ProbeId::parse("tool.git").unwrap(),
                *secret,
                FindingSeverity::Error,
                None,
            )
            .expect_err("secret label must fail");
            assert!(!remediation.to_string().contains(secret));
            assert!(!descriptor.to_string().contains(secret));
        }
        assert!(RemediationSpec::new("Inspect local service state.", None).is_ok());
    }

    fn secret_examples() -> &'static [&'static str] {
        &[
            "--api-key=do-not-leak",
            "--auth=abc123",
            "auth token do-not-leak",
            "authorization=Bearer abc123",
            "Bearer eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.signature",
            "secret=do-not-leak",
            "sk_live_do-not-leak",
            "ghp_do-not-leak",
            "github_pat_do-not-leak",
            "tskey-do-not-leak",
            "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.signature",
            "diagnostic: eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.signature",
            "-----BEGIN PRIVATE KEY-----",
        ]
    }

    #[test]
    fn only_the_worker_probe_module_can_implement_worker_probe() {
        assert_fixture_fails("sealed_worker_probe.rs", &["Sealed"]);
    }

    #[test]
    fn raw_probe_status_cannot_be_serialized_directly() {
        assert_fixture_fails("raw_status_serialization.rs", &["ProbeStatus", "Serialize"]);
    }

    #[test]
    fn raw_probe_status_cannot_be_hidden_in_a_serialization_proxy() {
        assert_fixture_fails(
            "proxy_status_serialization.rs",
            &["ProbeStatus", "Serialize"],
        );
    }

    #[test]
    fn remediation_cannot_accept_arbitrary_argv() {
        assert_fixture_fails("closed_remediation.rs", &["StyrnCommand", "Vec"]);
    }

    #[test]
    fn guarded_wire_dtos_cannot_be_constructed_by_a_probe_implementation() {
        assert_fixture_fails("wire_dto_construction.rs", &["private"]);
    }

    fn assert_fixture_fails(fixture_name: &str, required_diagnostics: &[&str]) {
        let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        let fixture = manifest_dir
            .join("src/setup/probe/fixtures")
            .join(fixture_name);
        let artifacts = cargo_managed_artifacts(&manifest_dir);
        let output_path = artifacts
            .target_dir
            .join(format!("{fixture_name}.compile-fail-output"));
        let mut command = Command::new("rustc");
        command
            .arg("--edition=2021")
            .arg(&fixture)
            .arg("-L")
            .arg(format!("dependency={}", artifacts.deps_dir.display()));
        for dependency in ["base64", "serde", "serde_json", "thiserror"] {
            command.arg("--extern").arg(format!(
                "{dependency}={}",
                artifacts.paths[dependency].display()
            ));
        }
        let output = command
            .arg("-o")
            .arg(output_path)
            .output()
            .expect("rustc must be available for compile-fail boundary tests");
        assert!(
            !output.status.success(),
            "{fixture_name} unexpectedly compiled"
        );
        let stderr = String::from_utf8_lossy(&output.stderr);
        for diagnostic in required_diagnostics {
            assert!(
                stderr.contains(diagnostic),
                "{fixture_name} did not fail for {diagnostic:?}:\n{stderr}"
            );
        }
    }

    struct CargoArtifacts {
        target_dir: PathBuf,
        deps_dir: PathBuf,
        paths: BTreeMap<String, PathBuf>,
    }

    fn cargo_managed_artifacts(manifest_dir: &Path) -> &'static CargoArtifacts {
        static ARTIFACTS: OnceLock<CargoArtifacts> = OnceLock::new();
        ARTIFACTS.get_or_init(|| {
            let target_dir = std::env::temp_dir().join(format!(
                "styrn-probe-compile-fixtures-{}",
                std::process::id()
            ));
            let output = Command::new("cargo")
                .current_dir(manifest_dir)
                .args([
                    "build",
                    "--locked",
                    "--message-format=json-render-diagnostics",
                    "--target-dir",
                ])
                .arg(&target_dir)
                .output()
                .expect("cargo must be available for compile-fail boundary tests");
            assert!(
                output.status.success(),
                "Cargo dependency build failed:\n{}",
                String::from_utf8_lossy(&output.stderr)
            );
            let mut paths = BTreeMap::new();
            for line in String::from_utf8_lossy(&output.stdout).lines() {
                let Ok(message) = serde_json::from_str::<serde_json::Value>(line) else {
                    continue;
                };
                if message["reason"] != "compiler-artifact" {
                    continue;
                }
                let Some(name) = message["target"]["name"].as_str() else {
                    continue;
                };
                if !["base64", "serde", "serde_json", "thiserror"].contains(&name) {
                    continue;
                }
                let artifact = message["filenames"]
                    .as_array()
                    .and_then(|filenames| {
                        filenames
                            .iter()
                            .filter_map(|filename| filename.as_str())
                            .find(|filename| filename.ends_with(".rlib"))
                    })
                    .map(PathBuf::from)
                    .expect("Cargo must report a library artifact for each direct dependency");
                paths.insert(name.to_owned(), artifact);
            }
            for dependency in ["base64", "serde", "serde_json", "thiserror"] {
                assert!(
                    paths.contains_key(dependency),
                    "Cargo did not report the {dependency} artifact"
                );
            }
            let deps_dir = target_dir.join("debug/deps");
            CargoArtifacts {
                target_dir,
                deps_dir,
                paths,
            }
        })
    }
}
