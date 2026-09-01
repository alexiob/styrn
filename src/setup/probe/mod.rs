//! Read-only worker-local probe inputs.
//!
//! Guarded observations and doctor wire DTOs live in sibling `setup::probe_wire`.
//! Implementations can supply only specs and raw statuses; the setup parent
//! mediates conversion into serializable output.

use crate::setup::ObservedState;
use std::collections::HashSet;
use thiserror::Error;

pub(crate) use super::probe_values::{
    FindingSeverity, ProbeDescriptorSpec, ProbeId, RemediationSpec, StyrnCommand,
};

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
            if !probe.descriptor().is_valid() {
                return Err(ProbeCatalogError::InvalidDescriptor);
            }
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
    #[error("worker-local probe descriptor is invalid")]
    InvalidDescriptor,
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
        fs,
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

            pub(super) fn rejects_untrusted_descriptor_inputs() -> bool {
                ProbeId::parse("tool.invalid-").is_err()
                    && ProbeDescriptorSpec::new(
                        ProbeId::parse("tool.safe").expect("safe test ID"),
                        "Bearer=secret-credential",
                        FindingSeverity::Error,
                        None,
                    )
                    .is_err()
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
        assert!(legitimate_descendant::ChildProbe::rejects_untrusted_descriptor_inputs());
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
        for case in credential_case_matrix()
            .iter()
            .filter(|case| case.is_secret)
        {
            let secret = case.value;
            for status in [
                ProbeStatus::Present {
                    version: Some(secret.to_owned()),
                    healthy: true,
                },
                ProbeStatus::Broken {
                    reason: secret.to_owned(),
                },
                ProbeStatus::Unknowable {
                    reason: secret.to_owned(),
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
        for case in credential_case_matrix()
            .iter()
            .filter(|case| case.is_secret)
        {
            let secret = case.value;
            let remediation = RemediationSpec::new(secret, Some(StyrnCommand::MachineInit))
                .expect_err("secret remediation must fail");
            let descriptor = ProbeDescriptorSpec::new(
                ProbeId::parse("tool.git").unwrap(),
                secret,
                FindingSeverity::Error,
                None,
            )
            .expect_err("secret label must fail");
            assert!(!remediation.to_string().contains(secret));
            assert!(!descriptor.to_string().contains(secret));
        }
        for case in credential_case_matrix()
            .iter()
            .filter(|case| !case.is_secret)
        {
            let ordinary_text = case.value;
            assert!(RemediationSpec::new(ordinary_text, None).is_ok());
            let descriptor = ProbeDescriptorSpec::new(
                ProbeId::parse("tool.safe").unwrap(),
                ordinary_text,
                FindingSeverity::Info,
                None,
            )
            .expect("ordinary descriptor must be accepted");
            let observed = ProbeCatalog::new(vec![Box::new(FakeProbe {
                descriptor,
                result: Ok(ProbeStatus::Present {
                    version: None,
                    healthy: true,
                }),
                calls: Arc::new(AtomicUsize::new(0)),
            })])
            .unwrap()
            .observe();
            assert!(serde_json::to_string(observed.iter().next().unwrap())
                .unwrap()
                .contains(ordinary_text));
        }
    }

    #[derive(Clone, Copy)]
    struct CredentialCase {
        value: &'static str,
        is_secret: bool,
    }

    fn credential_case_matrix() -> &'static [CredentialCase] {
        &[
            CredentialCase {
                value: "--api-key=do-not-leak",
                is_secret: true,
            },
            CredentialCase {
                value: "api_key=abc123",
                is_secret: true,
            },
            CredentialCase {
                value: "--auth=abc123",
                is_secret: true,
            },
            CredentialCase {
                value: "auth token do-not-leak",
                is_secret: true,
            },
            CredentialCase {
                value: "authorization=Bearer abc123",
                is_secret: true,
            },
            CredentialCase {
                value: "Bearer=abc123",
                is_secret: true,
            },
            CredentialCase {
                value: "Bearer eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.signature",
                is_secret: true,
            },
            CredentialCase {
                value: "secret=do-not-leak",
                is_secret: true,
            },
            CredentialCase {
                value: "token=abc123",
                is_secret: true,
            },
            CredentialCase {
                value: "token: abc123",
                is_secret: true,
            },
            CredentialCase {
                value: "auth = abc123",
                is_secret: true,
            },
            CredentialCase {
                value: "AUTH : abc123",
                is_secret: true,
            },
            CredentialCase {
                value: "password: hunter2",
                is_secret: true,
            },
            CredentialCase {
                value: "api_key: abc123",
                is_secret: true,
            },
            CredentialCase {
                value: "Bearer abcdefgh",
                is_secret: true,
            },
            CredentialCase {
                value: "received Bearer abcdefgh",
                is_secret: true,
            },
            CredentialCase {
                value: "using Bearer abcdefgh",
                is_secret: true,
            },
            CredentialCase {
                value: "received bearer=abcdefgh",
                is_secret: true,
            },
            CredentialCase {
                value: "authorization bearer abcdefgh",
                is_secret: true,
            },
            CredentialCase {
                value: "authorization bearer: abcdefgh",
                is_secret: true,
            },
            CredentialCase {
                value: "token: (abc123)",
                is_secret: true,
            },
            CredentialCase {
                value: "AUTH = [abc123]",
                is_secret: true,
            },
            CredentialCase {
                value: "auth token (abc123)",
                is_secret: true,
            },
            CredentialCase {
                value: "authorization bearer [abcdefgh]",
                is_secret: true,
            },
            CredentialCase {
                value: "received Bearer (abcdefgh)",
                is_secret: true,
            },
            CredentialCase {
                value: "secret = {abc123}",
                is_secret: true,
            },
            CredentialCase {
                value: "auth_token=abc123",
                is_secret: true,
            },
            CredentialCase {
                value: "--auth-token: (abc123)",
                is_secret: true,
            },
            CredentialCase {
                value: "access_token=[abc123]",
                is_secret: true,
            },
            CredentialCase {
                value: "bearer-token=abcdefgh",
                is_secret: true,
            },
            CredentialCase {
                value: "api key: abc123",
                is_secret: true,
            },
            CredentialCase {
                value: "access key=abc123",
                is_secret: true,
            },
            CredentialCase {
                value: "authorization token=abc123",
                is_secret: true,
            },
            CredentialCase {
                value: "refresh-token=abc123",
                is_secret: true,
            },
            CredentialCase {
                value: "id_token=abc123",
                is_secret: true,
            },
            CredentialCase {
                value: "session token=abc123",
                is_secret: true,
            },
            CredentialCase {
                value: "private_key=abc123",
                is_secret: true,
            },
            CredentialCase {
                value: "secret key=abc123",
                is_secret: true,
            },
            CredentialCase {
                value: "client-secret=abc123",
                is_secret: true,
            },
            CredentialCase {
                value: "credentials: abc123",
                is_secret: true,
            },
            CredentialCase {
                value: "password hunter2",
                is_secret: true,
            },
            CredentialCase {
                value: "api key abc123",
                is_secret: true,
            },
            CredentialCase {
                value: "API_KEY abc123",
                is_secret: true,
            },
            CredentialCase {
                value: "auth_token abc123",
                is_secret: true,
            },
            CredentialCase {
                value: "bearer-token abc123",
                is_secret: true,
            },
            CredentialCase {
                value: "authorization_bearer_token abc123",
                is_secret: true,
            },
            CredentialCase {
                value: "private [key]=abc123",
                is_secret: true,
            },
            CredentialCase {
                value: "https://host/path?token=abc123",
                is_secret: true,
            },
            CredentialCase {
                value: "token-abc123",
                is_secret: true,
            },
            CredentialCase {
                value: "token_abc123",
                is_secret: true,
            },
            CredentialCase {
                value: "password-hunter2",
                is_secret: true,
            },
            CredentialCase {
                value: "api-key-abc123",
                is_secret: true,
            },
            CredentialCase {
                value: "private_key_abc123",
                is_secret: true,
            },
            CredentialCase {
                value: "token is absent hunter2",
                is_secret: true,
            },
            CredentialCase {
                value: "password is unavailable hunter2",
                is_secret: true,
            },
            CredentialCase {
                value: "api key support is enabled abc123",
                is_secret: true,
            },
            CredentialCase {
                value: "bearer token cache is healthy abc123",
                is_secret: true,
            },
            CredentialCase {
                value: "authorization bearer token support is enabled abc123",
                is_secret: true,
            },
            CredentialCase {
                value: "private key state is absent abc123",
                is_secret: true,
            },
            CredentialCase {
                value: "auth token status is healthy abc123",
                is_secret: true,
            },
            CredentialCase {
                value: "token cache is healthy: abc123",
                is_secret: true,
            },
            CredentialCase {
                value: "api.key=abc123",
                is_secret: true,
            },
            CredentialCase {
                value: "private.key=abc123",
                is_secret: true,
            },
            CredentialCase {
                value: "access.key=abc123",
                is_secret: true,
            },
            CredentialCase {
                value: "secret.key=abc123",
                is_secret: true,
            },
            CredentialCase {
                value: "api?key=abc123",
                is_secret: true,
            },
            CredentialCase {
                value: "token.value",
                is_secret: true,
            },
            CredentialCase {
                value: "password.hunter2",
                is_secret: true,
            },
            CredentialCase {
                value: "api.key.abc123",
                is_secret: true,
            },
            CredentialCase {
                value: "private.key.hunter2",
                is_secret: true,
            },
            CredentialCase {
                value: "sk_live_do-not-leak",
                is_secret: true,
            },
            CredentialCase {
                value: "ghp_do-not-leak",
                is_secret: true,
            },
            CredentialCase {
                value: "github_pat_do-not-leak",
                is_secret: true,
            },
            CredentialCase {
                value: "tskey-do-not-leak",
                is_secret: true,
            },
            CredentialCase {
                value: "prefix/sk_live_do-not-leak",
                is_secret: true,
            },
            CredentialCase {
                value: "https://host/sk_live_do-not-leak",
                is_secret: true,
            },
            CredentialCase {
                value: "diagnostic-sk_live_do-not-leak",
                is_secret: true,
            },
            CredentialCase {
                value: "foo?ghp_do-not-leak",
                is_secret: true,
            },
            CredentialCase {
                value: "prefix/ghp_do-not-leak",
                is_secret: true,
            },
            CredentialCase {
                value: "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.signature",
                is_secret: true,
            },
            CredentialCase {
                value: "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.signature.",
                is_secret: true,
            },
            CredentialCase {
                value: "eyJ0eXAiOiJKV1QifQ.eyJzdWIiOiIxIn0.signature",
                is_secret: true,
            },
            CredentialCase {
                value: "eyJhbGciOiJSU0EtT0FFUCIsImVuYyI6IkEyNTZHQ00ifQ.a.b.c.d",
                is_secret: true,
            },
            CredentialCase {
                value: "prefix/eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.signature",
                is_secret: true,
            },
            CredentialCase {
                value: "diagnostic-eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.signature",
                is_secret: true,
            },
            CredentialCase {
                value: "diagnostic_eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.signature",
                is_secret: true,
            },
            CredentialCase {
                value: "diagnosticeyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.signature",
                is_secret: true,
            },
            CredentialCase {
                value: "diagnostic: eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.signature",
                is_secret: true,
            },
            CredentialCase {
                value: "diagnostic=eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.signature",
                is_secret: true,
            },
            CredentialCase {
                value: "diagnostic=eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.signature.",
                is_secret: true,
            },
            CredentialCase {
                value: "diagnostic:eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.signature,",
                is_secret: true,
            },
            CredentialCase {
                value: "-----BEGIN PRIVATE KEY-----",
                is_secret: true,
            },
            CredentialCase {
                value: "Inspect local service state.",
                is_secret: false,
            },
            CredentialCase {
                value: "Diagnostic: local version 1.2.3 is healthy.",
                is_secret: false,
            },
            CredentialCase {
                value: "Authoritative machine identity is healthy.",
                is_secret: false,
            },
            CredentialCase {
                value: "authentication service is healthy.",
                is_secret: false,
            },
            CredentialCase {
                value: "the bearer process is healthy.",
                is_secret: false,
            },
            CredentialCase {
                value: "Bearer process is healthy.",
                is_secret: false,
            },
            CredentialCase {
                value: "Bearer process was healthy.",
                is_secret: false,
            },
            CredentialCase {
                value: "Bearer support is enabled.",
                is_secret: false,
            },
            CredentialCase {
                value: "Bearer authentication is healthy.",
                is_secret: false,
            },
            CredentialCase {
                value: "Bearer process status is healthy.",
                is_secret: false,
            },
            CredentialCase {
                value: "Auth token support is enabled.",
                is_secret: false,
            },
            CredentialCase {
                value: "API key support is enabled.",
                is_secret: false,
            },
            CredentialCase {
                value: "Access token cache is healthy.",
                is_secret: false,
            },
            CredentialCase {
                value: "Bearer token support is enabled.",
                is_secret: false,
            },
            CredentialCase {
                value: "Bearer token",
                is_secret: false,
            },
            CredentialCase {
                value: "Bearer token is absent.",
                is_secret: false,
            },
            CredentialCase {
                value: "Auth token cache is healthy.",
                is_secret: false,
            },
            CredentialCase {
                value: "Authorization bearer token support is enabled.",
                is_secret: false,
            },
            CredentialCase {
                value: "Password reset service is enabled.",
                is_secret: false,
            },
            CredentialCase {
                value: "Token refresh service is healthy.",
                is_secret: false,
            },
            CredentialCase {
                value: "API key rotation is enabled.",
                is_secret: false,
            },
            CredentialCase {
                value: "Private key permissions status is healthy.",
                is_secret: false,
            },
            CredentialCase {
                value: "Token status: absent.",
                is_secret: false,
            },
            CredentialCase {
                value: "Private key file is absent.",
                is_secret: false,
            },
            CredentialCase {
                value: "Password policy is enabled.",
                is_secret: false,
            },
            CredentialCase {
                value: "Token status is absent!",
                is_secret: false,
            },
            CredentialCase {
                value: "Token status is absent (managed).",
                is_secret: false,
            },
            CredentialCase {
                value: "task_worker",
                is_secret: false,
            },
            CredentialCase {
                value: "task_status",
                is_secret: false,
            },
            CredentialCase {
                value: "flask_service",
                is_secret: false,
            },
            CredentialCase {
                value: "mask_enabled",
                is_secret: false,
            },
            CredentialCase {
                value: "Token:, cache is healthy.",
                is_secret: false,
            },
            CredentialCase {
                value: "Bearer; process is healthy.",
                is_secret: false,
            },
            CredentialCase {
                value: "Auth service is healthy.",
                is_secret: false,
            },
            CredentialCase {
                value: "Token cache is healthy.",
                is_secret: false,
            },
            CredentialCase {
                value: "The auth process is healthy.",
                is_secret: false,
            },
            CredentialCase {
                value: "Token is absent.",
                is_secret: false,
            },
        ]
    }

    #[test]
    fn only_the_worker_probe_module_can_implement_worker_probe() {
        assert_fixture_fails(
            "sealed_worker_probe.rs",
            &[FixtureExpectation::new(
                "E0277",
                "the trait bound `ControllerCheck: Sealed` is not satisfied",
                13,
                "unsatisfied trait bound",
            )],
        );
    }

    #[test]
    fn raw_probe_status_cannot_be_serialized_directly() {
        assert_fixture_fails(
            "raw_status_serialization.rs",
            &[FixtureExpectation::new(
                "E0277",
                "the trait bound `ProbeStatus: serde::Serialize` is not satisfied",
                5,
                "unsatisfied trait bound",
            )],
        );
    }

    #[test]
    fn raw_probe_status_cannot_be_hidden_in_a_serialization_proxy() {
        assert_fixture_fails(
            "proxy_status_serialization.rs",
            &[FixtureExpectation::new(
                "E0277",
                "the trait bound `ProbeStatus: serde::Serialize` is not satisfied",
                13,
                "unsatisfied trait bound",
            )],
        );
    }

    #[test]
    fn remediation_cannot_accept_arbitrary_argv() {
        assert_fixture_fails(
            "closed_remediation.rs",
            &[FixtureExpectation::new(
                "E0308",
                "mismatched types",
                7,
                "expected `StyrnCommand`, found `Vec<String>`",
            )],
        );
    }

    #[test]
    fn guarded_wire_dtos_cannot_be_constructed_by_a_probe_implementation() {
        assert_fixture_fails(
            "wire_dto_construction.rs",
            &[
                FixtureExpectation::new(
                    "E0451",
                    "fields `descriptor` and `status` of struct `ProbeObservation` are private",
                    10,
                    "private field",
                ),
                FixtureExpectation::new(
                    "E0451",
                    "fields `id`, `state`, `severity`, `message` and `remediation` of struct `DoctorFinding` are private",
                    17,
                    "private field",
                ),
            ],
        );
    }

    #[test]
    fn compile_fixture_rejects_source_echoes_that_are_not_primary_diagnostics() {
        assert!(
            verify_fixture_failure(
                "raw_status_serialization.rs",
                &[FixtureExpectation::new(
                    "E0277",
                    "the trait bound `ProbeStatus: serde::Serialize` is not satisfied",
                    5,
                    "to_value",
                )],
            )
            .is_err(),
            "a source echo must not satisfy a primary diagnostic expectation"
        );
    }

    #[test]
    fn fixture_artifact_cache_is_process_independent() {
        let cache = fixture_artifact_cache_dir();
        assert_eq!(cache, fixture_artifact_cache_dir());
        assert!(cache
            .file_name()
            .and_then(|name| name.to_str())
            .is_some_and(|name| {
                name.starts_with("styrn-probe-compile-fixture-cache-v2-")
                    && name.len() == "styrn-probe-compile-fixture-cache-v2-".len() + 16
            }));
    }

    #[test]
    fn scoped_fixture_output_is_removed_when_its_guard_drops() {
        let output_path;
        {
            let output = ScopedFixtureOutput::new();
            output_path = output.path.clone();
            fs::write(&output_path, "test artifact").unwrap();
            assert!(output_path.exists());
        }
        assert!(!output_path.exists());
    }

    #[derive(Clone, Copy)]
    struct FixtureExpectation {
        code: &'static str,
        message: &'static str,
        line: u64,
        primary_label: &'static str,
    }

    impl FixtureExpectation {
        const fn new(
            code: &'static str,
            message: &'static str,
            line: u64,
            primary_label: &'static str,
        ) -> Self {
            Self {
                code,
                message,
                line,
                primary_label,
            }
        }
    }

    fn assert_fixture_fails(fixture_name: &str, expectations: &[FixtureExpectation]) {
        if let Err(problem) = verify_fixture_failure(fixture_name, expectations) {
            panic!("{fixture_name} must report the expected primary diagnostic: {problem}");
        }
    }

    fn verify_fixture_failure(
        fixture_name: &str,
        expectations: &[FixtureExpectation],
    ) -> Result<(), String> {
        let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        let fixture = manifest_dir
            .join("src/setup/probe/fixtures")
            .join(fixture_name);
        let artifacts = cargo_managed_artifacts(&manifest_dir);
        let output_path = ScopedFixtureOutput::new();
        let mut command = Command::new("rustc");
        command
            .arg("--edition=2021")
            .arg("--error-format=json")
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
            .arg(&output_path.path)
            .output()
            .expect("rustc must be available for compile-fail boundary tests");
        if output.status.success() {
            return Err("fixture unexpectedly compiled".to_owned());
        }
        let diagnostics = String::from_utf8_lossy(&output.stderr)
            .lines()
            .map(|line| {
                serde_json::from_str::<serde_json::Value>(line).map_err(|error| error.to_string())
            })
            .collect::<Result<Vec<_>, _>>()?;
        if diagnostics
            .iter()
            .any(|diagnostic| diagnostic["level"] == "warning")
        {
            return Err("fixture emitted a compiler warning".to_owned());
        }
        if diagnostics.iter().any(|diagnostic| {
            diagnostic["level"] == "error"
                && diagnostic["code"].is_null()
                && !diagnostic["message"]
                    .as_str()
                    .is_some_and(|message| message.starts_with("aborting due to"))
        }) {
            return Err("fixture emitted an unexpected non-diagnostic compiler error".to_owned());
        }
        let errors = diagnostics
            .iter()
            .filter(|diagnostic| diagnostic["level"] == "error" && !diagnostic["code"].is_null())
            .collect::<Vec<_>>();
        if errors.len() != expectations.len() {
            return Err(format!(
                "expected {} coded compiler errors, got {}",
                expectations.len(),
                errors.len()
            ));
        }
        for expectation in expectations {
            if !errors.iter().any(|diagnostic| {
                diagnostic["code"]["code"] == expectation.code
                    && diagnostic["message"] == expectation.message
                    && diagnostic["spans"].as_array().is_some_and(|spans| {
                        spans.iter().any(|span| {
                            span["is_primary"] == true
                                && span["file_name"]
                                    .as_str()
                                    .is_some_and(|name| name.ends_with(fixture_name))
                                && span["line_start"] == expectation.line
                                && span["label"] == expectation.primary_label
                        })
                    })
            }) {
                return Err(format!(
                    "missing {} at {fixture_name}:{} with primary label {:?}",
                    expectation.code, expectation.line, expectation.primary_label
                ));
            }
        }
        Ok(())
    }

    struct CargoArtifacts {
        deps_dir: PathBuf,
        paths: BTreeMap<String, PathBuf>,
    }

    fn cargo_managed_artifacts(manifest_dir: &Path) -> &'static CargoArtifacts {
        static ARTIFACTS: OnceLock<CargoArtifacts> = OnceLock::new();
        ARTIFACTS.get_or_init(|| {
            let target_dir = fixture_artifact_cache_dir();
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
            CargoArtifacts { deps_dir, paths }
        })
    }

    fn fixture_artifact_cache_dir() -> PathBuf {
        let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        let lockfile = fs::read(manifest_dir.join("Cargo.lock"))
            .expect("fixture cache must be keyed by the Cargo lockfile");
        let rustc = Command::new("rustc")
            .args(["--version", "--verbose"])
            .output()
            .expect("rustc must be available to key the fixture artifact cache");
        assert!(
            rustc.status.success(),
            "rustc must report its version to key the fixture artifact cache"
        );
        let fingerprint = deterministic_fingerprint(&[&lockfile, &rustc.stdout]);
        std::env::temp_dir().join(format!(
            "styrn-probe-compile-fixture-cache-v2-{fingerprint}"
        ))
    }

    fn deterministic_fingerprint(parts: &[&[u8]]) -> String {
        let mut hash = 0xcbf2_9ce4_8422_2325_u64;
        for part in parts {
            for byte in *part {
                hash ^= u64::from(*byte);
                hash = hash.wrapping_mul(0x0000_0100_0000_01b3);
            }
        }
        format!("{hash:016x}")
    }

    struct ScopedFixtureOutput {
        path: PathBuf,
    }

    impl ScopedFixtureOutput {
        fn new() -> Self {
            static NEXT_OUTPUT: AtomicUsize = AtomicUsize::new(0);
            Self {
                path: std::env::temp_dir().join(format!(
                    "styrn-probe-rustc-output-{}-{}",
                    std::process::id(),
                    NEXT_OUTPUT.fetch_add(1, Ordering::Relaxed)
                )),
            }
        }
    }

    impl Drop for ScopedFixtureOutput {
        fn drop(&mut self) {
            let _ = fs::remove_file(&self.path);
        }
    }
}
