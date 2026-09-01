#[path = "../../mod.rs"]
mod setup;

mod worker_implementation {
    use super::setup::{DoctorFinding, DoctorFindingState, ProbeObservation};
    use super::setup::probe::{FindingSeverity, ProbeId, ProbeStatus};

    fn fabricate_observation() {
        let _ = ProbeObservation {
            descriptor: unsafe { std::mem::zeroed() },
            status: ProbeStatus::Absent,
        };
    }

    fn fabricate_finding() {
        let _ = DoctorFinding {
            id: ProbeId::parse("tool.fake").unwrap(),
            state: DoctorFindingState::Pass,
            severity: FindingSeverity::Info,
            message: "fabricated".to_owned(),
            remediation: None,
        };
    }
}

fn main() {}
