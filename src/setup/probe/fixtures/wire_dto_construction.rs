#[path = "../../mod.rs"]
mod setup;

mod worker_implementation {
    use super::setup::{DoctorFinding, DoctorFindingState, ProbeObservation};
    use super::setup::probe::{FindingSeverity, ProbeId, ProbeStatus};

    pub(super) fn fabricate() {
        let _ = ProbeObservation {
            descriptor: fixture_value(),
            status: ProbeStatus::Absent,
        };
        let _ = DoctorFinding {
            id: ProbeId::parse("tool.fake").unwrap(),
            state: DoctorFindingState::Pass,
            severity: FindingSeverity::Info,
            message: "fabricated".to_owned(),
            remediation: None,
        };
    }

    fn fixture_value<T>() -> T {
        panic!("compile-fail fixture never runs")
    }
}

fn main() {
    worker_implementation::fabricate();
}
