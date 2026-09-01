#[path = "../../mod.rs"]
mod setup;

use setup::probe::{FindingSeverity, ProbeDescriptorSpec, ProbeFailure, ProbeId, ProbeStatus, WorkerProbe};

mod controller_check {
    use super::*;

    struct ControllerCheck {
        descriptor: ProbeDescriptorSpec,
    }

    impl WorkerProbe for ControllerCheck {
        fn descriptor(&self) -> &ProbeDescriptorSpec {
            &self.descriptor
        }

        fn observe(&self) -> Result<ProbeStatus, ProbeFailure> {
            Ok(ProbeStatus::Absent)
        }
    }
}

fn main() {
    let _ = ProbeDescriptorSpec::new(
        ProbeId::parse("controller.check").unwrap(),
        "controller check",
        FindingSeverity::Error,
        None,
    );
}
