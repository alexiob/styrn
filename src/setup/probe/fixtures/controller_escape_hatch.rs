#[path = "../mod.rs"]
mod probe;

use probe::{
    FindingSeverity, ProbeCatalog, ProbeDescriptor, ProbeId, ProbeStatus, Remediation, WorkerProbe,
};

struct ControllerCheck {
    descriptor: ProbeDescriptor,
}

impl WorkerProbe for ControllerCheck {
    fn descriptor(&self) -> &ProbeDescriptor {
        &self.descriptor
    }

    fn observe(&self) -> ProbeStatus {
        ProbeStatus::Absent
    }
}

fn main() {
    let _ = serde_json::to_value(ProbeStatus::Absent);
    let _ = Remediation::new(
        "unsafe shell",
        Some(vec!["sh".to_owned(), "-c".to_owned(), "echo unsafe".to_owned()]),
    );
    let controller = ControllerCheck {
        descriptor: ProbeDescriptor::new(
            ProbeId::parse("controller.tailscale-reachability").unwrap(),
            "controller check",
            FindingSeverity::Error,
            None,
        )
        .unwrap(),
    };
    let _ = Remediation::new(
        "unsafe shell",
        Some(vec![
            "powershell".to_owned(),
            "-Command".to_owned(),
            "echo unsafe".to_owned(),
        ]),
    );
    let _ = Remediation::new(
        "unrelated executable",
        Some(vec!["curl".to_owned(), "https://example.invalid".to_owned()]),
    );
    let _ = ProbeCatalog::new(vec![Box::new(controller)]);
}
