#![allow(unexpected_cfgs)] // Exact rustc compile-boundary fixtures use private cfg names.

#[allow(dead_code)]
pub(crate) mod action;
#[allow(dead_code)]
pub(crate) mod plan;
#[allow(dead_code)]
pub(crate) mod probe;
#[allow(dead_code)]
mod probe_values;
#[allow(dead_code)]
mod probe_wire;
#[allow(dead_code)]
#[cfg(not(action_core_fixture))]
pub(crate) mod receipt;

#[allow(unused_imports)]
pub(crate) use probe_wire::{DoctorFinding, DoctorFindingState, ObservedState, ProbeObservation};

fn observe_worker_probes(probes: &[Box<dyn probe::WorkerProbe>]) -> ObservedState {
    probe_wire::observe(probes)
}

fn validate_probe_static_text(value: &str) -> bool {
    probe_wire::validate_static_text(value)
}
