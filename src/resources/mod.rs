use crate::manifest::MachineManifest;
use chrono::{SecondsFormat, Utc};
use serde::{Deserialize, Serialize};
use std::fmt;
use std::path::Path;
use sysinfo::{Disks, System};

#[derive(Clone, Debug, Deserialize, Serialize)]
pub(crate) struct MachineStatus {
    pub(crate) machine_id: uuid::Uuid,
    pub(crate) time: String,
    pub(crate) cpu: CpuStatus,
    pub(crate) memory: MemoryStatus,
    pub(crate) disk: DiskStatus,
    pub(crate) jobs: JobStatus,
    pub(crate) substrate: SubstrateStatus,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub(crate) struct CpuStatus {
    pub(crate) logical: u64,
    pub(crate) load_percent: f32,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub(crate) struct MemoryStatus {
    pub(crate) total_bytes: u64,
    pub(crate) available_bytes: u64,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub(crate) struct DiskStatus {
    pub(crate) root: String,
    pub(crate) free_bytes: u64,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub(crate) struct JobStatus {
    pub(crate) running: u64,
    pub(crate) heavy_running: u64,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub(crate) struct SubstrateStatus {
    pub(crate) kind: Option<String>,
    pub(crate) state: String,
    pub(crate) session: Option<String>,
}

#[derive(Debug)]
pub(crate) struct StatusError;

impl fmt::Display for StatusError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("machine resource status is unavailable")
    }
}

impl std::error::Error for StatusError {}

impl MachineStatus {
    pub(crate) fn validate_for_client(
        &self,
        expected_machine_id: uuid::Uuid,
    ) -> Result<(), StatusError> {
        if self.machine_id != expected_machine_id
            || chrono::DateTime::parse_from_rfc3339(&self.time).is_err()
            || self.time.len() > 64
            || self.cpu.logical == 0
            || !self.cpu.load_percent.is_finite()
            || !(0.0..=100.0).contains(&self.cpu.load_percent)
            || self.memory.total_bytes == 0
            || self.memory.available_bytes > self.memory.total_bytes
            || self.disk.root.is_empty()
            || self.disk.root.len() > 32 * 1024
            || self.disk.root.chars().any(char::is_control)
            || crate::manifest::contains_secret_shaped_text(&self.disk.root)
            || self.jobs.heavy_running > self.jobs.running
            || !valid_substrate_status(&self.substrate)
        {
            return Err(StatusError);
        }
        Ok(())
    }
}

fn valid_substrate_status(status: &SubstrateStatus) -> bool {
    let valid_session = status.session.as_ref().is_none_or(|session| {
        !session.is_empty()
            && session.len() <= 255
            && !session.chars().any(char::is_control)
            && !crate::manifest::contains_secret_shaped_text(session)
    });
    valid_session
        && match status.state.as_str() {
            "none" => status.kind.is_none() && status.session.is_none(),
            "registered" => status.kind.as_deref() == Some("herdr"),
            "active" => status.kind.as_deref() == Some("herdr") && status.session.is_some(),
            _ => false,
        }
}

pub(crate) fn capture_machine_status(
    manifest: &MachineManifest,
) -> Result<MachineStatus, StatusError> {
    let mut system = System::new_all();
    system.refresh_memory();
    system.refresh_cpu_usage();

    let disks = Disks::new_with_refreshed_list();
    let root = Path::new(&manifest.paths.root);
    let disk = disks
        .list()
        .iter()
        .filter(|disk| root.starts_with(disk.mount_point()))
        .max_by_key(|disk| disk.mount_point().components().count())
        .ok_or(StatusError)?;
    let substrate = manifest
        .herdr
        .as_ref()
        .filter(|herdr| herdr.installed.unwrap_or(false) && herdr.enabled.unwrap_or(true));

    Ok(MachineStatus {
        machine_id: manifest.machine_id,
        time: Utc::now().to_rfc3339_opts(SecondsFormat::AutoSi, true),
        cpu: CpuStatus {
            logical: u64::try_from(system.cpus().len()).map_err(|_| StatusError)?,
            load_percent: system.global_cpu_usage(),
        },
        memory: MemoryStatus {
            total_bytes: system.total_memory(),
            available_bytes: system.available_memory(),
        },
        disk: DiskStatus {
            root: manifest.paths.root.clone(),
            free_bytes: disk.available_space(),
        },
        jobs: JobStatus {
            running: 0,
            heavy_running: 0,
        },
        substrate: SubstrateStatus {
            kind: substrate.map(|_| "herdr".to_owned()),
            state: substrate.map_or_else(|| "none".to_owned(), |_| "registered".to_owned()),
            session: substrate.and_then(|herdr| herdr.session.clone()),
        },
    })
}
