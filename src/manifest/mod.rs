use crate::platform;
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use chrono::{DateTime, FixedOffset};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::BTreeMap;
use std::fs;
use std::io::Write;
use std::path::PathBuf;
use thiserror::Error;
use uuid::Uuid;

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct MachineManifest {
    pub(crate) schema_version: u64,
    pub(crate) machine_id: Uuid,
    pub(crate) name: String,
    pub(crate) roles: Vec<MachineRole>,
    pub(crate) platform: Platform,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) transport: Option<Transport>,
    pub(crate) paths: Paths,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) controller: Option<Controller>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) worker: Option<Worker>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) resources: Option<Resources>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) capabilities: Option<BTreeMap<String, bool>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) scheduling: Option<Scheduling>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) tailscale: Option<Tailscale>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) ssh: Option<Ssh>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) herdr: Option<Herdr>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) agents: Option<BTreeMap<String, Agent>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) toolchains: Option<BTreeMap<String, Toolchain>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) caches: Option<BTreeMap<String, Cache>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) install: Option<Install>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) desktop: Option<Desktop>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) pending_actions: Option<Vec<PendingAction>>,
}

#[derive(Serialize)]
struct MachineManifestWire<'a> {
    schema_version: u64,
    machine_id: Uuid,
    name: &'a str,
    roles: &'a [MachineRole],
    platform: &'a Platform,
    #[serde(skip_serializing_if = "Option::is_none")]
    transport: &'a Option<Transport>,
    paths: &'a Paths,
    #[serde(skip_serializing_if = "Option::is_none")]
    controller: &'a Option<Controller>,
    #[serde(skip_serializing_if = "Option::is_none")]
    worker: &'a Option<Worker>,
    #[serde(skip_serializing_if = "Option::is_none")]
    resources: &'a Option<Resources>,
    #[serde(skip_serializing_if = "Option::is_none")]
    capabilities: &'a Option<BTreeMap<String, bool>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    scheduling: &'a Option<Scheduling>,
    #[serde(skip_serializing_if = "Option::is_none")]
    tailscale: &'a Option<Tailscale>,
    #[serde(skip_serializing_if = "Option::is_none")]
    ssh: &'a Option<Ssh>,
    #[serde(skip_serializing_if = "Option::is_none")]
    herdr: &'a Option<Herdr>,
    #[serde(skip_serializing_if = "Option::is_none")]
    agents: &'a Option<BTreeMap<String, Agent>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    toolchains: &'a Option<BTreeMap<String, Toolchain>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    caches: &'a Option<BTreeMap<String, Cache>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    install: &'a Option<Install>,
    #[serde(skip_serializing_if = "Option::is_none")]
    desktop: &'a Option<Desktop>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pending_actions: &'a Option<Vec<PendingAction>>,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawMachineManifest {
    schema_version: u64,
    machine_id: Option<String>,
    name: String,
    roles: Vec<MachineRole>,
    platform: Platform,
    transport: Option<Transport>,
    paths: Paths,
    controller: Option<Controller>,
    worker: Option<Worker>,
    resources: Option<Resources>,
    capabilities: Option<BTreeMap<String, bool>>,
    scheduling: Option<Scheduling>,
    tailscale: Option<Tailscale>,
    ssh: Option<Ssh>,
    herdr: Option<Herdr>,
    agents: Option<BTreeMap<String, Agent>>,
    toolchains: Option<BTreeMap<String, Toolchain>>,
    caches: Option<BTreeMap<String, Cache>>,
    install: Option<Install>,
    desktop: Option<Desktop>,
    pending_actions: Option<Vec<PendingAction>>,
}

#[allow(dead_code)] // T0.5's identity-free write API is consumed by future setup generation.
#[derive(Clone, Debug)]
pub(crate) struct MachineManifestDraft {
    pub(crate) schema_version: u64,
    pub(crate) name: String,
    pub(crate) roles: Vec<MachineRole>,
    pub(crate) platform: Platform,
    pub(crate) transport: Option<Transport>,
    pub(crate) paths: Paths,
    pub(crate) controller: Option<Controller>,
    pub(crate) worker: Option<Worker>,
    pub(crate) resources: Option<Resources>,
    pub(crate) capabilities: Option<BTreeMap<String, bool>>,
    pub(crate) scheduling: Option<Scheduling>,
    pub(crate) tailscale: Option<Tailscale>,
    pub(crate) ssh: Option<Ssh>,
    pub(crate) herdr: Option<Herdr>,
    pub(crate) agents: Option<BTreeMap<String, Agent>>,
    pub(crate) toolchains: Option<BTreeMap<String, Toolchain>>,
    pub(crate) caches: Option<BTreeMap<String, Cache>>,
    pub(crate) install: Option<Install>,
    pub(crate) desktop: Option<Desktop>,
    pub(crate) pending_actions: Option<Vec<PendingAction>>,
}

macro_rules! manifest_types {
    ($($name:ident { $($field:ident : $type:ty),* $(,)? })*) => {$(
        #[derive(Clone, Debug, Deserialize, Serialize)]
        #[serde(deny_unknown_fields)]
        pub(crate) struct $name { $(pub(crate) $field: $type,)* }
    )*};
}

manifest_types! {
    Platform { os: OperatingSystem, arch: Architecture, hostname: String, headless: Option<bool> }
    Transport { kind: TransportKind, host: String, port: Option<u16>, user: Option<String> }
    Paths { root: String, repos: String, jobs: String, cache: String, artifacts: String, logs: String }
    Controller { enabled: Option<bool>, inventory: Option<String> }
    Worker { enabled: Option<bool>, accept_jobs: Option<bool> }
    Resources { detected: Option<DetectedResources>, policy: Option<ResourcePolicy> }
    DetectedResources { logical_cpus: Option<u64>, memory_bytes: Option<u64>, disk_bytes: Option<u64> }
    ResourcePolicy { reserved_memory_bytes: Option<u64>, reserved_disk_bytes: Option<u64>, reserved_disk_percent: Option<u8>, reserved_cpus: Option<u64>, max_parallel_compile_jobs: Option<u64>, max_parallel_test_jobs: Option<u64>, max_heavy_jobs: Option<u64>, max_job_disk_bytes: Option<u64> }
    Scheduling { priority: Option<i64>, prefer_remote_workers: Option<bool> }
    Tailscale { installed: Option<bool>, mode: Option<TailscaleMode>, unattended: Option<bool> }
    Ssh { installed: Option<bool>, server: Option<bool>, public_key_auth: Option<bool> }
    Herdr { installed: Option<bool>, enabled: Option<bool>, session: Option<String>, autostart: Option<String> }
    Agent { installed: Option<bool>, command: Option<String>, sandbox: Option<String>, shell: Option<String> }
    Toolchain { installed: Option<bool>, host: Option<String>, version: Option<String> }
    Cache { installed: Option<bool>, max_bytes: Option<u64> }
    Install { channel: InstallChannel, version: Option<String>, installed_at: Option<DateTime<FixedOffset>> }
    Desktop { kind: Option<DesktopKind>, enabled: Option<bool> }
    PendingAction { id: String, severity: PendingSeverity, message: String }
}

macro_rules! string_enum {
    ($name:ident { $($variant:ident => $value:literal),+ $(,)? }) => {
        #[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
        #[serde(rename_all = "snake_case")]
        pub(crate) enum $name { $($variant),+ }
    };
}

string_enum! { MachineRole { Controller => "controller", Worker => "worker" } }
string_enum! { OperatingSystem { Linux => "linux", Macos => "macos", Windows => "windows" } }
string_enum! { Architecture { X86_64 => "x86_64", Aarch64 => "aarch64" } }
string_enum! { TransportKind { Ssh => "ssh" } }
string_enum! { TailscaleMode { Service => "service", Gui => "gui", Tailscaled => "tailscaled" } }
string_enum! { InstallChannel { Direct => "direct", Homebrew => "homebrew", Winget => "winget", Scoop => "scoop", Chocolatey => "chocolatey", Apt => "apt", Cargo => "cargo", Unknown => "unknown" } }
string_enum! { PendingSeverity { Info => "info", Warning => "warning", Error => "error" } }

#[derive(Clone, Debug, Deserialize, Serialize)]
pub(crate) enum DesktopKind {
    #[serde(rename = "rdp")]
    Rdp,
    #[serde(rename = "screen-sharing")]
    ScreenSharing,
    #[serde(rename = "vnc")]
    Vnc,
    #[serde(rename = "none")]
    None,
}

impl MachineManifest {
    #[allow(dead_code)] // Kept as the typed parse entry point for callers beyond the CLI store.
    pub(crate) fn parse_toml(input: &str) -> Result<Self, ManifestError> {
        let raw = parse_raw(input)?;
        let machine_id = raw
            .machine_id
            .as_deref()
            .map(parse_canonical_uuid)
            .transpose()?;
        let Some(machine_id) = machine_id else {
            return Err(ManifestError::Validation(
                "machine_id is required".to_owned(),
            ));
        };
        let manifest = raw.into_manifest(machine_id);
        manifest.validate()?;
        Ok(manifest)
    }

    pub(crate) fn validate(&self) -> Result<(), ManifestError> {
        if self.schema_version != 1 {
            return invalid("schema_version must be 1");
        }
        if self.machine_id.get_version_num() != 7
            || self.machine_id.get_variant() != uuid::Variant::RFC4122
        {
            return invalid("machine_id must be an RFC UUIDv7");
        }
        non_empty("name", &self.name)?;
        if self.roles.is_empty() {
            return invalid("roles must not be empty");
        }
        for role in &self.roles {
            if self
                .roles
                .iter()
                .filter(|candidate| *candidate == role)
                .count()
                > 1
            {
                return invalid("roles must be unique");
            }
        }
        non_empty("platform.hostname", &self.platform.hostname)?;
        for (name, value) in [
            ("paths.root", &self.paths.root),
            ("paths.repos", &self.paths.repos),
            ("paths.jobs", &self.paths.jobs),
            ("paths.cache", &self.paths.cache),
            ("paths.artifacts", &self.paths.artifacts),
            ("paths.logs", &self.paths.logs),
        ] {
            non_empty(name, value)?;
        }
        if let Some(transport) = &self.transport {
            non_empty("transport.host", &transport.host)?;
            if transport.port == Some(0) {
                return invalid("transport.port must be in 1..=65535");
            }
            if let Some(user) = &transport.user {
                non_empty("transport.user", user)?;
            }
        }
        if let Some(resources) = &self.resources {
            if let Some(detected) = &resources.detected {
                if detected.logical_cpus == Some(0) {
                    return invalid("resources.detected.logical_cpus must be at least 1");
                }
            }
            if let Some(policy) = &resources.policy {
                if policy.reserved_disk_bytes.is_some() == policy.reserved_disk_percent.is_some() {
                    return invalid("resources.policy requires exactly one disk reserve selector");
                }
                if policy
                    .reserved_disk_percent
                    .is_some_and(|percent| percent > 99)
                {
                    return invalid("resources.policy.reserved_disk_percent must be in 0..=99");
                }
                for (name, count) in [
                    (
                        "max_parallel_compile_jobs",
                        policy.max_parallel_compile_jobs,
                    ),
                    ("max_parallel_test_jobs", policy.max_parallel_test_jobs),
                    ("max_heavy_jobs", policy.max_heavy_jobs),
                ] {
                    if count == Some(0) {
                        return invalid(&format!("resources.policy.{name} must be at least 1"));
                    }
                }
            }
        }
        if let Some(actions) = &self.pending_actions {
            for action in actions {
                non_empty("pending_actions.id", &action.id)?;
                non_empty("pending_actions.message", &action.message)?;
            }
        }
        self.ensure_secret_free()?;
        Ok(())
    }

    pub(crate) fn to_json_value(&self) -> Result<Value, ManifestError> {
        let mut value = self.wire_value()?;
        scan_secret_free(&value, "$")?;
        prune_nulls(&mut value);
        Ok(value)
    }

    pub(crate) fn to_toml(&self) -> Result<String, ManifestError> {
        let wire = self.wire();
        let value = serde_json::to_value(&wire).map_err(ManifestError::Json)?;
        scan_secret_free(&value, "$")?;
        toml::to_string_pretty(&wire).map_err(ManifestError::TomlSerialize)
    }

    #[allow(dead_code)] // Generated writes intentionally accept identity-free data only.
    pub(crate) fn without_machine_id(self) -> MachineManifestDraft {
        MachineManifestDraft::from(self)
    }

    fn wire(&self) -> MachineManifestWire<'_> {
        MachineManifestWire {
            schema_version: self.schema_version,
            machine_id: self.machine_id,
            name: &self.name,
            roles: &self.roles,
            platform: &self.platform,
            transport: &self.transport,
            paths: &self.paths,
            controller: &self.controller,
            worker: &self.worker,
            resources: &self.resources,
            capabilities: &self.capabilities,
            scheduling: &self.scheduling,
            tailscale: &self.tailscale,
            ssh: &self.ssh,
            herdr: &self.herdr,
            agents: &self.agents,
            toolchains: &self.toolchains,
            caches: &self.caches,
            install: &self.install,
            desktop: &self.desktop,
            pending_actions: &self.pending_actions,
        }
    }

    fn wire_value(&self) -> Result<Value, ManifestError> {
        serde_json::to_value(self.wire()).map_err(ManifestError::Json)
    }

    fn ensure_secret_free(&self) -> Result<(), ManifestError> {
        scan_secret_free(&self.wire_value()?, "$")
    }
}

impl RawMachineManifest {
    fn into_manifest(self, machine_id: Uuid) -> MachineManifest {
        MachineManifest {
            schema_version: self.schema_version,
            machine_id,
            name: self.name,
            roles: self.roles,
            platform: self.platform,
            transport: self.transport,
            paths: self.paths,
            controller: self.controller,
            worker: self.worker,
            resources: self.resources,
            capabilities: self.capabilities,
            scheduling: self.scheduling,
            tailscale: self.tailscale,
            ssh: self.ssh,
            herdr: self.herdr,
            agents: self.agents,
            toolchains: self.toolchains,
            caches: self.caches,
            install: self.install,
            desktop: self.desktop,
            pending_actions: self.pending_actions,
        }
    }
}

impl From<MachineManifest> for MachineManifestDraft {
    fn from(value: MachineManifest) -> Self {
        Self {
            schema_version: value.schema_version,
            name: value.name,
            roles: value.roles,
            platform: value.platform,
            transport: value.transport,
            paths: value.paths,
            controller: value.controller,
            worker: value.worker,
            resources: value.resources,
            capabilities: value.capabilities,
            scheduling: value.scheduling,
            tailscale: value.tailscale,
            ssh: value.ssh,
            herdr: value.herdr,
            agents: value.agents,
            toolchains: value.toolchains,
            caches: value.caches,
            install: value.install,
            desktop: value.desktop,
            pending_actions: value.pending_actions,
        }
    }
}

#[allow(dead_code)]
impl MachineManifestDraft {
    fn with_machine_id(&self, machine_id: Uuid) -> MachineManifest {
        MachineManifest {
            schema_version: self.schema_version,
            machine_id,
            name: self.name.clone(),
            roles: self.roles.clone(),
            platform: self.platform.clone(),
            transport: self.transport.clone(),
            paths: self.paths.clone(),
            controller: self.controller.clone(),
            worker: self.worker.clone(),
            resources: self.resources.clone(),
            capabilities: self.capabilities.clone(),
            scheduling: self.scheduling.clone(),
            tailscale: self.tailscale.clone(),
            ssh: self.ssh.clone(),
            herdr: self.herdr.clone(),
            agents: self.agents.clone(),
            toolchains: self.toolchains.clone(),
            caches: self.caches.clone(),
            install: self.install.clone(),
            desktop: self.desktop.clone(),
            pending_actions: self.pending_actions.clone(),
        }
    }
}

#[derive(Debug)]
pub(crate) struct ReadOutcome {
    pub(crate) manifest: MachineManifest,
    pub(crate) machine_id_minted: bool,
}

#[derive(Debug)]
pub(crate) struct MachineManifestStore {
    path: PathBuf,
    trusted_root: PathBuf,
    security: ManifestSecurity,
    destination_origin: DestinationOrigin,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum DestinationOrigin {
    Canonical,
    Override,
    Test,
}

#[allow(dead_code)] // Test-only policies are unused by the binary test harness itself.
#[derive(Clone, Copy, Debug)]
enum ManifestSecurity {
    System,
    #[cfg(test)]
    CurrentProcess,
    #[cfg(test)]
    FailBeforeReplace,
    #[cfg(test)]
    FailAfterReplace,
    #[cfg(test)]
    DirectoryPublicationRace,
    #[cfg(test)]
    DirectoryPublicationAndCleanupFailure,
    #[cfg(test)]
    CurrentProcessWorker,
}

fn canonical_manifest_path() -> PathBuf {
    #[cfg(target_os = "linux")]
    {
        PathBuf::from("/etc/styrn/machine.toml")
    }
    #[cfg(target_os = "macos")]
    {
        PathBuf::from("/Library/Application Support/Styrn/machine.toml")
    }
    #[cfg(target_os = "windows")]
    {
        PathBuf::from(r"C:\ProgramData\Styrn\machine.toml")
    }
}

#[allow(dead_code)] // Referenced by the executable; integration tests compile this module separately.
pub(crate) fn configured_manifest_store() -> MachineManifestStore {
    if let Some(directory) = std::env::var_os("STYRN_CONFIG_DIR") {
        return MachineManifestStore::new(PathBuf::from(directory).join("machine.toml"));
    }
    MachineManifestStore::new_canonical(canonical_manifest_path())
}

impl MachineManifestStore {
    #[allow(dead_code)] // Integration test crates include this module without the executable.
    pub(crate) fn new(path: impl Into<PathBuf>) -> Self {
        let path = path.into();
        let trusted_root = path
            .parent()
            .map(std::path::Path::to_path_buf)
            .unwrap_or_default();
        Self {
            path,
            trusted_root,
            security: ManifestSecurity::System,
            destination_origin: DestinationOrigin::Override,
        }
    }

    fn new_canonical(path: impl Into<PathBuf>) -> Self {
        let path = path.into();
        let trusted_root = path
            .parent()
            .map(std::path::Path::to_path_buf)
            .unwrap_or_default();
        Self {
            path,
            trusted_root,
            security: ManifestSecurity::System,
            destination_origin: DestinationOrigin::Canonical,
        }
    }

    #[cfg(test)]
    #[allow(dead_code)]
    pub(crate) fn new_for_test(path: impl Into<PathBuf>) -> Self {
        let path = path.into();
        let trusted_root = path
            .parent()
            .map(std::path::Path::to_path_buf)
            .unwrap_or_default();
        Self {
            path,
            trusted_root,
            security: ManifestSecurity::CurrentProcess,
            destination_origin: DestinationOrigin::Test,
        }
    }

    #[cfg(test)]
    #[allow(dead_code)]
    pub(crate) fn new_for_test_with_trusted_root(
        path: impl Into<PathBuf>,
        trusted_root: impl Into<PathBuf>,
    ) -> Self {
        Self {
            path: path.into(),
            trusted_root: trusted_root.into(),
            security: ManifestSecurity::CurrentProcess,
            destination_origin: DestinationOrigin::Test,
        }
    }

    #[cfg(test)]
    #[allow(dead_code)]
    pub(crate) fn new_for_test_with_worker_owned_parent(path: impl Into<PathBuf>) -> Self {
        let path = path.into();
        let trusted_root = path
            .parent()
            .map(std::path::Path::to_path_buf)
            .unwrap_or_default();
        Self {
            path,
            trusted_root,
            security: ManifestSecurity::CurrentProcessWorker,
            destination_origin: DestinationOrigin::Override,
        }
    }

    #[cfg(test)]
    #[allow(dead_code)]
    pub(crate) fn new_override_for_test(path: impl Into<PathBuf>) -> Self {
        let path = path.into();
        let trusted_root = path
            .parent()
            .map(std::path::Path::to_path_buf)
            .unwrap_or_default();
        Self {
            path,
            trusted_root,
            security: ManifestSecurity::CurrentProcess,
            destination_origin: DestinationOrigin::Override,
        }
    }

    #[cfg(test)]
    #[allow(dead_code)]
    pub(crate) fn new_with_failing_hardening(path: impl Into<PathBuf>) -> Self {
        let path = path.into();
        let trusted_root = path
            .parent()
            .map(std::path::Path::to_path_buf)
            .unwrap_or_default();
        Self {
            path,
            trusted_root,
            security: ManifestSecurity::FailBeforeReplace,
            destination_origin: DestinationOrigin::Test,
        }
    }

    #[cfg(test)]
    #[allow(dead_code)]
    pub(crate) fn new_override_with_failing_hardening(path: impl Into<PathBuf>) -> Self {
        let path = path.into();
        let trusted_root = path
            .parent()
            .map(std::path::Path::to_path_buf)
            .unwrap_or_default();
        Self {
            path,
            trusted_root,
            security: ManifestSecurity::FailBeforeReplace,
            destination_origin: DestinationOrigin::Override,
        }
    }

    #[cfg(test)]
    #[allow(dead_code)]
    pub(crate) fn new_with_directory_publication_race(path: impl Into<PathBuf>) -> Self {
        let path = path.into();
        let trusted_root = path
            .parent()
            .map(std::path::Path::to_path_buf)
            .unwrap_or_default();
        Self {
            path,
            trusted_root,
            security: ManifestSecurity::DirectoryPublicationRace,
            destination_origin: DestinationOrigin::Test,
        }
    }

    #[cfg(test)]
    #[allow(dead_code)]
    pub(crate) fn new_with_directory_publication_and_cleanup_failure(
        path: impl Into<PathBuf>,
    ) -> Self {
        let path = path.into();
        let trusted_root = path
            .parent()
            .map(std::path::Path::to_path_buf)
            .unwrap_or_default();
        Self {
            path,
            trusted_root,
            security: ManifestSecurity::DirectoryPublicationAndCleanupFailure,
            destination_origin: DestinationOrigin::Test,
        }
    }

    #[cfg(test)]
    #[allow(dead_code)]
    pub(crate) fn new_with_failing_post_replace_verification(path: impl Into<PathBuf>) -> Self {
        let path = path.into();
        let trusted_root = path
            .parent()
            .map(std::path::Path::to_path_buf)
            .unwrap_or_default();
        Self {
            path,
            trusted_root,
            security: ManifestSecurity::FailAfterReplace,
            destination_origin: DestinationOrigin::Test,
        }
    }

    pub(crate) fn read(&self) -> Result<ReadOutcome, ManifestError> {
        self.validate_destination_policy()?;
        platform::verify_manifest_file_target(&self.path).map_err(ManifestError::Security)?;
        self.verify_security()?;
        let raw = parse_raw(&fs::read_to_string(&self.path).map_err(ManifestError::Read)?)?;
        let machine_id = raw
            .machine_id
            .as_deref()
            .map(parse_canonical_uuid)
            .transpose()?;
        let machine_id = machine_id
            .ok_or_else(|| ManifestError::Validation("machine_id is required".to_owned()))?;
        let manifest = raw.into_manifest(machine_id);
        manifest.validate()?;
        Ok(ReadOutcome {
            manifest,
            machine_id_minted: false,
        })
    }

    pub(crate) fn reconcile(&self) -> Result<ReadOutcome, ManifestError> {
        self.with_mutation_lock(|| self.reconcile_locked())
    }

    fn reconcile_locked(&self) -> Result<ReadOutcome, ManifestError> {
        platform::verify_manifest_file_target(&self.path).map_err(ManifestError::Write)?;
        self.verify_security()?;
        let raw = parse_raw(&fs::read_to_string(&self.path).map_err(ManifestError::Read)?)?;
        let machine_id = raw
            .machine_id
            .as_deref()
            .map(parse_canonical_uuid)
            .transpose()?;
        match machine_id {
            Some(machine_id) => {
                let manifest = raw.into_manifest(machine_id);
                manifest.validate()?;
                self.write_manifest(&manifest)?;
                Ok(ReadOutcome {
                    manifest,
                    machine_id_minted: false,
                })
            }
            None => {
                let manifest = raw.into_manifest(Uuid::now_v7());
                manifest.validate()?;
                self.write_manifest(&manifest)?;
                Ok(ReadOutcome {
                    manifest,
                    machine_id_minted: true,
                })
            }
        }
    }

    #[allow(dead_code)] // Public-to-the-crate T0.5 store API for future setup generation.
    pub(crate) fn write_generated(
        &self,
        draft: &MachineManifestDraft,
    ) -> Result<Uuid, ManifestError> {
        self.with_mutation_lock(|| {
            let machine_id = self
                .existing_machine_id_for_generated()?
                .unwrap_or_else(Uuid::now_v7);
            let manifest = draft.with_machine_id(machine_id);
            manifest.validate()?;
            self.write_manifest(&manifest)?;
            Ok(machine_id)
        })
    }

    fn existing_machine_id_for_generated(&self) -> Result<Option<Uuid>, ManifestError> {
        match fs::symlink_metadata(&self.path) {
            Ok(_) => {
                platform::verify_manifest_file_target(&self.path).map_err(ManifestError::Write)?;
                self.verify_security()?;
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(error) => return Err(ManifestError::Read(error)),
        }
        let raw = parse_raw(&fs::read_to_string(&self.path).map_err(ManifestError::Read)?)?;
        let machine_id = raw
            .machine_id
            .as_deref()
            .map(parse_canonical_uuid)
            .transpose()?
            .unwrap_or_else(Uuid::now_v7);
        raw.into_manifest(machine_id).validate()?;
        Ok(Some(machine_id))
    }

    fn with_mutation_lock<T>(
        &self,
        operation: impl FnOnce() -> Result<T, ManifestError>,
    ) -> Result<T, ManifestError> {
        let destination_dir = self.validate_destination_policy()?;
        self.prepare_destination(destination_dir)?;
        let lock_path = destination_dir.join(format!(
            ".{}.lock",
            self.path
                .file_name()
                .and_then(|name| name.to_str())
                .unwrap_or("machine.toml")
        ));
        let lock = platform::open_manifest_lock(&lock_path, self.platform_owner())
            .map_err(ManifestError::Write)?;
        lock.lock().map_err(ManifestError::Write)?;
        operation()
    }

    fn prepare_destination(&self, destination_dir: &std::path::Path) -> Result<(), ManifestError> {
        let metadata = match fs::symlink_metadata(destination_dir) {
            Ok(metadata) => Some(metadata),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => None,
            Err(error) => return Err(ManifestError::Write(error)),
        };

        if self.requires_system_parent_chain() {
            let parent = destination_dir.parent().ok_or_else(|| {
                ManifestError::Validation(
                    "manifest directory must be below an existing parent".to_owned(),
                )
            })?;
            platform::verify_manifest_parent_chain(parent, self.platform_owner(), "styrn")
                .map_err(ManifestError::Write)?;

            if metadata.is_none() {
                return self.create_and_publish_directory(destination_dir);
            }

            if self.destination_origin == DestinationOrigin::Override {
                return platform::verify_manifest_directory_security(
                    destination_dir,
                    self.platform_owner(),
                    "styrn",
                )
                .map_err(ManifestError::Write);
            }
            return self.harden_directory(destination_dir);
        }

        if metadata.is_none() {
            self.create_and_publish_directory(destination_dir)?;
        }
        platform::verify_manifest_ancestors(
            destination_dir,
            self.platform_owner(),
            "styrn",
            &self.trusted_root,
        )
        .map_err(ManifestError::Write)?;
        if self.destination_origin == DestinationOrigin::Override && metadata.is_some() {
            platform::verify_manifest_directory_security(
                destination_dir,
                self.platform_owner(),
                "styrn",
            )
            .map_err(ManifestError::Write)
        } else {
            if metadata.is_some() {
                self.harden_directory(destination_dir)
            } else {
                Ok(())
            }
        }
    }

    fn create_and_publish_directory(
        &self,
        destination: &std::path::Path,
    ) -> Result<(), ManifestError> {
        let parent = destination.parent().ok_or_else(|| {
            ManifestError::Validation(
                "manifest directory must be below an existing parent".to_owned(),
            )
        })?;
        let leaf = destination
            .file_name()
            .and_then(|name| name.to_str())
            .unwrap_or("styrn");
        let staging_path = parent.join(format!(".{leaf}.{}.tmp", Uuid::now_v7()));
        let staging = platform::create_private_manifest_staging_directory(
            &staging_path,
            self.platform_owner(),
        )
        .map_err(ManifestError::Write)?;

        let operation = (|| {
            self.harden_directory(staging.path())?;
            self.inject_directory_publication_race(staging.path(), destination)?;
            platform::publish_manifest_directory(&staging, destination)
                .map_err(ManifestError::Write)
        })();
        match operation {
            Ok(()) => Ok(()),
            Err(operation) => match fs::remove_dir(staging.path()) {
                Ok(()) => Err(operation),
                Err(cleanup) => Err(ManifestError::StagingDirectoryCleanup {
                    operation: Box::new(operation),
                    cleanup,
                }),
            },
        }
    }

    fn inject_directory_publication_race(
        &self,
        _staging: &std::path::Path,
        _destination: &std::path::Path,
    ) -> Result<(), ManifestError> {
        #[cfg(test)]
        if matches!(
            self.security,
            ManifestSecurity::DirectoryPublicationRace
                | ManifestSecurity::DirectoryPublicationAndCleanupFailure
        ) {
            fs::create_dir(_destination).map_err(ManifestError::Write)?;
            fs::write(_destination.join("race-winner"), b"winner").map_err(ManifestError::Write)?;
            if matches!(
                self.security,
                ManifestSecurity::DirectoryPublicationAndCleanupFailure
            ) {
                fs::write(_staging.join("cleanup-blocker"), b"block")
                    .map_err(ManifestError::Write)?;
            }
        }
        Ok(())
    }

    fn validate_destination_policy(&self) -> Result<&std::path::Path, ManifestError> {
        let destination_dir = self.path.parent().ok_or_else(|| {
            ManifestError::Validation("manifest path has no parent directory".to_owned())
        })?;
        if self.destination_origin != DestinationOrigin::Test
            && (!self.path.is_absolute()
                || self.path.components().any(|component| {
                    matches!(
                        component,
                        std::path::Component::CurDir | std::path::Component::ParentDir
                    )
                })
                || self.path.components().collect::<PathBuf>().as_os_str() != self.path.as_os_str()
                || !has_supported_system_path_root(&self.path)
                || destination_dir != self.trusted_root
                || destination_dir
                    .components()
                    .filter(|component| matches!(component, std::path::Component::Normal(_)))
                    .count()
                    < 2
                || is_broad_system_root(destination_dir))
        {
            return Err(ManifestError::Validation(
                "system manifest destination must be a normalized dedicated directory below a system root"
                    .to_owned(),
            ));
        }
        Ok(destination_dir)
    }

    fn write_manifest(&self, manifest: &MachineManifest) -> Result<(), ManifestError> {
        let destination_dir = self.path.parent().ok_or_else(|| {
            ManifestError::Validation("manifest path has no parent directory".to_owned())
        })?;
        let temporary = destination_dir.join(format!(
            ".{}.{}.tmp",
            self.path
                .file_name()
                .and_then(|name| name.to_str())
                .unwrap_or("machine.toml"),
            Uuid::now_v7()
        ));
        let result = (|| {
            let mut file = platform::create_private_file(&temporary, self.platform_owner())
                .map_err(ManifestError::Write)?;
            file.write_all(manifest.to_toml()?.as_bytes())
                .map_err(ManifestError::Write)?;
            file.flush().map_err(ManifestError::Write)?;
            file.sync_all().map_err(ManifestError::Write)?;
            self.harden_temporary(&temporary)?;
            platform::replace_file(&temporary, &self.path).map_err(ManifestError::Write)?;
            self.verify_security_after_replace()
        })();
        if result.is_err() {
            let _ = fs::remove_file(&temporary);
        }
        result
    }

    fn harden_directory(&self, path: &std::path::Path) -> Result<(), ManifestError> {
        self.ensure_hardening_available()?;
        platform::harden_manifest_directory(path, self.platform_owner(), "styrn")
            .map_err(ManifestError::Write)
    }

    fn harden_temporary(&self, path: &std::path::Path) -> Result<(), ManifestError> {
        self.ensure_hardening_available()?;
        platform::harden_manifest_file(path, self.platform_owner(), "styrn")
            .map_err(ManifestError::Write)
    }

    fn verify_security(&self) -> Result<(), ManifestError> {
        self.verify_security_io().map_err(ManifestError::Security)
    }

    fn verify_security_after_replace(&self) -> Result<(), ManifestError> {
        #[cfg(test)]
        if matches!(self.security, ManifestSecurity::FailAfterReplace) {
            return Err(ManifestError::PostReplaceSecurity(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                "injected post-replacement verification failure",
            )));
        }
        self.verify_security_io()
            .map_err(ManifestError::PostReplaceSecurity)
    }

    fn verify_security_io(&self) -> std::io::Result<()> {
        platform::verify_manifest_security(
            &self.path,
            self.platform_owner(),
            "styrn",
            &self.trusted_root,
        )
    }

    fn platform_owner(&self) -> platform::ManifestOwner {
        match self.security {
            ManifestSecurity::System => platform::ManifestOwner::System,
            #[cfg(test)]
            ManifestSecurity::CurrentProcess
            | ManifestSecurity::FailBeforeReplace
            | ManifestSecurity::DirectoryPublicationRace
            | ManifestSecurity::DirectoryPublicationAndCleanupFailure => {
                platform::ManifestOwner::CurrentProcess
            }
            #[cfg(test)]
            ManifestSecurity::FailAfterReplace => platform::ManifestOwner::CurrentProcess,
            #[cfg(test)]
            ManifestSecurity::CurrentProcessWorker => platform::ManifestOwner::CurrentProcessWorker,
        }
    }

    fn requires_system_parent_chain(&self) -> bool {
        if matches!(self.security, ManifestSecurity::System) {
            return true;
        }
        #[cfg(test)]
        {
            matches!(self.security, ManifestSecurity::CurrentProcessWorker)
        }
        #[cfg(not(test))]
        {
            false
        }
    }

    fn ensure_hardening_available(&self) -> Result<(), ManifestError> {
        #[cfg(test)]
        if matches!(self.security, ManifestSecurity::FailBeforeReplace) {
            return Err(ManifestError::Write(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                "injected manifest hardening failure",
            )));
        }
        Ok(())
    }
}

fn is_broad_system_root(path: &std::path::Path) -> bool {
    #[cfg(target_os = "macos")]
    {
        path.to_str()
            .is_some_and(|path| path.eq_ignore_ascii_case("/Library/Application Support"))
    }
    #[cfg(not(target_os = "macos"))]
    {
        let _ = path;
        false
    }
}

fn has_supported_system_path_root(path: &std::path::Path) -> bool {
    #[cfg(windows)]
    {
        let mut components = path.components();
        matches!(
            components.next(),
            Some(std::path::Component::Prefix(prefix))
                if matches!(prefix.kind(), std::path::Prefix::Disk(_))
        ) && matches!(components.next(), Some(std::path::Component::RootDir))
    }
    #[cfg(not(windows))]
    {
        let _ = path;
        true
    }
}

fn parse_raw(input: &str) -> Result<RawMachineManifest, ManifestError> {
    toml::from_str(input).map_err(ManifestError::Toml)
}

fn parse_canonical_uuid(input: &str) -> Result<Uuid, ManifestError> {
    let uuid = Uuid::parse_str(input).map_err(|error| {
        ManifestError::Validation(format!("machine_id must be a canonical UUIDv7: {error}"))
    })?;
    if uuid.to_string() != input {
        return invalid("machine_id must use canonical lowercase UUID text");
    }
    Ok(uuid)
}

fn non_empty(name: &str, value: &str) -> Result<(), ManifestError> {
    if value.is_empty() {
        invalid(&format!("{name} must not be empty"))
    } else {
        Ok(())
    }
}

fn invalid<T>(message: &str) -> Result<T, ManifestError> {
    Err(ManifestError::Validation(message.to_owned()))
}

fn prune_nulls(value: &mut Value) {
    match value {
        Value::Array(values) => values.iter_mut().for_each(prune_nulls),
        Value::Object(values) => {
            values.retain(|_, value| !value.is_null());
            values.values_mut().for_each(prune_nulls);
        }
        _ => {}
    }
}

fn scan_secret_free(value: &Value, path: &str) -> Result<(), ManifestError> {
    match value {
        Value::Array(values) => {
            for (index, value) in values.iter().enumerate() {
                scan_secret_free(value, &format!("{path}[{index}]"))?;
            }
        }
        Value::Object(values) => {
            for (key, value) in values {
                if let Some(reason) = secret_shaped_key_reason(key) {
                    return Err(ManifestError::Secret {
                        path: redacted_key_path(path),
                        reason,
                    });
                }
                let field_path = json_field_path(path, key);
                if is_forbidden_secret_name(key) {
                    return Err(ManifestError::Secret {
                        path: field_path,
                        reason: "forbidden secret-bearing field name",
                    });
                }
                scan_secret_free(value, &field_path)?;
            }
        }
        Value::String(value) => {
            if is_private_key(value) {
                return Err(ManifestError::Secret {
                    path: path.to_owned(),
                    reason: "private key material",
                });
            }
            if is_compact_jwt(value) {
                return Err(ManifestError::Secret {
                    path: path.to_owned(),
                    reason: "JWT-shaped credential",
                });
            }
        }
        _ => {}
    }
    Ok(())
}

fn secret_shaped_key_reason(key: &str) -> Option<&'static str> {
    if is_private_key(key) {
        Some("private key material in object key")
    } else if is_compact_jwt(key) {
        Some("JWT-shaped credential in object key")
    } else {
        None
    }
}

fn redacted_key_path(parent: &str) -> String {
    format!("{parent}[redacted-secret-key]")
}

fn json_field_path(parent: &str, key: &str) -> String {
    if key
        .bytes()
        .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_')
    {
        format!("{parent}.{key}")
    } else {
        format!(
            "{parent}[{}]",
            serde_json::to_string(key).expect("string serializes")
        )
    }
}

fn is_forbidden_secret_name(key: &str) -> bool {
    matches!(
        key.bytes()
            .filter(|byte| !matches!(byte, b'_' | b'-' | b'.'))
            .map(char::from)
            .flat_map(char::to_lowercase)
            .collect::<String>()
            .as_str(),
        "privatekey"
            | "apikey"
            | "authkey"
            | "tailscaleauthkey"
            | "token"
            | "accesstoken"
            | "password"
            | "passphrase"
            | "secret"
            | "identity"
    )
}

fn is_private_key(value: &str) -> bool {
    matches!(
        value.trim_start().to_ascii_uppercase().as_str(),
        marker if marker.starts_with("-----BEGIN PRIVATE KEY-----")
            || marker.starts_with("-----BEGIN RSA PRIVATE KEY-----")
            || marker.starts_with("-----BEGIN EC PRIVATE KEY-----")
            || marker.starts_with("-----BEGIN DSA PRIVATE KEY-----")
            || marker.starts_with("-----BEGIN OPENSSH PRIVATE KEY-----")
    )
}

fn is_compact_jwt(value: &str) -> bool {
    let segments: Vec<_> = value.split('.').collect();
    segments.len() == 3
        && segments[0].starts_with("eyJ")
        && segments.iter().all(|segment| {
            segment.len() >= 12
                && segment
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
        })
        && URL_SAFE_NO_PAD
            .decode(segments[0])
            .ok()
            .and_then(|header| serde_json::from_slice::<Value>(&header).ok())
            .is_some_and(|header| header.is_object())
}

#[derive(Debug, Error)]
pub(crate) enum ManifestError {
    #[error("could not parse machine manifest: {0}")]
    Toml(#[from] toml::de::Error),
    #[error("could not serialize machine manifest: {0}")]
    TomlSerialize(toml::ser::Error),
    #[error("could not serialize machine manifest JSON: {0}")]
    Json(serde_json::Error),
    #[error("could not read machine manifest: {0}")]
    Read(std::io::Error),
    #[error("could not write machine manifest: {0}")]
    Write(std::io::Error),
    #[error("machine manifest security verification failed: {0}")]
    Security(std::io::Error),
    #[error("machine manifest was replaced but security verification failed: {0}")]
    PostReplaceSecurity(std::io::Error),
    #[error(
        "manifest staging directory operation failed ({operation}); cleanup also failed: {cleanup}"
    )]
    StagingDirectoryCleanup {
        operation: Box<ManifestError>,
        cleanup: std::io::Error,
    },
    #[error("manifest secret rejected at {path}: {reason}")]
    Secret { path: String, reason: &'static str },
    #[error("invalid machine manifest: {0}")]
    Validation(String),
}

#[cfg(test)]
mod destination_policy_tests {
    use super::*;
    use std::path::Path;

    #[cfg(target_os = "linux")]
    #[test]
    fn linux_override_policy_uses_normalized_absolute_dedicated_locations() {
        assert_destination_policy(
            &[
                Path::new("/opt/custom-config/machine.toml"),
                Path::new("/srv/example/settings/machine.toml"),
            ],
            &[
                Path::new("/"),
                Path::new("/etc/machine.toml"),
                Path::new("/opt/custom-config/../custom-config/machine.toml"),
                Path::new("/opt//custom-config/machine.toml"),
            ],
        );
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn macos_override_policy_uses_normalized_absolute_dedicated_locations() {
        assert_destination_policy(
            &[
                Path::new("/opt/custom-config/machine.toml"),
                Path::new("/srv/example/settings/machine.toml"),
            ],
            &[
                Path::new("/"),
                Path::new("/etc/machine.toml"),
                Path::new("/Library/Application Support/machine.toml"),
                Path::new("/opt/custom-config/../custom-config/machine.toml"),
                Path::new("/opt//custom-config/machine.toml"),
            ],
        );
    }

    fn assert_destination_policy(safe: &[&Path], broad_or_invalid: &[&Path]) {
        for safe in safe {
            assert!(
                MachineManifestStore::new(safe)
                    .validate_destination_policy()
                    .is_ok(),
                "{} must be accepted as a dedicated system manifest destination",
                safe.display()
            );
        }
        for broad_or_invalid in broad_or_invalid {
            assert!(
                MachineManifestStore::new(broad_or_invalid)
                    .validate_destination_policy()
                    .is_err(),
                "{} must not be accepted as a system manifest destination",
                broad_or_invalid.display()
            );
        }
    }

    #[cfg(windows)]
    #[test]
    fn windows_override_policy_uses_drive_qualified_normalized_local_paths() {
        assert_destination_policy(
            &[
                Path::new(r"C:\ProgramData\custom-config\machine.toml"),
                Path::new(r"D:\service\settings\machine.toml"),
            ],
            &[
                Path::new(r"C:\machine.toml"),
                Path::new(r"C:\ProgramData\machine.toml"),
                Path::new(r"C:\ProgramData\custom-config\..\custom-config\machine.toml"),
                Path::new("C:\\ProgramData\\\\custom-config\\machine.toml"),
                Path::new(r"\\server\share\custom-config\machine.toml"),
                Path::new(r"\\?\C:\ProgramData\custom-config\machine.toml"),
                Path::new(r"\\?\UNC\server\share\custom-config\machine.toml"),
                Path::new(
                    r"\\?\Volume{12345678-1234-1234-1234-123456789abc}\custom-config\machine.toml",
                ),
                Path::new(r"\\.\PIPE\custom-config\machine.toml"),
                Path::new(r"C:ProgramData\custom-config\machine.toml"),
                Path::new(r"\ProgramData\custom-config\machine.toml"),
            ],
        );
    }
}
