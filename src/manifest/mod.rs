use crate::platform;
use chrono::{DateTime, FixedOffset};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::BTreeMap;
use std::fs::{self, OpenOptions};
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
    Herdr { installed: Option<bool>, session: Option<String>, autostart: Option<String> }
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
}

#[allow(dead_code)] // Referenced by the executable; integration tests compile this module separately.
pub(crate) fn configured_manifest_path() -> PathBuf {
    if let Some(directory) = std::env::var_os("STYRN_CONFIG_DIR") {
        return PathBuf::from(directory).join("machine.toml");
    }
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

impl MachineManifestStore {
    pub(crate) fn new(path: impl Into<PathBuf>) -> Self {
        Self { path: path.into() }
    }

    pub(crate) fn read_or_repair(&self) -> Result<ReadOutcome, ManifestError> {
        let raw = parse_raw(&fs::read_to_string(&self.path).map_err(ManifestError::Read)?)?;
        let machine_id = raw
            .machine_id
            .as_deref()
            .map(parse_canonical_uuid)
            .transpose()?;
        if let Some(machine_id) = machine_id {
            let manifest = raw.into_manifest(machine_id);
            manifest.validate()?;
            return Ok(ReadOutcome {
                manifest,
                machine_id_minted: false,
            });
        }
        self.with_mutation_lock(|| self.read_or_repair_locked())
    }

    fn read_or_repair_locked(&self) -> Result<ReadOutcome, ManifestError> {
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
        if !self.path.exists() {
            return Ok(None);
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
        let destination_dir = self.path.parent().ok_or_else(|| {
            ManifestError::Validation("manifest path has no parent directory".to_owned())
        })?;
        fs::create_dir_all(destination_dir).map_err(ManifestError::Write)?;
        let lock_path = destination_dir.join(format!(
            ".{}.lock",
            self.path
                .file_name()
                .and_then(|name| name.to_str())
                .unwrap_or("machine.toml")
        ));
        let lock = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(lock_path)
            .map_err(ManifestError::Write)?;
        lock.lock().map_err(ManifestError::Write)?;
        operation()
    }

    fn write_manifest(&self, manifest: &MachineManifest) -> Result<(), ManifestError> {
        let destination_dir = self.path.parent().ok_or_else(|| {
            ManifestError::Validation("manifest path has no parent directory".to_owned())
        })?;
        fs::create_dir_all(destination_dir).map_err(ManifestError::Write)?;
        let temporary = destination_dir.join(format!(
            ".{}.{}.tmp",
            self.path
                .file_name()
                .and_then(|name| name.to_str())
                .unwrap_or("machine.toml"),
            Uuid::now_v7()
        ));
        let result = (|| {
            let mut file = OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&temporary)
                .map_err(ManifestError::Write)?;
            file.write_all(manifest.to_toml()?.as_bytes())
                .map_err(ManifestError::Write)?;
            file.flush().map_err(ManifestError::Write)?;
            file.sync_all().map_err(ManifestError::Write)?;
            platform::replace_file(&temporary, &self.path).map_err(ManifestError::Write)
        })();
        if result.is_err() {
            let _ = fs::remove_file(&temporary);
        }
        result
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
    #[error("manifest secret rejected at {path}: {reason}")]
    Secret { path: String, reason: &'static str },
    #[error("invalid machine manifest: {0}")]
    Validation(String),
}
