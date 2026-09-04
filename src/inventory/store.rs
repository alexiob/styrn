#![allow(dead_code)] // The public host CLI consumes this concrete store in Task 4 of this wave.

use crate::manifest::{contains_secret_shaped_text, MachineManifest};
use crate::output::{ErrorCode, StyrnExit};
use crate::platform::{self, ManifestOwner, WorkerPrincipal};
use crate::transport::{PinnedHostKey, RpcTarget, TransportError};
use chrono::{DateTime, FixedOffset, SecondsFormat};
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::fmt;
use std::fs::{self, File};
use std::io::{Read, Write};
use std::path::{Component, Path, PathBuf};
use uuid::Uuid;

const INVENTORY_SCHEMA_VERSION: u64 = 1;
const CACHE_SCHEMA_VERSION: u64 = 1;
const MAX_HOSTS: usize = 1_024;
const MAX_DOCUMENT_BYTES: u64 = 4 * 1024 * 1024;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum InventoryErrorKind {
    InvalidArgument,
    InvalidConfig,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct InventoryError {
    kind: InventoryErrorKind,
}

impl InventoryError {
    fn argument() -> Self {
        Self {
            kind: InventoryErrorKind::InvalidArgument,
        }
    }

    fn config() -> Self {
        Self {
            kind: InventoryErrorKind::InvalidConfig,
        }
    }

    pub(crate) const fn code(self) -> ErrorCode {
        match self.kind {
            InventoryErrorKind::InvalidArgument => ErrorCode::UsageInvalidArgument,
            InventoryErrorKind::InvalidConfig => ErrorCode::UsageConfigInvalid,
        }
    }

    pub(crate) const fn exit_code(self) -> StyrnExit {
        self.code().exit_code()
    }
}

impl fmt::Display for InventoryError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self.kind {
            InventoryErrorKind::InvalidArgument => "the host inventory request is invalid",
            InventoryErrorKind::InvalidConfig => "the local host inventory is invalid or insecure",
        })
    }
}

impl std::error::Error for InventoryError {}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct StoredSsh {
    host: String,
    user: String,
    port: u16,
    identity: PathBuf,
    host_key: PinnedHostKey,
}

impl StoredSsh {
    pub(crate) fn new(
        host: &str,
        user: &str,
        port: u16,
        identity: PathBuf,
        host_key: PinnedHostKey,
    ) -> Result<Self, InventoryError> {
        RpcTarget::new(host, user, port, identity.clone(), host_key.clone())
            .map_err(|_| InventoryError::argument())?;
        Ok(Self {
            host: host.to_owned(),
            user: user.to_owned(),
            port,
            identity,
            host_key,
        })
    }

    pub(crate) fn host(&self) -> &str {
        &self.host
    }

    pub(crate) fn user(&self) -> &str {
        &self.user
    }

    pub(crate) const fn port(&self) -> u16 {
        self.port
    }

    pub(crate) fn identity(&self) -> &Path {
        &self.identity
    }

    pub(crate) const fn host_key(&self) -> &PinnedHostKey {
        &self.host_key
    }

    pub(crate) fn rpc_target(&self) -> Result<RpcTarget, TransportError> {
        RpcTarget::new(
            &self.host,
            &self.user,
            self.port,
            self.identity.clone(),
            self.host_key.clone(),
        )
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct InventoryHost {
    name: String,
    machine_id: Uuid,
    manifest_cache: String,
    transport: StoredSsh,
}

impl InventoryHost {
    pub(crate) fn new(
        name: &str,
        machine_id: Uuid,
        transport: StoredSsh,
    ) -> Result<Self, InventoryError> {
        if !valid_name(name)
            || machine_id.get_version_num() != 7
            || machine_id.get_variant() != uuid::Variant::RFC4122
        {
            return Err(InventoryError::argument());
        }
        Ok(Self {
            name: name.to_owned(),
            machine_id,
            manifest_cache: format!("manifests/{machine_id}.toml"),
            transport,
        })
    }

    pub(crate) fn name(&self) -> &str {
        &self.name
    }

    pub(crate) const fn machine_id(&self) -> Uuid {
        self.machine_id
    }

    pub(crate) fn manifest_cache(&self) -> &str {
        &self.manifest_cache
    }

    pub(crate) const fn transport(&self) -> &StoredSsh {
        &self.transport
    }

    pub(crate) fn rpc_target(&self) -> Result<RpcTarget, TransportError> {
        self.transport.rpc_target()
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct InventoryDocument {
    hosts: Vec<InventoryHost>,
}

impl InventoryDocument {
    pub(crate) fn empty() -> Self {
        Self { hosts: Vec::new() }
    }

    pub(crate) fn new(mut hosts: Vec<InventoryHost>) -> Result<Self, InventoryError> {
        hosts.sort_by(|left, right| left.name.cmp(&right.name));
        validate_hosts(&hosts).map_err(|_| InventoryError::argument())?;
        Ok(Self { hosts })
    }

    pub(crate) fn hosts(&self) -> &[InventoryHost] {
        &self.hosts
    }

    pub(crate) fn host(&self, name: &str) -> Option<&InventoryHost> {
        self.hosts.iter().find(|host| host.name == name)
    }

    pub(crate) fn select(&self, name: Option<&str>) -> Result<&InventoryHost, InventoryError> {
        match name {
            Some(name) => self.host(name).ok_or_else(InventoryError::argument),
            None if self.hosts.len() == 1 => Ok(&self.hosts[0]),
            None => Err(InventoryError::argument()),
        }
    }

    /// Inserts an enrollment only when neither its alias nor machine ID conflicts.
    /// Returns true for a new host and false for an exact idempotent record.
    pub(crate) fn upsert_exact(&mut self, host: InventoryHost) -> Result<bool, InventoryError> {
        if let Some(existing) = self
            .hosts
            .iter()
            .find(|existing| existing.name == host.name || existing.machine_id == host.machine_id)
        {
            return if existing == &host {
                Ok(false)
            } else {
                Err(InventoryError::config())
            };
        }
        if self.hosts.len() == MAX_HOSTS {
            return Err(InventoryError::argument());
        }
        self.hosts.push(host);
        self.hosts.sort_by(|left, right| left.name.cmp(&right.name));
        Ok(true)
    }

    fn canonical_toml(&self) -> Result<String, InventoryError> {
        validate_hosts(&self.hosts).map_err(|_| InventoryError::config())?;
        let wire = InventoryWireRef {
            schema_version: INVENTORY_SCHEMA_VERSION,
            hosts: self.hosts.iter().map(InventoryHostWireRef::from).collect(),
        };
        toml::to_string(&wire).map_err(|_| InventoryError::config())
    }

    fn parse(input: &str) -> Result<Self, InventoryError> {
        if contains_secret_shaped_text(input) {
            return Err(InventoryError::config());
        }
        let wire: InventoryWire = toml::from_str(input).map_err(|_| InventoryError::config())?;
        if wire.schema_version != INVENTORY_SCHEMA_VERSION {
            return Err(InventoryError::config());
        }
        let mut hosts = Vec::with_capacity(wire.hosts.len());
        for host in wire.hosts {
            let expected_cache = format!("manifests/{}.toml", host.machine_id);
            if host.manifest_cache != expected_cache || host.transport.kind != "ssh" {
                return Err(InventoryError::config());
            }
            let pin = PinnedHostKey::from_parts(
                &host.transport.host_key_algorithm,
                &host.transport.host_key_base64,
                &host.transport.host_key_fingerprint,
            )
            .map_err(|_| InventoryError::config())?;
            let transport = StoredSsh::new(
                &host.transport.host,
                &host.transport.user,
                host.transport.port,
                PathBuf::from(host.transport.identity),
                pin,
            )
            .map_err(|_| InventoryError::config())?;
            let mut parsed = InventoryHost::new(&host.name, host.machine_id, transport)
                .map_err(|_| InventoryError::config())?;
            parsed.manifest_cache = host.manifest_cache;
            hosts.push(parsed);
        }
        Self::new(hosts).map_err(|_| InventoryError::config())
    }
}

#[derive(Clone, Debug)]
pub(crate) struct ManifestCache {
    cached_at: DateTime<FixedOffset>,
    styrn_version: String,
    manifest_schema_version: u64,
    manifest_toml: String,
    machine_id: Uuid,
}

impl ManifestCache {
    pub(crate) fn new(
        cached_at: DateTime<FixedOffset>,
        styrn_version: &str,
        manifest: &MachineManifest,
    ) -> Result<Self, InventoryError> {
        if !valid_version(styrn_version) {
            return Err(InventoryError::argument());
        }
        let manifest_toml = manifest.to_toml().map_err(|_| InventoryError::argument())?;
        let cache = Self {
            cached_at,
            styrn_version: styrn_version.to_owned(),
            manifest_schema_version: manifest.schema_version,
            manifest_toml,
            machine_id: manifest.machine_id,
        };
        cache.validate().map_err(|_| InventoryError::argument())?;
        Ok(cache)
    }

    pub(crate) const fn machine_id(&self) -> Uuid {
        self.machine_id
    }

    pub(crate) const fn cached_at(&self) -> DateTime<FixedOffset> {
        self.cached_at
    }

    pub(crate) fn styrn_version(&self) -> &str {
        &self.styrn_version
    }

    pub(crate) const fn manifest_schema_version(&self) -> u64 {
        self.manifest_schema_version
    }

    pub(crate) fn manifest_toml(&self) -> &str {
        &self.manifest_toml
    }

    pub(crate) fn manifest(&self) -> Result<MachineManifest, InventoryError> {
        MachineManifest::parse_toml(&self.manifest_toml).map_err(|_| InventoryError::config())
    }

    fn validate(&self) -> Result<(), InventoryError> {
        let manifest = self.manifest()?;
        if self.manifest_schema_version != manifest.schema_version
            || self.machine_id != manifest.machine_id
            || !valid_version(&self.styrn_version)
            || manifest.to_toml().ok().as_deref() != Some(self.manifest_toml.as_str())
        {
            return Err(InventoryError::config());
        }
        Ok(())
    }

    fn canonical_toml(&self) -> Result<String, InventoryError> {
        self.validate()?;
        toml::to_string(&ManifestCacheWireRef {
            schema_version: CACHE_SCHEMA_VERSION,
            cached_at: self.cached_at.to_rfc3339_opts(SecondsFormat::AutoSi, true),
            styrn_version: &self.styrn_version,
            manifest_schema_version: self.manifest_schema_version,
            manifest_toml: &self.manifest_toml,
        })
        .map_err(|_| InventoryError::config())
    }

    fn parse(input: &str, machine_id: Uuid) -> Result<Self, InventoryError> {
        if contains_secret_shaped_text(input) {
            return Err(InventoryError::config());
        }
        let wire: ManifestCacheWire =
            toml::from_str(input).map_err(|_| InventoryError::config())?;
        if wire.schema_version != CACHE_SCHEMA_VERSION {
            return Err(InventoryError::config());
        }
        let cached_at =
            DateTime::parse_from_rfc3339(&wire.cached_at).map_err(|_| InventoryError::config())?;
        let cache = Self {
            cached_at,
            styrn_version: wire.styrn_version,
            manifest_schema_version: wire.manifest_schema_version,
            manifest_toml: wire.manifest_toml,
            machine_id,
        };
        cache.validate()?;
        Ok(cache)
    }
}

pub(crate) struct InventoryStore {
    root: PathBuf,
    inventory: PathBuf,
    manifests: PathBuf,
    known_hosts: PathBuf,
    principal: WorkerPrincipal,
}

impl InventoryStore {
    pub(crate) fn configured() -> Result<Self, InventoryError> {
        let root = configured_root()?;
        Self::at(&root)
    }

    pub(crate) fn at(root: &Path) -> Result<Self, InventoryError> {
        validate_root_path(root)?;
        let principal =
            platform::resolve_current_worker_principal().map_err(|_| InventoryError::config())?;
        prepare_private_directory(root, &principal)?;
        let manifests = root.join("manifests");
        prepare_private_directory(&manifests, &principal)?;
        Ok(Self {
            root: root.to_path_buf(),
            inventory: root.join("inventory.toml"),
            manifests,
            known_hosts: root.join("known_hosts"),
            principal,
        })
    }

    pub(crate) fn inventory_path(&self) -> &Path {
        &self.inventory
    }

    pub(crate) fn known_hosts_path(&self) -> &Path {
        &self.known_hosts
    }

    pub(crate) fn read(&self) -> Result<InventoryDocument, InventoryError> {
        self.verify_root()?;
        match read_verified(&self.inventory, &self.root, &self.principal) {
            Ok(input) => InventoryDocument::parse(&input),
            Err(ReadVerifiedError::Missing) => Ok(InventoryDocument::empty()),
            Err(ReadVerifiedError::Invalid) => Err(InventoryError::config()),
        }
    }

    pub(crate) fn with_lock<T>(
        &self,
        operation: impl FnOnce(&mut InventoryLock<'_>) -> Result<T, InventoryError>,
    ) -> Result<T, InventoryError> {
        self.verify_root()?;
        let lock_path = self.root.join(".inventory.toml.lock");
        let lock = platform::open_manifest_lock(&lock_path, ManifestOwner::User, &self.principal)
            .map_err(|_| InventoryError::config())?;
        lock.lock().map_err(|_| InventoryError::config())?;
        let mut session = InventoryLock {
            store: self,
            _lock: lock,
        };
        operation(&mut session)
    }

    pub(crate) fn write_cache(&self, cache: &ManifestCache) -> Result<(), InventoryError> {
        let bytes = cache.canonical_toml()?;
        let path = self.cache_path(cache.machine_id)?;
        write_verified(&path, &bytes, &self.root, &self.principal)
    }

    pub(crate) fn read_cache(&self, machine_id: Uuid) -> Result<ManifestCache, InventoryError> {
        let path = self.cache_path(machine_id)?;
        let input = read_verified(&path, &self.root, &self.principal)
            .map_err(|_| InventoryError::config())?;
        ManifestCache::parse(&input, machine_id)
    }

    pub(crate) fn candidate_known_hosts(
        &self,
        host: &str,
        port: u16,
        pin: &PinnedHostKey,
    ) -> Result<CandidateKnownHosts, InventoryError> {
        let contents = pin
            .known_hosts_line(host, port)
            .map_err(|_| InventoryError::argument())?;
        let path = self
            .root
            .join(format!(".enrollment-known-hosts-{}.tmp", Uuid::now_v7()));
        if let Err(error) = write_new_verified(&path, &contents, &self.root, &self.principal) {
            let _ = fs::remove_file(&path);
            return Err(error);
        }
        Ok(CandidateKnownHosts { path })
    }

    fn cache_path(&self, machine_id: Uuid) -> Result<PathBuf, InventoryError> {
        if machine_id.get_version_num() != 7 || machine_id.get_variant() != uuid::Variant::RFC4122 {
            return Err(InventoryError::argument());
        }
        Ok(self.manifests.join(format!("{machine_id}.toml")))
    }

    fn verify_root(&self) -> Result<(), InventoryError> {
        platform::verify_manifest_parent_chain(&self.root, ManifestOwner::User, &self.principal)
            .and_then(|()| {
                platform::verify_manifest_directory_security(
                    &self.root,
                    ManifestOwner::User,
                    &self.principal,
                )
            })
            .and_then(|()| {
                platform::verify_manifest_directory_security(
                    &self.manifests,
                    ManifestOwner::User,
                    &self.principal,
                )
            })
            .map_err(|_| InventoryError::config())
    }
}

pub(crate) struct CandidateKnownHosts {
    path: PathBuf,
}

impl CandidateKnownHosts {
    pub(crate) fn path(&self) -> &Path {
        &self.path
    }
}

impl Drop for CandidateKnownHosts {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.path);
    }
}

pub(crate) struct InventoryLock<'a> {
    store: &'a InventoryStore,
    _lock: File,
}

impl InventoryLock<'_> {
    pub(crate) fn read_locked(&self) -> Result<InventoryDocument, InventoryError> {
        self.store.read()
    }

    pub(crate) fn replace_inventory(
        &mut self,
        document: &InventoryDocument,
    ) -> Result<(), InventoryError> {
        let bytes = document.canonical_toml()?;
        write_verified(
            &self.store.inventory,
            &bytes,
            &self.store.root,
            &self.store.principal,
        )
    }

    pub(crate) fn rebuild_known_hosts(
        &mut self,
        document: &InventoryDocument,
    ) -> Result<(), InventoryError> {
        let mut contents = String::new();
        for host in document.hosts() {
            contents.push_str(
                &host
                    .transport
                    .host_key
                    .known_hosts_line(&host.transport.host, host.transport.port)
                    .map_err(|_| InventoryError::config())?,
            );
        }
        write_verified(
            &self.store.known_hosts,
            &contents,
            &self.store.root,
            &self.store.principal,
        )
    }

    pub(crate) fn select(
        &self,
        document: &InventoryDocument,
        name: Option<&str>,
    ) -> Result<InventoryHost, InventoryError> {
        document.select(name).cloned()
    }
}

#[derive(Deserialize)]
struct InventoryWire {
    schema_version: u64,
    hosts: Vec<InventoryHostWire>,
}

#[derive(Deserialize)]
struct InventoryHostWire {
    name: String,
    machine_id: Uuid,
    manifest_cache: String,
    transport: StoredSshWire,
}

#[derive(Deserialize)]
struct StoredSshWire {
    kind: String,
    host: String,
    user: String,
    port: u16,
    identity: String,
    host_key_algorithm: String,
    host_key_base64: String,
    host_key_fingerprint: String,
}

#[derive(Serialize)]
struct InventoryWireRef<'a> {
    schema_version: u64,
    hosts: Vec<InventoryHostWireRef<'a>>,
}

#[derive(Serialize)]
struct InventoryHostWireRef<'a> {
    name: &'a str,
    machine_id: Uuid,
    manifest_cache: &'a str,
    transport: StoredSshWireRef<'a>,
}

impl<'a> From<&'a InventoryHost> for InventoryHostWireRef<'a> {
    fn from(host: &'a InventoryHost) -> Self {
        Self {
            name: &host.name,
            machine_id: host.machine_id,
            manifest_cache: &host.manifest_cache,
            transport: StoredSshWireRef {
                kind: "ssh",
                host: &host.transport.host,
                user: &host.transport.user,
                port: host.transport.port,
                identity: host.transport.identity.to_string_lossy(),
                host_key_algorithm: host.transport.host_key.algorithm(),
                host_key_base64: host.transport.host_key.base64(),
                host_key_fingerprint: host.transport.host_key.fingerprint(),
            },
        }
    }
}

#[derive(Serialize)]
struct StoredSshWireRef<'a> {
    kind: &'static str,
    host: &'a str,
    user: &'a str,
    port: u16,
    identity: std::borrow::Cow<'a, str>,
    host_key_algorithm: &'a str,
    host_key_base64: &'a str,
    host_key_fingerprint: &'a str,
}

#[derive(Deserialize)]
struct ManifestCacheWire {
    schema_version: u64,
    cached_at: String,
    styrn_version: String,
    manifest_schema_version: u64,
    manifest_toml: String,
}

#[derive(Serialize)]
struct ManifestCacheWireRef<'a> {
    schema_version: u64,
    cached_at: String,
    styrn_version: &'a str,
    manifest_schema_version: u64,
    manifest_toml: &'a str,
}

fn validate_hosts(hosts: &[InventoryHost]) -> Result<(), ()> {
    if hosts.len() > MAX_HOSTS {
        return Err(());
    }
    let mut names = HashSet::with_capacity(hosts.len());
    let mut machine_ids = HashSet::with_capacity(hosts.len());
    let mut previous = None;
    for host in hosts {
        if !valid_name(&host.name)
            || !names.insert(host.name.as_str())
            || !machine_ids.insert(host.machine_id)
            || previous.is_some_and(|previous: &str| previous >= host.name.as_str())
            || host.manifest_cache != format!("manifests/{}.toml", host.machine_id)
            || host.transport.rpc_target().is_err()
        {
            return Err(());
        }
        previous = Some(&host.name);
    }
    Ok(())
}

fn valid_name(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 255
        && !value.chars().any(char::is_control)
        && !contains_secret_shaped_text(value)
}

fn valid_version(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && !value.chars().any(char::is_control)
        && !contains_secret_shaped_text(value)
}

fn configured_root() -> Result<PathBuf, InventoryError> {
    if let Some(root) = std::env::var_os("STYRN_CONFIG_DIR") {
        return Ok(PathBuf::from(root));
    }
    #[cfg(target_os = "linux")]
    let root = std::env::var_os("XDG_CONFIG_HOME")
        .map(PathBuf::from)
        .or_else(|| std::env::var_os("HOME").map(|home| PathBuf::from(home).join(".config")))
        .map(|root| root.join("styrn"));
    #[cfg(target_os = "macos")]
    let root = std::env::var_os("HOME")
        .map(PathBuf::from)
        .map(|home| home.join("Library/Application Support/Styrn"));
    #[cfg(target_os = "windows")]
    let root = std::env::var_os("APPDATA")
        .map(PathBuf::from)
        .map(|root| root.join("Styrn"));
    root.ok_or_else(InventoryError::config)
}

fn validate_root_path(path: &Path) -> Result<(), InventoryError> {
    if !path.is_absolute()
        || path.file_name().is_none()
        || path
            .components()
            .any(|component| matches!(component, Component::CurDir | Component::ParentDir))
        || path.components().collect::<PathBuf>().as_os_str() != path.as_os_str()
    {
        return Err(InventoryError::config());
    }
    Ok(())
}

fn prepare_private_directory(
    directory: &Path,
    principal: &WorkerPrincipal,
) -> Result<(), InventoryError> {
    let mut missing = Vec::new();
    let mut current = directory;
    loop {
        match fs::symlink_metadata(current) {
            Ok(_) => break,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                missing.push(current.to_path_buf());
                current = current.parent().ok_or_else(InventoryError::config)?;
            }
            Err(_) => return Err(InventoryError::config()),
        }
    }
    for path in missing.into_iter().rev() {
        match platform::create_private_manifest_staging_directory(
            &path,
            ManifestOwner::User,
            principal,
        ) {
            Ok(_) => {
                platform::harden_manifest_directory(&path, ManifestOwner::User, principal)
                    .and_then(|()| {
                        platform::sync_parent_directory(
                            path.parent()
                                .ok_or_else(|| std::io::Error::other("missing parent"))?,
                        )
                    })
                    .map_err(|_| InventoryError::config())?;
            }
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
            Err(_) => return Err(InventoryError::config()),
        }
    }
    platform::verify_manifest_parent_chain(directory, ManifestOwner::User, principal)
        .and_then(|()| {
            platform::verify_manifest_directory_security(directory, ManifestOwner::User, principal)
        })
        .map_err(|_| InventoryError::config())
}

enum ReadVerifiedError {
    Missing,
    Invalid,
}

fn read_verified(
    path: &Path,
    root: &Path,
    principal: &WorkerPrincipal,
) -> Result<String, ReadVerifiedError> {
    let expected = match platform::private_file_identity(path) {
        Ok(identity) => identity,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            return Err(ReadVerifiedError::Missing)
        }
        Err(_) => return Err(ReadVerifiedError::Invalid),
    };
    let mut file =
        platform::open_verified_manifest_file_for_read(path, ManifestOwner::User, principal, root)
            .map_err(|_| ReadVerifiedError::Invalid)?;
    if platform::private_file_identity_from_handle(&file).map_err(|_| ReadVerifiedError::Invalid)?
        != expected
        || file
            .metadata()
            .map_err(|_| ReadVerifiedError::Invalid)?
            .len()
            > MAX_DOCUMENT_BYTES
    {
        return Err(ReadVerifiedError::Invalid);
    }
    let mut bytes = Vec::new();
    std::io::Read::by_ref(&mut file)
        .take(MAX_DOCUMENT_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| ReadVerifiedError::Invalid)?;
    if bytes.len() as u64 > MAX_DOCUMENT_BYTES
        || platform::private_file_identity(path).map_err(|_| ReadVerifiedError::Invalid)?
            != expected
    {
        return Err(ReadVerifiedError::Invalid);
    }
    String::from_utf8(bytes).map_err(|_| ReadVerifiedError::Invalid)
}

fn write_verified(
    path: &Path,
    contents: &str,
    root: &Path,
    principal: &WorkerPrincipal,
) -> Result<(), InventoryError> {
    if contents.len() as u64 > MAX_DOCUMENT_BYTES || contains_secret_shaped_text(contents) {
        return Err(InventoryError::config());
    }
    verify_replace_target(path)?;
    let parent = path.parent().ok_or_else(InventoryError::config)?;
    let temporary = parent.join(format!(".inventory-document-{}.tmp", Uuid::now_v7()));
    let result = (|| {
        write_new_verified(&temporary, contents, root, principal)?;
        platform::verify_manifest_parent_chain(parent, ManifestOwner::User, principal)
            .map_err(|_| InventoryError::config())?;
        verify_replace_target(path)?;
        platform::replace_file(&temporary, path).map_err(|_| InventoryError::config())?;
        let read_back =
            read_verified(path, root, principal).map_err(|_| InventoryError::config())?;
        if read_back != contents {
            return Err(InventoryError::config());
        }
        platform::sync_parent_directory(parent).map_err(|_| InventoryError::config())
    })();
    if result.is_err() {
        let _ = fs::remove_file(&temporary);
    }
    result
}

fn write_new_verified(
    path: &Path,
    contents: &str,
    root: &Path,
    principal: &WorkerPrincipal,
) -> Result<(), InventoryError> {
    if contents.len() as u64 > MAX_DOCUMENT_BYTES || contains_secret_shaped_text(contents) {
        return Err(InventoryError::config());
    }
    let mut file = platform::create_private_file(path, ManifestOwner::User, principal)
        .map_err(|_| InventoryError::config())?;
    file.write_all(contents.as_bytes())
        .and_then(|()| file.flush())
        .and_then(|()| file.sync_all())
        .map_err(|_| InventoryError::config())?;
    drop(file);
    platform::harden_manifest_file(path, ManifestOwner::User, principal)
        .and_then(|()| {
            platform::verify_manifest_security(path, ManifestOwner::User, principal, root)
        })
        .map_err(|_| InventoryError::config())
}

fn verify_replace_target(path: &Path) -> Result<(), InventoryError> {
    match fs::symlink_metadata(path) {
        Ok(_) => platform::verify_manifest_file_target(path).map_err(|_| InventoryError::config()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(_) => Err(InventoryError::config()),
    }
}
