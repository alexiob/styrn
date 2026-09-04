#![allow(dead_code)]

#[path = "../src/cli/mod.rs"]
mod cli;
#[path = "../src/inventory/mod.rs"]
mod inventory;
#[path = "../src/manifest/mod.rs"]
mod manifest;
#[path = "../src/output/mod.rs"]
mod output;
#[path = "../src/platform/mod.rs"]
mod platform;
#[path = "../src/resources/mod.rs"]
mod resources;
#[path = "../src/rpc/mod.rs"]
mod rpc;
#[path = "../src/setup/mod.rs"]
mod setup;
#[path = "../src/transport/mod.rs"]
mod transport;

use inventory::{InventoryDocument, InventoryHost, InventoryStore, ManifestCache, StoredSsh};
use jsonschema::Validator;
use output::ErrorCode;
use std::fs;
use std::path::{Path, PathBuf};
use transport::PinnedHostKey;
use uuid::Uuid;

const ED25519_KEY: &str = "AAAAC3NzaC1lZDI1NTE5AAAAIAABAgMEBQYHCAkKCwwNDg8QERITFBUWFxgZGhscHR4f";
const ED25519_FINGERPRINT: &str = "SHA256:ZkAslGjFiUHdGf/WUL8rQvkib4PTvQatUV0OUQSncCA";

struct TestRoot(PathBuf);

impl TestRoot {
    fn new() -> Self {
        let path = std::env::current_dir()
            .unwrap()
            .join("target")
            .join(format!("styrn-inventory-{}", Uuid::now_v7()));
        fs::create_dir(&path).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).unwrap();
        }
        Self(path)
    }

    fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for TestRoot {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn pin() -> PinnedHostKey {
    PinnedHostKey::from_parts("ssh-ed25519", ED25519_KEY, ED25519_FINGERPRINT).unwrap()
}

fn inventory_validator() -> Validator {
    let schema: serde_json::Value =
        serde_json::from_str(include_str!("../schemas/inventory-v1.schema.json")).unwrap();
    jsonschema::validator_for(&schema).unwrap()
}

fn host(name: &str, machine_id: &str) -> InventoryHost {
    let transport = StoredSsh::new(
        name,
        "alex",
        22,
        PathBuf::from("/controller/keys/styrn_ed25519"),
        pin(),
    )
    .unwrap();
    InventoryHost::new(name, Uuid::parse_str(machine_id).unwrap(), transport).unwrap()
}

#[test]
fn inventory_store_round_trips_in_deterministic_name_order() {
    let root = TestRoot::new();
    let store = InventoryStore::at(root.path()).unwrap();
    let document = InventoryDocument::new(vec![
        host("zeta.example", "01991f60-1111-7abc-9def-0123456789ab"),
        host("alpha.example", "01991f5d-d72f-7b5e-a43d-9fcb61bd3265"),
    ])
    .unwrap();

    store
        .with_lock(|locked| locked.replace_inventory(&document))
        .unwrap();

    let restored = store.read().unwrap();
    assert_eq!(
        restored
            .hosts()
            .iter()
            .map(InventoryHost::name)
            .collect::<Vec<_>>(),
        ["alpha.example", "zeta.example"]
    );
    let bytes = fs::read_to_string(store.inventory_path()).unwrap();
    assert!(bytes.find("alpha.example").unwrap() < bytes.find("zeta.example").unwrap());
}

#[test]
fn inventory_example_matches_the_v1_schema_and_cache_derivation() {
    let example: toml::Value = toml::from_str(include_str!("../examples/inventory.toml")).unwrap();
    let value = serde_json::to_value(example).unwrap();
    inventory_validator().validate(&value).unwrap();
    assert_eq!(
        value["hosts"][0]["manifest_cache"],
        format!(
            "manifests/{}.toml",
            value["hosts"][0]["machine_id"].as_str().unwrap()
        )
    );
}

#[test]
fn inventory_corruption_is_never_silently_reset_or_echoed() {
    let root = TestRoot::new();
    let store = InventoryStore::at(root.path()).unwrap();
    let document = InventoryDocument::new(vec![host(
        "alpha.example",
        "01991f5d-d72f-7b5e-a43d-9fcb61bd3265",
    )])
    .unwrap();
    store
        .with_lock(|locked| locked.replace_inventory(&document))
        .unwrap();

    let hostile = "token = 'this-must-never-be-echoed-or-reset'\n";
    fs::write(store.inventory_path(), hostile).unwrap();
    let error = store.read().unwrap_err();
    assert_eq!(error.code(), ErrorCode::UsageConfigInvalid);
    assert!(!error.to_string().contains("never-be-echoed"));
    assert_eq!(fs::read_to_string(store.inventory_path()).unwrap(), hostile);
    assert!(fs::read_dir(root.path()).unwrap().all(|entry| !entry
        .unwrap()
        .file_name()
        .to_string_lossy()
        .contains(".tmp")));
}

#[test]
fn inventory_exact_reenrollment_converges_but_alias_or_machine_conflict_refuses() {
    let first = host("alpha.example", "01991f5d-d72f-7b5e-a43d-9fcb61bd3265");
    let mut document = InventoryDocument::new(vec![first.clone()]).unwrap();
    assert!(!document.upsert_exact(first).unwrap());

    let conflict = host("alpha.example", "01991f60-1111-7abc-9def-0123456789ab");
    let error = document.upsert_exact(conflict).unwrap_err();
    assert_eq!(error.code(), ErrorCode::UsageConfigInvalid);
    assert_eq!(document.hosts().len(), 1);

    assert_eq!(
        InventoryDocument::empty().select(None).unwrap_err().code(),
        ErrorCode::UsageInvalidArgument
    );
    let two = InventoryDocument::new(vec![
        host("alpha.example", "01991f5d-d72f-7b5e-a43d-9fcb61bd3265"),
        host("zeta.example", "01991f60-1111-7abc-9def-0123456789ab"),
    ])
    .unwrap();
    assert_eq!(
        two.select(None).unwrap_err().code(),
        ErrorCode::UsageInvalidArgument
    );
}

#[test]
fn inventory_cache_and_known_hosts_are_bound_deterministic_documents() {
    let root = TestRoot::new();
    let store = InventoryStore::at(root.path()).unwrap();
    let document = InventoryDocument::new(vec![
        host("zeta.example", "01991f60-1111-7abc-9def-0123456789ab"),
        host("alpha.example", "01991f5d-d72f-7b5e-a43d-9fcb61bd3265"),
    ])
    .unwrap();
    store
        .with_lock(|locked| {
            locked.replace_inventory(&document)?;
            locked.rebuild_known_hosts(&document)
        })
        .unwrap();
    let known_hosts = fs::read_to_string(store.known_hosts_path()).unwrap();
    assert!(known_hosts.find("alpha.example").unwrap() < known_hosts.find("zeta.example").unwrap());
    assert_eq!(known_hosts.lines().count(), 2);

    let manifest = manifest::MachineManifest::parse_toml(include_str!(
        "../examples/machine.controller-worker.toml"
    ))
    .unwrap();
    let cached_at = chrono::DateTime::parse_from_rfc3339("2026-09-04T12:00:00+00:00").unwrap();
    let cache = ManifestCache::new(cached_at, "0.1.0", &manifest).unwrap();
    store.write_cache(&cache).unwrap();
    let restored = store.read_cache(manifest.machine_id).unwrap();
    assert_eq!(restored.machine_id(), manifest.machine_id);
    assert_eq!(restored.styrn_version(), "0.1.0");
    assert_eq!(restored.manifest().unwrap().machine_id, manifest.machine_id);

    let candidate_path = {
        let candidate = store
            .candidate_known_hosts("candidate.example", 22, &pin())
            .unwrap();
        assert!(candidate.path().is_file());
        candidate.path().to_path_buf()
    };
    assert!(!candidate_path.exists());
}

#[cfg(unix)]
#[test]
fn inventory_link_is_rejected_without_touching_its_target() {
    use std::os::unix::fs::symlink;

    let root = TestRoot::new();
    let store = InventoryStore::at(root.path()).unwrap();
    let target = root.path().join("outside.toml");
    fs::write(&target, b"do-not-touch\n").unwrap();
    symlink(&target, store.inventory_path()).unwrap();

    let error = store.read().unwrap_err();
    assert_eq!(error.code(), ErrorCode::UsageConfigInvalid);
    assert_eq!(fs::read(&target).unwrap(), b"do-not-touch\n");
}
