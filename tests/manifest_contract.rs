#[path = "../src/platform/mod.rs"]
mod platform;

#[path = "../src/manifest/mod.rs"]
mod manifest;

use jsonschema::JSONSchema;
use manifest::{MachineManifest, MachineManifestStore};
use serde_json::Value;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::{mpsc, Arc, Barrier};
use uuid::Uuid;

fn schema_validator() -> JSONSchema {
    let schema: Value = serde_json::from_str(
        &fs::read_to_string(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/schemas/machine-v1.schema.json"
        ))
        .unwrap(),
    )
    .unwrap();
    JSONSchema::compile(&schema).unwrap()
}

fn assert_schema_valid(value: &Value) {
    if let Err(errors) = schema_validator().validate(value) {
        panic!(
            "machine JSON must validate against the checked-in schema:\n{}",
            errors
                .map(|error| error.to_string())
                .collect::<Vec<_>>()
                .join("\n")
        );
    }
}

#[test]
fn checked_in_examples_parse_validate_and_round_trip_without_losing_fields() {
    for example in [
        "examples/machine.toml",
        "examples/machine.controller-worker.toml",
    ] {
        let input = fs::read_to_string(example).unwrap();
        let manifest = MachineManifest::parse_toml(&input).unwrap();
        manifest.validate().unwrap();
        let json = manifest.to_json_value().unwrap();
        assert_schema_valid(&json);

        let reparsed = MachineManifest::parse_toml(&manifest.to_toml().unwrap()).unwrap();
        assert_eq!(reparsed.to_json_value().unwrap(), json, "{example}");
    }
}

#[test]
fn guarded_serialization_rejects_secret_named_dynamic_entries() {
    let valid = fs::read_to_string("examples/machine.controller-worker.toml").unwrap();
    let cases = [
        ("capabilities", "private_key"),
        ("agents", "PRIVATE.KEY"),
        ("toolchains", "api-key"),
        ("caches", "AUTH_KEY"),
        ("agents", "tailscale-auth-key"),
        ("toolchains", "token"),
        ("caches", "ACCESS.TOKEN"),
        ("agents", "password"),
        ("toolchains", "passphrase"),
        ("caches", "secret"),
        ("agents", "identity"),
    ];

    for (section, key) in cases {
        let mut manifest = MachineManifest::parse_toml(&valid).unwrap();
        match section {
            "capabilities" => {
                manifest
                    .capabilities
                    .as_mut()
                    .unwrap()
                    .insert(key.to_owned(), true);
            }
            "agents" => {
                manifest.agents.as_mut().unwrap().insert(
                    key.to_owned(),
                    manifest::Agent {
                        installed: Some(true),
                        command: None,
                        sandbox: None,
                        shell: None,
                    },
                );
            }
            "toolchains" => {
                manifest.toolchains.as_mut().unwrap().insert(
                    key.to_owned(),
                    manifest::Toolchain {
                        installed: Some(true),
                        host: None,
                        version: None,
                    },
                );
            }
            "caches" => {
                manifest.caches.as_mut().unwrap().insert(
                    key.to_owned(),
                    manifest::Cache {
                        installed: Some(true),
                        max_bytes: None,
                    },
                );
            }
            _ => unreachable!(),
        }
        for result in [
            manifest.to_toml().map(|_| ()),
            manifest.to_json_value().map(|_| ()),
        ] {
            let error = result.expect_err("{section}.{key} must not serialize");
            let rendered = error.to_string();
            assert!(rendered.contains(section), "{rendered}");
            assert!(rendered.contains(key), "{rendered}");
        }
    }
}

#[test]
fn guarded_serialization_rejects_private_key_and_jwt_values_without_echoing_them() {
    let valid = fs::read_to_string("examples/machine.toml").unwrap();
    let cases = [
        "-----BEGIN PRIVATE KEY-----",
        "  -----begin private key-----",
        "-----BEGIN RSA PRIVATE KEY-----",
        "-----BEGIN EC PRIVATE KEY-----",
        "-----BEGIN DSA PRIVATE KEY-----",
        "-----BEGIN OPENSSH PRIVATE KEY-----",
        "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJzdHlybiIsInJvbGUiOiJ3b3JrZXIifQ.signaturesegmentwithenoughbase64urlchars123",
    ];

    for value in cases {
        let mut manifest = MachineManifest::parse_toml(&valid).unwrap();
        manifest
            .agents
            .as_mut()
            .unwrap()
            .get_mut("codex")
            .unwrap()
            .sandbox = Some(value.to_owned());
        for result in [
            manifest.to_toml().map(|_| ()),
            manifest.to_json_value().map(|_| ()),
        ] {
            let error = result.expect_err("secret-shaped value must not serialize");
            let rendered = error.to_string();
            assert!(rendered.contains("agents.codex.sandbox"), "{rendered}");
            assert!(!rendered.contains(value), "{rendered}");
        }
    }
}

#[test]
fn guarded_serialization_allows_public_and_non_secret_near_misses() {
    let valid = fs::read_to_string("examples/machine.toml").unwrap();
    let cases = [
        "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIGenuinePublicKeyMaterial user@host",
        "-----BEGIN PUBLIC KEY-----",
        "api.styrn.dev",
        "1.2.3",
        "tokenizer",
        "public_key_auth",
        "VGhpcy1pcy1sb25nLWJ1dC1iZW5pZ24tYmFzZTY0LWxpa2UtdGV4dC13aXRob3V0LWRvdHM",
    ];

    for value in cases {
        let manifest = MachineManifest::parse_toml(&valid.replacen(
            "sandbox = \"elevated\"",
            &format!("sandbox = \"{value}\""),
            1,
        ))
        .unwrap();
        assert!(manifest.to_toml().is_ok(), "{value}");
        assert!(manifest.to_json_value().is_ok(), "{value}");
    }
}

#[test]
fn manifest_rejects_hand_authored_invalid_contract_cases() {
    let valid = fs::read_to_string("examples/machine.toml").unwrap();
    let cases = [
        (
            "missing schema version",
            remove_line(&valid, "schema_version ="),
        ),
        (
            "wrong schema version",
            valid.replacen("schema_version = 1", "schema_version = 2", 1),
        ),
        (
            "non version seven uuid",
            valid.replacen(
                "01991f5d-d72f-7b5e-a43d-9fcb61bd3265",
                "01991f5d-d72f-4b5e-a43d-9fcb61bd3265",
                1,
            ),
        ),
        (
            "non canonical uppercase uuid",
            valid.replacen(
                "01991f5d-d72f-7b5e-a43d-9fcb61bd3265",
                "01991F5D-D72F-7B5E-A43D-9FCB61BD3265",
                1,
            ),
        ),
        (
            "duplicate roles",
            valid.replacen(
                "roles = [\"worker\"]",
                "roles = [\"worker\", \"worker\"]",
                1,
            ),
        ),
        (
            "empty roles",
            valid.replacen("roles = [\"worker\"]", "roles = []", 1),
        ),
        (
            "both disk reserve selectors",
            valid.replacen(
                "reserved_disk_bytes = 85899345920",
                "reserved_disk_bytes = 85899345920\nreserved_disk_percent = 15",
                1,
            ),
        ),
        (
            "no disk reserve selector",
            remove_line(&valid, "reserved_disk_bytes ="),
        ),
        (
            "zero positive count",
            valid.replacen("max_heavy_jobs = 1", "max_heavy_jobs = 0", 1),
        ),
        (
            "invalid percent",
            replace_line(
                &fs::read_to_string("examples/machine.controller-worker.toml").unwrap(),
                "reserved_disk_percent =",
                "reserved_disk_percent = 100",
            ),
        ),
        ("unknown field", format!("{valid}\nunexpected = true\n")),
    ];

    for (name, input) in cases {
        let result = MachineManifest::parse_toml(&input).and_then(|manifest| manifest.validate());
        assert!(result.is_err(), "{name} unexpectedly validated");
    }
}

#[test]
fn schema_valid_optional_desktop_kind_is_accepted() {
    let input = format!(
        "{}\n[desktop]\nenabled = false\n",
        fs::read_to_string("examples/machine.toml")
            .unwrap()
            .replace("[desktop]\nkind = \"rdp\"\nenabled = true", "")
    );
    let manifest = MachineManifest::parse_toml(&input).unwrap();
    assert_schema_valid(&manifest.to_json_value().unwrap());
}

#[test]
fn generated_write_mints_once_and_preserves_identity_across_updates() {
    let temp = TestDir::new();
    let path = temp.path().join("machine.toml");
    let store = MachineManifestStore::new(&path);
    let draft = MachineManifest::parse_toml(&fs::read_to_string("examples/machine.toml").unwrap())
        .unwrap()
        .without_machine_id();

    let first = store.write_generated(&draft).unwrap();
    assert_eq!(first.get_version_num(), 7);
    let mut changed = draft.clone();
    changed.name = "renamed-worker".to_owned();
    let second = store.write_generated(&changed).unwrap();

    assert_eq!(first, second);
    let stored = store.read_or_repair().unwrap();
    assert!(!stored.machine_id_minted);
    assert_eq!(stored.manifest.machine_id, first);
    assert_eq!(stored.manifest.name, "renamed-worker");
}

#[test]
fn complete_legitimate_manifest_round_trips_and_persists_without_false_positives() {
    let mut manifest = MachineManifest::parse_toml(
        &fs::read_to_string("examples/machine.controller-worker.toml").unwrap(),
    )
    .unwrap();
    let codex = manifest.agents.as_mut().unwrap().get_mut("codex").unwrap();
    codex.command = Some("codex --ask-for-approval never".to_owned());
    codex.sandbox = Some("workspace-write".to_owned());
    codex.shell = Some("zsh".to_owned());
    manifest.pending_actions = Some(vec![manifest::PendingAction {
        id: "first-login".to_owned(),
        severity: manifest::PendingSeverity::Info,
        message: "Complete the first interactive login.".to_owned(),
    }]);

    manifest.validate().unwrap();
    let canonical_toml = manifest.to_toml().unwrap();
    assert_eq!(
        MachineManifest::parse_toml(&canonical_toml)
            .unwrap()
            .to_json_value()
            .unwrap(),
        manifest.to_json_value().unwrap()
    );

    let temp = TestDir::new();
    let store = MachineManifestStore::new(temp.path().join("machine.toml"));
    let machine_id = store
        .write_generated(&manifest.clone().without_machine_id())
        .unwrap();
    manifest.machine_id = machine_id;
    assert_eq!(
        store
            .read_or_repair()
            .unwrap()
            .manifest
            .to_json_value()
            .unwrap(),
        manifest.to_json_value().unwrap()
    );
}

#[test]
fn secret_bearing_generated_writes_preserve_destinations_and_leave_no_temporary_files() {
    let temp = TestDir::new();
    let path = temp.path().join("machine.toml");
    let store = MachineManifestStore::new(&path);
    let mut secret_draft =
        MachineManifest::parse_toml(&fs::read_to_string("examples/machine.toml").unwrap())
            .unwrap()
            .without_machine_id();
    secret_draft
        .agents
        .as_mut()
        .unwrap()
        .get_mut("codex")
        .unwrap()
        .command = Some("-----BEGIN PRIVATE KEY-----".to_owned());

    assert!(store.write_generated(&secret_draft).is_err());
    assert!(!path.exists());
    assert_no_manifest_temporaries(temp.path());

    let original = fs::read("examples/machine.toml").unwrap();
    fs::write(&path, &original).unwrap();
    assert!(store.write_generated(&secret_draft).is_err());
    assert_eq!(fs::read(&path).unwrap(), original);
    assert_no_manifest_temporaries(temp.path());
}

#[test]
fn secret_bearing_legacy_manifest_does_not_self_heal_or_rewrite() {
    let temp = TestDir::new();
    let path = temp.path().join("machine.toml");
    let secret_legacy = remove_line(
        &fs::read_to_string("examples/machine.toml")
            .unwrap()
            .replacen(
                "sandbox = \"elevated\"",
                "sandbox = \"-----BEGIN OPENSSH PRIVATE KEY-----\"",
                1,
            ),
        "machine_id =",
    );
    fs::write(&path, &secret_legacy).unwrap();

    assert!(MachineManifestStore::new(&path).read_or_repair().is_err());
    assert_eq!(fs::read_to_string(&path).unwrap(), secret_legacy);
    assert_no_manifest_temporaries(temp.path());
}

#[test]
fn invalid_generated_write_does_not_repair_an_existing_stage_zero_manifest() {
    let temp = TestDir::new();
    let path = temp.path().join("machine.toml");
    let stage_zero = remove_line(
        &fs::read_to_string("examples/machine.toml").unwrap(),
        "machine_id =",
    );
    fs::write(&path, &stage_zero).unwrap();
    let mut invalid_draft =
        MachineManifest::parse_toml(&fs::read_to_string("examples/machine.toml").unwrap())
            .unwrap()
            .without_machine_id();
    invalid_draft.schema_version = 2;

    assert!(MachineManifestStore::new(&path)
        .write_generated(&invalid_draft)
        .is_err());
    assert_eq!(fs::read_to_string(path).unwrap(), stage_zero);
}

#[test]
fn missing_machine_id_repairs_once_and_invalid_input_never_rewrites() {
    let temp = TestDir::new();
    let path = temp.path().join("machine.toml");
    let valid = fs::read_to_string("examples/machine.toml").unwrap();
    fs::write(&path, remove_line(&valid, "machine_id =")).unwrap();
    let store = MachineManifestStore::new(&path);

    let repaired = store.read_or_repair().unwrap();
    assert!(repaired.machine_id_minted);
    assert_eq!(repaired.manifest.machine_id.get_version_num(), 7);
    let bytes_after_repair = fs::read(&path).unwrap();
    let second = store.read_or_repair().unwrap();
    assert!(!second.machine_id_minted);
    assert_eq!(second.manifest.machine_id, repaired.manifest.machine_id);
    assert_eq!(fs::read(&path).unwrap(), bytes_after_repair);

    let invalid_bytes = b"schema_version = 1\nname = 'bad'\n".to_vec();
    fs::write(&path, &invalid_bytes).unwrap();
    assert!(store.read_or_repair().is_err());
    assert_eq!(fs::read(&path).unwrap(), invalid_bytes);
}

#[test]
fn complete_manifest_read_is_byte_preserving() {
    let temp = TestDir::new();
    let path = temp.path().join("machine.toml");
    let original = fs::read("examples/machine.toml").unwrap();
    fs::write(&path, &original).unwrap();

    let outcome = MachineManifestStore::new(&path).read_or_repair().unwrap();
    assert!(!outcome.machine_id_minted);
    assert_eq!(fs::read(path).unwrap(), original);
}

#[test]
fn simultaneous_missing_id_repairs_return_one_persisted_uuid() {
    let temp = TestDir::new();
    let path = temp.path().join("machine.toml");
    fs::write(
        &path,
        remove_line(
            &fs::read_to_string("examples/machine.toml").unwrap(),
            "machine_id =",
        ),
    )
    .unwrap();
    let workers = 16;
    let barrier = Arc::new(Barrier::new(workers));
    let (sender, receiver) = mpsc::channel();

    std::thread::scope(|scope| {
        for _ in 0..workers {
            let barrier = Arc::clone(&barrier);
            let sender = sender.clone();
            let path = path.clone();
            scope.spawn(move || {
                barrier.wait();
                sender
                    .send(
                        MachineManifestStore::new(path)
                            .read_or_repair()
                            .unwrap()
                            .manifest
                            .machine_id,
                    )
                    .unwrap();
            });
        }
    });
    drop(sender);
    let ids: Vec<Uuid> = receiver.into_iter().collect();
    assert_eq!(ids.len(), workers);
    assert!(ids.windows(2).all(|pair| pair[0] == pair[1]));
}

struct TestDir(PathBuf);

impl TestDir {
    fn new() -> Self {
        let path = std::env::temp_dir().join(format!("styrn-manifest-test-{}", Uuid::now_v7()));
        fs::create_dir_all(&path).unwrap();
        Self(path)
    }

    fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for TestDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn remove_line(input: &str, starts_with: &str) -> String {
    input
        .lines()
        .filter(|line| !line.trim_start().starts_with(starts_with))
        .collect::<Vec<_>>()
        .join("\n")
}

fn replace_line(input: &str, starts_with: &str, replacement: &str) -> String {
    input
        .lines()
        .map(|line| {
            if line.trim_start().starts_with(starts_with) {
                replacement
            } else {
                line
            }
        })
        .collect::<Vec<_>>()
        .join("\n")
}

fn assert_no_manifest_temporaries(directory: &Path) {
    assert!(
        fs::read_dir(directory)
            .unwrap()
            .map(Result::unwrap)
            .all(|entry| !entry.file_name().to_string_lossy().contains(".tmp")),
        "secret rejection must not leave a temporary manifest"
    );
}
